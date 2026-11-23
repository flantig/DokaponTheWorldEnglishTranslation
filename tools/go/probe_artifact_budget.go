package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type ProbeArtifactAction uint8

const (
	probeArtifactReserve ProbeArtifactAction = iota
	probeArtifactCommit
	probeArtifactRelease
)

type ProbeArtifactClass uint8

const (
	probeArtifactNormal ProbeArtifactClass = iota
	probeArtifactFinalizer
	probeArtifactNative
)

type ProbeArtifactClaim struct {
	ID, Path       string
	MaxFinalBytes  uint64
	Class          ProbeArtifactClass
	ExpectedSHA256 string
	ExpectedInfo   os.FileInfo
}

// ProbeArtifactBudget is owned by the serialized lifecycle, never by a writer.
// Finalizer capacity stays unavailable to ordinary work even after finalization.
// NativeFiles grants mutation only to exact names; a nil pin admits a future file
// only after a named reservation, and its first observed inode becomes the pin.
// SnapshotRoots admits one unknown-name birth per claim, not a directory quota.
// Inventory refuses more than 1<<20 files or min(MaxFiles, 1<<20) distinct
// directories, including empty directories. These are proof limits, not usage.
// Exact registered native sockets count as one file with zero payload bytes;
// Commit never reads a socket. Finalizer-only actions can use their partition
// after ordinary overage, which stays recorded and blocks ordinary actions.
// This is cooperative accounting, not a kernel quota against native writers.
type ProbeArtifactBudget struct {
	MaxFiles, MaxBytes, FinalizerFiles, FinalizerBytes uint64
	Roots, NativeFiles, SnapshotRoots                  map[string]os.FileInfo
	NativeSettings                                     *ProbeNativeSettings
	claims                                             map[string]ProbeArtifactClaim
	active                                             map[string]bool
	observed                                           map[string]os.FileInfo
	held                                               map[string]uint64
	snapshotBaseline                                   map[string]map[string]os.FileInfo
	snapshotBirth                                      map[string]string
	ordinaryExceeded                                   bool
	finalizing                                         bool
}

// accountProbeArtifacts inventories only pinned private roots and exact native
// files. Exposure is the per-path maximum of observed bytes and reserved final
// bytes, including files whose disappearance has not been acknowledged. Commit
// requires the caller's writer AND parent-directory durability acknowledgment;
// ExpectedInfo and SHA256 add stable readback, never manufacture that authority.
// A native claim at an exact SnapshotRoot reserves one additional unknown file
// above a pinned baseline. Commit explicitly binds its ID to the new child using
// writer-provided identity/hash. Release instead requires the directory pin and
// caller's completed unlink/directory-sync (or owned-writer-exit) acknowledgment,
// with the baseline restored. Failed/uncertain actions retain reservations.
func accountProbeArtifacts(budget *ProbeArtifactBudget, action ProbeArtifactAction, claims []ProbeArtifactClaim) error {
	if budget == nil || budget.MaxFiles == 0 || budget.MaxBytes == 0 || budget.FinalizerFiles > budget.MaxFiles || budget.FinalizerBytes > budget.MaxBytes || len(budget.Roots) == 0 {
		return fmt.Errorf("artifact budget requires owned roots and valid file/byte partitions")
	}
	switch action {
	case probeArtifactReserve, probeArtifactCommit, probeArtifactRelease:
	default:
		return fmt.Errorf("unsupported artifact accounting action")
	}
	finalizerOnly := len(claims) != 0
	for _, claim := range claims {
		if claim.Class != probeArtifactFinalizer {
			finalizerOnly = false
		}
	}
	roots := maps.Clone(budget.Roots)
	nativeFiles := maps.Clone(budget.NativeFiles)
	nativeRetirement := false
	for root, pin := range budget.SnapshotRoots {
		if prior, ok := roots[root]; ok && (pin == nil || prior == nil || !os.SameFile(prior, pin)) {
			return fmt.Errorf("artifact snapshot root pin differs: %s", root)
		}
		roots[root] = pin
	}
	directoryLimit := min(budget.MaxFiles, uint64(1<<20))
	queue := make([]string, 0, len(roots))
	queued := map[string]bool{}
	for root, pin := range roots {
		info, err := os.Lstat(root)
		resolved, resolveErr := filepath.EvalSymlinks(root)
		if err != nil || resolveErr != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) || resolved != root || pin == nil || !info.IsDir() || info.Mode().Perm() != 0700 || !os.SameFile(pin, info) {
			return fmt.Errorf("artifact root is not its pinned private0700 directory: %s", root)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Getuid()) {
			return fmt.Errorf("artifact root is not owned by this user: %s", root)
		}
		queue = append(queue, root)
		queued[root] = true
	}
	current := map[string]os.FileInfo{}
	visited := map[string]os.FileInfo{}
	settingsPath, settingsTemp := "", ""
	if settings := budget.NativeSettings; settings != nil {
		reserved := budget.active[settings.Prepared.ID] && budget.claims[settings.Prepared.ID].MaxFinalBytes == 1<<20
		for _, claim := range claims {
			if action == probeArtifactReserve && claim.ID == settings.Prepared.ID && claim.Path == settings.Prepared.Path && claim.MaxFinalBytes == 1<<20 {
				reserved = true
			}
		}
		if settings.Armed || reserved {
			settingsPath = settings.Prepared.Path
		}
	}
	directoryIDs := map[[2]uint64]string{}
	for len(queue) != 0 {
		directory := queue[0]
		queue = queue[1:]
		delete(queued, directory)
		if uint64(len(visited)+len(queue)+1) > directoryLimit {
			return fmt.Errorf("artifact directory inventory exceeds its proof limit")
		}
		if _, seen := visited[directory]; seen {
			continue
		}
		info, err := os.Lstat(directory)
		resolved, resolveErr := filepath.EvalSymlinks(directory)
		if err != nil || resolveErr != nil || resolved != directory || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("artifact inventory directory changed: %s", directory)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Getuid()) {
			return fmt.Errorf("artifact inventory directory owner differs: %s", directory)
		}
		identity := [2]uint64{uint64(stat.Dev), stat.Ino}
		if priorPath, alias := directoryIDs[identity]; alias && priorPath != directory {
			return fmt.Errorf("artifact directory alias is not admitted: %s", directory)
		}
		directoryIDs[identity] = directory
		visited[directory] = info
		file, err := os.Open(directory)
		if err != nil {
			return err
		}
		opened, statErr := file.Stat()
		var entries []os.DirEntry
		var readErr error
		for {
			var batch []os.DirEntry
			batch, readErr = file.ReadDir(256)
			entries = append(entries, batch...)
			if len(entries) > 1<<20 || readErr != nil {
				break
			}
		}
		closeErr := file.Close()
		if statErr != nil || !os.SameFile(info, opened) || readErr != nil && readErr != io.EOF || closeErr != nil || len(entries) > 1<<20 {
			return fmt.Errorf("artifact inventory exceeds its bounded directory read: %s", directory)
		}
		for _, entry := range entries {
			path := filepath.Join(directory, entry.Name())
			info, err := os.Lstat(path)
			if err != nil {
				return fmt.Errorf("artifact inventory entry unavailable: %s", path)
			}
			settingsCandidate := settingsPath != "" && filepath.Dir(path) == filepath.Dir(settingsPath) && strings.HasPrefix(path, settingsPath+".")
			if settingsCandidate && (!budget.NativeSettings.Armed || !info.Mode().IsRegular()) {
				return fmt.Errorf("native settings staging file is not admitted: %s", path)
			}
			if info.IsDir() {
				if _, snapshot := budget.SnapshotRoots[directory]; snapshot {
					return fmt.Errorf("artifact snapshot root contains a directory")
				}
				if _, seen := visited[path]; !seen && !queued[path] {
					if uint64(len(visited)+len(queue)) >= directoryLimit {
						return fmt.Errorf("artifact directory inventory exceeds its proof limit")
					}
					queue = append(queue, path)
					queued[path] = true
				}
				continue
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			_, native := budget.NativeFiles[path]
			ownedSocket := native && info.Mode()&os.ModeSocket != 0
			if !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 || !info.Mode().IsRegular() && !ownedSocket || info.Mode().Perm()&0022 != 0 || info.Size() < 0 {
				return fmt.Errorf("artifact is not an exclusive owned regular file: %s", path)
			}
			current[path] = info
			if settingsCandidate {
				suffix := strings.TrimPrefix(path, settingsPath+".")
				if len(suffix) != 6 || strings.Trim(suffix, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != "" || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 1<<20 || settingsTemp != "" {
					return fmt.Errorf("native settings staging file exceeds its exact slot: %s", path)
				}
				settingsTemp = path
				if !os.SameFile(budget.NativeSettings.Parent, visited[directory]) || info.Mode().Perm() != 0600 {
					return fmt.Errorf("native settings staging parent differs")
				}
				if prior := budget.observed[path]; prior != nil && !os.SameFile(prior, info) {
					return fmt.Errorf("native settings staging inode changed: %s", path)
				}
				// Measured native exposure survives a later semantic/action refusal;
				// this discovery does not accept a new destination identity.
				if budget.held == nil {
					budget.held = map[string]uint64{}
				}
				if budget.observed == nil {
					budget.observed = map[string]os.FileInfo{}
				}
				budget.held[path] = max(budget.held[path], uint64(info.Size()))
				budget.observed[path] = info
			}
			if len(current) > 1<<20 {
				return fmt.Errorf("artifact file inventory exceeds its proof limit")
			}
		}
	}
	for path, pin := range nativeFiles {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("native artifact requires a canonical exact path")
		}
		owned := false
		for root := range roots {
			if strings.HasPrefix(path, root+string(filepath.Separator)) {
				owned = true
			}
		}
		if !owned {
			return fmt.Errorf("native artifact is outside owned roots: %s", path)
		}
		info := current[path]
		if info == nil {
			if pin != nil {
				if action != probeArtifactRelease || len(claims) != 1 {
					return fmt.Errorf("pinned native artifact disappeared: %s", path)
				}
				claim := claims[0]
				prior, exists := budget.claims[claim.ID]
				if !exists || !budget.active[claim.ID] || claim.ID != "native:"+path || prior.Path != path || prior.Class != probeArtifactNative || prior.MaxFinalBytes != 0 || claim.Path != path || claim.Class != probeArtifactNative || claim.MaxFinalBytes != 0 || pin.Mode()&os.ModeSocket == 0 || claim.ExpectedInfo == nil || !os.SameFile(pin, claim.ExpectedInfo) {
					return fmt.Errorf("native socket retirement lacks its exact outstanding inode claim: %s", path)
				}
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					return fmt.Errorf("native socket retirement cannot prove absence: %s", path)
				}
				delete(nativeFiles, path)
				nativeRetirement = true
			}
			continue
		}
		if pin == nil {
			reserved := false
			for id, claim := range budget.claims {
				if budget.active[id] && claim.Path == path && claim.Class == probeArtifactNative {
					reserved = true
				}
			}
			if !reserved {
				return fmt.Errorf("native artifact appeared without its reservation: %s", path)
			}
		} else if !os.SameFile(pin, info) {
			return fmt.Errorf("native artifact inode changed: %s", path)
		}
	}
	if settingsPath != "" {
		if info := current[settingsPath]; info != nil {
			if budget.held == nil {
				budget.held = map[string]uint64{}
			}
			// A refused semantic replacement can still have consumed real bytes.
			budget.held[settingsPath] = max(budget.held[settingsPath], uint64(info.Size()))
		}
		verified, err := validateProbeNativeSettings(budget.NativeSettings, current[settingsPath])
		if err != nil {
			return err
		}
		current[settingsPath] = verified
	}
	for path, prior := range budget.observed {
		info := current[path]
		if info == nil {
			continue // Retain exposure until an explicit absence acknowledgment.
		}
		if path != settingsPath && !os.SameFile(prior, info) {
			return fmt.Errorf("observed artifact inode changed: %s", path)
		}
		mutable := path == settingsPath || path == settingsTemp
		if _, ok := budget.NativeFiles[path]; ok {
			mutable = true
		}
		for id, claim := range budget.claims {
			if budget.active[id] && (claim.Path == path || budget.snapshotBirth[id] == path) {
				mutable = true
			}
		}
		if !mutable && (prior.Size() != info.Size() || prior.ModTime() != info.ModTime() || prior.Mode() != info.Mode()) {
			return fmt.Errorf("unreserved immutable artifact changed: %s", path)
		}
	}
	staged := maps.Clone(budget.claims)
	if staged == nil {
		staged = map[string]ProbeArtifactClaim{}
	}
	active := maps.Clone(budget.active)
	if active == nil {
		active = map[string]bool{}
	}
	baselines := maps.Clone(budget.snapshotBaseline)
	if baselines == nil {
		baselines = map[string]map[string]os.FileInfo{}
	}
	births := maps.Clone(budget.snapshotBirth)
	if births == nil {
		births = map[string]string{}
	}
	observed := maps.Clone(budget.observed)
	if observed == nil {
		observed = map[string]os.FileInfo{}
	}
	held := maps.Clone(budget.held)
	if held == nil {
		held = map[string]uint64{}
	}
	for path, info := range current {
		observed[path] = info
		size := uint64(info.Size())
		if info.Mode()&os.ModeSocket != 0 {
			size = 0
		}
		held[path] = max(held[path], size)
	}
	// Discovery can only increase retained exposure, including on later failures.
	discovered := maps.Clone(observed)
	if settingsPath != "" {
		// A semantically accepted replacement is still provisional until the
		// action and final directory guards succeed. Exposure may only grow.
		if prior := budget.observed[settingsPath]; prior != nil {
			discovered[settingsPath] = prior
		} else {
			delete(discovered, settingsPath)
		}
	}
	budget.observed, budget.held = discovered, maps.Clone(held)
	for id, baseline := range baselines {
		claim := staged[id]
		fresh := ""
		for path, prior := range baseline {
			info := current[path]
			if info == nil || !os.SameFile(prior, info) || prior.Size() != info.Size() || prior.ModTime() != info.ModTime() {
				return fmt.Errorf("snapshot reservation baseline changed")
			}
		}
		for path := range current {
			if filepath.Dir(path) != claim.Path {
				continue
			}
			if _, old := baseline[path]; old {
				continue
			}
			if fresh != "" || births[id] != "" && births[id] != path {
				return fmt.Errorf("snapshot reservation observed more than one new file")
			}
			fresh = path
		}
		if fresh != "" {
			births[id] = fresh
		}
	}
	// Preserve a discovered birth even when a caller supplies an invalid action.
	budget.snapshotBirth = maps.Clone(births)
	seenIDs := map[string]bool{}
	for _, claim := range claims {
		if claim.ID == "" || seenIDs[claim.ID] || !filepath.IsAbs(claim.Path) || filepath.Clean(claim.Path) != claim.Path || claim.Class > probeArtifactNative || claim.MaxFinalBytes > budget.MaxBytes {
			return fmt.Errorf("artifact claim requires a unique ID, canonical path and bounded class/size")
		}
		seenIDs[claim.ID] = true
		owned := false
		for root := range roots {
			if strings.HasPrefix(claim.Path, root+string(filepath.Separator)) {
				owned = true
			}
		}
		_, snapshot := budget.SnapshotRoots[claim.Path]
		if snapshot && claim.Class != probeArtifactNative || !owned && !snapshot {
			return fmt.Errorf("artifact claim is outside its admitted owned namespace")
		}
		prior, exists := staged[claim.ID]
		conversion := exists && baselines[claim.ID] != nil && action == probeArtifactCommit && filepath.Dir(claim.Path) == prior.Path && births[claim.ID] == claim.Path
		if exists && (prior.Class != claim.Class || prior.Path != claim.Path && !conversion) {
			return fmt.Errorf("artifact claim ID changed its path or class")
		}
		for id, other := range staged {
			if id != claim.ID && other.Path == claim.Path && (other.Class != claim.Class || snapshot) {
				return fmt.Errorf("artifact path has conflicting classes or snapshot claims")
			}
		}
		if !snapshot {
			parent := filepath.Dir(claim.Path)
			for {
				if _, admitted := visited[parent]; admitted {
					break
				}
				if info, err := os.Lstat(parent); err == nil || !os.IsNotExist(err) || info != nil {
					return fmt.Errorf("artifact parent is not an inventoried owned directory")
				}
				next := filepath.Dir(parent)
				if next == parent {
					return fmt.Errorf("artifact parent escapes owned directories")
				}
				parent = next
			}
		}
		switch action {
		case probeArtifactReserve:
			if claim.Class == probeArtifactNative && !snapshot {
				if _, admitted := budget.NativeFiles[claim.Path]; !admitted {
					return fmt.Errorf("mutable artifact class requires an exact native-file grant")
				}
			}
			if info := current[claim.Path]; info != nil && claim.ExpectedInfo != nil && !os.SameFile(info, claim.ExpectedInfo) {
				return fmt.Errorf("artifact reservation expected inode differs")
			}
			if exists {
				claim.MaxFinalBytes = max(prior.MaxFinalBytes, claim.MaxFinalBytes)
			}
			if snapshot && !exists {
				baseline := map[string]os.FileInfo{}
				for path, info := range current {
					if filepath.Dir(path) == claim.Path {
						baseline[path] = info
					}
				}
				baselines[claim.ID] = baseline
			}
			staged[claim.ID], active[claim.ID] = claim, true
		case probeArtifactCommit:
			if !exists || !active[claim.ID] || snapshot || baselines[claim.ID] != nil && !conversion {
				return fmt.Errorf("artifact commit requires its active exact-file reservation")
			}
			info := current[claim.Path]
			digest, err := hex.DecodeString(claim.ExpectedSHA256)
			if info == nil || !info.Mode().IsRegular() || claim.ExpectedInfo == nil || !os.SameFile(info, claim.ExpectedInfo) || info.Size() != claim.ExpectedInfo.Size() || info.ModTime() != claim.ExpectedInfo.ModTime() || uint64(info.Size()) > prior.MaxFinalBytes || err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != claim.ExpectedSHA256 {
				return fmt.Errorf("artifact commit lacks its writer identity/hash or exceeds reservation")
			}
			file, err := os.OpenFile(claim.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
			if err != nil {
				return err
			}
			opened, openErr := file.Stat()
			hash := sha256.New()
			count, readErr := io.Copy(hash, io.LimitReader(file, info.Size()+1))
			after, afterErr := file.Stat()
			closeErr := file.Close()
			pathAfter, pathErr := os.Lstat(claim.Path)
			if openErr != nil || readErr != nil || afterErr != nil || closeErr != nil || pathErr != nil || !os.SameFile(info, opened) || !os.SameFile(info, after) || !os.SameFile(info, pathAfter) || info.Size() != after.Size() || info.ModTime() != after.ModTime() || after.Size() != pathAfter.Size() || after.ModTime() != pathAfter.ModTime() || count != info.Size() || fmt.Sprintf("%x", hash.Sum(nil)) != claim.ExpectedSHA256 {
				return fmt.Errorf("artifact commit stable readback differs")
			}
			claim.MaxFinalBytes = uint64(info.Size())
			staged[claim.ID], active[claim.ID] = claim, false
			held[claim.Path] = uint64(info.Size())
			delete(baselines, claim.ID)
			delete(births, claim.ID)
		case probeArtifactRelease:
			if !exists {
				return fmt.Errorf("artifact release requires its outstanding claim")
			}
			if !snapshot && claim.Class == probeArtifactNative && claim.ExpectedInfo != nil && claim.ExpectedInfo.Mode()&os.ModeSocket != 0 && !nativeRetirement {
				return fmt.Errorf("native socket retirement requires its pinned inode")
			}
			if snapshot {
				if claim.ExpectedInfo == nil || !os.SameFile(claim.ExpectedInfo, budget.SnapshotRoots[claim.Path]) {
					return fmt.Errorf("snapshot release requires its acknowledged directory identity")
				}
				for path := range current {
					if filepath.Dir(path) == claim.Path {
						if _, baseline := baselines[claim.ID][path]; !baseline {
							return fmt.Errorf("snapshot release has an unremoved new file")
						}
					}
				}
				delete(held, births[claim.ID])
				delete(observed, births[claim.ID])
			} else {
				if _, err := os.Lstat(claim.Path); !os.IsNotExist(err) {
					return fmt.Errorf("artifact release cannot prove absence")
				}
				delete(held, claim.Path)
				delete(observed, claim.Path)
			}
			delete(staged, claim.ID)
			delete(active, claim.ID)
			delete(baselines, claim.ID)
			delete(births, claim.ID)
		}
	}
	exposure := maps.Clone(held)
	classes := map[string]ProbeArtifactClass{}
	var ordinaryFiles, ordinaryBytes, finalizerFiles, finalizerBytes uint64
	ordinaryExceeded := budget.ordinaryExceeded
	if settingsPath != "" {
		// Reserve the maximum two-file save overlap before the writer starts.
		// Destination capacity belongs to its existing exact-file reservation.
		claim, present := staged[budget.NativeSettings.Prepared.ID]
		if !present || !active[claim.ID] || claim.Path != settingsPath || claim.Class != probeArtifactNormal || claim.MaxFinalBytes != 1<<20 {
			return fmt.Errorf("native settings lack their exact destination reservation")
		}
		if budget.MaxBytes-budget.FinalizerBytes < 1<<20 {
			return fmt.Errorf("native settings temporary slot exceeds ordinary capacity")
		}
		ordinaryFiles, ordinaryBytes = 1, 1<<20
	}
	for id, claim := range staged {
		path := claim.Path
		if baselines[id] != nil {
			path = births[id]
			if path == "" {
				ordinaryFiles++
				if claim.MaxFinalBytes > budget.MaxBytes-budget.FinalizerBytes-ordinaryBytes {
					return fmt.Errorf("artifact snapshot byte reservation exceeds ordinary capacity")
				}
				ordinaryBytes += claim.MaxFinalBytes
				continue
			}
		}
		exposure[path] = max(exposure[path], claim.MaxFinalBytes)
		classes[path] = claim.Class
	}
	for path, size := range exposure {
		if path == settingsTemp {
			continue // Its live exposure is already charged to the one-MiB slot.
		}
		if classes[path] == probeArtifactFinalizer {
			finalizerFiles++
			if size > budget.FinalizerBytes-finalizerBytes {
				return fmt.Errorf("artifact finalizer byte capacity exceeded")
			}
			finalizerBytes += size
		} else {
			ordinaryFiles++
			if size > budget.MaxBytes-budget.FinalizerBytes-ordinaryBytes {
				ordinaryExceeded = true
				ordinaryBytes = budget.MaxBytes - budget.FinalizerBytes
			} else {
				ordinaryBytes += size
			}
		}
	}
	if finalizerFiles > budget.FinalizerFiles {
		return fmt.Errorf("artifact finalizer file capacity exceeded")
	}
	ordinaryExceeded = ordinaryExceeded || ordinaryFiles > budget.MaxFiles-budget.FinalizerFiles
	budget.ordinaryExceeded = ordinaryExceeded
	if ordinaryExceeded && !finalizerOnly && !(nativeRetirement && budget.finalizing) {
		return fmt.Errorf("artifact ordinary capacity exceeded; only reserved finalization remains available")
	}
	for directory, prior := range visited {
		info, err := os.Lstat(directory)
		resolved, resolveErr := filepath.EvalSymlinks(directory)
		if err != nil || resolveErr != nil || resolved != directory || !info.IsDir() || !os.SameFile(prior, info) || prior.Mode() != info.Mode() {
			return fmt.Errorf("artifact directory authority changed during accounting: %s", directory)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Getuid()) {
			return fmt.Errorf("artifact directory owner changed during accounting: %s", directory)
		}
	}
	if settingsPath != "" {
		prior := current[settingsPath]
		info, err := os.Lstat(settingsPath)
		if err != nil || !os.SameFile(prior, info) || prior.Size() != info.Size() || prior.ModTime() != info.ModTime() || prior.Mode() != info.Mode() {
			return fmt.Errorf("native settings changed before accounting acknowledgment")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
			return fmt.Errorf("native settings ownership changed before acknowledgment")
		}
		if settingsTemp != "" {
			info, err := os.Lstat(settingsTemp)
			if err != nil || !os.SameFile(current[settingsTemp], info) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 0 || info.Size() > 1<<20 {
				return fmt.Errorf("native settings staging identity changed before acknowledgment")
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
				return fmt.Errorf("native settings staging ownership changed before acknowledgment")
			}
			observed[settingsTemp] = info
			held[settingsTemp] = max(held[settingsTemp], uint64(info.Size()))
		}
		parent, err := os.Lstat(filepath.Dir(settingsPath))
		if err != nil || !os.SameFile(budget.NativeSettings.Parent, parent) || !parent.IsDir() || parent.Mode().Perm() != 0700 {
			return fmt.Errorf("native settings parent changed before acknowledgment")
		}
		parentStat, ok := parent.Sys().(*syscall.Stat_t)
		if !ok || parentStat.Uid != uint32(os.Getuid()) {
			return fmt.Errorf("native settings parent owner changed before acknowledgment")
		}
	}
	budget.claims, budget.active = staged, active
	budget.snapshotBaseline, budget.snapshotBirth = baselines, births
	budget.observed, budget.held = observed, held
	budget.NativeFiles = nativeFiles
	for path, pin := range budget.NativeFiles {
		if pin == nil && current[path] != nil {
			budget.NativeFiles[path] = current[path]
		}
	}
	return nil
}
