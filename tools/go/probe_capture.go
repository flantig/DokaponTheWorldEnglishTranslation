package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// captureProbeEvidence performs one serialized screenshot transaction. Lock wait
// and capture have separate source budgets; uncertain attempts are not retried.
// Original PNGs and failed partials remain intact. No resize/JPEG parity follows.
func captureProbeEvidence(raw, runtimeRaw []byte) (ProbeCaptureReceipt, error) {
	var receipt ProbeCaptureReceipt
	if len(raw) == 0 || len(raw) > 4<<20 || len(runtimeRaw) == 0 || len(runtimeRaw) > 65536 {
		return receipt, fmt.Errorf("capture requires bounded profile and explicit runtime descriptor")
	}
	for _, data := range [][]byte{raw, runtimeRaw} {
		if err := checkJSON(checkedJSON{raw: data, allObjects: true, text: true}); err != nil {
			return receipt, err
		}
	}
	var profile ProbeCaptureProfile
	var runtime ProbeCaptureRuntime
	for index, data := range [][]byte{raw, runtimeRaw} {
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		var target any = &profile
		if index == 1 {
			target = &runtime
		}
		if err := decoder.Decode(target); err != nil {
			return receipt, err
		}
	}
	if profile.Version != 1 || profile.SourceSHA256 != "5439db31097c19d3b92969d5403c2c19dc3518cea4ed4c075df1a3830b8ef56f" || profile.PadSourceSHA256 != "1c1dab832d28026ad960eeb9d08e19c5ab40e00f9c30517aadc906921c555a36" {
		return receipt, fmt.Errorf("unsupported capture version or backend source")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(profile.CaptureID) || profile.EventID < 1 || profile.Checkpoint < 1 || profile.LogOffset < 0 || profile.LogBytes < 1 || profile.LogBytes > 1<<20 {
		return receipt, fmt.Errorf("capture requires stable ID and bounded source event slice")
	}
	if profile.LockTimeoutMS == 0 {
		profile.LockTimeoutMS = 10000
	}
	if profile.CaptureTimeoutMS == 0 {
		profile.CaptureTimeoutMS = 10000
	}
	if profile.LockTimeoutMS < 1 || profile.LockTimeoutMS > 10000 || profile.CaptureTimeoutMS < 1 || profile.CaptureTimeoutMS > 10000 || profile.MaxSnapshotFiles < 1 || profile.MaxSnapshotFiles > 256 || profile.MaxImageBytes < 1 || profile.MaxImageBytes > 16<<20 || profile.MaxPixels < 1 || profile.MaxPixels > 1<<20 || profile.MaxRetainedFiles < 2 || profile.MaxRetainedFiles > 1024 || profile.MaxRetainedBytes < 1 || profile.MaxRetainedBytes > 512<<20 {
		return receipt, fmt.Errorf("capture policy exceeds finite source/resource bounds")
	}
	if runtime.Memory.Provenance != "synthetic_peer" && runtime.Memory.Provenance != "live" && runtime.Memory.Provenance != "owned_go" || runtime.BackendPID < 1 {
		return receipt, fmt.Errorf("capture requires explicit backend ownership and provenance")
	}
	if runtime.Memory.Provenance == "live" && (profile.LockTimeoutMS != 10000 || profile.CaptureTimeoutMS != 10000) {
		return receipt, fmt.Errorf("live capture requires separate source10s lock and capture budgets")
	}
	var memoryPlan ProbeMemoryBundle
	if err := json.Unmarshal(profile.Memory, &memoryPlan); err != nil {
		return receipt, err
	}
	if len(memoryPlan.Replies) != 0 || len(memoryPlan.Requests) < 1 || len(memoryPlan.Requests) > 256 {
		return receipt, fmt.Errorf("capture requires a live-plan read set with at most512 before/after requests")
	}
	declaredTags, declaredUI := false, false
	for _, decoder := range memoryPlan.Decoders {
		switch decoder.Kind {
		case "frame_tags":
			declaredTags = true
		case "fixed", "player", "cursor", "texture", "char":
			declaredUI = true
		}
	}
	if !declaredTags || !declaredUI {
		return receipt, fmt.Errorf("capture plan requires source frame tags and UI decoders")
	}
	admission, err := admitProbeRecords(memoryPlan.Admission)
	if err != nil {
		return receipt, err
	}
	var records ProbeRecordBundle
	_ = json.Unmarshal(memoryPlan.Admission, &records)
	var owned ProbeProcessRecord
	var admittedProfile ProbeProfileRecord
	for _, record := range records.Records {
		switch record.Role {
		case "owned":
			_ = json.Unmarshal(record.Data, &owned)
		case "profile":
			_ = json.Unmarshal(record.Data, &admittedProfile)
		}
	}
	if (runtime.Memory.Provenance == "live" || runtime.Memory.Provenance == "owned_go") && runtime.Snapshots != filepath.Join(admittedProfile.DataRoot, "snaps") {
		return receipt, fmt.Errorf("capture snapshot root differs from admitted native data root")
	}
	dirs := []string{runtime.Memory.Root, runtime.Snapshots, runtime.Output}
	var directoryInfo []os.FileInfo
	for _, directory := range dirs {
		info, err := os.Lstat(directory)
		resolved, resolveErr := filepath.EvalSymlinks(directory)
		if err != nil || resolveErr != nil || !filepath.IsAbs(directory) || resolved != directory || !info.IsDir() || info.Mode().Perm() != 0700 {
			return receipt, fmt.Errorf("capture roots must be explicit private0700 directories without symlinks")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Getuid()) {
			return receipt, fmt.Errorf("capture roots must be owned by this user")
		}
		for _, prior := range directoryInfo {
			if os.SameFile(prior, info) {
				return receipt, fmt.Errorf("capture roots must be distinct")
			}
		}
		directoryInfo = append(directoryInfo, info)
	}
	imageName, receiptName := profile.CaptureID+".png", profile.CaptureID+".json"
	logPath := filepath.Join(runtime.Memory.Root, "events.jsonl")
	logInfo, err := os.Lstat(logPath)
	if err != nil || !logInfo.Mode().IsRegular() || profile.LogOffset > logInfo.Size()-int64(profile.LogBytes) {
		return receipt, fmt.Errorf("capture source log slice unavailable")
	}
	logFile, err := os.Open(logPath)
	if err != nil {
		return receipt, err
	}
	logData := make([]byte, profile.LogBytes)
	_, readErr := logFile.ReadAt(logData, profile.LogOffset)
	_ = logFile.Close()
	if readErr != nil || fmt.Sprintf("%x", sha256.Sum256(logData)) != profile.LogSHA256 || logData[len(logData)-1] != '\n' {
		return receipt, fmt.Errorf("capture source log slice differs")
	}
	var event struct {
		EventID    int    `json:"event_id"`
		Checkpoint int    `json:"checkpoint"`
		Event      string `json:"event"`
	}
	if err := checkJSON(checkedJSON{raw: logData, allObjects: true, text: true}); err != nil {
		return receipt, err
	}
	if err := json.Unmarshal(logData, &event); err != nil || event.EventID != profile.EventID || event.Checkpoint != profile.Checkpoint || event.Event == "" {
		return receipt, fmt.Errorf("capture source event identity differs")
	}
	receipt = ProbeCaptureReceipt{Version: 1, SourceSHA256: profile.SourceSHA256, PadSourceSHA256: profile.PadSourceSHA256, CaptureID: profile.CaptureID, EventID: profile.EventID, Checkpoint: profile.Checkpoint, RunID: admission.RunID, Session: admission.Session, Epoch: admission.Epoch, PID: owned.PID, Starttime: owned.Starttime, ISOSHA256: admission.ISOSHA256, BuildSHA256: memoryPlan.BuildSHA256, Provenance: runtime.Memory.Provenance, Status: "UNKNOWN", Reason: "capture did not complete", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), LockBudgetMS: profile.LockTimeoutMS, CaptureBudgetMS: profile.CaptureTimeoutMS, SnapshotPreserved: true, LogOffset: profile.LogOffset, LogSHA256: profile.LogSHA256, LogHex: hex.EncodeToString(logData), Representation: "original-png", Derivatives: "Pillow RGB/default640x480 resize and JPEG parity unqualified; no derivative produced", PolicyStatus: "profile-caps-enforced; native owner retention/resource agreement pending"}
	lockPath := filepath.Join(filepath.Dir(runtime.Snapshots), "capture.lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return receipt, err
	}
	defer lock.Close()
	lockInfo, err := lock.Stat()
	if err != nil || !lockInfo.Mode().IsRegular() {
		return receipt, fmt.Errorf("capture lock must be regular")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	var imageData []byte
	outputAdmitted := false
transaction:
	for {
		lockDeadline := time.Now().Add(time.Duration(profile.LockTimeoutMS) * time.Millisecond)
		for {
			err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			if err == nil {
				break
			}
			if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
				receipt.Reason = "capture lock failed"
				break transaction
			}
			remaining := time.Until(lockDeadline)
			if remaining <= 0 {
				receipt.Reason = "capture lock timeout"
				break transaction
			}
			time.Sleep(min(20*time.Millisecond, remaining))
		}
		// The second budget starts only after this request acquires the shared lock.
		deadline := time.Now().Add(time.Duration(profile.CaptureTimeoutMS) * time.Millisecond)
		// Check capacity under the shared lock so queued captures cannot all
		// reserve the same remaining space before an earlier capture publishes.
		outputDir, err := os.Open(runtime.Output)
		if err != nil {
			return receipt, err
		}
		entries, scanErr := outputDir.ReadDir(profile.MaxRetainedFiles + 1)
		_ = outputDir.Close()
		if scanErr != nil && scanErr != io.EOF {
			return receipt, scanErr
		}
		totalBytes := int64(0)
		for _, entry := range entries {
			info, err := os.Lstat(filepath.Join(runtime.Output, entry.Name()))
			if err != nil || !info.Mode().IsRegular() {
				return receipt, fmt.Errorf("capture output contains an unsupported entry")
			}
			totalBytes += info.Size()
			if entry.Name() == imageName || entry.Name() == receiptName {
				return receipt, fmt.Errorf("capture ID already has an output; no retry or overwrite")
			}
		}
		if len(entries)+2 > profile.MaxRetainedFiles || profile.MaxImageBytes+(4<<20) > profile.MaxRetainedBytes-totalBytes {
			receipt.Reason = "capture retention capacity exhausted before trigger"
			break
		}
		outputAdmitted = true
		baseline := map[string]os.FileInfo{}
		snapshotDir, err := os.Open(runtime.Snapshots)
		if err != nil {
			receipt.Reason = "snapshot inventory unavailable"
			break
		}
		old, err := snapshotDir.ReadDir(profile.MaxSnapshotFiles + 1)
		_ = snapshotDir.Close()
		if err != nil && err != io.EOF || len(old) >= profile.MaxSnapshotFiles {
			receipt.Reason = "snapshot inventory has no fresh-file capacity"
			break
		}
		for _, entry := range old {
			info, err := os.Lstat(filepath.Join(runtime.Snapshots, entry.Name()))
			if err != nil || !info.Mode().IsRegular() {
				receipt.Reason = "snapshot inventory has an unsupported entry"
				break transaction
			}
			baseline[entry.Name()] = info
		}
		memoryRuntime := runtime.Memory
		memoryRuntime.TimeoutMS = min(memoryRuntime.TimeoutMS, int(time.Until(deadline).Milliseconds()))
		memoryRaw, _ := json.Marshal(memoryRuntime)
		before, err := readProbeMemory(profile.Memory, memoryRaw)
		if err != nil {
			receipt.Status, receipt.Reason = "REFUSED", "capture pre-read: "+err.Error()
			break
		}
		receipt.MemoryBefore = &before
		knownTags, knownUI := false, false
		for _, decoded := range before.Decoded {
			if decoded.Status != "KNOWN" {
				continue
			}
			switch decoded.Kind {
			case "frame_tags":
				knownTags = len(decoded.FrameTags) == 3
			case "player":
				knownUI = knownUI || decoded.Player != nil
			case "cursor":
				knownUI = knownUI || decoded.Cursor != nil
			case "fixed", "texture", "char":
				knownUI = knownUI || decoded.Text != nil
			}
		}
		if !knownTags || !knownUI || len(before.Observations) == 0 {
			receipt.Reason = "capture lacks known source frame tags or decoded UI"
			break
		}
		padSocket := "/tmp/claude-1000/dokapon/vpad.sock"
		if runtime.Memory.Provenance == "synthetic_peer" || runtime.Memory.Provenance == "owned_go" {
			padSocket = filepath.Join(runtime.Memory.Root, "pad.sock")
		}
		padInfo, err := os.Lstat(padSocket)
		if err != nil || padInfo.Mode()&os.ModeSocket == 0 {
			receipt.Reason = "capture backend socket unavailable"
			break
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			receipt.Reason = "capture budget exhausted before trigger"
			break
		}
		pad, err := net.DialTimeout("unix", padSocket, remaining)
		if err != nil {
			receipt.Reason = "capture backend connection failed"
			break
		}
		peerFile, fileErr := pad.(*net.UnixConn).File()
		if fileErr != nil {
			_ = pad.Close()
			receipt.Reason = "capture backend identity unavailable"
			break
		}
		credentials, credentialErr := syscall.GetsockoptUcred(int(peerFile.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		_ = peerFile.Close()
		if credentialErr != nil || int(credentials.Pid) != runtime.BackendPID || credentials.Uid != uint32(os.Getuid()) {
			_ = pad.Close()
			receipt.Status, receipt.Reason = "REFUSED", "capture backend is not the declared owned peer"
			break
		}
		_ = pad.SetDeadline(deadline)
		receipt.GuideCommand = "tap GUIDE 0.05"
		_, sendErr := io.Copy(pad, strings.NewReader(receipt.GuideCommand))
		// The Go backend frames one command by half-close; legacy one-read peers
		// receive the same complete payload before replying.
		if sendErr == nil {
			sendErr = pad.(*net.UnixConn).CloseWrite()
		}
		ack, ackErr := io.ReadAll(io.LimitReader(pad, 257))
		_ = pad.Close()
		receipt.GuideAckHex = hex.EncodeToString(ack)
		if sendErr != nil || ackErr != nil || len(ack) > 256 || strings.TrimSpace(string(ack)) != "ok" {
			receipt.Reason = "capture trigger acknowledgement unknown"
			break
		}
		var capturedInfo os.FileInfo
		for {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				receipt.Reason = "capture deadline expired without a complete stable PNG"
				break transaction
			}
			currentDir, err := os.Lstat(runtime.Snapshots)
			if err != nil || !os.SameFile(directoryInfo[1], currentDir) {
				receipt.Status, receipt.Reason = "REFUSED", "snapshot directory identity changed"
				break transaction
			}
			directory, err := os.Open(runtime.Snapshots)
			if err != nil {
				receipt.Reason = "snapshot directory unavailable"
				break transaction
			}
			entries, scanErr := directory.ReadDir(profile.MaxSnapshotFiles + 1)
			_ = directory.Close()
			if scanErr != nil && scanErr != io.EOF || len(entries) > profile.MaxSnapshotFiles {
				receipt.Reason = "snapshot file budget exceeded"
				break transaction
			}
			var candidates []string
			for _, entry := range entries {
				info, err := os.Lstat(filepath.Join(runtime.Snapshots, entry.Name()))
				if err != nil || !info.Mode().IsRegular() {
					receipt.Status, receipt.Reason = "REFUSED", "snapshot entry is not a stable regular file"
					break transaction
				}
				if prior, old := baseline[entry.Name()]; old {
					if !os.SameFile(prior, info) || prior.Size() != info.Size() || prior.ModTime() != info.ModTime() {
						receipt.Status, receipt.Reason = "REFUSED", "preexisting snapshot changed"
						break transaction
					}
					continue
				}
				if strings.HasSuffix(entry.Name(), ".png") {
					candidates = append(candidates, entry.Name())
				}
			}
			if len(candidates) > 1 {
				receipt.Reason = "ambiguous fresh snapshots"
				break transaction
			}
			if len(candidates) == 1 {
				receipt.Snapshot = candidates[0]
				path := filepath.Join(runtime.Snapshots, receipt.Snapshot)
				observed, statErr := os.Lstat(path)
				if statErr != nil {
					receipt.Reason = "fresh snapshot disappeared"
					break transaction
				}
				if observed.Size() > profile.MaxImageBytes {
					receipt.Reason = "fresh PNG exceeds byte budget"
					break transaction
				}
				data, err := readInput(path, profile.MaxImageBytes)
				if err == nil {
					raster, _, decodeErr := decodePNG(data, profile.MaxPixels)
					if decodeErr == nil {
						capturedInfo, err = os.Lstat(path)
						if err != nil {
							receipt.Reason = "fresh snapshot disappeared"
							break transaction
						}
						if !os.SameFile(observed, capturedInfo) || observed.Size() != capturedInfo.Size() || observed.ModTime() != capturedInfo.ModTime() {
							// A producer may still be finishing the new PNG. It must settle
							// within this same deadline before any bytes can be accepted.
							time.Sleep(min(20*time.Millisecond, time.Until(deadline)))
							continue
						}
						receipt.ImageSHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
						receipt.ImageBytes = int64(len(data))
						receipt.Width = raster.Bounds().Dx()
						receipt.Height = raster.Bounds().Dy()
						imageData = data
						break
					}
				}
			}
			time.Sleep(min(20*time.Millisecond, remaining))
		}
		memoryRuntime.TimeoutMS = min(runtime.Memory.TimeoutMS, int(time.Until(deadline).Milliseconds()))
		memoryRaw, _ = json.Marshal(memoryRuntime)
		after, err := readProbeMemory(profile.Memory, memoryRaw)
		if err != nil {
			receipt.Status, receipt.Reason = "REFUSED", "capture post-read: "+err.Error()
			break
		}
		receipt.MemoryAfter = &after
		if before.Session != after.Session || before.Epoch != after.Epoch || before.BuildSHA256 != after.BuildSHA256 || before.SessionEvidenceSHA256 != after.SessionEvidenceSHA256 {
			receipt.Status, receipt.Reason = "REFUSED", "capture session or build changed"
			break
		}
		if !reflect.DeepEqual(before.Decoded, after.Decoded) {
			receipt.Reason = "decoded UI changed across sequential capture"
			break
		}
		for index, path := range dirs {
			info, err := os.Lstat(path)
			if err != nil || !os.SameFile(directoryInfo[index], info) {
				receipt.Status, receipt.Reason = "REFUSED", "capture root identity changed"
				break transaction
			}
		}
		currentLog, err := os.Lstat(logPath)
		if err != nil || !os.SameFile(logInfo, currentLog) {
			receipt.Status, receipt.Reason = "REFUSED", "capture log identity changed"
			break
		}
		file, err := os.Open(logPath)
		if err != nil {
			receipt.Status, receipt.Reason = "REFUSED", "capture log unavailable after acquisition"
			break
		}
		currentData := make([]byte, len(logData))
		_, err = file.ReadAt(currentData, profile.LogOffset)
		_ = file.Close()
		if err != nil || !bytes.Equal(currentData, logData) {
			receipt.Status, receipt.Reason = "REFUSED", "capture source log changed"
			break
		}
		path := filepath.Join(runtime.Snapshots, receipt.Snapshot)
		finalDirectory, err := os.Open(runtime.Snapshots)
		if err != nil {
			receipt.Status, receipt.Reason = "REFUSED", "snapshot directory unavailable before publication"
			break
		}
		finalEntries, finalErr := finalDirectory.ReadDir(profile.MaxSnapshotFiles + 1)
		_ = finalDirectory.Close()
		fresh := 0
		for _, entry := range finalEntries {
			if _, old := baseline[entry.Name()]; !old && strings.HasSuffix(entry.Name(), ".png") {
				fresh++
			}
		}
		if finalErr != nil && finalErr != io.EOF || len(finalEntries) > profile.MaxSnapshotFiles || fresh != 1 {
			receipt.Reason = "ambiguous fresh snapshots"
			break
		}
		current, err := os.Lstat(path)
		stableData, readErr := readInput(path, profile.MaxImageBytes)
		if err != nil || readErr != nil || !os.SameFile(capturedInfo, current) || !bytes.Equal(stableData, imageData) {
			receipt.Status, receipt.Reason = "REFUSED", "captured PNG changed before publication"
			break
		}
		if time.Now().After(deadline) {
			receipt.Reason = "capture deadline expired before publication"
			break
		}
		if err := writeNewFile(filepath.Join(runtime.Output, imageName), bytes.NewReader(imageData), int64(len(imageData)), receipt.ImageSHA256, 0600); err != nil {
			receipt.Status, receipt.Reason = "REFUSED", "capture image publication failed: "+err.Error()
			break
		}
		receipt.ImagePath = imageName
		receipt.Status, receipt.Reason = "CAPTURED", ""
		break
	}
	receipt.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if !outputAdmitted {
		// Failed lock/quota admission grants no persistent artifact capacity.
		return receipt, nil
	}
	encoded, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return receipt, err
	}
	if len(encoded) > 4<<20 {
		return receipt, fmt.Errorf("capture receipt exceeds4MiB budget")
	}
	if err := writeNewFile(filepath.Join(runtime.Output, receiptName), bytes.NewReader(encoded), int64(len(encoded)), fmt.Sprintf("%x", sha256.Sum256(encoded)), 0600); err != nil {
		return receipt, err
	}
	return receipt, nil
}
