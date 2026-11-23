package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
)

// captureProbeEvidence performs one serialized screenshot transaction. Lock wait
// and capture have separate source budgets; uncertain attempts are not retried.
// A nil managed output preserves original PNGs/partials and the raw contract.
// Internal managed callers reserve transient input/working bytes before calling;
// only fully checked, unlinked samples populate the output. This is no run quota.
func captureProbeEvidence(raw, runtimeRaw []byte, managed *ProbeFrameSample, budget *ProbeArtifactBudget) (ProbeCaptureReceipt, error) {
	var receipt ProbeCaptureReceipt
	if managed != nil {
		*managed = ProbeFrameSample{}
		receipt.ManagedFailure = probeCaptureAuthority
	}
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
	if profile.Version != 1 || profile.SourceSHA256 != "5439db31097c19d3b92969d5403c2c19dc3518cea4ed4c075df1a3830b8ef56f" {
		return receipt, fmt.Errorf("unsupported capture version or backend source")
	}
	if !regexp.MustCompile(probeCaptureIDPattern).MatchString(profile.CaptureID) || profile.EventID < 1 || profile.Checkpoint < 0 || profile.LogOffset < 0 || profile.LogBytes < 1 || profile.LogBytes > 1<<20 {
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
	if !declaredTags || managed == nil && !declaredUI {
		return receipt, fmt.Errorf("capture plan requires source frame tags and UI decoders")
	}
	admission, err := admitProbeRecords(memoryPlan.Admission)
	if err != nil {
		return receipt, err
	}
	var records ProbeRecordBundle
	_ = json.Unmarshal(memoryPlan.Admission, &records)
	privateX11 := profile.TriggerBackend == "private-x11"
	if privateX11 {
		if records.GoOwner == nil || records.GoOwner.Profile.PadBackend != "private-x11" || records.GoOwner.Profile.PrivateX11 == nil || profile.PadSourceSHA256 != fmt.Sprintf("%x", sha256.Sum256(probePadLayout)) || runtime.Memory.Provenance != "owned_go" {
			return receipt, fmt.Errorf("private capture trigger lacks admitted keyboard transport")
		}
	} else if profile.TriggerBackend != "" || profile.PadSourceSHA256 != "1c1dab832d28026ad960eeb9d08e19c5ab40e00f9c30517aadc906921c555a36" || records.GoOwner != nil && records.GoOwner.Profile.PadBackend == "private-x11" {
		return receipt, fmt.Errorf("unsupported capture trigger transport or source")
	}
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
	if managed != nil {
		if profile.Checkpoint != 0 || memoryPlan.Version != 1 || memoryPlan.SourceSHA256 != profile.SourceSHA256 || len(memoryPlan.WordGuards) != 0 || memoryPlan.DiagnosticVersion != "" || len(memoryPlan.Requests) != 3 || len(memoryPlan.Decoders) != 1 {
			return receipt, fmt.Errorf("managed capture requires ordinary admitted Go epoch and canonical tag plan")
		}
		switch runtime.Memory.Provenance {
		case "owned_go":
			if records.GoOwner == nil || owned.Epoch == nil || *owned.Epoch != admission.Epoch || memoryPlan.BuildSHA256 != records.GoOwner.Profile.Program.SHA256 {
				return receipt, fmt.Errorf("managed capture lacks its admitted Go epoch")
			}
		case "synthetic_peer":
			if admission.SourceSchema != "text-probe-legacy-2026-11-13" || records.GoOwner != nil {
				return receipt, fmt.Errorf("managed synthetic fixture requires legacy admission without Go ownership")
			}
		default:
			return receipt, fmt.Errorf("managed capture requires owned Go or explicit synthetic provenance")
		}
		for index, field := range []struct {
			Opcode  uint8
			Address uint32
		}{{1, 0x56581c}, {1, 0x56b598}, {0, 0x56b18c}} {
			read := memoryPlan.Requests[index]
			if read.ID != fmt.Sprintf("tag%d", index) || read.Opcode == nil || read.Address == nil || *read.Opcode != field.Opcode || *read.Address != field.Address {
				return receipt, fmt.Errorf("managed capture tag requests differ from source")
			}
		}
		decoder := memoryPlan.Decoders[0]
		if decoder.ID != "source-tags" || decoder.Kind != "frame_tags" || !slices.Equal(decoder.Requests, []string{"tag0", "tag1", "tag2"}) || len(decoder.Glyphmap) != 0 {
			return receipt, fmt.Errorf("managed capture requires one canonical frame-tags decoder")
		}
	}
	if (managed != nil || runtime.Memory.Provenance == "live" || runtime.Memory.Provenance == "owned_go") && runtime.Snapshots != filepath.Join(admittedProfile.DataRoot, "snaps") {
		return receipt, fmt.Errorf("capture snapshot root differs from admitted native data root")
	}
	dirs := []string{runtime.Memory.Root, runtime.Snapshots, runtime.Output}
	if managed != nil {
		parent := filepath.Dir(runtime.Snapshots)
		if !slices.Contains(dirs, parent) {
			dirs = append(dirs, parent)
		}
	}
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
	// Positive checkpoint logs historically ignored all fields except this header.
	var event struct {
		Event      string `json:"event"`
		EventID    int    `json:"event_id"`
		Checkpoint *int   `json:"checkpoint"`
	}
	if err := checkJSON(checkedJSON{raw: logData, allObjects: true, text: true}); err != nil {
		return receipt, err
	}
	if err := json.Unmarshal(logData, &event); err != nil || event.EventID != profile.EventID || event.Checkpoint == nil || *event.Checkpoint != profile.Checkpoint || event.Event == "" {
		return receipt, fmt.Errorf("capture source event identity differs")
	}
	if profile.Checkpoint == 0 {
		if err := checkJSON(checkedJSON{raw: raw, requiredByDepth: map[int][]string{1: {"checkpoint"}}, nonNullByDepth: map[int][]string{1: {"checkpoint"}}, aliasesByDepth: map[int][]string{1: {"checkpoint"}}}); err != nil {
			return receipt, err
		}
		var ordinary ProbeCaptureEvent
		if err := json.Unmarshal(logData, &ordinary); err != nil || event.Event != probeOrdinaryFrameEventKind || ordinary.CaptureID != profile.CaptureID {
			return receipt, fmt.Errorf("ordinary capture source kind or capture ID differs")
		}
		if _, err := time.Parse("2006-01-02T15:04:05-0700", ordinary.Time); err != nil {
			return receipt, fmt.Errorf("ordinary capture source time differs")
		}
	} else if event.Event == probeOrdinaryFrameEventKind {
		return receipt, fmt.Errorf("ordinary capture requires explicit checkpoint zero")
	}

	receipt = ProbeCaptureReceipt{ManagedFailure: receipt.ManagedFailure, Version: 1, SourceSHA256: profile.SourceSHA256, PadSourceSHA256: profile.PadSourceSHA256, CaptureID: profile.CaptureID, EventID: profile.EventID, Checkpoint: profile.Checkpoint, RunID: admission.RunID, Session: admission.Session, Epoch: admission.Epoch, PID: owned.PID, Starttime: owned.Starttime, ISOSHA256: admission.ISOSHA256, BuildSHA256: memoryPlan.BuildSHA256, Provenance: runtime.Memory.Provenance, Status: "UNKNOWN", Reason: "capture did not complete", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), LockBudgetMS: profile.LockTimeoutMS, CaptureBudgetMS: profile.CaptureTimeoutMS, SnapshotPreserved: true, LogOffset: profile.LogOffset, LogSHA256: profile.LogSHA256, LogHex: hex.EncodeToString(logData), Representation: "original-png", Derivatives: "Pillow RGB/default640x480 resize and JPEG parity unqualified; no derivative produced", PolicyStatus: "profile-caps-enforced; native owner retention/resource agreement pending"}
	receipt.TriggerBackend = profile.TriggerBackend
	if managed != nil {
		receipt.Representation = "transient-rgb640"
		receipt.Derivatives = "RGB640 and RGB64 in memory only; no JPEG or compatibility claim"
		receipt.PolicyStatus = "internal-managed; native caps enforced; whole-run reservation is caller precondition"
	}
	lockPath := filepath.Join(filepath.Dir(runtime.Snapshots), "capture.lock")
	if budget != nil {
		if _, err := os.Lstat(lockPath); os.IsNotExist(err) {
			empty := []byte{}
			if err := writeProbeArtifact(budget, probeArtifactNormal, lockPath, bytes.NewReader(empty), 0, fmt.Sprintf("%x", sha256.Sum256(empty)), 0600); err != nil {
				return receipt, err
			}
		} else if err != nil {
			return receipt, err
		}
	}
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
	var pending ProbeFrameSample
	managedIssue := ""
	managedIssueKind := ProbeCaptureFailureKind("")
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
		if managed == nil {
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
			if budget != nil {
				claims := []ProbeArtifactClaim{{ID: "artifact:" + filepath.Join(runtime.Output, imageName), Path: filepath.Join(runtime.Output, imageName), Class: probeArtifactNormal, MaxFinalBytes: uint64(profile.MaxImageBytes)}, {ID: "artifact:" + filepath.Join(runtime.Output, receiptName), Path: filepath.Join(runtime.Output, receiptName), Class: probeArtifactNormal, MaxFinalBytes: 4 << 20}, {ID: "raw-native:" + profile.CaptureID, Path: runtime.Snapshots, Class: probeArtifactNative, MaxFinalBytes: uint64(profile.MaxImageBytes)}}
				if err := accountProbeArtifacts(budget, probeArtifactReserve, claims); err != nil {
					receipt.Status, receipt.Reason = "REFUSED", "capture artifact reservation: "+err.Error()
					return receipt, err
				}
			}
		}
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
			if managed != nil && (err == nil || err == io.EOF) {
				receipt.ManagedFailure = probeCaptureResource
			}
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
		if managed != nil {
			receipt.ManagedPineAttempted = true
		}
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
		if !knownTags || managed == nil && !knownUI || len(before.Observations) == 0 {
			receipt.Reason = "capture lacks known source frame tags or decoded UI"
			break
		}
		if managed != nil {
			receipt.ManagedPineAt = time.Now()
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
		if privateX11 {
			receipt.GuideCommand += " " + profile.CaptureID
		}
		_, sendErr := io.Copy(pad, strings.NewReader(receipt.GuideCommand))
		// The Go backend frames one command by half-close; legacy one-read peers
		// receive the same complete payload before replying.
		if sendErr == nil {
			sendErr = pad.(*net.UnixConn).CloseWrite()
		}
		ackLimit := int64(256)
		if privateX11 {
			ackLimit = 65536
		}
		ack, ackErr := io.ReadAll(io.LimitReader(pad, ackLimit+1))
		_ = pad.Close()
		receipt.GuideAckHex = hex.EncodeToString(ack)
		if sendErr != nil || ackErr != nil || int64(len(ack)) > ackLimit || !privateX11 && strings.TrimSpace(string(ack)) != "ok" {
			receipt.Reason = "capture trigger acknowledgement unknown"
			break
		}
		if privateX11 {
			var effect ProbeX11Effect
			if err := effect.admit(ack, profile.CaptureID, *records.GoOwner.Profile.PrivateX11, owned); err != nil {
				receipt.Reason = err.Error()
				break
			}
			receipt.X11Effect = &effect
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
				if managed != nil && (scanErr == nil || scanErr == io.EOF) {
					receipt.ManagedFailure = probeCaptureResource
				}
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
					if managed != nil {
						receipt.ManagedFailure = probeCaptureResource
					}
					break transaction
				}
				data, err := readInput(path, profile.MaxImageBytes)
				if err == nil {
					raster, _, decodeErr := decodePNG(data, profile.MaxPixels)
					if decodeErr == nil || managed != nil && errors.Is(decodeErr, errPNGPixelBudget) {
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
						imageData = data
						if decodeErr != nil {
							managedIssue, managedIssueKind = "fresh PNG exceeds pixel budget", probeCaptureResource
						} else {
							receipt.Width = raster.Bounds().Dx()
							receipt.Height = raster.Bounds().Dy()
							if managed != nil {
								if data[24] != 8 || !slices.Contains([]byte{0, 2, 6}, data[25]) {
									managedIssue, managedIssueKind = "managed normalization supports only8-bit Gray/RGB/RGBA PNG", probeCaptureObservation
								} else {
									var normalizeErr error
									pending.Normalized, pending.Sample, pending.Facts, normalizeErr = normalizeProbeFrame(raster)
									if normalizeErr != nil {
										managedIssue, managedIssueKind = "managed normalization capacity: "+normalizeErr.Error(), probeCaptureResource
									}
								}
							}
						}
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
			if managed == nil {
				receipt.Reason = "decoded UI changed across sequential capture"
				break
			}
			if managedIssue == "" {
				managedIssue, managedIssueKind = "frame tags changed across sequential capture", probeCaptureObservation
			}
		}
		for index, path := range dirs {
			info, err := os.Lstat(path)
			if err != nil || !os.SameFile(directoryInfo[index], info) {
				receipt.Status, receipt.Reason = "REFUSED", "capture root identity changed"
				break transaction
			}
			if managed != nil {
				stat, ok := info.Sys().(*syscall.Stat_t)
				if !ok || stat.Uid != uint32(os.Getuid()) || !info.IsDir() || info.Mode().Perm() != 0700 {
					receipt.Status, receipt.Reason = "REFUSED", "managed capture root privacy changed"
					break transaction
				}
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
		expired := time.Now().After(deadline)
		if managed == nil && expired {
			receipt.Reason = "capture deadline expired before publication"
			break
		}
		if managed != nil {
			stat, ok := current.Sys().(*syscall.Stat_t)
			resolved, resolveErr := filepath.EvalSymlinks(path)
			if !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 || resolveErr != nil || resolved != path || !current.Mode().IsRegular() {
				receipt.Status, receipt.Reason = "REFUSED", "managed snapshot deletion authority is unavailable"
				break
			}
			if managedIssue != "" {
				receipt.Reason, receipt.ManagedFailure = managedIssue, managedIssueKind
				break
			}
			if expired {
				receipt.Reason, receipt.ManagedFailure = "capture deadline expired before managed cleanup", probeCaptureObservation
				break
			}
			if err := os.Remove(path); err != nil {
				receipt.Status, receipt.Reason = "REFUSED", "managed snapshot unlink failed"
				break
			}
			receipt.SnapshotPreserved = false
			directory, err := os.Open(runtime.Snapshots)
			if err != nil {
				receipt.Status, receipt.Reason = "REFUSED", "managed snapshot directory unavailable after unlink"
				break
			}
			syncErr := directory.Sync()
			closeErr := directory.Close()
			if syncErr != nil || closeErr != nil {
				receipt.Status, receipt.Reason = "REFUSED", "managed snapshot deletion durability unknown"
				break
			}
			pending.Facts.CaptureID = profile.CaptureID
			*managed = pending
			receipt.Status, receipt.Reason, receipt.ManagedFailure = "SAMPLED", "", ""
			break
		}
		if budget != nil {
			file, openErr := os.Open(path)
			if openErr != nil {
				return receipt, openErr
			}
			opened, statErr := file.Stat()
			syncErr := file.Sync()
			closeErr := file.Close()
			directory, dirErr := os.Open(runtime.Snapshots)
			if dirErr == nil {
				dirErr = directory.Sync()
				dirErr = errors.Join(dirErr, directory.Close())
			}
			if statErr != nil || syncErr != nil || closeErr != nil || dirErr != nil || !os.SameFile(current, opened) {
				return receipt, fmt.Errorf("raw native snapshot durability/identity unavailable")
			}
			claim := ProbeArtifactClaim{ID: "raw-native:" + profile.CaptureID, Path: path, Class: probeArtifactNative, ExpectedInfo: opened, ExpectedSHA256: receipt.ImageSHA256}
			if err := accountProbeArtifacts(budget, probeArtifactCommit, []ProbeArtifactClaim{claim}); err != nil {
				return receipt, err
			}
		}
		if err := writeProbeArtifact(budget, probeArtifactNormal, filepath.Join(runtime.Output, imageName), bytes.NewReader(imageData), int64(len(imageData)), receipt.ImageSHA256, 0600); err != nil {
			receipt.Status, receipt.Reason = "REFUSED", "capture image publication failed: "+err.Error()
			break
		}
		receipt.ImagePath = imageName
		receipt.Status, receipt.Reason = "CAPTURED", ""
		break
	}
	receipt.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if managed != nil {
		return receipt, nil
	}
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
	if err := writeProbeArtifact(budget, probeArtifactNormal, filepath.Join(runtime.Output, receiptName), bytes.NewReader(encoded), int64(len(encoded)), fmt.Sprintf("%x", sha256.Sum256(encoded)), 0600); err != nil {
		return receipt, err
	}
	return receipt, nil
}
