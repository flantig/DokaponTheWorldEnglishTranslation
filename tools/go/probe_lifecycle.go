package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// runProbeLifecycle owns one bounded direct-child session. Immutable pending
// receipts are directory-synced before effects; incomplete effects never replay.
// This slice uses an owned event sink, not an emulator/uinput handover or a soak.
func runProbeLifecycle(raw []byte) (ProbeLifecycleReport, error) {
	var report ProbeLifecycleReport
	if len(raw) == 0 || len(raw) > 1<<20 {
		return report, fmt.Errorf("lifecycle profile exceeds1MiB")
	}
	if err := checkJSON(checkedJSON{raw: raw, allObjects: true, text: true, nonNull: true}); err != nil {
		return report, err
	}
	var profile ProbeLifecycleProfile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return report, err
	}
	if profile.Version != 1 || profile.SourceFormat != "go-owned-lifecycle-v1" || len(profile.Requests) < 1 || len(profile.Requests) > 32 || len(profile.Session) < 1 || len(profile.Session) > 128 || strings.TrimSpace(profile.Session) != profile.Session || len(profile.ProgramArgs) > 16 {
		return report, fmt.Errorf("unsupported lifecycle version or bounded session/request contract")
	}
	if profile.Requests[len(profile.Requests)-1].Operation != "stop" {
		return report, fmt.Errorf("bounded lifecycle slice must end with an explicit stop request")
	}
	if profile.ReadyTimeoutMS == 0 {
		profile.ReadyTimeoutMS = 10000
	}
	if profile.StopTimeoutMS == 0 {
		profile.StopTimeoutMS = 10000
	}
	if profile.QuietMS == 0 {
		profile.QuietMS = 15000
	}
	if profile.ReadyTimeoutMS < 1 || profile.ReadyTimeoutMS > 10000 || profile.StopTimeoutMS < 1 || profile.StopTimeoutMS > 10000 || profile.QuietMS < 1 || profile.QuietMS > 15000 {
		return report, fmt.Errorf("lifecycle deadlines exceed bounded first-slice limits")
	}
	if len(profile.Inputs) != 4 {
		return report, fmt.Errorf("lifecycle requires iso/settings/bios/card input roles")
	}
	if policy := profile.Policy; policy != nil && (policy.PollMS < 1 || policy.PollMS > 1000 || policy.WarnRepeats < 1 || policy.TerminalRepeats < policy.WarnRepeats || policy.TerminalRepeats > 4096 || policy.MaxPolls < 1 || policy.MaxPolls > 4096 || policy.MaxRecoveries < 0 || policy.MaxRecoveries > 16 || policy.MaxDistinctSkips < 1 || policy.MaxDistinctSkips > 32) {
		return report, fmt.Errorf("invalid explicit bounded Go lifecycle policy")
	}
	for _, role := range []string{"iso", "settings", "bios", "card"} {
		if profile.Inputs[role].Path == "" {
			return report, fmt.Errorf("missing lifecycle input role %s", role)
		}
	}
	rootInfo, err := os.Lstat(profile.Root)
	resolved, resolveErr := filepath.EvalSymlinks(profile.Root)
	if err != nil || resolveErr != nil || !filepath.IsAbs(profile.Root) || resolved != profile.Root || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0700 {
		return report, fmt.Errorf("lifecycle requires an explicit private0700 canonical root")
	}
	owner, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) {
		return report, fmt.Errorf("lifecycle root is not owned")
	}
	lock, err := os.OpenFile(filepath.Join(profile.Root, "lifecycle.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return report, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return report, fmt.Errorf("lifecycle root already has a controller")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	receiptDir := filepath.Join(profile.Root, "receipts")
	if err := os.Mkdir(receiptDir, 0700); err != nil && !os.IsExist(err) {
		return report, err
	}
	receiptInfo, err := os.Lstat(receiptDir)
	if err != nil || !receiptInfo.IsDir() || receiptInfo.Mode().Perm() != 0700 {
		return report, fmt.Errorf("lifecycle receipts require a private directory")
	}
	var table struct {
		Version int
		Actions map[string]struct {
			From    []string
			Effects []string
			To      string
		}
		WarmCommand       string               `json:"warm_command"`
		WarmSettleMS      int                  `json:"warm_settle_ms"`
		WarmWidths        []uint64             `json:"warm_widths"`
		PauseCommand      string               `json:"pause_command"`
		PauseSettleMS     int                  `json:"pause_settle_ms"`
		StatusPolls       int                  `json:"status_polls"`
		StatusPollMS      int                  `json:"status_poll_ms"`
		WatchSourceSHA256 string               `json:"watch_source_sha256"`
		WatchReads        []ProbeMemoryRequest `json:"watch_reads"`
		ProgressOrder     []string             `json:"progress_order"`
	}
	if err := json.Unmarshal(probeLifecycleActions, &table); err != nil {
		return report, err
	}
	report = ProbeLifecycleReport{Version: 1, SourceFormat: profile.SourceFormat, Session: profile.Session, Status: "COMPLETED", Steps: []ProbeLifecycleStep{}, SourceSHA256: map[string]string{}, PadLayoutSHA256: fmt.Sprintf("%x", sha256.Sum256(probePadLayout)), Limits: "Offline Go-owned direct-child/event-sink lifecycle and qualified saved-source resume. No native emulator/device/SDL/BIOS/card acceptance, legacy fixed-file IPC compatibility, Continue/restored-state proof, gameplay coverage or full.05 credit. Resource/soak agreement and native qualification remain pending."}
	facts := profile
	facts.Requests = nil
	factsBytes, _ := json.Marshal(facts)
	factsSHA := fmt.Sprintf("%x", sha256.Sum256(factsBytes))
	roleOrder := []string{"iso", "settings", "bios", "card", "program"}
	sourceInputs := map[string]RegistryInput{}
	for role, input := range profile.Inputs {
		sourceInputs[role] = input
	}
	sourceInputs["program"] = profile.Program
	var resumeFacts *ProbeResumeFacts
	var resumeEvidence ProbeEvidenceBundle
	if profile.Resume != nil {
		if profile.Seed == nil || profile.Requests[0].Operation != "resume" {
			return report, fmt.Errorf("saved resume requires its explicit seed and first resume request")
		}
		resumeRoot, rootErr := filepath.EvalSymlinks(profile.Resume.Root)
		if rootErr != nil || !filepath.IsAbs(resumeRoot) || resumeRoot != profile.Resume.Root || resumeRoot == profile.Root {
			return report, fmt.Errorf("resume requires a distinct canonical source root")
		}
		for role, input := range map[string]RegistryInput{"resume-receipt": profile.Resume.Receipt, "resume-evidence": profile.Resume.Evidence} {
			resolved, err := filepath.EvalSymlinks(input.Path)
			rel, relErr := filepath.Rel(resumeRoot, input.Path)
			local, _ := filepath.Rel(profile.Root, input.Path)
			info, statErr := os.Lstat(input.Path)
			if err != nil || relErr != nil || resolved != input.Path || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || local != ".." && !strings.HasPrefix(local, ".."+string(filepath.Separator)) || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0222 != 0 || input.Size < 1 || input.Size > 8<<20 || info.Size() != input.Size {
				return report, fmt.Errorf("resume metadata must be readonly regular files inside its source root")
			}
			sourceInputs[role] = input
			roleOrder = append(roleOrder, role)
		}
		rawReceipt, err := readInput(profile.Resume.Receipt.Path, 8<<20)
		if err == nil && (int64(len(rawReceipt)) != profile.Resume.Receipt.Size || fmt.Sprintf("%x", sha256.Sum256(rawReceipt)) != profile.Resume.Receipt.SHA256) {
			return report, fmt.Errorf("loaded resume receipt hash differs")
		}
		if err != nil || checkJSON(checkedJSON{raw: rawReceipt, allObjects: true, text: true}) != nil {
			return report, fmt.Errorf("resume receipt is malformed")
		}
		resumeFacts = &ProbeResumeFacts{}
		if json.Unmarshal(rawReceipt, resumeFacts) != nil || resumeFacts.Seed == nil || *resumeFacts.Seed != *profile.Seed {
			return report, fmt.Errorf("resume receipt seed differs")
		}
		rawEvidence, err := readInput(profile.Resume.Evidence.Path, 8<<20)
		if err == nil && (int64(len(rawEvidence)) != profile.Resume.Evidence.Size || fmt.Sprintf("%x", sha256.Sum256(rawEvidence)) != profile.Resume.Evidence.SHA256) {
			return report, fmt.Errorf("loaded resume evidence hash differs")
		}
		if err != nil || checkJSON(checkedJSON{raw: rawEvidence, allObjects: true, text: true}) != nil || json.Unmarshal(rawEvidence, &resumeEvidence) != nil {
			return report, fmt.Errorf("resume evidence is malformed")
		}
		loaded := map[string][]byte{}
		for _, role := range []string{"run", "sequence", "events", "card"} {
			input, ok := resumeFacts.Artifacts[role]
			resolved, err := filepath.EvalSymlinks(input.Path)
			rel, relErr := filepath.Rel(resumeRoot, input.Path)
			local, _ := filepath.Rel(profile.Root, input.Path)
			info, statErr := os.Lstat(input.Path)
			if !ok || err != nil || relErr != nil || resolved != input.Path || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || local != ".." && !strings.HasPrefix(local, ".."+string(filepath.Separator)) || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0222 != 0 || info.Size() < 1 || info.Size() > 64<<20 || input.Size != 0 && input.Size != info.Size() {
				return report, fmt.Errorf("resume artifact %s is outside its readonly source contract", role)
			}
			input.Size = info.Size()
			resumeFacts.Artifacts[role] = input
			sourceInputs["resume-"+role] = input
			roleOrder = append(roleOrder, "resume-"+role)
			if role != "card" {
				loaded[role], err = readInput(input.Path, 8<<20)
				if err != nil {
					return report, err
				}
				if int64(len(loaded[role])) != input.Size || fmt.Sprintf("%x", sha256.Sum256(loaded[role])) != input.SHA256 {
					return report, fmt.Errorf("loaded resume artifact hash differs: %s", role)
				}
			}
		}
		resumeFacts.Run, resumeFacts.Sequence = loaded["run"], loaded["sequence"]
		resumeFacts.Screenshots = map[string]RegistryInput{}
		resumeEvidence.Events = nil
		offset := int64(0)
		lines := bytes.SplitAfter(loaded["events"], []byte{'\n'})
		for _, line := range lines {
			if len(line) == 0 {
				continue
			}
			if line[len(line)-1] != '\n' {
				return report, fmt.Errorf("resume event stream has a partial final record")
			}
			data := bytes.TrimSuffix(line, []byte{'\n'})
			if len(data) == 0 {
				return report, fmt.Errorf("resume event stream has an empty record")
			}
			resumeEvidence.Events = append(resumeEvidence.Events, ProbeEvidenceEvent{Offset: offset, Data: bytes.Clone(data)})
			offset += int64(len(line))
			var event struct {
				Event      string `json:"event"`
				Checkpoint int    `json:"checkpoint"`
				Screenshot string `json:"screenshot"`
			}
			if json.Unmarshal(data, &event) != nil {
				return report, fmt.Errorf("resume event stream malformed")
			}
			if slices.Contains(resumeFacts.AcceptedCheckpoints, event.Checkpoint) && (event.Event == "save-complete" || event.Event == "reload-verified") {
				if event.Screenshot == "" || filepath.IsAbs(event.Screenshot) || filepath.Clean(event.Screenshot) != event.Screenshot || strings.HasPrefix(event.Screenshot, "..") {
					return report, fmt.Errorf("resume screenshot path is invalid")
				}
				path := filepath.Join(filepath.Dir(resumeFacts.Artifacts["events"].Path), event.Screenshot)
				resolved, err := filepath.EvalSymlinks(path)
				rel, relErr := filepath.Rel(resumeRoot, path)
				info, statErr := os.Lstat(path)
				if err != nil || relErr != nil || resolved != path || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0222 != 0 || info.Size() < 1 || info.Size() > 16<<20 {
					return report, fmt.Errorf("resume screenshot is missing or mutable")
				}
				contents, err := readInput(path, 16<<20)
				if err != nil {
					return report, err
				}
				input := RegistryInput{Path: path, Size: int64(len(contents)), SHA256: fmt.Sprintf("%x", sha256.Sum256(contents))}
				resumeFacts.Screenshots[event.Screenshot] = input
				sourceInputs["resume-shot-"+event.Screenshot] = input
			}
		}
		for role := range sourceInputs {
			if strings.HasPrefix(role, "resume-shot-") {
				roleOrder = append(roleOrder, role)
			}
		}
		sort.Strings(roleOrder)
		if resumeFacts.ISOSHA256 != profile.Inputs["iso"].SHA256 || resumeFacts.Artifacts["card"].Path != profile.Inputs["card"].Path || resumeFacts.Artifacts["card"].SHA256 != profile.Inputs["card"].SHA256 {
			return report, fmt.Errorf("resume ISO or copied source card differs")
		}
		resumeEvidence.Resume = resumeFacts
	}
	profileDir := filepath.Join(profile.Root, "profile")
	dataRoot := filepath.Join(profileDir, "PCSX2")
	cardPath := filepath.Join(dataRoot, "memcards", "probe-slot1.ps2")
	phase, epoch, lastNonce := "new", 0, uint64(0)
	var owned *ProbeProcessRecord
	var child *exec.Cmd
	var readyDeadline time.Time
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	padReady, padDone := make(chan error, 1), make(chan error, 1)
	padStarted := false
	skipReasons := map[string]bool{}
	recoveryAttempts := 0
	readFailure, ambiguousFailure := false, false
	lastSafeCardSHA := ""
	resumeVerified, gameplayStarted := false, false
	scheduledIntervals := []int{}
	noncePattern := regexp.MustCompile(`^([1-9][0-9]*)-(initial|warm|cold|stop|pause|unpause|watch|recover|resume)$`)
	for _, request := range profile.Requests {
		step := ProbeLifecycleStep{Request: request, Status: "REFUSED", Epoch: epoch, Owned: owned, Effects: []string{}, RecoveryAttempts: recoveryAttempts}
		// Current source bytes and role identities precede effects, not supplied claims.
		sourceOK := true
		for _, role := range roleOrder {
			input := sourceInputs[role]
			info, statErr := os.Lstat(input.Path)
			canonical, canonicalErr := filepath.EvalSymlinks(input.Path)
			if statErr != nil || canonicalErr != nil || !filepath.IsAbs(input.Path) || canonical != input.Path || !info.Mode().IsRegular() || input.Size < 1 || input.Size > 8<<30 || info.Size() != input.Size || len(input.SHA256) != 64 || role != "program" && info.Mode().Perm()&0222 != 0 {
				step.Reason = "lifecycle input role identity differs: " + role
				sourceOK = false
				break
			}
			if role == "card" {
				stat, ok := info.Sys().(*syscall.Stat_t)
				if !ok || stat.Nlink != 1 {
					step.Reason = "source card is not exclusive"
					sourceOK = false
					break
				}
			}
			file, openErr := os.Open(input.Path)
			if openErr != nil {
				step.Reason = "lifecycle input unavailable: " + role
				sourceOK = false
				break
			}
			hasher := sha256.New()
			count, hashErr := io.Copy(hasher, io.LimitReader(file, input.Size+1))
			after, afterErr := file.Stat()
			_ = file.Close()
			if hashErr != nil || afterErr != nil || count != input.Size || !os.SameFile(info, after) || info.Size() != after.Size() || info.ModTime() != after.ModTime() || fmt.Sprintf("%x", hasher.Sum(nil)) != input.SHA256 {
				step.Reason = "lifecycle input hash differs: " + role
				sourceOK = false
				break
			}
			report.SourceSHA256[role] = input.SHA256
		}
		if !sourceOK {
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		if resumeFacts != nil && !resumeVerified {
			data, _ := json.Marshal(resumeEvidence)
			qualified, err := reportProbeEvidence(data)
			if err != nil || qualified.ResumeStatus != "QUALIFIED_SAVED_FACTS" || qualified.ISOSHA256 != profile.Inputs["iso"].SHA256 || qualified.Session == profile.Session {
				return report, fmt.Errorf("saved resume qualification failed: %w", err)
			}
			epoch = qualified.Epoch + 1
			step.Epoch = epoch
			resumeVerified = true
			scheduledIntervals = slices.Clone(resumeFacts.ScheduledIntervals)
			gameplayStarted = true
			step.ResumeEvidenceSHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
		}
		if request.Session != profile.Session {
			step.Reason = "lifecycle request session differs"
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		if request.Phase != "requested" {
			step.Reason = "lifecycle request phase is not requested"
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		parts := noncePattern.FindStringSubmatch(request.Nonce)
		if len(parts) != 3 || parts[2] != request.Operation {
			step.Reason = "invalid lifecycle operation/nonce"
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		ordinal, parseErr := strconv.ParseUint(parts[1], 10, 64)
		if parseErr != nil {
			step.Reason = "invalid lifecycle nonce sequence"
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		completePath := filepath.Join(receiptDir, request.Nonce+".complete.json")
		if old, err := readInput(completePath, 1<<20); err == nil {
			var saved ProbeLifecycleStep
			if json.Unmarshal(old, &saved) != nil || saved.Status != "COMPLETED" || saved.ProfileSHA256 != factsSHA || !reflect.DeepEqual(saved.Request, request) {
				step.Reason = "conflicting completed lifecycle nonce"
				report.Status = "INCOMPLETE"
			} else {
				step = saved
				step.Replayed = true
			}
			report.Steps = append(report.Steps, step)
			continue
		} else if !os.IsNotExist(err) {
			step.Reason = "lifecycle completion receipt unreadable"
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		existing, err := os.ReadDir(receiptDir)
		if err != nil {
			return report, err
		}
		if len(existing) > 512 {
			return report, fmt.Errorf("lifecycle receipt budget exceeded")
		}
		pending := false
		for _, entry := range existing {
			if strings.HasPrefix(entry.Name(), request.Nonce+"-") && strings.HasSuffix(entry.Name(), ".pending.json") {
				pending = true
			}
		}
		if pending {
			step.Status, step.Reason = "UNKNOWN", "durable pending effect prevents replay"
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		if ordinal <= lastNonce {
			step.Reason = "replayed or reordered lifecycle nonce"
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		action, ok := table.Actions[request.Operation]
		if !ok || !slices.Contains(action.From, phase) {
			step.Reason = "lifecycle operation not valid in current state"
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		if request.Operation == "stop" && phase == "unknown" && (owned == nil || child == nil) {
			step.Reason = "safe stop requires an established owned child"
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		if request.Operation == "watch" && profile.Policy == nil {
			step.Reason = "watch requires explicit bounded Go policy"
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		if request.Operation == "resume" {
			if !resumeVerified {
				return report, fmt.Errorf("resume requires qualified bound saved artifacts")
			}
			if _, err := os.Lstat(profileDir); !os.IsNotExist(err) {
				return report, fmt.Errorf("resume destination is not a fresh profile")
			}
		}
		if request.Operation == "recover" {
			if profile.Policy == nil || recoveryAttempts >= profile.Policy.MaxRecoveries {
				step.Reason = "explicit Go recovery budget exhausted"
			} else if !readFailure || ambiguousFailure || lastSafeCardSHA == "" || child != nil || owned != nil {
				step.Reason = "recovery requires proved disposal after a read-only failure"
			} else {
				data, err := readInput(cardPath, 64<<20)
				if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != lastSafeCardSHA {
					step.Reason = "recovery retained card differs from stable postflush bytes"
				}
			}
			if step.Reason != "" {
				report.Status = "INCOMPLETE"
				report.Steps = append(report.Steps, step)
				continue
			}
			recoveryAttempts++
			step.RecoveryAttempts, step.CardAfter = recoveryAttempts, lastSafeCardSHA
		}
		step.Status = "UNKNOWN"
		step.ProfileSHA256 = factsSHA
		lastNonce = ordinal
		requestBytes, _ := json.Marshal(request)
		requestSHA := fmt.Sprintf("%x", sha256.Sum256(requestBytes))
	actions:
		for index, effect := range action.Effects {
			pendingRow := ProbeLifecycleEffect{Version: 1, Session: profile.Session, Nonce: request.Nonce, RequestSHA256: requestSHA, Action: effect, Phase: "pending"}
			pendingData, _ := json.Marshal(pendingRow)
			effectBase := fmt.Sprintf("%s-%02d-%s", request.Nonce, index, effect)
			if err := writeNewFile(filepath.Join(receiptDir, effectBase+".pending.json"), bytes.NewReader(pendingData), int64(len(pendingData)), fmt.Sprintf("%x", sha256.Sum256(pendingData)), 0600); err != nil {
				step.Reason = "pending effect publication failed"
				break
			}
			directory, err := os.Open(receiptDir)
			if err == nil {
				err = directory.Sync()
				_ = directory.Close()
			}
			if err != nil {
				step.Reason = "pending directory durability failed"
				break
			}
			switch effect {
			case "prepare":
				settings, err := readInput(profile.Inputs["settings"].Path, 1<<20)
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				required := map[string]string{"Folders.Bios": "bios", "Folders.Snapshots": "snaps", "Folders.Savestates": "sstates", "Folders.MemoryCards": "memcards", "Folders.Logs": "logs", "Folders.Cheats": "cheats", "Folders.Patches": "patches", "Folders.UserResources": "resources", "Folders.Cache": "cache", "Folders.Textures": "textures", "Folders.InputProfiles": "inputprofiles", "Folders.Videos": "videos", "Folders.DebuggerLayouts": "debuggerlayouts", "Folders.DebuggerSettings": "debuggersettings", "Filenames.BIOS": filepath.Base(profile.Inputs["bios"].Path), "MemoryCards.Slot1_Enable": "true", "MemoryCards.Slot1_Filename": "probe-slot1.ps2", "MemoryCards.Slot2_Enable": "false", "Hotkeys.ResetVM": "SDL-0/RightStick", "Hotkeys.TogglePause": "SDL-0/LeftStick"}
				values := map[string]string{}
				section := ""
				for _, line := range strings.Split(string(settings), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
						continue
					}
					if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
						section = line[1 : len(line)-1]
						continue
					}
					key, value, found := strings.Cut(line, "=")
					name := section + "." + strings.TrimSpace(key)
					if !found || values[name] != "" {
						step.Reason = "settings template is not normalized"
						break actions
					}
					values[name] = strings.TrimSpace(value)
				}
				for key, value := range required {
					if values[key] != value {
						step.Reason = "private settings contract differs: " + key
						break actions
					}
				}
				for key, value := range values {
					if key != "Hotkeys.ResetVM" && key != "Hotkeys.TogglePause" && (strings.Contains(value, "SDL-0/RightStick") || strings.Contains(value, "SDL-0/LeftStick")) {
						step.Reason = "private control hotkey overlaps game input"
						break actions
					}
				}
				if err := os.Mkdir(profileDir, 0700); err != nil {
					step.Reason = "private profile already exists or cannot be created"
					break actions
				}
				for _, name := range []string{"inis", "bios", "memcards", "snaps", "logs", "sstates", "cache", "cheats", "patches", "resources", "textures", "inputprofiles", "videos", "debuggerlayouts", "debuggersettings"} {
					if err := os.MkdirAll(filepath.Join(dataRoot, name), 0700); err != nil {
						step.Reason = err.Error()
						break actions
					}
				}
				for _, copyRole := range []string{"settings", "bios", "card"} {
					input := profile.Inputs[copyRole]
					target := cardPath
					if copyRole == "settings" {
						target = filepath.Join(dataRoot, "inis", "PCSX2.ini")
					}
					if copyRole == "bios" {
						target = filepath.Join(dataRoot, "bios", filepath.Base(input.Path))
					}
					source, err := os.Open(input.Path)
					if err != nil {
						step.Reason = err.Error()
						break actions
					}
					err = writeNewFile(target, source, input.Size, input.SHA256, 0600)
					_ = source.Close()
					if err != nil {
						step.Reason = err.Error()
						break actions
					}
				}
			case "pad":
				go serveProbePad(ctx, ProbePadSpec{Root: profile.Root, Backend: "event-sink"}, padReady, padDone)
				if err := <-padReady; err != nil {
					_ = <-padDone
					step.Reason = "pad service failed: " + err.Error()
					break actions
				}
				padStarted = true
			case "launch":
				if child != nil {
					step.Reason = "a child is already owned"
					break actions
				}
				if request.Operation == "cold" || request.Operation == "recover" {
					epoch++
				}
				args := append(slices.Clone(profile.ProgramArgs), "-datapath", profileDir, "-batch", profile.Inputs["iso"].Path)
				child = exec.Command(profile.Program.Path, args...)
				child.Env = append(os.Environ(), "DOKAPON_PROBE_SESSION_ROOT="+profile.Root)
				log, err := os.OpenFile(filepath.Join(profile.Root, fmt.Sprintf("child-epoch-%d.log", epoch)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if err != nil {
					child = nil
					step.Reason = err.Error()
					break actions
				}
				child.Stdout, child.Stderr = log, log
				if err := child.Start(); err != nil {
					_ = log.Close()
					child = nil
					step.Reason = "child launch failed: " + err.Error()
					break actions
				}
				_ = log.Close()
				readyDeadline = time.Now().Add(time.Duration(profile.ReadyTimeoutMS) * time.Millisecond)
				// exec startup can briefly expose an empty /proc cmdline. Wait for
				// the exact identity, never adopt a partial or mismatched command.
				var observed ProbeProcessRecord
				for {
					observed, err = observeProbeProcess(ProbeMemoryRuntime{Provenance: "owned_child", Root: profile.Root}, child.Process.Pid, nil, profile.Program.SHA256)
					if err == nil && reflect.DeepEqual(observed.Cmdline, child.Args) || !time.Now().Before(readyDeadline) {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if err != nil || !reflect.DeepEqual(observed.Cmdline, child.Args) {
					step.Reason = "launched child identity differs"
					if err != nil {
						step.Reason += ": " + err.Error()
					} else {
						step.Reason += fmt.Sprintf(": observed command %q does not match launched argv %q", observed.Cmdline, child.Args)
					}
					break actions
				}
				observed.Session, observed.Profile, observed.ISO, observed.ISOSHA256 = profile.Session, profileDir, profile.Inputs["iso"].Path, profile.Inputs["iso"].SHA256
				currentEpoch := epoch
				observed.Epoch = &currentEpoch
				owned = &observed
				step.Owned = owned
				step.Epoch = epoch
			case "verify", "verify-warm", "quiescent", "status-running", "status-paused", "watch-progress":
				if owned == nil {
					step.Reason = "no owned child for observation"
					break actions
				}
				deadline := time.Now().Add(time.Duration(profile.ReadyTimeoutMS) * time.Millisecond)
				if effect == "verify" {
					deadline = readyDeadline
				}
				quietSince := time.Now()
				lastCard := ""
				if effect == "quiescent" {
					deadline = time.Now().Add(time.Duration(profile.QuietMS+profile.ReadyTimeoutMS) * time.Millisecond)
				}
				statusOnly := effect == "status-running" || effect == "status-paused"
				watch := effect == "watch-progress"
				pollLimit := int(^uint(0) >> 1)
				if statusOnly {
					pollLimit = table.StatusPolls
					if index == 0 {
						pollLimit = 1
					}
					deadline = time.Now().Add(time.Duration(table.StatusPolls*table.StatusPollMS+profile.ReadyTimeoutMS) * time.Millisecond)
				}
				if watch {
					pollLimit = profile.Policy.MaxPolls
					deadline = time.Now().Add(time.Duration(profile.Policy.PollMS*pollLimit+profile.ReadyTimeoutMS) * time.Millisecond)
				}
				var previousProgress []uint64
				verified := false
				for polls := 0; polls < pollLimit && time.Now().Before(deadline); polls++ {
					if _, err := observeProbeProcess(ProbeMemoryRuntime{Provenance: "owned_child", Root: profile.Root}, owned.PID, owned, profile.Program.SHA256); err != nil {
						step.Reason = err.Error()
						break actions
					}
					connection, err := net.DialTimeout("unix", filepath.Join(profile.Root, "peer.sock"), 100*time.Millisecond)
					if err != nil {
						time.Sleep(10 * time.Millisecond)
						continue
					}
					_ = connection.SetDeadline(time.Now().Add(100 * time.Millisecond))
					peerFile, peerErr := connection.(*net.UnixConn).File()
					if peerErr != nil {
						_ = connection.Close()
						step.Reason = "PINE peer identity unavailable"
						break actions
					}
					credentials, credentialErr := syscall.GetsockoptUcred(int(peerFile.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
					_ = peerFile.Close()
					if credentialErr != nil || int(credentials.Pid) != owned.PID || credentials.Uid != uint32(os.Getuid()) {
						_ = connection.Close()
						step.Reason = "PINE peer is not the owned child"
						break actions
					}
					status, err := exchangeProbeFrame(connection, []byte{5, 0, 0, 0, 15}, 9)
					readSet := table.WatchReads[:1]
					if watch {
						readSet = table.WatchReads
					}
					if statusOnly {
						readSet = nil
					}
					readMap := map[string]ProbeMemoryRequest{}
					payloads := map[string][]byte{}
					values := map[string]uint64{}
					memory := ProbeMemoryReport{Version: 1, SourceSHA256: table.WatchSourceSHA256, BuildSHA256: profile.Program.SHA256, Session: profile.Session, Epoch: epoch, ISOSHA256: profile.Inputs["iso"].SHA256, Provenance: "go-owned-lifecycle-v1", ProcessGuarded: true, Observations: []ProbeMemoryObservation{}, Decoded: []ProbeMemoryDecoded{}, Limits: "Actual owned Go-child finite reads; not legacy admission or gameplay/coverage acceptance."}
					decoders := []ProbeMemoryDecoder{}
					for _, read := range readSet {
						if err != nil {
							break
						}
						requestData := []byte{9, 0, 0, 0, *read.Opcode, 0, 0, 0, 0}
						binary.LittleEndian.PutUint32(requestData[5:], *read.Address)
						var reply []byte
						reply, err = exchangeProbeFrame(connection, requestData, 5+1<<*read.Opcode)
						if err != nil {
							break
						}
						var padded [8]byte
						copy(padded[:], reply[5:])
						value := binary.LittleEndian.Uint64(padded[:])
						readMap[read.ID], payloads[read.ID], values[read.ID] = read, reply[5:], value
						memory.Observations = append(memory.Observations, ProbeMemoryObservation{ID: read.ID, RequestHex: fmt.Sprintf("%x", requestData), ReplyHex: fmt.Sprintf("%x", reply), Value: value})
						decoders = append(decoders, ProbeMemoryDecoder{ID: read.ID, Kind: "scalar", Requests: []string{read.ID}})
					}
					_ = connection.Close()
					if err != nil {
						if watch || statusOnly {
							step.Reason = "owned observation failed: " + err.Error()
							break actions
						}
						time.Sleep(10 * time.Millisecond)
						continue
					}
					vmStatus := binary.LittleEndian.Uint32(status[5:])
					if statusOnly {
						wanted := uint32(0)
						if effect == "status-paused" {
							wanted = 1
						}
						if index == 0 {
							value := vmStatus
							step.VMStatusBefore = &value
						} else {
							value := vmStatus
							step.VMStatusAfter = &value
						}
						if vmStatus == wanted {
							verified = true
							break
						}
						if index == 0 || vmStatus != 1-wanted {
							step.Reason = "unexpected VM status during guarded toggle"
							break actions
						}
						time.Sleep(time.Duration(table.StatusPollMS) * time.Millisecond)
						continue
					}
					if vmStatus != 0 {
						step.Reason = "owned VM is not running"
						break actions
					}
					if watch {
						memory.Decoded, err = decodeProbeMemory(readMap, payloads, values, decoders)
						if err != nil {
							step.Reason = err.Error()
							break actions
						}
						step.Memory = &memory
						step.Samples++
						if !gameplayStarted && profile.Seed != nil && values["story"] >= 1 && values["story"] <= 49 {
							intervals, err := probeCheckpointIntervals(*profile.Seed, len(scheduledIntervals)+1)
							if err != nil || !slices.Equal(intervals[:len(scheduledIntervals)], scheduledIntervals) {
								step.Reason = "checkpoint schedule prefix differs"
								break actions
							}
							scheduledIntervals = intervals
							gameplayStarted = true
						}
						step.ScheduledIntervals = slices.Clone(scheduledIntervals)
						progress := []uint64{}
						for _, id := range table.ProgressOrder {
							value := values[id]
							if id == "week" {
								value++
							}
							progress = append(progress, value)
						}
						if previousProgress != nil && reflect.DeepEqual(previousProgress, progress) {
							step.Repeated++
						} else {
							step.Repeated = 0
						}
						previousProgress = progress
						if step.Repeated >= profile.Policy.WarnRepeats {
							step.Warning = true
						}
						skip := ""
						switch {
						case values["current"] > 3:
							skip = "invalid current player"
						case values["mode"] != 0x1b0:
							skip = "event or combat instead of board menu"
						case values["board_options"] != 5:
							skip = "unsupported board menu"
						case values["board_handle"] != 1 || values["board_cursor"] != 0:
							skip = "board Move selection inactive"
						}
						if skip != "" && !skipReasons[skip] {
							if len(skipReasons) >= profile.Policy.MaxDistinctSkips {
								step.Reason = "explicit Go skip budget exhausted"
								break actions
							}
							skipReasons[skip] = true
							step.Skips = append(step.Skips, skip)
						}
						if step.Repeated >= profile.Policy.TerminalRepeats {
							step.WatchOutcome = "STALLED"
							step.Reason = "progress stalled"
							break actions
						}
						if polls+1 == pollLimit {
							step.WatchOutcome = "OBSERVED"
							verified = true
							break
						}
						time.Sleep(time.Duration(profile.Policy.PollMS) * time.Millisecond)
						continue
					}
					width := values["mode"]
					if effect == "quiescent" {
						if width != 0x2e0 {
							step.Reason = "warm reset requires the saved-card UI"
							break actions
						}
						data, err := readInput(cardPath, 64<<20)
						if err != nil {
							step.Reason = err.Error()
							break actions
						}
						digest := fmt.Sprintf("%x", sha256.Sum256(data))
						if digest != lastCard {
							lastCard = digest
							quietSince = time.Now()
						}
						if time.Since(quietSince) >= time.Duration(profile.QuietMS)*time.Millisecond {
							step.CardBefore = digest
							value := width
							step.WidthBefore = &value
							verified = true
							break
						}
					} else if slices.Contains(table.WarmWidths, width) {
						value := width
						step.WidthAfter = &value
						verified = true
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if !verified {
					step.Reason = "owned boot/quiescence observation timed out"
					break actions
				}
			case "reset", "toggle-pause":
				if owned == nil {
					step.Reason = "warm reset has no owned child"
					break actions
				}
				if _, err := observeProbeProcess(ProbeMemoryRuntime{Provenance: "owned_child", Root: profile.Root}, owned.PID, owned, profile.Program.SHA256); err != nil {
					step.Reason = err.Error()
					break actions
				}
				connection, err := net.DialTimeout("unix", filepath.Join(profile.Root, "pad.sock"), time.Second)
				if err != nil {
					step.Reason = "owned pad unavailable"
					break actions
				}
				_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
				command, settle := table.WarmCommand, table.WarmSettleMS
				if effect == "toggle-pause" {
					command, settle = table.PauseCommand, table.PauseSettleMS
				}
				_, sendErr := io.Copy(connection, strings.NewReader(command))
				_ = connection.(*net.UnixConn).CloseWrite()
				ack, ackErr := io.ReadAll(io.LimitReader(connection, 257))
				_ = connection.Close()
				if sendErr != nil || ackErr != nil || strings.TrimSpace(string(ack)) != "ok" {
					step.Reason = "warm reset effect is ambiguous"
					break actions
				}
				time.Sleep(time.Duration(settle) * time.Millisecond)
			case "terminate":
				if owned == nil || child == nil {
					step.Reason = "no current owned child to stop"
					break actions
				}
				observed, err := observeProbeProcess(ProbeMemoryRuntime{Provenance: "owned_child", Root: profile.Root}, owned.PID, owned, profile.Program.SHA256)
				if err != nil {
					// Reaping a known direct child proves disposal without signaling
					// a stale/replaced PID. A live mismatching process is never killed.
					var status syscall.WaitStatus
					pid, waitErr := syscall.Wait4(child.Process.Pid, &status, syscall.WNOHANG, nil)
					if waitErr == nil && pid == owned.PID && child.Process.Pid == owned.PID {
						step.ExitedBeforeStop = true
						_ = child.Process.Release()
						child, owned = nil, nil
						break
					}
					step.Reason = err.Error()
					break actions
				}
				if observed.Profile != "" && observed.Profile != profileDir {
					step.Reason = "owned profile changed"
					break actions
				}
				data, err := readInput(cardPath, 64<<20)
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				step.CardBefore = fmt.Sprintf("%x", sha256.Sum256(data))
				if err := child.Process.Signal(syscall.SIGTERM); err != nil {
					step.Reason = "owned graceful stop failed: " + err.Error()
					break actions
				}
				stopped := false
				deadline := time.Now().Add(time.Duration(profile.StopTimeoutMS) * time.Millisecond)
				for time.Now().Before(deadline) {
					var status syscall.WaitStatus
					pid, err := syscall.Wait4(owned.PID, &status, syscall.WNOHANG, nil)
					if err != nil {
						step.Reason = "owned wait failed: " + err.Error()
						break actions
					}
					if pid == owned.PID {
						stopped = true
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if !stopped {
					step.Reason = "owned graceful stop timed out; no replacement"
					break actions
				}
				_ = child.Process.Release()
				child = nil
				owned = nil
			case "flush":
				if child != nil {
					step.Reason = "card flush requires confirmed process exit"
					break actions
				}
				file, err := os.Open(cardPath)
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				err = file.Sync()
				_ = file.Close()
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				data, err := readInput(cardPath, 64<<20)
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				post := fmt.Sprintf("%x", sha256.Sum256(data))
				time.Sleep(250 * time.Millisecond)
				stable, err := readInput(cardPath, 64<<20)
				if err != nil || fmt.Sprintf("%x", sha256.Sum256(stable)) != post {
					step.Reason = "private card still changing after exit"
					break actions
				}
				step.CardAfter = post
				lastSafeCardSHA = post
			case "backup":
				data, err := readInput(cardPath, 64<<20)
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				if err := writeNewFile(filepath.Join(receiptDir, request.Nonce+".flushed-card"), bytes.NewReader(data), int64(len(data)), step.CardAfter, 0600); err != nil {
					step.Reason = err.Error()
					break actions
				}
			default:
				step.Reason = "unsupported lifecycle action"
				break actions
			}
			step.Effects = append(step.Effects, effect)
			pendingRow.Phase = "complete"
			detail, _ := json.Marshal(step)
			pendingRow.Details = detail
			completeData, _ := json.Marshal(pendingRow)
			if err := writeNewFile(filepath.Join(receiptDir, effectBase+".complete.json"), bytes.NewReader(completeData), int64(len(completeData)), fmt.Sprintf("%x", sha256.Sum256(completeData)), 0600); err != nil {
				step.Reason = "effect completion publication failed"
				break
			}
			directory, err = os.Open(receiptDir)
			if err == nil {
				err = directory.Sync()
				_ = directory.Close()
			}
			if err != nil {
				step.Reason = "effect completion durability failed"
				break
			}
		}
		if step.Reason == "" && len(step.Effects) == len(action.Effects) {
			step.Status = "COMPLETED"
			if request.Operation == "recover" {
				readFailure = false
			}
			phase = action.To
			step.Epoch = epoch
			completeData, _ := json.Marshal(step)
			if err := writeNewFile(completePath, bytes.NewReader(completeData), int64(len(completeData)), fmt.Sprintf("%x", sha256.Sum256(completeData)), 0600); err != nil {
				step.Status, step.Reason = "UNKNOWN", "operation completion publication failed"
			} else {
				directory, err := os.Open(receiptDir)
				if err == nil {
					err = directory.Sync()
					_ = directory.Close()
				}
				if err != nil {
					step.Status, step.Reason = "UNKNOWN", "operation completion durability failed"
				}
			}
		} else {
			phase = "unknown"
			if request.Operation == "watch" {
				readFailure = true
			} else if request.Operation != "stop" {
				ambiguousFailure = true
			}
		}
		if step.Status != "COMPLETED" {
			report.Status = "INCOMPLETE"
		}
		report.Steps = append(report.Steps, step)
	}
	cancel()
	if padStarted {
		if err := <-padDone; err != nil {
			report.Status = "INCOMPLETE"
		}
	}
	if child != nil {
		report.Status = "INCOMPLETE"
	}
	return report, nil
}
