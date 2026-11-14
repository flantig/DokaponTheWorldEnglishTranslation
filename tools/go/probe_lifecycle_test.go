package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestProbeLifecycleChild is a gated test executable, never a production mode.
// One synchronous deadline-bound server owns its socket and flushes its private
// fixture card on SIGTERM, so cold/stop can prove changed post-exit bytes.
func TestProbeLifecycleChild(t *testing.T) {
	if os.Getenv("DOKAPON_PROBE_LIFECYCLE_CHILD") != "1" {
		t.Skip("controlled child only")
	}
	root := os.Getenv("DOKAPON_PROBE_SESSION_ROOT")
	if root == "" {
		t.Fatal("missing controlled root")
	}
	stopped := make(chan os.Signal, 1)
	parentPID := os.Getppid()
	expires := time.Now().Add(30 * time.Second)
	signal.Notify(stopped, syscall.SIGTERM)
	defer signal.Stop(stopped)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(root, "peer.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	entries, err := os.ReadDir(filepath.Join(root, "receipts"))
	if err != nil {
		t.Fatal(err)
	}
	pending := []string{}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".pending.json") {
			pending = append(pending, entry.Name())
		}
	}
	evidence, _ := json.Marshal(map[string]any{"pid": os.Getpid(), "argv": os.Args, "pending": pending})
	if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("child-evidence-%d.json", os.Getpid())), evidence, 0600); err != nil {
		t.Fatal(err)
	}
	mode := uint16(608)
	watchAdvance := slices.Contains(os.Args, "watch-advance")
	watchStall := slices.Contains(os.Args, "watch-stall")
	watchCrash := slices.Contains(os.Args, "watch-crash")
	toggleTimeout := slices.Contains(os.Args, "toggle-timeout")
	watchSample, modeReads, seenPause := 0, 0, 0
	vmStatus := uint32(0)
	failedReady := slices.Contains(os.Args, "failed-ready")
	if failedReady {
		mode = 424
	}
	padBytes, _ := os.ReadFile(filepath.Join(root, "pad-events.bin"))
	seenReset := 0
	for offset := 0; offset+24 <= len(padBytes); offset += 24 {
		if binary.LittleEndian.Uint16(padBytes[offset+16:]) == 1 && binary.LittleEndian.Uint16(padBytes[offset+18:]) == 318 && binary.LittleEndian.Uint32(padBytes[offset+20:]) == 1 {
			seenReset++
		}
	}
	for {
		if os.Getppid() != parentPID || time.Now().After(expires) {
			return
		}
		select {
		case <-stopped:
			card := filepath.Join(root, "profile", "PCSX2", "memcards", "probe-slot1.ps2")
			data, err := os.ReadFile(card)
			if err != nil || len(data) == 0 {
				t.Fatalf("private card: %v", err)
			}
			data[0]++
			file, err := os.OpenFile(card, os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				t.Fatal(err)
			}
			_, err = file.Write(data)
			if err == nil {
				err = file.Sync()
			}
			closeErr := file.Close()
			if err != nil || closeErr != nil {
				t.Fatalf("flush: %v %v", err, closeErr)
			}
			return
		default:
		}
		_ = listener.SetDeadline(time.Now().Add(50 * time.Millisecond))
		connection, err := listener.AcceptUnix()
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			t.Fatal(err)
		}
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		for {
			header := make([]byte, 4)
			if _, err := io.ReadFull(connection, header); err != nil {
				if err != io.EOF {
					t.Error(err)
				}
				break
			}
			length := int(binary.LittleEndian.Uint32(header))
			if length != 5 && length != 9 {
				t.Errorf("bad frame size%d", length)
				break
			}
			payload := make([]byte, length-4)
			if _, err := io.ReadFull(connection, payload); err != nil {
				t.Error(err)
				break
			}
			var reply []byte
			switch {
			case bytes.Equal(payload, []byte{15}):
				events, _ := os.ReadFile(filepath.Join(root, "pad-events.bin"))
				pauses := 0
				for offset := 0; offset+24 <= len(events); offset += 24 {
					if binary.LittleEndian.Uint16(events[offset+16:]) == 1 && binary.LittleEndian.Uint16(events[offset+18:]) == 317 && binary.LittleEndian.Uint32(events[offset+20:]) == 1 {
						pauses++
					}
				}
				if pauses > seenPause && !toggleTimeout {
					vmStatus ^= uint32((pauses - seenPause) & 1)
				}
				seenPause = pauses
				reply = []byte{9, 0, 0, 0, 0, 0, 0, 0, 0}
				binary.LittleEndian.PutUint32(reply[5:], vmStatus)
			case bytes.Equal(payload, []byte{1, 0x1c, 0x58, 0x56, 0}):
				modeReads++
				if (watchAdvance || watchStall || watchCrash) && modeReads > 1 {
					watchSample++
					if watchCrash {
						_ = connection.Close()
						return
					}
					mode = 0x1b0
					if watchSample%2 == 0 {
						mode = 0x250
					}
				}
				events, _ := os.ReadFile(filepath.Join(root, "pad-events.bin"))
				resets := 0
				for offset := 0; offset+24 <= len(events); offset += 24 {
					if binary.LittleEndian.Uint16(events[offset+16:]) == 1 && binary.LittleEndian.Uint16(events[offset+18:]) == 318 && binary.LittleEndian.Uint32(events[offset+20:]) == 1 {
						resets++
					}
				}
				if resets > seenReset {
					mode = 608
					seenReset = resets
				}
				reply = []byte{7, 0, 0, 0, 0, 0, 0}
				binary.LittleEndian.PutUint16(reply[5:], mode)
				if !failedReady {
					mode = 736
				}
			case len(payload) == 5 && payload[0] <= 2:
				address := binary.LittleEndian.Uint32(payload[1:])
				value := uint32(0)
				known := true
				switch address {
				case 0x56b598:
					value = 1
					if watchAdvance && watchSample >= 4 {
						value = 2
					}
				case 0x56b18c, 0x56b190, 0x56a808:
					value = 0
				case 0x56a804:
					value = 5
				case 0x56a800:
					value = 1
				default:
					known = false
					for player := 0; player < 4; player++ {
						name := uint32(0x56bfcc + player*0x1fc)
						if address == name-2 {
							value = uint32(10 + player)
							known = true
						}
						if address == name+0x34 {
							value = uint32(1000 + player)
							known = true
						}
					}
				}
				if !known {
					t.Errorf("unexpected source read%x", payload)
					break
				}
				width := 1 << payload[0]
				reply = make([]byte, 5+width)
				binary.LittleEndian.PutUint32(reply, uint32(len(reply)))
				var encoded [4]byte
				binary.LittleEndian.PutUint32(encoded[:], value)
				copy(reply[5:], encoded[:width])
			default:
				t.Errorf("unexpected read-only request%x", payload)
			}
			if _, err := connection.Write(reply); err != nil {
				t.Error(err)
				break
			}
		}
		_ = connection.Close()
	}
}

// TestProbeLifecycle owns child creation/termination and durable side effects,
// unlike saved-record and local memory-peer tables in TestProbeRecords.
func TestProbeLifecycle(t *testing.T) {
	raw, err := os.ReadFile("testdata/probe-lifecycle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SourceFormat, Settings, SourceCard, PostColdCard, PostStopCard string
		Requests                                                       []ProbeLifecycleRequest
		ExpectedStatus                                                 []string   `json:"expected_status"`
		ExpectedEpoch                                                  []int      `json:"expected_epoch"`
		ExpectedReasons                                                []string   `json:"expected_reasons"`
		ExpectedEffects                                                [][]string `json:"expected_effects"`
		PadSetupSHA                                                    string     `json:"pad_setup_sha256"`
		PadAxesSHA                                                     string     `json:"pad_axes_sha256"`
		PadEventsSHA                                                   string     `json:"pad_events_sha256"`
		PadHatSHA                                                      string     `json:"pad_hat_sha256"`
		PadTriggerSHA                                                  string     `json:"pad_trigger_sha256"`
	}
	// Underscored source fields are explicit, not guessed by JSON field matching.
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fixture) != nil || json.Unmarshal(raw, &fields) != nil {
		t.Fatal("bad literal fixture")
	}
	for key, target := range map[string]*string{"source_format": &fixture.SourceFormat, "source_card": &fixture.SourceCard, "post_cold_card": &fixture.PostColdCard, "post_stop_card": &fixture.PostStopCard} {
		if json.Unmarshal(fields[key], target) != nil {
			t.Fatal(key)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	programBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	sources := t.TempDir()
	profile := ProbeLifecycleProfile{Version: 1, SourceFormat: fixture.SourceFormat, Root: root, Session: "offline-lifecycle", Program: RegistryInput{Path: executable, Size: int64(len(programBytes)), SHA256: fmt.Sprintf("%x", sha256.Sum256(programBytes))}, ProgramArgs: []string{"-test.run=^TestProbeLifecycleChild$", "--"}, Inputs: map[string]RegistryInput{}, Requests: fixture.Requests, ReadyTimeoutMS: 2000, StopTimeoutMS: 2000, QuietMS: 20}
	for role, content := range map[string]string{"iso": "synthetic-iso", "bios": "synthetic-bios", "card": fixture.SourceCard, "settings": fixture.Settings} {
		name := role + ".bin"
		path := filepath.Join(sources, name)
		if err := os.WriteFile(path, []byte(content), 0400); err != nil {
			t.Fatal(err)
		}
		profile.Inputs[role] = RegistryInput{Path: path, Size: int64(len(content)), SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(content)))}
	}
	t.Setenv("DOKAPON_PROBE_LIFECYCLE_CHILD", "1")
	requestRaw, _ := json.Marshal(profile)
	report, err := runProbeLifecycle(requestRaw)
	var failedExpected struct {
		InitialStatus string `json:"initial_status"`
		InitialReason string `json:"initial_reason"`
		StopStatus    string `json:"stop_status"`
		PostStopCard  string `json:"post_stop_card"`
	}
	if json.Unmarshal(fields["failed_ready"], &failedExpected) != nil {
		t.Fatal("failed-ready pre-output oracle")
	}
	failedProfile := profile
	failedProfile.Root = t.TempDir()
	_ = os.Chmod(failedProfile.Root, 0700)
	failedProfile.ProgramArgs = append(slices.Clone(profile.ProgramArgs), "failed-ready")
	failedProfile.Requests = []ProbeLifecycleRequest{fixture.Requests[0], fixture.Requests[len(fixture.Requests)-1]}
	failedProfile.ReadyTimeoutMS = 200
	failedRaw, _ := json.Marshal(failedProfile)
	failedReport, failedErr := runProbeLifecycle(failedRaw)
	for _, outcome := range []ProbeLifecycleReport{report, failedReport} {
		for _, step := range outcome.Steps {
			if strings.HasPrefix(step.Reason, "launched child identity differs") {
				for _, childRoot := range []string{root, failedProfile.Root} {
					log, _ := os.ReadFile(filepath.Join(childRoot, "child-epoch-0.log"))
					t.Logf("controlled child startup log: %s", log)
				}
			}
		}
	}
	// Cleanup only our controlled test executable if a regression left it alive.
	// It never targets a shared emulator or adopts another process.
	for _, step := range append(slices.Clone(report.Steps), failedReport.Steps...) {
		if step.Owned != nil {
			if _, observeErr := observeProbeProcess(ProbeMemoryRuntime{}, step.Owned.PID, step.Owned, profile.Program.SHA256); observeErr == nil {
				_ = syscall.Kill(step.Owned.PID, syscall.SIGTERM)
				var status syscall.WaitStatus
				_, _ = syscall.Wait4(step.Owned.PID, &status, 0, nil)
			}
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	if failedErr != nil || failedReport.Status != "INCOMPLETE" || len(failedReport.Steps) != 2 {
		t.Fatalf("failed-ready outcome: %+v %v", failedReport, failedErr)
	}
	if failedReport.Steps[0].Status != failedExpected.InitialStatus || failedReport.Steps[0].Reason != failedExpected.InitialReason || failedReport.Steps[1].Status != failedExpected.StopStatus || !reflect.DeepEqual(failedReport.Steps[1].Effects, []string{"terminate", "flush"}) || failedReport.Steps[1].CardAfter != fmt.Sprintf("%x", sha256.Sum256([]byte(failedExpected.PostStopCard))) {
		t.Errorf("safe stop after failed-ready: %+v", failedReport)
	}
	if len(report.Steps) != len(fixture.ExpectedStatus) {
		t.Fatalf("steps: %+v", report)
	}
	for index, step := range report.Steps {
		if step.Status != fixture.ExpectedStatus[index] || step.Epoch != fixture.ExpectedEpoch[index] || step.Reason != fixture.ExpectedReasons[index] || !reflect.DeepEqual(step.Effects, fixture.ExpectedEffects[index]) {
			t.Errorf("step%d: %+v", index, step)
		}
	}
	if report.Status != "INCOMPLETE" || !report.Steps[1].Replayed {
		t.Errorf("explicit refusals/replay lost: %+v", report)
	}
	first, warm, cold, stop := report.Steps[0], report.Steps[2], report.Steps[3], report.Steps[6]
	if first.Owned == nil || warm.Owned == nil || cold.Owned == nil {
		t.Fatalf("missing actual ownership: %+v", report)
	}
	if first.Owned.PID != warm.Owned.PID || first.Owned.Starttime != warm.Owned.Starttime || first.Owned.PID == cold.Owned.PID {
		t.Error("warm/cold process distinction")
	}
	if first.WidthAfter == nil || *first.WidthAfter != 608 || warm.WidthBefore == nil || *warm.WidthBefore != 736 || warm.WidthAfter == nil || *warm.WidthAfter != 608 {
		t.Error("boot/saved/reset width observations")
	}
	if cold.CardBefore != fmt.Sprintf("%x", sha256.Sum256([]byte(fixture.SourceCard))) || cold.CardAfter != fmt.Sprintf("%x", sha256.Sum256([]byte(fixture.PostColdCard))) || stop.CardBefore != cold.CardAfter || stop.CardAfter != fmt.Sprintf("%x", sha256.Sum256([]byte(fixture.PostStopCard))) {
		t.Errorf("changed postflush hashes: cold%+v stop%+v", cold, stop)
	}
	for role, input := range profile.Inputs {
		data, err := os.ReadFile(input.Path)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != input.SHA256 {
			t.Errorf("source%s changed", role)
		}
	}
	for _, owned := range []*ProbeProcessRecord{first.Owned, cold.Owned} {
		data, err := os.ReadFile(filepath.Join(root, fmt.Sprintf("child-evidence-%d.json", owned.PID)))
		if err != nil {
			t.Fatal(err)
		}
		var child struct {
			PID           int
			Argv, Pending []string
		}
		if json.Unmarshal(data, &child) != nil || child.PID != owned.PID || !reflect.DeepEqual(child.Argv, owned.Cmdline) || !slices.Contains(child.Pending, map[bool]string{false: "1-initial-02-launch.pending.json", true: "3-cold-03-launch.pending.json"}[owned.PID == cold.Owned.PID]) {
			t.Errorf("pre-effect child witness: %s", data)
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, "receipts"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 33 {
		t.Errorf("durable receipt count%d want33", len(entries))
	}
	var completeCount, pendingCount int
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".pending.json") {
			pendingCount++
			paired := strings.TrimSuffix(entry.Name(), ".pending.json") + ".complete.json"
			if _, err := os.Stat(filepath.Join(root, "receipts", paired)); err != nil {
				t.Error(err)
			}
		}
		if strings.HasSuffix(entry.Name(), ".complete.json") {
			completeCount++
		}
	}
	if pendingCount != 14 || completeCount != 18 {
		t.Errorf("durable effects%d/%d", pendingCount, completeCount)
	}
	beforeEntries := len(entries)
	replay, err := runProbeLifecycle(requestRaw)
	if err != nil {
		t.Fatal(err)
	}
	for index, step := range replay.Steps {
		if fixture.ExpectedStatus[index] == "COMPLETED" && !step.Replayed {
			t.Errorf("not replay%d: %+v", index, step)
		}
	}
	entries, _ = os.ReadDir(filepath.Join(root, "receipts"))
	if len(entries) != beforeEntries {
		t.Error("replay created effects")
	}
	pendingPath := filepath.Join(root, "receipts", "5-warm-00-quiescent.pending.json")
	if err := os.WriteFile(pendingPath, []byte(`{"phase":"pending"}`), 0600); err != nil {
		t.Fatal(err)
	}
	profile.Requests = []ProbeLifecycleRequest{{Session: profile.Session, Operation: "warm", Phase: "requested", Nonce: "5-warm"}, fixture.Requests[len(fixture.Requests)-1]}
	pendingRaw, _ := json.Marshal(profile)
	pendingReport, err := runProbeLifecycle(pendingRaw)
	if err != nil || pendingReport.Steps[0].Status != "UNKNOWN" || pendingReport.Steps[0].Reason != "durable pending effect prevents replay" || !pendingReport.Steps[1].Replayed {
		t.Errorf("pending cannot retry: %+v %v", pendingReport, err)
	}
	// C-global source/header oracle comparisons use only an owned event file.
	padRoot := t.TempDir()
	_ = os.Chmod(padRoot, 0700)
	ctx, cancel := context.WithCancel(context.Background())
	ready, done := make(chan error, 1), make(chan error, 1)
	go serveProbePad(ctx, ProbePadSpec{Root: padRoot, Backend: "event-sink"}, ready, done)
	if err := <-ready; err != nil {
		cancel()
		t.Fatal(err)
	}
	commands := []string{"tap CROSS 0.01", "tap UP 0.01", "tap L2 0.01", "tap CROSS NaN"}
	for index, command := range commands {
		connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(padRoot, "pad.sock"), Net: "unix"})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = io.WriteString(connection, command)
		if err == nil {
			err = connection.CloseWrite()
		}
		ack, readErr := io.ReadAll(io.LimitReader(connection, 257))
		_ = connection.Close()
		expected := "ok\n"
		if index == 3 {
			expected = "err invalid owned pad command\n"
		}
		if err != nil || readErr != nil || string(ack) != expected {
			t.Errorf("pad command%s %q %v %v", command, ack, err, readErr)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	events, err := os.ReadFile(filepath.Join(padRoot, "pad-events.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 288 {
		t.Fatalf("event bytes%d", len(events))
	}
	for index, expected := range []string{fixture.PadEventsSHA, fixture.PadHatSHA, fixture.PadTriggerSHA} {
		if fmt.Sprintf("%x", sha256.Sum256(events[index*96:(index+1)*96])) != expected {
			t.Errorf("independent ABI event%d mismatch", index)
		}
	}
	metadata, err := os.ReadFile(filepath.Join(padRoot, "pad-device.json"))
	if err != nil {
		t.Fatal(err)
	}
	var device struct {
		Setup string `json:"setup_hex"`
		Axes  string `json:"axes_hex"`
	}
	if json.Unmarshal(metadata, &device) != nil {
		t.Fatal("pad metadata")
	}
	for encoded, expected := range map[string]string{device.Setup: fixture.PadSetupSHA, device.Axes: fixture.PadAxesSHA} {
		data, err := hex.DecodeString(encoded)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != expected {
			t.Error("primary-header setup/axis oracle mismatch")
		}
	}
	if _, err := os.Lstat(filepath.Join(padRoot, "pad.sock")); !os.IsNotExist(err) {
		t.Error("owned pad socket survived cleanup")
	}
	var cadence struct {
		Prefixes []struct {
			Seed      string `json:"seed_uint64_decimal"`
			Count     int
			Intervals []int
			Next      int
		}
		Long struct {
			Seed      string `json:"seed_uint64_decimal"`
			Count     int
			Intervals []int
			Next      int
			SHA       string `json:"uint32_le_sha256"`
		} `json:"long_stream"`
	}
	cadenceRaw, err := os.ReadFile("testdata/probe-checkpoint-intervals.json")
	if err != nil || json.Unmarshal(cadenceRaw, &cadence) != nil {
		t.Fatal("independent cadence fixture", err)
	}
	for _, sample := range cadence.Prefixes {
		seed, err := strconv.ParseUint(sample.Seed, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		got, err := probeCheckpointIntervals(seed, sample.Count+1)
		if err != nil || len(got) != sample.Count+1 || !reflect.DeepEqual(got[:sample.Count], sample.Intervals) || got[sample.Count] != sample.Next {
			t.Fatalf("CPython prefix%s: %v %v", sample.Seed, got, err)
		}
	}
	longSeed, err := strconv.ParseUint(cadence.Long.Seed, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	long, err := probeCheckpointIntervals(longSeed, cadence.Long.Count+1)
	if err != nil || len(long) != 701 {
		t.Fatal("long cadence", err)
	}
	encodedIntervals := make([]byte, cadence.Long.Count*4)
	for index, value := range long[:cadence.Long.Count] {
		binary.LittleEndian.PutUint32(encodedIntervals[index*4:], uint32(value))
	}
	if !reflect.DeepEqual(long[:cadence.Long.Count], cadence.Long.Intervals) || long[cadence.Long.Count] != cadence.Long.Next || fmt.Sprintf("%x", sha256.Sum256(encodedIntervals)) != cadence.Long.SHA {
		t.Fatal("independent twist/rejection/continuation cadence")
	}
	for _, count := range []int{-1, 4097} {
		if _, err := probeCheckpointIntervals(0, count); err == nil {
			t.Error("unbounded cadence count admitted")
		}
	}
	var policyFixture struct {
		Policy ProbeLifecyclePolicy `json:"go_policy"`
		Cases  []struct {
			ID, Child            string
			Operations, Statuses []string
			Samples              int    `json:"watch_samples"`
			Repeated             int    `json:"watch_repeated"`
			Warning              bool   `json:"watch_warning"`
			Outcome              string `json:"watch_outcome"`
			Skips                []string
			Taps                 int  `json:"l3_taps"`
			Replay               bool `json:"last_stop_replay"`
			Recoveries           int  `json:"recovery_attempts"`
			MaxRecoveries        int  `json:"max_recoveries"`
		}
	}
	policyRaw, err := os.ReadFile("testdata/probe-lifecycle-policy.json")
	if err != nil || json.Unmarshal(policyRaw, &policyFixture) != nil {
		t.Fatal("source policy fixture", err)
	}
	var actionFacts struct {
		Source struct {
			PollMS   int `json:"poll_ms"`
			Warn     int `json:"warn_repeats"`
			Terminal int `json:"terminal_repeats"`
		} `json:"watch_source_policy"`
		Pause  string `json:"pause_command"`
		Settle int    `json:"pause_settle_ms"`
		Polls  int    `json:"status_polls"`
		PollMS int    `json:"status_poll_ms"`
	}
	if json.Unmarshal(probeLifecycleActions, &actionFacts) != nil || actionFacts.Source.PollMS != 1000 || actionFacts.Source.Warn != 200 || actionFacts.Source.Terminal != 1200 || actionFacts.Pause != "tap L3 0.1" || actionFacts.Settle != 50 || actionFacts.Polls != 20 || actionFacts.PollMS != 50 {
		t.Fatal("canonical source policy changed")
	}
	for _, sample := range policyFixture.Cases {
		candidate := profile
		candidate.Root = t.TempDir()
		_ = os.Chmod(candidate.Root, 0700)
		policy := policyFixture.Policy
		if sample.MaxRecoveries > 0 {
			policy.MaxRecoveries = sample.MaxRecoveries
		}
		candidate.Policy = &policy
		candidate.ProgramArgs = append(slices.Clone(profile.ProgramArgs), sample.Child)
		candidate.Requests = nil
		lastStop := ""
		for index, operation := range sample.Operations {
			nonce := fmt.Sprintf("%d-%s", index+1, operation)
			if operation == "stop" {
				if sample.Replay && index == len(sample.Operations)-1 {
					nonce = lastStop
				} else {
					lastStop = nonce
				}
			}
			candidate.Requests = append(candidate.Requests, ProbeLifecycleRequest{Session: candidate.Session, Operation: operation, Phase: "requested", Nonce: nonce})
		}
		input, _ := json.Marshal(candidate)
		outcome, err := runProbeLifecycle(input)
		for _, step := range outcome.Steps {
			if step.Owned != nil {
				if _, err := observeProbeProcess(ProbeMemoryRuntime{}, step.Owned.PID, step.Owned, candidate.Program.SHA256); err == nil {
					_ = syscall.Kill(step.Owned.PID, syscall.SIGTERM)
					var status syscall.WaitStatus
					_, _ = syscall.Wait4(step.Owned.PID, &status, 0, nil)
				}
			}
		}
		if err != nil || len(outcome.Steps) != len(sample.Statuses) {
			t.Fatalf("%s: %+v %v", sample.ID, outcome, err)
		}
		for index, step := range outcome.Steps {
			if step.Status != sample.Statuses[index] {
				t.Errorf("%s step%d: %+v", sample.ID, index, step)
			}
			if step.Status == "UNKNOWN" && step.Reason == "" {
				t.Error("unknown reason lost")
			}
		}
		if sample.Replay && !outcome.Steps[len(outcome.Steps)-1].Replayed {
			t.Error("completed safe stop repeated")
		}
		if sample.Samples > 0 {
			for _, step := range outcome.Steps {
				if step.Request.Operation == "watch" {
					if step.Samples != sample.Samples || step.Repeated != sample.Repeated || step.Warning != sample.Warning || step.WatchOutcome != sample.Outcome || !reflect.DeepEqual(step.Skips, sample.Skips) {
						t.Errorf("%s typed watch %+v", sample.ID, step)
					}
				}
			}
		}
		if sample.ID == "advance" {
			paused, resumed := outcome.Steps[1], outcome.Steps[2]
			if paused.VMStatusBefore == nil || *paused.VMStatusBefore != 0 || paused.VMStatusAfter == nil || *paused.VMStatusAfter != 1 || resumed.VMStatusBefore == nil || *resumed.VMStatusBefore != 1 || resumed.VMStatusAfter == nil || *resumed.VMStatusAfter != 0 || paused.Owned.PID != resumed.Owned.PID {
				t.Error("guarded same-owner pause/unpause")
			}
		}
		if sample.Recoveries > 0 {
			if !outcome.Steps[2].ExitedBeforeStop || !outcome.Steps[5].ExitedBeforeStop || outcome.Steps[3].RecoveryAttempts != 1 || outcome.Steps[3].Epoch != 1 {
				t.Errorf("crash disposal/recovery budget: %+v", outcome)
			}
			if sample.ID == "crash-recovery-budget" && outcome.Steps[6].Reason != "explicit Go recovery budget exhausted" {
				t.Errorf("recovery budget bypass: %+v", outcome)
			}
			if sample.ID == "per-epoch-recovery" && (outcome.Steps[6].RecoveryAttempts != 2 || outcome.Steps[6].Epoch != 2 || outcome.Steps[8].Reason != "recovery requires proved disposal after a read-only failure") {
				t.Errorf("prior failure reused by later epoch: %+v", outcome)
			}
		}
		events, err := os.ReadFile(filepath.Join(candidate.Root, "pad-events.bin"))
		if err != nil {
			t.Fatal(err)
		}
		taps := 0
		for offset := 0; offset+24 <= len(events); offset += 24 {
			if binary.LittleEndian.Uint16(events[offset+16:]) == 1 && binary.LittleEndian.Uint16(events[offset+18:]) == 317 && binary.LittleEndian.Uint32(events[offset+20:]) == 1 {
				taps++
			}
		}
		if taps != sample.Taps {
			t.Errorf("%s L3 effects%d want%d", sample.ID, taps, sample.Taps)
		}
		for role, input := range candidate.Inputs {
			content, err := os.ReadFile(input.Path)
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(content)) != input.SHA256 {
				t.Errorf("%s source%s changed", sample.ID, role)
			}
		}
	}
	resumeRaw, err := os.ReadFile("testdata/probe-lifecycle-resume.json")
	if err != nil {
		t.Fatal(err)
	}
	var resumeNames struct{ Refusals []string }
	if json.Unmarshal(resumeRaw, &resumeNames) != nil {
		t.Fatal("resume fixture")
	}
	for _, variant := range append([]string{"valid"}, resumeNames.Refusals...) {
		var source struct {
			Bundle   ProbeEvidenceBundle
			Receipt  ProbeResumeFacts
			Run      map[string]any
			Expected struct {
				Epoch     int   `json:"new_epoch"`
				Next      int   `json:"next_interval"`
				Intervals []int `json:"watch_intervals"`
			}
		}
		if json.Unmarshal(resumeRaw, &source) != nil {
			t.Fatal("source resume fixture")
		}
		priorRoot := t.TempDir()
		_ = os.Chmod(priorRoot, 0700)
		if err := os.MkdirAll(filepath.Join(priorRoot, "checkpoints", "screenshots"), 0700); err != nil {
			t.Fatal(err)
		}
		if variant == "native-slot" {
			value := 3
			source.Receipt.Slot = &value
		}
		if variant == "control" {
			value := uint32(2)
			source.Receipt.OriginalControl = &value
		}
		if variant == "cleanup" {
			source.Run["cleanup_complete"] = false
		}
		if variant == "event-order" {
			source.Bundle.Events[17], source.Bundle.Events[18] = source.Bundle.Events[18], source.Bundle.Events[17]
		}
		if variant == "seeded-prefix" {
			source.Receipt.ScheduledIntervals[0]++
			var event map[string]any
			_ = json.Unmarshal(source.Bundle.Events[0].Data, &event)
			event["interval_seconds"] = 5327
			source.Bundle.Events[0].Data, _ = json.Marshal(event)
		}
		if variant == "fingerprint" {
			var event map[string]any
			_ = json.Unmarshal(source.Bundle.Events[18].Data, &event)
			state := event["state"].(map[string]any)
			state["players"].([]any)[0].(map[string]any)["money"] = 101
			source.Bundle.Events[18].Data, _ = json.Marshal(event)
		}
		if variant == "already-resumed" {
			event, _ := json.Marshal(map[string]any{"event": "resumed", "event_id": 22, "checkpoint": 2, "time": "2026-11-13T00:01:06+0000", "slot": 2, "expected": source.Receipt.Expected})
			source.Bundle.Events = append(source.Bundle.Events, ProbeEvidenceEvent{Data: event})
		}
		var pngBytes bytes.Buffer
		if err := png.Encode(&pngBytes, image.NewNRGBA(image.Rect(0, 0, 1, 1))); err != nil {
			t.Fatal(err)
		}
		var eventBytes bytes.Buffer
		for _, saved := range source.Bundle.Events {
			var compact bytes.Buffer
			if err := json.Compact(&compact, saved.Data); err != nil {
				t.Fatal(err)
			}
			eventBytes.Write(compact.Bytes())
			eventBytes.WriteByte('\n')
			var event struct {
				Checkpoint int
				Screenshot string
			}
			_ = json.Unmarshal(saved.Data, &event)
			if event.Checkpoint == 1 && event.Screenshot != "" {
				if err := os.WriteFile(filepath.Join(priorRoot, "checkpoints", event.Screenshot), pngBytes.Bytes(), 0400); err != nil {
					t.Fatal(err)
				}
			}
		}
		card := []byte(fixture.PostColdCard)
		cardSHA := fmt.Sprintf("%x", sha256.Sum256(card))
		source.Run["private_card_final_sha256"] = cardSHA
		runData, _ := json.Marshal(source.Run)
		sequenceData, _ := json.Marshal(map[string]any{"status": "failed", "iso_sha256": source.Receipt.ISOSHA256, "runs": []any{map[string]any{"run": source.Receipt.SourceFrameRoot, "result": source.Run}}})
		source.Receipt.Artifacts = map[string]RegistryInput{}
		for role, data := range map[string][]byte{"run": runData, "sequence": sequenceData, "events": eventBytes.Bytes(), "card": card} {
			path := filepath.Join(priorRoot, role+".json")
			if role == "events" {
				path = filepath.Join(priorRoot, "checkpoints", "events.jsonl")
			}
			if role == "card" {
				path = filepath.Join(priorRoot, "card.ps2")
			}
			if err := os.WriteFile(path, data, 0400); err != nil {
				t.Fatal(err)
			}
			source.Receipt.Artifacts[role] = RegistryInput{Path: path, Size: int64(len(data)), SHA256: fmt.Sprintf("%x", sha256.Sum256(data))}
		}
		receiptData, _ := json.Marshal(source.Receipt)
		source.Bundle.Events = nil // The actual pinned JSONL is the sole event authority.
		evidenceData, _ := json.Marshal(source.Bundle)
		metadata := map[string]RegistryInput{}
		for role, data := range map[string][]byte{"receipt": receiptData, "evidence": evidenceData} {
			path := filepath.Join(priorRoot, role+".json")
			if err := os.WriteFile(path, data, 0400); err != nil {
				t.Fatal(err)
			}
			metadata[role] = RegistryInput{Path: path, Size: int64(len(data)), SHA256: fmt.Sprintf("%x", sha256.Sum256(data))}
		}
		candidate := profile
		candidate.Root = t.TempDir()
		_ = os.Chmod(candidate.Root, 0700)
		candidate.Session = "new-resume-session"
		candidate.Seed = source.Receipt.Seed
		candidate.Policy = &policyFixture.Policy
		candidate.ProgramArgs = append(slices.Clone(profile.ProgramArgs), "watch-advance")
		candidate.Inputs = map[string]RegistryInput{}
		for role, input := range profile.Inputs {
			candidate.Inputs[role] = input
		}
		candidate.Inputs["card"] = source.Receipt.Artifacts["card"]
		candidate.Resume = &ProbeLifecycleResume{Root: priorRoot, Receipt: metadata["receipt"], Evidence: metadata["evidence"]}
		if variant == "artifact-hash" {
			candidate.Resume.Evidence.SHA256 = strings.Repeat("0", 64)
		}
		candidate.Requests = []ProbeLifecycleRequest{{Session: candidate.Session, Operation: "resume", Phase: "requested", Nonce: "1-resume"}, {Session: candidate.Session, Operation: "watch", Phase: "requested", Nonce: "2-watch"}, {Session: candidate.Session, Operation: "stop", Phase: "requested", Nonce: "3-stop"}}
		input, _ := json.Marshal(candidate)
		outcome, runErr := runProbeLifecycle(input)
		for _, step := range outcome.Steps {
			if step.Owned != nil {
				if _, err := observeProbeProcess(ProbeMemoryRuntime{}, step.Owned.PID, step.Owned, candidate.Program.SHA256); err == nil {
					_ = syscall.Kill(step.Owned.PID, syscall.SIGTERM)
					var status syscall.WaitStatus
					_, _ = syscall.Wait4(step.Owned.PID, &status, 0, nil)
				}
			}
		}
		if variant == "valid" {
			if runErr != nil || outcome.Status != "COMPLETED" || len(outcome.Steps) != 3 {
				t.Fatalf("valid bound resume: %+v %v", outcome, runErr)
			}
			if outcome.Steps[0].Epoch != source.Expected.Epoch || outcome.Steps[0].ResumeEvidenceSHA256 == "" || !reflect.DeepEqual(outcome.Steps[1].ScheduledIntervals, source.Expected.Intervals) || outcome.Steps[2].CardAfter != fmt.Sprintf("%x", sha256.Sum256([]byte(fixture.PostStopCard))) {
				t.Errorf("resume preservation/draw prefix: %+v", outcome)
			}
		} else {
			if runErr == nil && (len(outcome.Steps) == 0 || outcome.Steps[0].Status != "REFUSED") {
				t.Errorf("%s invalid resume admitted: %+v", variant, outcome)
			}
			if _, err := os.Lstat(filepath.Join(candidate.Root, "profile")); !os.IsNotExist(err) {
				t.Errorf("%s invalid resume mutated profile", variant)
			}
			entries, _ := os.ReadDir(filepath.Join(candidate.Root, "receipts"))
			if len(entries) != 0 {
				t.Errorf("%s invalid resume emitted effect receipts", variant)
			}
		}
		for role, artifact := range source.Receipt.Artifacts {
			contents, err := os.ReadFile(artifact.Path)
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(contents)) != artifact.SHA256 {
				t.Errorf("%s resume source%s changed", variant, role)
			}
		}
	}
}
