package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"slices"
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
		for requestIndex := 0; requestIndex < 2; requestIndex++ {
			header := make([]byte, 4)
			if _, err := io.ReadFull(connection, header); err != nil {
				t.Error(err)
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
				reply = []byte{9, 0, 0, 0, 0, 0, 0, 0, 0}
			case bytes.Equal(payload, []byte{1, 0x1c, 0x58, 0x56, 0}):
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
}
