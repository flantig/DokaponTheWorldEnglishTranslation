package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestProbeRecords(t *testing.T) {
	data, err := os.ReadFile("testdata/probe-records.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Bundle   json.RawMessage
		Expected map[string]any
		Cases    []struct {
			Name          string
			RemoveRoles   []string          `json:"remove_roles"`
			DuplicateRole string            `json:"duplicate_role"`
			DuplicateKey  bool              `json:"duplicate_key"`
			CopyRoles     map[string]string `json:"copy_roles"`
			Changes       []struct {
				Role   string
				File   string
				Path   []string
				Value  any
				Delete bool
			}
			Expected     map[string]any
			OmitExpected []string `json:"omit_expected"`
			Error        string
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, test := range fixture.Cases {
		var document map[string]any
		if err := json.Unmarshal(fixture.Bundle, &document); err != nil {
			t.Fatal(test.Name, err)
		}
		records := []any{}
		for _, value := range document["records"].([]any) {
			record := value.(map[string]any)
			if !slices.Contains(test.RemoveRoles, record["role"].(string)) {
				records = append(records, value)
			}
		}
		document["records"] = records
		for destination, source := range test.CopyRoles {
			var copied any
			for _, value := range records {
				if record := value.(map[string]any); record["role"] == source {
					encoded, _ := json.Marshal(record["data"])
					if err := json.Unmarshal(encoded, &copied); err != nil {
						t.Fatal(test.Name, err)
					}
				}
			}
			for _, value := range records {
				if record := value.(map[string]any); record["role"] == destination {
					record["data"] = copied
				}
			}
		}
		for _, change := range test.Changes {
			target := document
			if change.Role != "" || change.File != "" {
				collection, role := records, change.Role
				if change.File != "" {
					collection, role = document["files"].([]any), change.File
				}
				for _, value := range collection {
					record := value.(map[string]any)
					if record["role"] == role {
						target = record
						if change.Role != "" {
							target = record["data"].(map[string]any)
						}
					}
				}
			}
			for _, key := range change.Path[:len(change.Path)-1] {
				target = target[key].(map[string]any)
			}
			key := change.Path[len(change.Path)-1]
			if change.Delete {
				delete(target, key)
			} else {
				target[key] = change.Value
			}
		}
		if test.DuplicateRole != "" {
			for _, value := range records {
				if value.(map[string]any)["role"] == test.DuplicateRole {
					document["records"] = append(records, value)
					break
				}
			}
		}
		raw, err := json.Marshal(document)
		if err != nil {
			t.Fatal(test.Name, err)
		}
		if test.DuplicateKey {
			raw = bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
		}
		before := bytes.Clone(raw)
		report, err := admitProbeRecords(raw)
		if !bytes.Equal(raw, before) {
			t.Fatal(test.Name, "admission changed input")
		}
		if test.Error != "" {
			if err == nil || err.Error() != test.Error {
				t.Fatalf("%s: got %v, want %q", test.Name, err, test.Error)
			}
			continue
		}
		if err != nil {
			t.Fatal(test.Name, err)
		}
		expected := maps.Clone(fixture.Expected)
		for key, value := range test.Expected {
			expected[key] = value
		}
		for _, key := range test.OmitExpected {
			delete(expected, key)
		}
		expected["bundle_sha256"] = fmt.Sprintf("%x", sha256.Sum256(raw))
		order, pins := []any{}, map[string]any{}
		for _, value := range document["records"].([]any) {
			record := value.(map[string]any)
			role := record["role"].(string)
			encoded, _ := json.Marshal(record["data"])
			order = append(order, role)
			pins[role] = fmt.Sprintf("%x", sha256.Sum256(encoded))
		}
		expected["record_order"], expected["record_sha256"] = order, pins
		encoded, err := json.Marshal(report)
		if err != nil {
			t.Fatal(test.Name, err)
		}
		var actual map[string]any
		if err := json.Unmarshal(encoded, &actual); err != nil || !reflect.DeepEqual(actual, expected) {
			t.Fatalf("%s: full report mismatch: %s, expected %v (%v)", test.Name, encoded, expected, err)
		}
		// None of the bundle's claimed runtime paths exist; only the bundle is read.
		bundlePath := t.TempDir() + "/records.json"
		if err := os.WriteFile(bundlePath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		var cli bytes.Buffer
		if err := run([]string{"--probe-records", bundlePath}, &cli); err != nil || strings.TrimSpace(cli.String()) != string(encoded) {
			t.Fatalf("%s: CLI differs: %v %s", test.Name, err, cli.String())
		}
	}
	// Full reports were frozen from source contracts before the report was run.
	evidenceData, err := os.ReadFile("testdata/probe-evidence.json")
	if err != nil {
		t.Fatal(err)
	}
	var evidenceFixture struct {
		Bundle   json.RawMessage
		Expected map[string]any
		Cases    []struct {
			Name    string
			Changes []struct {
				Path   []string
				Value  any
				Delete bool
			}
			Expected map[string]any
			Error    string
		}
	}
	if err := json.Unmarshal(evidenceData, &evidenceFixture); err != nil {
		t.Fatal(err)
	}
	for _, test := range evidenceFixture.Cases {
		var document map[string]any
		if err := json.Unmarshal(evidenceFixture.Bundle, &document); err != nil {
			t.Fatal(err)
		}
		for _, change := range test.Changes {
			var target any = document
			for _, key := range change.Path[:len(change.Path)-1] {
				switch container := target.(type) {
				case map[string]any:
					target = container[key]
				case []any:
					index, err := strconv.Atoi(key)
					if err != nil {
						t.Fatal(err)
					}
					target = container[index]
				default:
					t.Fatal(test.Name, "invalid fixture path")
				}
			}
			key := change.Path[len(change.Path)-1]
			switch container := target.(type) {
			case map[string]any:
				if change.Delete {
					delete(container, key)
				} else {
					container[key] = change.Value
				}
			case []any:
				index, err := strconv.Atoi(key)
				if err != nil || change.Delete {
					t.Fatal(test.Name, "invalid fixture array change")
				}
				container[index] = change.Value
			default:
				t.Fatal(test.Name, "invalid fixture target")
			}
		}
		raw, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		before := bytes.Clone(raw)
		report, err := reportProbeEvidence(raw)
		if !bytes.Equal(raw, before) {
			t.Fatal(test.Name, "evidence report changed source")
		}
		if test.Error != "" {
			if err == nil || err.Error() != test.Error {
				t.Fatalf("%s: got %v, want %q", test.Name, err, test.Error)
			}
			continue
		}
		if err != nil {
			t.Fatal(test.Name, err)
		}
		expected := maps.Clone(evidenceFixture.Expected)
		for key, value := range test.Expected {
			expected[key] = value
		}
		expected["bundle_sha256"] = fmt.Sprintf("%x", sha256.Sum256(raw))
		expected["events"] = document["events"]
		encoded, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		var actual map[string]any
		if err := json.Unmarshal(encoded, &actual); err != nil || !reflect.DeepEqual(actual, expected) {
			t.Fatalf("%s: full evidence report mismatch: %s; expected %v (%v)", test.Name, encoded, expected, err)
		}
		again, err := reportProbeEvidence(raw)
		if err != nil || !reflect.DeepEqual(report, again) {
			t.Fatal(test.Name, "nondeterministic report", err)
		}
		bundlePath := t.TempDir() + "/evidence.json"
		if err := os.WriteFile(bundlePath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		var cli bytes.Buffer
		if err := run([]string{"--probe-evidence", bundlePath}, &cli); err != nil || strings.TrimSpace(cli.String()) != string(encoded) {
			t.Fatalf("%s: evidence CLI differs: %v %s", test.Name, err, cli.String())
		}
	}
	// Literal packet/decoder goldens precede acquisition. UseNumber preserves u64.
	memoryData, err := os.ReadFile("testdata/probe-memory.json")
	if err != nil {
		t.Fatal(err)
	}
	var memoryFixture struct {
		Bundle   json.RawMessage
		Expected json.RawMessage
		Cases    []struct {
			Name    string
			Changes []struct {
				Path  []string
				Value any
			}
			Expected map[string]json.RawMessage
			Error    string
		}
	}
	memoryDecoder := json.NewDecoder(bytes.NewReader(memoryData))
	memoryDecoder.UseNumber()
	if err := memoryDecoder.Decode(&memoryFixture); err != nil {
		t.Fatal(err)
	}
	for _, test := range memoryFixture.Cases {
		var document map[string]any
		decoder := json.NewDecoder(bytes.NewReader(memoryFixture.Bundle))
		decoder.UseNumber()
		if err := decoder.Decode(&document); err != nil {
			t.Fatal(err)
		}
		for _, change := range test.Changes {
			var target any = document
			for _, key := range change.Path[:len(change.Path)-1] {
				switch object := target.(type) {
				case map[string]any:
					target = object[key]
				case []any:
					index, _ := strconv.Atoi(key)
					target = object[index]
				default:
					t.Fatal(test.Name, "invalid memory fixture path")
				}
			}
			key := change.Path[len(change.Path)-1]
			switch object := target.(type) {
			case map[string]any:
				object[key] = change.Value
			case []any:
				index, _ := strconv.Atoi(key)
				object[index] = change.Value
			default:
				t.Fatal(test.Name, "invalid memory fixture target")
			}
		}
		raw, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		before := bytes.Clone(raw)
		report, err := readProbeMemory(raw, nil)
		if !bytes.Equal(raw, before) {
			t.Fatal(test.Name, "memory reader changed source")
		}
		if test.Error != "" {
			if err == nil || err.Error() != test.Error {
				t.Fatalf("%s: got %v, want %s", test.Name, err, test.Error)
			}
			continue
		}
		if err != nil {
			t.Fatal(test.Name, err)
		}
		var expected map[string]any
		decoder = json.NewDecoder(bytes.NewReader(memoryFixture.Expected))
		decoder.UseNumber()
		if err := decoder.Decode(&expected); err != nil {
			t.Fatal(err)
		}
		for key, value := range test.Expected {
			var decoded any
			decoder = json.NewDecoder(bytes.NewReader(value))
			decoder.UseNumber()
			if err := decoder.Decode(&decoded); err != nil {
				t.Fatal(err)
			}
			expected[key] = decoded
		}
		expected["bundle_sha256"] = fmt.Sprintf("%x", sha256.Sum256(raw))
		admissionBytes, err := json.Marshal(document["admission"])
		if err != nil {
			t.Fatal(err)
		}
		expected["session_evidence_sha256"] = fmt.Sprintf("%x", sha256.Sum256(admissionBytes))
		encoded, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		var actual map[string]any
		decoder = json.NewDecoder(bytes.NewReader(encoded))
		decoder.UseNumber()
		if err := decoder.Decode(&actual); err != nil || !reflect.DeepEqual(actual, expected) {
			t.Fatalf("%s: full memory report differs: %s; expected %v (%v)", test.Name, encoded, expected, err)
		}
		path := t.TempDir() + "/memory.json"
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		var cli bytes.Buffer
		if err := run([]string{"--probe-memory", path}, &cli); err != nil || strings.TrimSpace(cli.String()) != string(encoded) {
			t.Fatal(test.Name, "memory CLI differs", err)
		}
	}
	captureData, err := os.ReadFile("testdata/probe-capture.json")
	if err != nil {
		t.Fatal(err)
	}
	var captureFixture struct {
		Profile  ProbeCaptureProfile
		Receipt  json.RawMessage
		ImageHex string `json:"image_hex"`
		Cases    []struct {
			Name, Fault, Error    string
			Capture               bool
			Status, Reason        string
			CaptureID             string `json:"capture_id"`
			Expected              map[string]json.RawMessage
			OmitExpected          []string        `json:"omit_expected"`
			NoGuide               bool            `json:"no_guide"`
			NoPersist             bool            `json:"no_persist"`
			ExpectedMemoryDecoded json.RawMessage `json:"expected_memory_decoded"`
		}
		LinkCases []struct{ Name, Status, Error, Mutate string } `json:"link_cases"`
	}
	if err := json.Unmarshal(captureData, &captureFixture); err != nil {
		t.Fatal(err)
	}
	originalPNG, err := hex.DecodeString(captureFixture.ImageHex)
	if err != nil {
		t.Fatal(err)
	}
	peerCases := []struct {
		Name, Fault, Error    string
		Capture               bool
		Status, Reason        string
		CaptureID             string `json:"capture_id"`
		Expected              map[string]json.RawMessage
		OmitExpected          []string        `json:"omit_expected"`
		NoGuide               bool            `json:"no_guide"`
		NoPersist             bool            `json:"no_persist"`
		ExpectedMemoryDecoded json.RawMessage `json:"expected_memory_decoded"`
	}{
		{Name: "fragmented peer"},
		{Name: "peer wrong length", Fault: "length", Error: "unexpected probe packet length"},
		{Name: "peer failed status", Fault: "status", Error: "probe memory read failed"},
		{Name: "peer short packet", Fault: "short", Error: "incomplete probe packet:"},
		{Name: "peer timeout", Fault: "timeout", Error: "incomplete probe packet:"},
		{Name: "stale process before read", Fault: "stale_before", Error: "probe runtime process identity is stale"},
		{Name: "stale process after read", Fault: "stale_after", Error: "probe runtime process identity is stale"},
		{Name: "session changed after read", Fault: "receipt_after", Error: "probe runtime admitted session evidence changed"},
		{Name: "build changed after read", Fault: "build_after", Error: "probe runtime executable build differs"},
	}
	peerCases = append(peerCases, captureFixture.Cases...)
	// One peer goroutine services the same PINE packets and, for capture cases,
	// the fixed GUIDE service between the two sequential read batches.
	for _, test := range peerCases {
		var plan ProbeMemoryBundle
		if err := json.Unmarshal(memoryFixture.Bundle, &plan); err != nil {
			t.Fatal(err)
		}
		replies := slices.Clone(plan.Replies)
		plan.Replies = nil
		switch test.Fault {
		case "capture_scalar_only":
			plan.Decoders = []ProbeMemoryDecoder{{ID: "only-scalar", Kind: "scalar", Requests: []string{"high"}}}
		case "capture_unsupported_ui":
			plan.Decoders = []ProbeMemoryDecoder{{ID: "tags", Kind: "frame_tags", Requests: []string{"mode", "story", "week"}}, {ID: "bad-ui", Kind: "cursor", Requests: []string{"unaligned"}}}
		}
		if test.Capture {
			var document any
			if err := json.Unmarshal(plan.Admission, &document); err != nil {
				t.Fatal(err)
			}
			plan.Admission, err = json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
		}
		raw, err := json.Marshal(plan)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &plan); err != nil {
			t.Fatal(err)
		}
		var records ProbeRecordBundle
		if err := json.Unmarshal(plan.Admission, &records); err != nil {
			t.Fatal(err)
		}
		var owned ProbeProcessRecord
		for _, record := range records.Records {
			if record.Role == "owned" {
				if err := json.Unmarshal(record.Data, &owned); err != nil {
					t.Fatal(err)
				}
			}
		}
		root := t.TempDir()
		if err := os.Chmod(root, 0700); err != nil {
			t.Fatal(err)
		}
		processRoot := filepath.Join(root, "proc", strconv.Itoa(owned.PID))
		if err := os.MkdirAll(processRoot, 0700); err != nil {
			t.Fatal(err)
		}
		statText := fmt.Sprintf("%d (probe peer) S %s%d 0\n", owned.PID, strings.Repeat("0 ", 18), owned.Starttime)
		if test.Fault == "stale_before" {
			statText = strings.Replace(statText, fmt.Sprintf("%d 0\n", owned.Starttime), fmt.Sprintf("%d 0\n", owned.Starttime+1), 1)
		}
		for path, data := range map[string][]byte{filepath.Join(root, "records.json"): plan.Admission, filepath.Join(processRoot, "stat"): []byte(statText), filepath.Join(processRoot, "cmdline"): []byte(strings.Join(owned.Cmdline, "\x00") + "\x00"), filepath.Join(processRoot, "exe"): []byte("synthetic-executable-v1")} {
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(root, "peer.sock"), Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		var padListener *net.UnixListener
		var heldLock *os.File
		profile := captureFixture.Profile
		profile.Memory = raw
		if test.CaptureID != "" {
			profile.CaptureID = test.CaptureID
		}
		snapshots, output := filepath.Join(root, "snaps"), filepath.Join(root, "captures")
		var logData []byte
		if test.Capture {
			for _, path := range []string{snapshots, output} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(snapshots, "old.png"), originalPNG, 0600); err != nil {
				t.Fatal(err)
			}
			var evidence map[string]any
			if err := json.Unmarshal(evidenceFixture.Bundle, &evidence); err != nil {
				t.Fatal(err)
			}
			for _, value := range evidence["events"].([]any) {
				event := value.(map[string]any)
				data := event["data"].(map[string]any)
				if int(data["event_id"].(float64)) == profile.EventID {
					logData, err = json.Marshal(data)
					if err != nil {
						t.Fatal(err)
					}
					logData = append(logData, '\n')
				}
			}
			if len(logData) == 0 {
				t.Fatal("missing literal capture source event")
			}
			profile.LogBytes = len(logData)
			profile.LogSHA256 = fmt.Sprintf("%x", sha256.Sum256(logData))
			carrier := append(make([]byte, profile.LogOffset), logData...)
			if err := os.WriteFile(filepath.Join(root, "events.jsonl"), carrier, 0600); err != nil {
				t.Fatal(err)
			}
			if test.Fault == "capture_partial_timeout" || test.Fault == "capture_no_image" {
				profile.CaptureTimeoutMS = 200
			}
			if test.Fault == "capture_capacity" {
				profile.MaxRetainedBytes = 100
			}
			if test.Fault == "capture_lock_timeout" {
				profile.LockTimeoutMS = 30
			}
			if test.Fault == "capture_separate_budgets" || test.Fault == "capture_lock_timeout" {
				heldLock, err = os.OpenFile(filepath.Join(root, "capture.lock"), os.O_CREATE|os.O_RDWR, 0600)
				if err != nil {
					t.Fatal(err)
				}
				if err := syscall.Flock(int(heldLock.Fd()), syscall.LOCK_EX); err != nil {
					t.Fatal(err)
				}
			}
			padListener, err = net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(root, "pad.sock"), Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
		}
		peerResult := make(chan error, 1)
		var guideCommands []string
		go func() {
			if heldLock != nil {
				time.Sleep(650 * time.Millisecond)
				_ = syscall.Flock(int(heldLock.Fd()), syscall.LOCK_UN)
			}
			rounds := 1
			if test.Capture {
				rounds = 2
			}
			for round := 0; round < rounds; round++ {
				connection, err := listener.AcceptUnix()
				if err != nil {
					if test.Fault == "stale_before" || test.NoGuide {
						peerResult <- nil
					} else {
						peerResult <- err
					}
					return
				}
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(time.Second))
				for index, request := range plan.Requests {
					packet := make([]byte, 9)
					if _, err := io.ReadFull(connection, packet); err != nil {
						peerResult <- err
						return
					}
					if binary.LittleEndian.Uint32(packet) != 9 || packet[4] != *request.Opcode || binary.LittleEndian.Uint32(packet[5:]) != *request.Address {
						peerResult <- fmt.Errorf("wrong request packet %x", packet)
						return
					}
					reply, err := hex.DecodeString(replies[index])
					if err != nil {
						peerResult <- err
						return
					}
					if index == 0 {
						switch test.Fault {
						case "length":
							reply[0]--
							_, err = connection.Write(reply[:4])
							peerResult <- err
							return
						case "status":
							reply[4] = 1
							_, err = connection.Write(reply)
							peerResult <- err
							return
						case "short":
							_, err = connection.Write(reply[:len(reply)-1])
							peerResult <- err
							return
						case "timeout":
							time.Sleep(60 * time.Millisecond)
							peerResult <- nil
							return
						}
					}
					if index == len(plan.Requests)-1 {
						switch test.Fault {
						case "stale_after":
							err = os.WriteFile(filepath.Join(processRoot, "stat"), []byte(strings.Replace(statText, fmt.Sprintf("%d 0\n", owned.Starttime), fmt.Sprintf("%d 0\n", owned.Starttime+1), 1)), 0600)
						case "receipt_after":
							err = os.WriteFile(filepath.Join(root, "records.json"), []byte("{}"), 0600)
						case "build_after":
							err = os.WriteFile(filepath.Join(processRoot, "exe"), []byte("different-build"), 0600)
						}
						if round == 1 {
							switch test.Fault {
							case "capture_changed_log":
								err = os.WriteFile(filepath.Join(root, "events.jsonl"), []byte("changed"), 0600)
							case "capture_changed_image":
								err = os.WriteFile(filepath.Join(snapshots, "new.png"), []byte("changed"), 0600)
							case "capture_ambiguous":
								err = os.WriteFile(filepath.Join(snapshots, "other.png"), originalPNG, 0600)
							}
						}
						if err != nil {
							peerResult <- err
							return
						}
					}
					for _, fragment := range [][]byte{reply[:2], reply[2:4], reply[4:]} {
						if _, err := io.Copy(connection, bytes.NewReader(fragment)); err != nil {
							peerResult <- err
							return
						}
					}
				}
				if test.Capture && round == 0 {
					if test.NoGuide {
						peerResult <- nil
						return
					}
					pad, err := padListener.AcceptUnix()
					if err != nil {
						peerResult <- err
						return
					}
					_ = pad.SetDeadline(time.Now().Add(time.Second))
					command := make([]byte, len("tap GUIDE 0.05"))
					if _, err := io.ReadFull(pad, command); err != nil {
						_ = pad.Close()
						peerResult <- err
						return
					}
					guideCommands = append(guideCommands, string(command))
					if string(command) != "tap GUIDE 0.05" {
						_ = pad.Close()
						peerResult <- fmt.Errorf("unexpected capture command %q", command)
						return
					}
					ack := "ok"
					if test.Fault == "capture_bad_ack" {
						ack = "no"
					}
					_, err = io.WriteString(pad, ack)
					_ = pad.Close()
					if err != nil {
						peerResult <- err
						return
					}
					if test.Fault == "capture_bad_ack" || test.Fault == "capture_no_image" {
						peerResult <- nil
						return
					}
					if test.Fault == "capture_separate_budgets" {
						time.Sleep(650 * time.Millisecond)
					}
					data := originalPNG
					if test.Fault == "capture_partial_timeout" || test.Fault == "capture_partial_then_complete" {
						data = originalPNG[:8]
					}
					if err := os.WriteFile(filepath.Join(snapshots, "new.png"), data, 0600); err != nil {
						peerResult <- err
						return
					}
					if test.Fault == "capture_partial_timeout" {
						peerResult <- nil
						return
					}
					if test.Fault == "capture_partial_then_complete" {
						time.Sleep(30 * time.Millisecond)
						if err := os.WriteFile(filepath.Join(snapshots, "new.png"), originalPNG, 0600); err != nil {
							peerResult <- err
							return
						}
					}
					if test.Fault == "capture_cross_session" {
						if err := os.WriteFile(filepath.Join(root, "records.json"), []byte("{}"), 0600); err != nil {
							peerResult <- err
							return
						}
						peerResult <- nil
						return
					}
				}
			}
			peerResult <- nil
		}()
		timeout := 1000
		if test.Fault == "timeout" {
			timeout = 20
		}
		memoryRuntime := ProbeMemoryRuntime{Provenance: "synthetic_peer", Root: root, TimeoutMS: timeout}
		runtimeRaw, err := json.Marshal(memoryRuntime)
		if err != nil {
			t.Fatal(err)
		}
		var report ProbeMemoryReport
		var captured ProbeCaptureReceipt
		var readErr error
		callStart := time.Now()
		if test.Capture {
			profileRaw, err := json.Marshal(profile)
			if err != nil {
				t.Fatal(err)
			}
			captureRuntime, err := json.Marshal(ProbeCaptureRuntime{Memory: memoryRuntime, Snapshots: snapshots, Output: output, BackendPID: os.Getpid()})
			if err != nil {
				t.Fatal(err)
			}
			if test.Fault == "" {
				profilePath, runtimePath := filepath.Join(root, "capture-profile.json"), filepath.Join(root, "capture-runtime.json")
				if err := os.WriteFile(profilePath, profileRaw, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(runtimePath, captureRuntime, 0600); err != nil {
					t.Fatal(err)
				}
				var cli bytes.Buffer
				readErr = run([]string{"--probe-capture", profilePath, "--probe-capture-runtime", runtimePath}, &cli)
				if readErr == nil {
					readErr = json.Unmarshal(cli.Bytes(), &captured)
				}
			} else {
				captured, readErr = captureProbeEvidence(profileRaw, captureRuntime)
			}
		} else {
			report, readErr = readProbeMemory(raw, runtimeRaw)
		}
		callEnd := time.Now()
		_ = listener.Close()
		if padListener != nil {
			_ = padListener.Close()
		}
		if heldLock != nil {
			_ = heldLock.Close()
		}
		if err := <-peerResult; err != nil {
			t.Fatal(test.Name, "peer failed", err)
		}
		if test.Error != "" {
			if readErr == nil || !strings.HasPrefix(readErr.Error(), test.Error) {
				t.Fatalf("%s: got %v, want prefix %q", test.Name, readErr, test.Error)
			}
			if len(report.Observations) != 0 || len(guideCommands) != 0 {
				t.Fatal(test.Name, "failed preflight returned observations or triggered GUIDE")
			}
			continue
		}
		if readErr != nil {
			t.Fatal(test.Name, readErr)
		}
		var expectedMemory struct {
			Observations []ProbeMemoryObservation
			Decoded      []ProbeMemoryDecoded
		}
		if err := json.Unmarshal(memoryFixture.Expected, &expectedMemory); err != nil {
			t.Fatal(err)
		}
		if len(test.ExpectedMemoryDecoded) != 0 {
			expectedMemory.Decoded = nil // A shorter oracle must not retain old optional fields.
			if err := json.Unmarshal(test.ExpectedMemoryDecoded, &expectedMemory.Decoded); err != nil {
				t.Fatal(err)
			}
		}
		if !test.Capture {
			if report.Provenance != "synthetic_peer" || report.ProcessGuarded || !reflect.DeepEqual(report.Observations, expectedMemory.Observations) || !reflect.DeepEqual(report.Decoded, expectedMemory.Decoded) {
				t.Fatal(test.Name, "peer report or provenance differs")
			}
			continue
		}
		if test.NoGuide && (len(guideCommands) != 0 || captured.GuideCommand != "") || !test.NoGuide && (len(guideCommands) != 1 || guideCommands[0] != "tap GUIDE 0.05") {
			t.Fatal(test.Name, "capture trigger count or command differs")
		}
		if captured.Status != test.Status || captured.Reason != test.Reason {
			t.Fatalf("%s: outcome %s/%s, want %s/%s", test.Name, captured.Status, captured.Reason, test.Status, test.Reason)
		}
		started, startErr := time.Parse(time.RFC3339Nano, captured.StartedAt)
		finished, finishErr := time.Parse(time.RFC3339Nano, captured.FinishedAt)
		if startErr != nil || finishErr != nil || started.Before(callStart) || finished.After(callEnd) || finished.Before(started) {
			t.Fatal(test.Name, "capture timing envelope differs")
		}
		old, err := os.ReadFile(filepath.Join(snapshots, "old.png"))
		if err != nil || !bytes.Equal(old, originalPNG) {
			t.Fatal(test.Name, "preexisting snapshot changed")
		}
		if !slices.Contains(test.OmitExpected, "memory_before") && (captured.MemoryBefore == nil || !reflect.DeepEqual(captured.MemoryBefore.Decoded, expectedMemory.Decoded)) {
			actualDecoded, _ := json.Marshal(captured.MemoryBefore)
			expectedDecoded, _ := json.Marshal(expectedMemory.Decoded)
			t.Fatal(test.Name, "capture lacks original typed oracle", string(actualDecoded), string(expectedDecoded))
		}
		if captured.MemoryAfter != nil && !reflect.DeepEqual(captured.MemoryAfter.Decoded, expectedMemory.Decoded) {
			t.Fatal(test.Name, "post capture typed oracle differs")
		}
		var expected map[string]any
		decoder := json.NewDecoder(bytes.NewReader(captureFixture.Receipt))
		decoder.UseNumber()
		if err := decoder.Decode(&expected); err != nil {
			t.Fatal(err)
		}
		for key, value := range test.Expected {
			var decoded any
			decoder = json.NewDecoder(bytes.NewReader(value))
			decoder.UseNumber()
			if err := decoder.Decode(&decoded); err != nil {
				t.Fatal(err)
			}
			expected[key] = decoded
		}
		expected["status"], expected["started_at"], expected["finished_at"] = test.Status, captured.StartedAt, captured.FinishedAt
		if test.Reason != "" {
			expected["reason"] = test.Reason
		}
		expected["build_sha256"] = plan.BuildSHA256
		expected["log_sha256"] = profile.LogSHA256
		expected["log_hex"] = hex.EncodeToString(logData)
		for _, key := range test.OmitExpected {
			delete(expected, key)
		}
		for _, item := range []struct {
			Key   string
			Value *ProbeMemoryReport
		}{{"memory_before", captured.MemoryBefore}, {"memory_after", captured.MemoryAfter}} {
			if slices.Contains(test.OmitExpected, item.Key) {
				if item.Value != nil {
					t.Fatal(test.Name, "unexpected typed observation after incomplete acquisition")
				}
				continue
			}
			if item.Value == nil {
				t.Fatal(test.Name, "required typed observation is absent")
			}
			var value map[string]any
			decoder = json.NewDecoder(bytes.NewReader(memoryFixture.Expected))
			decoder.UseNumber()
			if err := decoder.Decode(&value); err != nil {
				t.Fatal(err)
			}
			value["provenance"] = "synthetic_peer"
			value["bundle_sha256"] = fmt.Sprintf("%x", sha256.Sum256(raw))
			value["session_evidence_sha256"] = fmt.Sprintf("%x", sha256.Sum256(plan.Admission))
			if len(test.ExpectedMemoryDecoded) != 0 {
				var expectedDecoded any
				decoder = json.NewDecoder(bytes.NewReader(test.ExpectedMemoryDecoded))
				decoder.UseNumber()
				if err := decoder.Decode(&expectedDecoded); err != nil {
					t.Fatal(err)
				}
				value["decoded"] = expectedDecoded
			}
			expected[item.Key] = value
		}
		encoded, _ := json.Marshal(captured)
		var actual map[string]any
		decoder = json.NewDecoder(bytes.NewReader(encoded))
		decoder.UseNumber()
		if err := decoder.Decode(&actual); err != nil || !reflect.DeepEqual(actual, expected) {
			t.Fatalf("%s: full capture receipt differs: %s; want %v (%v)", test.Name, encoded, expected, err)
		}
		if test.NoPersist {
			entries, err := os.ReadDir(output)
			if err != nil || len(entries) != 0 {
				t.Fatal(test.Name, "failed admission persisted output", err)
			}
		} else {
			receiptData, err := os.ReadFile(filepath.Join(output, profile.CaptureID+".json"))
			var persisted ProbeCaptureReceipt
			if err != nil || json.Unmarshal(receiptData, &persisted) != nil || !reflect.DeepEqual(persisted, captured) {
				t.Fatal(test.Name, "persisted receipt differs")
			}
		}
		if test.Status == "CAPTURED" {
			published, err := os.ReadFile(filepath.Join(output, profile.CaptureID+".png"))
			snapshot, sourceErr := os.ReadFile(filepath.Join(snapshots, "new.png"))
			if err != nil || sourceErr != nil || !bytes.Equal(published, originalPNG) || !bytes.Equal(snapshot, originalPNG) {
				t.Fatal(test.Name, "original PNG identity or preservation differs")
			}
			for _, linkCase := range captureFixture.LinkCases {
				var evidence map[string]any
				if err := json.Unmarshal(evidenceFixture.Bundle, &evidence); err != nil {
					t.Fatal(err)
				}
				selected := captured
				imageHex := captureFixture.ImageHex
				switch linkCase.Mutate {
				case "unknown":
					selected.Status, selected.Reason = "UNKNOWN", "capture unavailable"
					selected.MemoryAfter = nil
					imageHex = ""
				case "session":
					selected.Session = "wrong"
				case "image":
					imageHex = "00"
				case "empty_decoded", "empty_observations", "evidence_hash", "live_guard":
					before, after := *selected.MemoryBefore, *selected.MemoryAfter
					selected.MemoryBefore, selected.MemoryAfter = &before, &after
					switch linkCase.Mutate {
					case "empty_decoded":
						before.Decoded, after.Decoded = nil, nil
					case "empty_observations":
						before.Observations, after.Observations = nil, nil
					case "evidence_hash":
						before.SessionEvidenceSHA256, after.SessionEvidenceSHA256 = strings.Repeat("b", 64), strings.Repeat("b", 64)
					case "live_guard":
						selected.Provenance, before.Provenance, after.Provenance = "live", "live", "live"
						before.ProcessGuarded, after.ProcessGuarded = false, false
					}
				}
				evidence["captures"] = []ProbeCaptureObservation{{Receipt: selected, ImageHex: imageHex}}
				input, err := json.Marshal(evidence)
				if err != nil {
					t.Fatal(err)
				}
				linked, linkErr := reportProbeEvidence(input)
				if linkCase.Error != "" {
					if linkErr == nil || linkErr.Error() != linkCase.Error {
						t.Fatal(linkCase.Name, "link refusal differs", linkErr)
					}
					continue
				}
				if linkErr != nil || linked.Status != linkCase.Status || len(linked.Captures) != 1 {
					t.Fatal(linkCase.Name, "capture linkage differs", linkErr)
				}
				if linkCase.Status == "UNKNOWN" && len(linked.CoveredAreas) != 0 {
					t.Fatal(linkCase.Name, "unavailable capture counted as coverage")
				}
				// Compose the full expected report from the preexisting literal
				// cohort oracle and the independent capture receipt contract.
				baseBytes, _ := json.Marshal(evidenceFixture.Expected)
				var wanted map[string]any
				if err := json.Unmarshal(baseBytes, &wanted); err != nil {
					t.Fatal(err)
				}
				wanted["bundle_sha256"], wanted["events"] = fmt.Sprintf("%x", sha256.Sum256(input)), evidence["events"]
				receiptBytes, _ := json.Marshal(selected)
				link := ProbeCaptureLink{CaptureID: profile.CaptureID, EventID: profile.EventID, Checkpoint: profile.Checkpoint, Status: "ACCEPTED", ReceiptSHA256: fmt.Sprintf("%x", sha256.Sum256(receiptBytes)), Provenance: "synthetic_peer", ImagePath: profile.CaptureID + ".png", ImageSHA256: fmt.Sprintf("%x", sha256.Sum256(originalPNG))}
				if linkCase.Status == "UNKNOWN" {
					wanted["status"], wanted["covered_areas"] = "UNKNOWN", []uint32{}
					wanted["checkpoints"].([]any)[0].(map[string]any)["status"] = "UNKNOWN"
					wanted["checkpoints"].([]any)[0].(map[string]any)["reason"] = "capture evidence unavailable"
					link.Status, link.Reason, link.ImagePath, link.ImageSHA256 = "UNKNOWN", "capture unavailable", "", ""
				}
				wanted["captures"] = []ProbeCaptureLink{link}
				wantedBytes, _ := json.Marshal(wanted)
				actualBytes, _ := json.Marshal(linked)
				var normalizedWanted, normalizedActual any
				if json.Unmarshal(wantedBytes, &normalizedWanted) != nil || json.Unmarshal(actualBytes, &normalizedActual) != nil || !reflect.DeepEqual(normalizedWanted, normalizedActual) {
					t.Fatal(linkCase.Name, "full linked report differs")
				}
			}
		} else {
			if _, err := os.Lstat(filepath.Join(output, profile.CaptureID+".png")); !os.IsNotExist(err) {
				t.Fatal(test.Name, "unaccepted image was published")
			}
		}
		if test.Fault == "capture_partial_timeout" {
			partial, err := os.ReadFile(filepath.Join(snapshots, "new.png"))
			if err != nil || !bytes.Equal(partial, originalPNG[:8]) {
				t.Fatal(test.Name, "failed partial was removed or changed")
			}
		}
	}
}
