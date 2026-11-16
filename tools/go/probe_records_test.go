package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"maps"
	"math"
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
		Bundle    json.RawMessage
		Expected  json.RawMessage
		ExitCases []struct {
			Name, State, Fault string
			Error, Done        bool
		} `json:"exit_cases"`
		Cases []struct {
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
	if len(memoryFixture.ExitCases) != 19 {
		t.Fatal("literal process-exit cases")
	}
	for _, row := range memoryFixture.ExitCases {
		root := t.TempDir()
		processRoot := filepath.Join(root, "proc", "421")
		if row.Fault != "missing-proc-root" {
			if err := os.Mkdir(filepath.Join(root, "proc"), 0700); err != nil {
				t.Fatal(err)
			}
		}
		if row.Fault != "missing-process" && row.Fault != "missing-proc-root" {
			if err := os.MkdirAll(processRoot, 0700); err != nil {
				t.Fatal(err)
			}
			stat := fmt.Sprintf("421 (probe peer) %s %s123 0\n", row.State, strings.Repeat("0 ", 18))
			switch row.Fault {
			case "malformed":
				stat = "421 (probe peer) Z broken\n"
			case "wrong-pid":
				stat = strings.Replace(stat, "421 (", "422 (", 1)
			}
			for name, data := range map[string]string{"stat": stat, "cmdline": "fixture-program\x00", "exe": "fixture-build"} {
				if name == "stat" && (row.Fault == "missing-stat" || row.Fault == "nil-expected-missing" || row.Fault == "missing-stat-symlink-exe") || name == "cmdline" && row.Fault == "missing-cmdline" || name == "exe" && row.Fault == "missing-exe" {
					continue
				}
				if name == "cmdline" && row.Fault == "changed-cmdline" || name == "exe" && row.Fault == "changed-exe" {
					data = "changed"
				}
				if name == "exe" && row.Fault == "missing-stat-symlink-exe" {
					if err := os.Symlink("stat", filepath.Join(processRoot, name)); err != nil {
						t.Fatal(err)
					}
					continue
				}
				if err := os.WriteFile(filepath.Join(processRoot, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if row.Fault == "permission-stat" {
				if os.Geteuid() == 0 {
					t.Log("root bypasses fixture file permissions")
					continue
				}
				if err := os.Chmod(filepath.Join(processRoot, "stat"), 0000); err != nil {
					t.Fatal(err)
				}
			}
		}
		expected := &ProbeProcessRecord{PID: 421, Starttime: 123, Cmdline: []string{"fixture-program"}}
		switch row.Fault {
		case "nil-expected", "nil-expected-missing":
			expected = nil
		case "invalid-pid":
			expected.PID = 422
		case "invalid-start":
			expected.Starttime = 0
		case "reused":
			expected.Starttime++
		}
		_, err := observeProbeProcess(ProbeMemoryRuntime{Provenance: "synthetic_peer", Root: root}, 421, expected, fmt.Sprintf("%x", sha256.Sum256([]byte("fixture-build"))))
		if (err != nil) != row.Error || errors.Is(err, os.ErrProcessDone) != row.Done {
			t.Fatalf("%s process-exit classification: %v", row.Name, err)
		}
	}
	// Flatpak contracts are literal offline facts, never permission to enumerate host processes.
	flatpakData, err := os.ReadFile("testdata/probe-flatpak.json")
	if err != nil {
		t.Fatal(err)
	}
	var flatpakFixture struct {
		Profile    ProbeLifecycleProfile
		LaunchArgs []string `json:"launch_args"`
		NativeArgs []string `json:"native_args"`
		PlanCases  []struct {
			Name, Fault string
			Error       bool
		} `json:"plan_cases"`
		AdmissionCases []struct {
			Name, Fault string
			Error       bool
		} `json:"admission_cases"`
		StartupCases []struct {
			Name, Log       string
			Complete, Error bool
		} `json:"startup_cases"`
		SelectorCases []struct {
			Name, Fault          string
			Matched, Unqualified int
			Error                bool
		} `json:"selector_cases"`
	}
	if err := json.Unmarshal(flatpakData, &flatpakFixture); err != nil {
		t.Fatal(err)
	}
	for _, row := range flatpakFixture.PlanCases {
		profileBytes, _ := json.Marshal(flatpakFixture.Profile)
		var profile ProbeLifecycleProfile
		if err := json.Unmarshal(profileBytes, &profile); err != nil {
			t.Fatal(err)
		}
		switch row.Fault {
		case "argv0":
			profile.Flatpak.RuntimeArgv0 = ""
		case "project":
			profile.Flatpak.ProjectRoot = "/elsewhere"
		case "iso":
			input := profile.Inputs["iso"]
			input.Path = "/fixture/source/fixture.iso"
			profile.Inputs["iso"] = input
		case "grant":
			profile.Flatpak.LauncherArgs = []string{"--filesystem=/"}
		case "runtime-prefix":
			profile.ProgramArgs = []string{"-datapath=/foreign"}
		case "launcher-hash":
			profile.Flatpak.Launcher.SHA256 = ""
		}
		before, _ := json.Marshal(profile)
		launchProgram, args, nativeArgs, err := planProbeLaunch(profile)
		after, _ := json.Marshal(profile)
		if (err != nil) != row.Error || !bytes.Equal(before, after) {
			t.Fatalf("%s launch plan/mutation: %v", row.Name, err)
		}
		if !row.Error && (launchProgram != profile.Flatpak.Launcher || !slices.Equal(args, flatpakFixture.LaunchArgs) || !slices.Equal(nativeArgs, flatpakFixture.NativeArgs)) {
			t.Fatalf("%s literal launch/native argv differs", row.Name)
		}
	}
	directProfile := flatpakFixture.Profile
	directProfile.Flatpak = nil
	directProfile.ProgramArgs = []string{"-existing-prefix"}
	_, directArgs, directNative, directErr := planProbeLaunch(directProfile)
	if directErr != nil || !slices.Equal(directArgs, []string{"-existing-prefix", "-datapath", "/fixture/generated/session/profile", "-batch", "/fixture/generated/work/fixture.iso"}) || !slices.Equal(directNative, append([]string{directProfile.Program.Path}, directArgs...)) {
		t.Fatal("direct launch order changed", directErr)
	}
	for _, row := range flatpakFixture.StartupCases {
		paths, complete, err := validateProbeStartup([]byte(row.Log), "/fixture/generated/session/profile/PCSX2")
		if (err != nil) != row.Error || complete != row.Complete || paths["Snapshots"] != "/fixture/generated/session/profile/PCSX2/snaps" {
			t.Fatalf("%s startup prefix: complete=%v err=%v", row.Name, complete, err)
		}
	}
	var frameGoAdmission json.RawMessage
	for _, row := range flatpakFixture.AdmissionCases {
		profileBytes, _ := json.Marshal(flatpakFixture.Profile)
		var profile ProbeLifecycleProfile
		if err := json.Unmarshal(profileBytes, &profile); err != nil {
			t.Fatal(err)
		}
		epoch := 0
		owned := ProbeProcessRecord{PID: 421, Starttime: 123, State: "S", Cmdline: slices.Clone(flatpakFixture.NativeArgs), Session: profile.Session, ISO: profile.Inputs["iso"].Path, ISOSHA256: profile.Inputs["iso"].SHA256, Profile: filepath.Join(profile.Root, "profile"), Epoch: &epoch, PINESocket: "/tmp/fixture-runtime/pcsx2.sock", EnvironmentSHA256: strings.Repeat("1", 64)}
		launcher := ProbeProcessRecord{PID: 321, Starttime: 100, State: "S", Cmdline: []string{"bwrap", "--source-wrapper"}}
		startup := RegistryInput{Path: filepath.Join(profile.Root, "startup-epoch-0.json"), Size: 1, SHA256: strings.Repeat("2", 64)}
		step := ProbeLifecycleStep{Request: profile.Requests[0], Status: "COMPLETED", Epoch: 0, Owned: &owned, Launcher: &launcher, Startup: &startup, Effects: []string{"prepare", "pad", "launch", "verify"}}
		facts := profile
		facts.Requests = nil
		factsBytes, _ := json.Marshal(facts)
		step.ProfileSHA256 = fmt.Sprintf("%x", sha256.Sum256(factsBytes))
		switch row.Fault {
		case "native-argv":
			owned.Cmdline = []string{profile.Flatpak.Launcher.Path, "run", probeFlatpakAppID}
		case "launcher":
			step.Launcher = nil
		case "startup":
			step.Startup = nil
		case "startup-epoch":
			startup.Path = filepath.Join(profile.Root, "startup-epoch-1.json")
		case "endpoint":
			owned.PINESocket = ""
		case "environment":
			owned.EnvironmentSHA256 = ""
		case "profile-hash":
			step.ProfileSHA256 = strings.Repeat("0", 64)
		case "native-birth":
			owned.Starttime = 0
		}
		dataRoot := filepath.Join(profile.Root, "profile", "PCSX2")
		view := ProbeProfileRecord{Datapath: owned.Profile, DataRoot: dataRoot, SourceSettings: profile.Inputs["settings"].Path, SourceSettingsSHA256: profile.Inputs["settings"].SHA256, SourceCard: profile.Inputs["card"].Path, SourceCardSHA256: profile.Inputs["card"].SHA256, Card: filepath.Join(dataRoot, "memcards", "probe-slot1.ps2"), CardInitialSHA256: profile.Inputs["card"].SHA256, BIOS: filepath.Join(dataRoot, "bios", filepath.Base(profile.Inputs["bios"].Path))}
		ownedBytes, _ := json.Marshal(owned)
		viewBytes, _ := json.Marshal(view)
		bundle := ProbeRecordBundle{Version: 1, SourceSchema: "go-probe-records-v1", SourceSHA256: "5439db31097c19d3b92969d5403c2c19dc3518cea4ed4c075df1a3830b8ef56f", RunRoot: profile.Root, Context: "owned_go", Records: []ProbeRecord{{Role: "profile", Data: viewBytes}, {Role: "owned", Data: ownedBytes}}, AfterProcess: &owned, GoOwner: &ProbeGoOwner{Profile: profile, Step: step, CardSHA256: strings.Repeat("3", 64)}}
		raw, _ := json.Marshal(bundle)
		if row.Fault == "" {
			frameGoAdmission = bytes.Clone(raw)
		}
		report, err := admitProbeRecords(raw)
		if (err != nil) != row.Error || !row.Error && (report.Status != "ADMITTED" || report.LiveOwnership) {
			t.Fatalf("%s saved Flatpak admission: %v", row.Name, err)
		}
	}
	for _, row := range flatpakFixture.SelectorCases {
		root := t.TempDir()
		processRoot := filepath.Join(root, "proc", "421")
		if err := os.MkdirAll(processRoot, 0700); err != nil {
			t.Fatal(err)
		}
		state, comm, executable, argv, notBefore := "S", "pcsx2-qt\n", "native-build", "pcsx2-qt\x00", uint64(100)
		switch row.Fault {
		case "build":
			executable = "launcher-build"
		case "argv":
			argv = "flatpak\x00"
		case "birth":
			notBefore = 124
		case "unrelated":
			comm = "unrelated\n"
		case "zombie":
			state = "Z"
		}
		for name, data := range map[string]string{"stat": fmt.Sprintf("421 (pcsx2-qt) %s %s123 0\n", state, strings.Repeat("0 ", 18)), "comm": comm, "exe": executable, "cmdline": argv, "environ": "XDG_RUNTIME_DIR=/tmp/fixture-runtime\x00"} {
			if err := os.WriteFile(filepath.Join(processRoot, name), []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if row.Fault == "comm-link" || row.Fault == "environ-link" {
			name := strings.TrimSuffix(row.Fault, "-link")
			if err := os.Remove(filepath.Join(processRoot, name)); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("stat", filepath.Join(processRoot, name)); err != nil {
				t.Fatal(err)
			}
		}
		runtime := ProbeMemoryRuntime{Provenance: "synthetic_flatpak", Root: root}
		build := fmt.Sprintf("%x", sha256.Sum256([]byte("native-build")))
		matched, unqualified, err := selectProbeProcesses(runtime, []int{421}, build, []string{"pcsx2-qt"}, notBefore)
		if (err != nil) != row.Error || len(matched) != row.Matched || len(unqualified) != row.Unqualified {
			t.Fatalf("%s selector: matched=%d unqualified=%d err=%v", row.Name, len(matched), len(unqualified), err)
		}
		if len(matched) > 0 && (matched[0].PINESocket != "/tmp/fixture-runtime/pcsx2.sock" || len(matched[0].EnvironmentSHA256) != 64) {
			t.Fatal("synthetic native namespace facts missing")
		}
		processes := ProbeLifecycleProcesses{Launched: true, Candidates: matched, Unqualified: unqualified}
		if _, err := terminateProbeProcesses(&processes, runtime, build, time.Millisecond); err == nil || !strings.Contains(err.Error(), "never authorize signaling") || processes.CleanupAttempts != 0 {
			t.Fatal("synthetic facts crossed signaling boundary", err)
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
	var frameCaptureBase json.RawMessage
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
			defer close(peerResult)
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
		peerErr := <-peerResult
		// The peer sends once; channel closure joins its deferred cleanup.
		<-peerResult
		if heldLock != nil {
			_ = heldLock.Close()
		}
		if peerErr != nil {
			t.Fatal(test.Name, "peer failed", peerErr)
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
			if frameCaptureBase == nil {
				frameCaptureBase, _ = json.Marshal(captured)
			}
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
	// Independent Pillow RGB conversion and resize/mean facts are saved data.
	// Reuse a previously qualified capture, without any additional acquisition.
	if len(frameCaptureBase) == 0 {
		t.Fatal("frame cases lack an existing qualified capture")
	}
	frameZipData, err := os.ReadFile("testdata/probe-frame-normalization.zip")
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(frameZipData)) != "5fc1cc91c1056c7f035642a07321b5cec1b6618d1b921de03a9c670b247126fc" {
		t.Fatal("frame oracle ZIP", err)
	}
	frameZip, err := zip.NewReader(bytes.NewReader(frameZipData), int64(len(frameZipData)))
	if err != nil || len(frameZip.File) != 14 {
		t.Fatal("frame oracle members", err)
	}
	indexFile, err := frameZip.Open("index.json")
	if err != nil {
		t.Fatal(err)
	}
	frameIndex, err := io.ReadAll(indexFile)
	_ = indexFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	var frameOracle struct {
		Comparisons []struct {
			ID              string
			CurrentID       string `json:"current_id"`
			PreviousID      string `json:"previous_id"`
			SumAbsRGB       uint64 `json:"sum_abs_rgb"`
			MeanFloat64Bits string `json:"mean_float64_bits"`
		}
	}
	var frameSources []struct {
		ID                      string
		PNGFile                 string `json:"png_file"`
		PNGSHA256               string `json:"png_sha256"`
		ConvertedRGB3SHA256     string `json:"converted_rgb3_sha256"`
		Normalized640RGB3SHA256 string `json:"normalized640_rgb3_sha256"`
		Sample64RGB3SHA256      string `json:"sample64_rgb3_sha256"`
		Width, Height           int
	}
	var sourceIndex struct{ Sources json.RawMessage }
	if json.Unmarshal(frameIndex, &frameOracle) != nil || json.Unmarshal(frameIndex, &sourceIndex) != nil || json.Unmarshal(sourceIndex.Sources, &frameSources) != nil || len(frameSources) != 13 || len(frameOracle.Comparisons) != 12 {
		t.Fatal("frame oracle index")
	}
	framePNGs := map[string][]byte{}
	frameSourceIndices := map[string]int{}
	for i, source := range frameSources {
		file, err := frameZip.Open(source.PNGFile)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(file)
		_ = file.Close()
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != source.PNGSHA256 {
			t.Fatal(source.ID, "frame PNG pin", err)
		}
		framePNGs[source.ID], frameSourceIndices[source.ID] = data, i
	}
	var baseFrameReceipt ProbeCaptureReceipt
	if err := json.Unmarshal(frameCaptureBase, &baseFrameReceipt); err != nil {
		t.Fatal(err)
	}
	var frameBaseBundle ProbeEvidenceBundle
	if err := json.Unmarshal(evidenceFixture.Bundle, &frameBaseBundle); err != nil {
		t.Fatal(err)
	}
	// Match the existing evidence fixture's canonical admission serialization,
	// preserving integer literals while retaining the capture's original hash.
	var frameAdmissionDocument any
	frameAdmissionDecoder := json.NewDecoder(bytes.NewReader(frameBaseBundle.Admission))
	frameAdmissionDecoder.UseNumber()
	if err := frameAdmissionDecoder.Decode(&frameAdmissionDocument); err != nil {
		t.Fatal(err)
	}
	frameBaseBundle.Admission, _ = json.Marshal(frameAdmissionDocument)
	if baseFrameReceipt.MemoryBefore.SessionEvidenceSHA256 != fmt.Sprintf("%x", sha256.Sum256(frameBaseBundle.Admission)) {
		t.Fatal("saved frame admission fixture does not match captured evidence hash")
	}
	frameStageChecks, framePairChecks := 0, 0
	for _, source := range frameSources {
		bundle := frameBaseBundle
		receipt := baseFrameReceipt
		receipt.CaptureID = "frame-first-" + source.ID
		receipt.ImagePath = receipt.CaptureID + ".png"
		receipt.ImageSHA256, receipt.ImageBytes, receipt.Width, receipt.Height = source.PNGSHA256, int64(len(framePNGs[source.ID])), source.Width, source.Height
		bundle.Captures = []ProbeCaptureObservation{{Receipt: receipt, ImageHex: hex.EncodeToString(framePNGs[source.ID])}}
		bundle.FrameComparisons = []ProbeFrameComparison{{CaptureID: receipt.CaptureID}}
		raw, _ := json.Marshal(bundle)
		before := bytes.Clone(raw)
		got, err := reportProbeEvidence(raw)
		if err != nil || len(got.FrameComparisons) != 1 || !bytes.Equal(raw, before) {
			t.Fatal(source.ID, "first frame analysis", err)
		}
		facts := got.FrameComparisons[0]
		if facts.Status != "AVAILABLE" || facts.SourceRGBSHA256 != source.ConvertedRGB3SHA256 || facts.NormalizedRGBSHA256 != source.Normalized640RGB3SHA256 || facts.ComparisonRGBSHA256 != source.Sample64RGB3SHA256 || facts.MeanRGBDifference == nil || *facts.MeanRGBDifference != 999 || facts.SumAbsRGB != nil {
			t.Fatalf("%s independent RGB stages/first999 differ: %+v", source.ID, facts)
		}
		bundle.FrameComparisons = nil
		noRequest, _ := json.Marshal(bundle)
		plain, err := reportProbeEvidence(noRequest)
		got.FrameComparisons = nil
		got.BundleSHA256 = plain.BundleSHA256
		plainJSON, _ := json.Marshal(plain)
		compatibleJSON, _ := json.Marshal(got)
		if err != nil || plain.FrameComparisons != nil || !reflect.DeepEqual(got, plain) || !bytes.Equal(plainJSON, compatibleJSON) || bytes.Contains(plainJSON, []byte("frame_comparisons")) {
			t.Fatal(source.ID, "omitted frame analysis changed existing report", err)
		}
		frameStageChecks += 3
	}
	for _, pair := range frameOracle.Comparisons {
		bundle := frameBaseBundle
		pairSources := []string{pair.CurrentID}
		if pair.PreviousID != "" {
			pairSources = append([]string{pair.PreviousID}, pairSources...)
		}
		for i, id := range pairSources {
			source := frameSources[frameSourceIndices[id]]
			receipt := baseFrameReceipt
			receipt.CaptureID = fmt.Sprintf("frame-%s-%d", pair.ID, i)
			receipt.ImagePath = receipt.CaptureID + ".png"
			receipt.ImageSHA256, receipt.ImageBytes, receipt.Width, receipt.Height = source.PNGSHA256, int64(len(framePNGs[id])), source.Width, source.Height
			bundle.Captures = append(bundle.Captures, ProbeCaptureObservation{Receipt: receipt, ImageHex: hex.EncodeToString(framePNGs[id])})
		}
		bundle.FrameComparisons = []ProbeFrameComparison{{CaptureID: bundle.Captures[len(bundle.Captures)-1].Receipt.CaptureID}}
		if pair.PreviousID != "" {
			bundle.FrameComparisons[0].PreviousCaptureID = bundle.Captures[0].Receipt.CaptureID
		}
		raw, _ := json.Marshal(bundle)
		got, err := reportProbeEvidence(raw)
		if err != nil || len(got.FrameComparisons) != 1 {
			t.Fatal(pair.ID, "frame pair", err)
		}
		facts := got.FrameComparisons[0]
		bits, err := strconv.ParseUint(pair.MeanFloat64Bits, 16, 64)
		if err != nil || facts.Status != "AVAILABLE" || facts.MeanRGBDifference == nil || math.Float64bits(*facts.MeanRGBDifference) != bits {
			t.Fatalf("%s independent mean differs: %+v", pair.ID, facts)
		}
		if pair.PreviousID == "" {
			if facts.SumAbsRGB != nil || *facts.MeanRGBDifference != 999 {
				t.Fatal(pair.ID, "missing predecessor fabricated sum")
			}
		} else {
			if facts.SumAbsRGB == nil || *facts.SumAbsRGB != pair.SumAbsRGB || facts.PreviousComparisonRGBSHA256 != frameSources[frameSourceIndices[pair.PreviousID]].Sample64RGB3SHA256 {
				t.Fatal(pair.ID, "independent sum/predecessor differs")
			}
			if bundle.Captures[0].Receipt.CaptureID == bundle.Captures[1].Receipt.CaptureID {
				t.Fatal("same source image is not same capture")
			}
		}
		framePairChecks++
	}
	if frameStageChecks != 39 || framePairChecks != 12 {
		t.Fatal("independent frame oracle coverage", frameStageChecks, framePairChecks)
	}
	// Multiple current captures may share one explicitly selected predecessor.
	multi := frameBaseBundle
	for i, id := range []string{"uniform-0", "uniform-3", "uniform-6"} {
		source := frameSources[frameSourceIndices[id]]
		receipt := baseFrameReceipt
		receipt.CaptureID = fmt.Sprintf("frame-shared-%d", i)
		receipt.ImagePath = receipt.CaptureID + ".png"
		receipt.ImageSHA256, receipt.ImageBytes, receipt.Width, receipt.Height = source.PNGSHA256, int64(len(framePNGs[id])), source.Width, source.Height
		multi.Captures = append(multi.Captures, ProbeCaptureObservation{Receipt: receipt, ImageHex: hex.EncodeToString(framePNGs[id])})
	}
	multi.FrameComparisons = []ProbeFrameComparison{{CaptureID: "frame-shared-0"}, {CaptureID: "frame-shared-1", PreviousCaptureID: "frame-shared-0"}, {CaptureID: "frame-shared-2", PreviousCaptureID: "frame-shared-0"}}
	multiRaw, _ := json.Marshal(multi)
	multiReport, err := reportProbeEvidence(multiRaw)
	if err != nil || len(multiReport.FrameComparisons) != 3 || *multiReport.FrameComparisons[0].MeanRGBDifference != 999 || *multiReport.FrameComparisons[1].MeanRGBDifference != 1 || *multiReport.FrameComparisons[2].MeanRGBDifference != 2 {
		t.Fatal("multiple frame pairs/shared predecessor", err)
	}
	for _, fault := range []string{"absent-current", "absent-previous", "self", "forward", "duplicate-current", "too-many", "current-unavailable", "previous-unavailable", "first-current-unavailable", "gray16", "palette", "intermediate-budget", "cross-pid", "cross-session", "cross-epoch", "cross-build", "cross-provenance"} {
		encoded, _ := json.Marshal(multi)
		var bundle ProbeEvidenceBundle
		if err := json.Unmarshal(encoded, &bundle); err != nil {
			t.Fatal(err)
		}
		bundle.FrameComparisons = []ProbeFrameComparison{{CaptureID: "frame-shared-1", PreviousCaptureID: "frame-shared-0"}}
		expectedError := true
		switch fault {
		case "absent-current":
			bundle.FrameComparisons[0].CaptureID = "absent"
		case "absent-previous":
			bundle.FrameComparisons[0].PreviousCaptureID = "absent"
		case "self":
			bundle.FrameComparisons[0].PreviousCaptureID = "frame-shared-1"
		case "forward":
			bundle.FrameComparisons[0].CaptureID = "frame-shared-0"
			bundle.FrameComparisons[0].PreviousCaptureID = "frame-shared-1"
		case "duplicate-current":
			bundle.FrameComparisons = append(bundle.FrameComparisons, bundle.FrameComparisons[0])
		case "too-many":
			bundle.FrameComparisons = make([]ProbeFrameComparison, 257)
		case "cross-pid":
			bundle.Captures[1].Receipt.PID++
		case "cross-session":
			bundle.Captures[1].Receipt.Session = "other"
		case "cross-epoch":
			bundle.Captures[1].Receipt.Epoch++
		case "cross-build":
			bundle.Captures[1].Receipt.BuildSHA256 = strings.Repeat("f", 64)
		case "cross-provenance":
			bundle.Captures[1].Receipt.Provenance = "other"
		case "current-unavailable", "previous-unavailable", "first-current-unavailable":
			expectedError = false
			if fault == "first-current-unavailable" {
				bundle.FrameComparisons[0].PreviousCaptureID = ""
			}
			at := 1
			if fault == "previous-unavailable" {
				at = 0
			}
			bundle.Captures[at].Receipt.Status, bundle.Captures[at].Receipt.Reason = "UNKNOWN", "source unavailable"
		case "gray16", "palette", "intermediate-budget":
			expectedError = false
			var raster image.Image = image.NewGray16(image.Rect(0, 0, 1, 1))
			if fault == "palette" {
				raster = image.NewPaletted(image.Rect(0, 0, 1, 1), color.Palette{color.Black, color.White})
			}
			if fault == "intermediate-budget" {
				raster = image.NewNRGBA(image.Rect(0, 0, 50, 4096))
			}
			var buffer bytes.Buffer
			if err := png.Encode(&buffer, raster); err != nil {
				t.Fatal(err)
			}
			data := buffer.Bytes()
			bundle.Captures[1].ImageHex = hex.EncodeToString(data)
			bundle.Captures[1].Receipt.ImageBytes = int64(len(data))
			bundle.Captures[1].Receipt.ImageSHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
			bundle.Captures[1].Receipt.Width, bundle.Captures[1].Receipt.Height = raster.Bounds().Dx(), raster.Bounds().Dy()
		}
		raw, _ := json.Marshal(bundle)
		got, err := reportProbeEvidence(raw)
		if (err != nil) != expectedError {
			t.Fatal(fault, "frame structural/availability result", err)
		}
		if expectedError {
			continue
		}
		if len(got.FrameComparisons) != 1 || got.FrameComparisons[0].Status != "UNKNOWN" || got.FrameComparisons[0].MeanRGBDifference != nil || got.FrameComparisons[0].SumAbsRGB != nil {
			t.Fatal(fault, "unavailable analysis fabricated numerical facts")
		}
		bundle.FrameComparisons = nil
		raw, _ = json.Marshal(bundle)
		plain, err := reportProbeEvidence(raw)
		got.FrameComparisons = nil
		got.BundleSHA256 = plain.BundleSHA256
		if err != nil || !reflect.DeepEqual(got, plain) {
			t.Fatal(fault, "frame unavailability changed raw capture/report", err)
		}
		if fault == "gray16" || fault == "palette" || fault == "intermediate-budget" {
			if plain.Captures[1].Status != "ACCEPTED" {
				t.Fatal(fault, "rawaccepted image suppressed")
			}
		}
	}

	// A valid saved-Go warm/cold pair must pass raw linkage before the new
	// comparison identity guard can be tested independently of old refusals.
	pairedData, err := os.ReadFile("testdata/probe-paired.json")
	if err != nil {
		t.Fatal(err)
	}
	var paired struct {
		Report struct{ Events []ProbeEvidenceEvent } `json:"full_normalized_report"`
	}
	if json.Unmarshal(pairedData, &paired) != nil || len(paired.Report.Events) != 10 || len(frameGoAdmission) == 0 {
		t.Fatal("saved Go cross-epoch source scaffold")
	}
	cross := frameBaseBundle
	cross.SourceSchema = "probe-evidence-go-v1"
	cross.Cohort = "go-checkpoint-only-v1"
	cross.Members = nil
	cross.Checks = nil
	cross.Captures = nil
	cross.Events = nil
	var sourceOffset int64
	for _, saved := range paired.Report.Events {
		var event map[string]json.RawMessage
		if json.Unmarshal(saved.Data, &event) != nil {
			t.Fatal("paired source event")
		}
		event["time"] = json.RawMessage(`"2026-11-16T00:00:00+0000"`)
		data, _ := json.Marshal(event)
		cross.Events = append(cross.Events, ProbeEvidenceEvent{Offset: sourceOffset, Data: data})
		sourceOffset += int64(len(data))
	}
	var actionFacts struct {
		Actions map[string]struct{ Effects []string }
	}
	if json.Unmarshal(probeLifecycleActions, &actionFacts) != nil {
		t.Fatal("saved Go operation facts")
	}
	for epoch, operation := range []string{"warm-load", "cold-load"} {
		var records ProbeRecordBundle
		if json.Unmarshal(frameGoAdmission, &records) != nil {
			t.Fatal("saved Go admission scaffold")
		}
		owned := *records.GoOwner.Step.Owned
		owned.PID, owned.Starttime, owned.Epoch = 421+epoch, uint64(123+epoch), &epoch
		request := ProbeLifecycleRequest{Session: records.GoOwner.Profile.Session, Phase: "requested", Nonce: fmt.Sprintf("%d-%s", 3+epoch*2, operation), Operation: operation}
		records.GoOwner.Profile.Requests = []ProbeLifecycleRequest{request}
		records.GoOwner.Step.Request, records.GoOwner.Step.Effects, records.GoOwner.Step.Epoch, records.GoOwner.Step.Owned = request, actionFacts.Actions[operation].Effects, epoch, &owned
		records.GoOwner.Step.Startup.Path = filepath.Join(records.RunRoot, fmt.Sprintf("startup-epoch-%d.json", epoch))
		records.GoOwner.Step.Launcher.PID, records.GoOwner.Step.Launcher.Starttime = 321+epoch, uint64(100+epoch)
		records.AfterProcess = &owned
		for i, record := range records.Records {
			if record.Role == "owned" {
				records.Records[i].Data, _ = json.Marshal(owned)
			}
		}
		admission, _ := json.Marshal(records)
		if _, err := admitProbeRecords(admission); err != nil {
			t.Fatal("saved Go epoch admission", epoch, err)
		}
		var receipt ProbeCaptureReceipt
		if json.Unmarshal(frameCaptureBase, &receipt) != nil {
			t.Fatal("capture scaffold")
		}
		receipt.CaptureID = fmt.Sprintf("frame-epoch-%d", epoch)
		receipt.EventID = 3 + epoch*3
		receipt.Checkpoint = 1
		receipt.RunID, receipt.Session, receipt.Epoch, receipt.PID, receipt.Starttime = owned.Session, owned.Session, epoch, owned.PID, owned.Starttime
		receipt.ISOSHA256, receipt.BuildSHA256 = owned.ISOSHA256, records.GoOwner.Profile.Program.SHA256
		for _, memory := range []*ProbeMemoryReport{receipt.MemoryBefore, receipt.MemoryAfter} {
			memory.Session, memory.Epoch, memory.ISOSHA256, memory.BuildSHA256 = receipt.Session, epoch, receipt.ISOSHA256, receipt.BuildSHA256
			memory.SessionEvidenceSHA256 = fmt.Sprintf("%x", sha256.Sum256(admission))
		}
		selected := cross.Events[receipt.EventID-1]
		receipt.LogHex, receipt.LogSHA256, receipt.LogOffset = hex.EncodeToString(selected.Data), fmt.Sprintf("%x", sha256.Sum256(selected.Data)), selected.Offset
		imageData := framePNGs["uniform-0"]
		receipt.ImagePath, receipt.ImageBytes, receipt.ImageSHA256, receipt.Width, receipt.Height = receipt.CaptureID+".png", int64(len(imageData)), fmt.Sprintf("%x", sha256.Sum256(imageData)), 1, 1
		cross.Captures = append(cross.Captures, ProbeCaptureObservation{Receipt: receipt, ImageHex: hex.EncodeToString(imageData), Admission: admission})
		cross.Admission, cross.RunID, cross.Session, cross.ISOSHA256, cross.Epoch = admission, owned.Session, owned.Session, owned.ISOSHA256, &epoch
	}
	crossRaw, _ := json.Marshal(cross)
	crossBaseline, err := reportProbeEvidence(crossRaw)
	if err != nil || len(crossBaseline.Captures) != 2 || crossBaseline.Captures[0].Status != "ACCEPTED" || crossBaseline.Captures[1].Status != "ACCEPTED" {
		t.Fatal("valid raw cross-epoch baseline", err)
	}
	cross.FrameComparisons = []ProbeFrameComparison{{CaptureID: "frame-epoch-1", PreviousCaptureID: "frame-epoch-0"}}
	crossRaw, _ = json.Marshal(cross)
	if _, err := reportProbeEvidence(crossRaw); err == nil || err.Error() != "frame comparison crosses actual process/session/epoch identity" {
		t.Fatal("exact new cross-epoch comparison guard", err)
	}

}
