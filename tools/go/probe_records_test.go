package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
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
}
