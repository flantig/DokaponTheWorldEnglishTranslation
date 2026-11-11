package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
)

// resolveHumanEntries joins bounded, pinned decoded/flow/authored resources.
// IDs join numerically, but aliases within one resource refuse. Identical decoded
// spellings keep their last record; only that winner's JP needs text validation.
// Overrides replace a JP field, never a missing source row. This pure source step
// has no registry, status or publication authority.
func resolveHumanEntries(inputs map[string][]byte) (RegistryHumanBatch, error) {
	batch := RegistryHumanBatch{Entries: make(map[uint64]RegistryHumanEntry)}
	rootFields := []string{"translations", "jp_overrides", "overwrite_drift", "discovered_by"}
	rowFields := []string{"en", "chapter", "character", "event", "tier", "note"}
	body := inputs["authored"]
	if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		return batch, fmt.Errorf("human authored input must be an object")
	}
	if err := checkJSON(checkedJSON{raw: body, allObjects: true, text: true, nonNull: true, fieldsByDepth: map[int][]string{1: rootFields, 3: rowFields}, requiredByDepth: map[int][]string{1: rootFields, 3: rowFields}}); err != nil {
		return batch, err
	}
	var declaration map[string]json.RawMessage
	_ = json.Unmarshal(body, &declaration)
	if json.Unmarshal(declaration["overwrite_drift"], &batch.OverwriteDrift) != nil || json.Unmarshal(declaration["discovered_by"], &batch.DiscoveredBy) != nil || batch.DiscoveredBy == "" || len(batch.DiscoveredBy) > 512 {
		return batch, fmt.Errorf("human authoring requires boolean overwrite_drift and discovered_by between 1..512 UTF-8 bytes")
	}
	overrides := make(map[uint64]string)
	for _, name := range []string{"translations", "jp_overrides"} {
		body := declaration[name]
		if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
			return batch, fmt.Errorf("human %s must be an ID-keyed object", name)
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		_, _ = decoder.Token()
		seen := make(map[uint64]bool)
		for decoder.More() {
			if len(seen) == 65536 {
				return batch, fmt.Errorf("human %s exceeds 65536 records", name)
			}
			token, err := decoder.Token()
			if err != nil {
				return batch, err
			}
			id := token.(string) // Complete JSON and the object opener were checked.
			key, err := number(id)
			if err != nil || seen[key] {
				return batch, fmt.Errorf("invalid or duplicate normalized human %s ID %q", name, id)
			}
			seen[key] = true
			if name == "jp_overrides" {
				var jp string
				if err := decoder.Decode(&jp); err != nil || jp == "" {
					return batch, fmt.Errorf("human JP override requires a nonempty string")
				}
				if _, present := batch.Entries[key]; !present {
					return batch, fmt.Errorf("human JP override %q has no authored entry", id)
				}
				overrides[key] = jp
				continue
			}
			var row RegistryHumanEntry
			if err := decoder.Decode(&row); err != nil || row.EN == "" || row.Chapter == "" || row.Character == "" || row.Event == "" || row.Tier == "" || row.Note == "" {
				return batch, fmt.Errorf("human translation %q requires six nonempty strings", id)
			}
			if !slices.Contains([]string{"prologue", "opening", "menu", "character-nameplate"}, row.Chapter) || !slices.Contains([]string{"A", "B", "authored"}, row.Tier) {
				return batch, fmt.Errorf("human translation %q has an invalid chapter or tier", id)
			}
			batch.Entries[key] = row
		}
	}
	scope := make(map[uint64]bool)
	selected := make(map[uint64]json.RawMessage)
	for _, name := range []string{"flow", "decoded"} {
		body := inputs[name]
		if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) {
			return batch, fmt.Errorf("human %s must be an array of objects", name)
		}
		if err := checkJSON(checkedJSON{raw: body, aliasesByDepth: map[int][]string{2: {"vma", "decoded_jp"}}}); err != nil {
			return batch, err
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		_, _ = decoder.Token()
		spellings := make(map[uint64]string)
		for count := 0; decoder.More(); count++ {
			if count == 65536 {
				return batch, fmt.Errorf("human %s exceeds 65536 records", name)
			}
			var row *struct {
				VMA *string         `json:"vma"`
				JP  json.RawMessage `json:"decoded_jp"`
			}
			if err := decoder.Decode(&row); err != nil || row == nil {
				return batch, fmt.Errorf("human %s records must be objects with string or null VMAs", name)
			}
			if name == "decoded" && (row.VMA == nil || *row.VMA == "") {
				continue // The decoder includes an unaddressed placeholder outside flow scope.
			}
			if row.VMA == nil {
				return batch, fmt.Errorf("human flow requires a VMA on every record")
			}
			id := *row.VMA
			key, err := number(id)
			if previous, present := spellings[key]; err != nil || present && previous != id {
				return batch, fmt.Errorf("invalid or ambiguous human %s VMA %q", name, id)
			}
			spellings[key] = id
			if name == "flow" {
				scope[key] = true
			} else if scope[key] {
				selected[key] = row.JP
			}
		}
	}
	if len(scope) != len(batch.Entries) || len(selected) != len(scope) {
		return batch, fmt.Errorf("human flow, decoded and authored ID cohorts differ")
	}
	for _, id := range slices.Sorted(maps.Keys(batch.Entries)) {
		row := batch.Entries[id]
		jp, present := overrides[id]
		if !scope[id] {
			return batch, fmt.Errorf("human authored ID %#x is outside flow scope", id)
		}
		if !present {
			raw := bytes.TrimSpace(selected[id])
			if err := checkJSON(checkedJSON{raw: raw, text: true}); err != nil {
				return batch, err
			}
			if json.Unmarshal(raw, &jp) != nil || jp == "" {
				return batch, fmt.Errorf("human selected ID %#x requires nonempty resolved JP", id)
			}
		}
		row.JP = jp
		batch.Entries[id] = row
	}
	return batch, nil
}
