package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math/big"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"
	"unicode/utf8"
)

// authorRegistry preserves raw JSON metadata while applying reviewed field policy
// or deriving source-bound reports. The caller owns the validated source handle
// and recipe selection; publication stays with writeNewFile. No canonical file is
// rewritten in place. Unknown metadata and exact JSON numbers remain raw.
// Additions accept reviewed draft data, not text readiness; identical existing
// JP/EN preserves that row. An all-present batch preserves the entire source.
// CSV export projects ordered flat scalar columns; it shares the same source
// guards and publisher. It reports registry plans, never installed disc truth.
// Status reports pin glossary, flow and a plain text/template separately. Counts
// preserve null/missing distinctions and source-order diagnostic IDs; templates
// own presentation, never source reads or custom functions.
func authorRegistry(source *os.File, tables []Recipes, registryRecipeData []byte, options RegistryOptions, stdout io.Writer) error {
	profile := tables[0]
	var err error
	author := profile.Operation == "registry_author"
	adding := profile.Operation == "registry_add"
	exporting := profile.Operation == "registry_export"
	summarizing := profile.Operation == "registry_status"
	reportOnly := profile.Operation == "text_shapes"
	derived := profile.Operation == "registry_markup" || reportOnly
	if reportOnly && options.Apply {
		return fmt.Errorf("text reports are read-only; use stdout for the combined report")
	}
	if len(tables) != 1 || profile.Evidence == "" ||
		!derived && (options.RegistryPath != "" || options.GlyphmapPath != "" || !exporting && !summarizing && len(profile.RegistryUpdates) == 0) ||
		derived && (options.RegistryPath == "" || options.GlyphmapPath == "" || profile.RegistryUpdates != nil) {
		return fmt.Errorf("registry operation requires one reviewed table and its declared inputs")
	}
	if author || adding || exporting || summarizing {
		var fields map[string]json.RawMessage
		required := []string{"operation", "source_size", "source_sha256", "evidence", "updated", "registry_updates"}
		if exporting {
			required = []string{"operation", "source_size", "source_sha256", "evidence", "registry_columns"}
		} else if summarizing {
			required = []string{"operation", "source_size", "source_sha256", "evidence", "updated", "registry_columns", "registry_inputs"}
		}
		if !utf8.Valid(registryRecipeData) || json.Unmarshal(registryRecipeData, &fields) != nil || len(fields) != len(required) {
			return fmt.Errorf("%s table requires %d explicit UTF-8 registry fields", profile.Operation, len(required))
		}
		for _, field := range required {
			if _, ok := fields[field]; !ok {
				return fmt.Errorf("%s table requires %s and forbids unrelated fields", profile.Operation, field)
			}
		}
	}
	accepted := Recipes{Operation: profile.Operation, SourceSize: profile.SourceSize, SourceSHA256: profile.SourceSHA256, Evidence: profile.Evidence}
	if exporting || summarizing {
		accepted.RegistryColumns = profile.RegistryColumns
	} else {
		accepted.RegistryUpdates = profile.RegistryUpdates
	}
	if !exporting {
		accepted.Updated = profile.Updated
	}
	if summarizing {
		accepted.RegistryInputs = profile.RegistryInputs
	}
	if derived {
		accepted.ISOELFOffset, accepted.ELFVMADelta = profile.ISOELFOffset, profile.ELFVMADelta
		accepted.GlyphmapSHA256, accepted.ScopeSHA256 = profile.GlyphmapSHA256, profile.ScopeSHA256
	}
	// An allowlist makes newly added recipe fields fail closed for these owners.
	if !reflect.DeepEqual(profile, accepted) {
		return fmt.Errorf("registry operation forbids unrelated image profile fields")
	}
	if exporting || summarizing {
		if len(profile.RegistryColumns) < 1 || len(profile.RegistryColumns) > 64 {
			return fmt.Errorf("registry export requires 1..64 ordered columns")
		}
		for i, column := range profile.RegistryColumns {
			if column == "" || len(column) > 256 || slices.Contains(profile.RegistryColumns[:i], column) {
				return fmt.Errorf("registry export columns must be nonempty, unique and at most 256 bytes")
			}
		}
	}
	if !exporting {
		if _, err := time.Parse("2006-01-02", profile.Updated); err != nil {
			return fmt.Errorf("registry operation requires an explicit YYYY-MM-DD updated date")
		}
	}
	registrySource, registryHash := source, profile.SourceSHA256
	if derived {
		registrySource, err = os.Open(options.RegistryPath)
		if err != nil {
			return err
		}
		defer registrySource.Close()
		registryHash = profile.ScopeSHA256
	}
	registryInfo, err := registrySource.Stat()
	if err != nil {
		return err
	}
	// shortcut: bound in-memory documents to 64 MiB; revisit for larger registries.
	if !registryInfo.Mode().IsRegular() || registryInfo.Size() <= 0 || registryInfo.Size() > 64<<20 {
		return fmt.Errorf("registry source must be a regular file between 1 byte and 64 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(registrySource, registryInfo.Size()+1))
	if err != nil {
		return err
	}
	if int64(len(data)) != registryInfo.Size() || fmt.Sprintf("%x", sha256.Sum256(data)) != registryHash || !utf8.Valid(data) {
		return fmt.Errorf("registry source hash/size/UTF-8 mismatch")
	}
	// Raw values preserve human fields, unknown metadata and exact JSON numbers.
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil || document == nil {
		return fmt.Errorf("registry must be a JSON object")
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(document["entries"], &entries); err != nil || entries == nil {
		return fmt.Errorf("registry entries must be an array of objects")
	}
	byID := make(map[uint64]map[string]json.RawMessage)
	for _, entry := range entries {
		var id string
		if err := json.Unmarshal(entry["id"], &id); err != nil {
			return fmt.Errorf("registry entry requires a hexadecimal string ID")
		}
		key, err := number(id)
		if err != nil || byID[key] != nil {
			return fmt.Errorf("invalid or duplicate registry ID %q", id)
		}
		byID[key] = entry
	}
	ids := slices.Sorted(maps.Keys(profile.RegistryUpdates))
	var reportInputs map[string][]byte
	if summarizing {
		if len(profile.RegistryInputs) != 3 {
			return fmt.Errorf("registry status requires pinned glossary, flow and template inputs")
		}
		for _, field := range []string{"status", "source_pool", "chapter", "tier"} {
			if !slices.Contains(profile.RegistryColumns, field) {
				return fmt.Errorf("registry status requires group %q", field)
			}
		}
		reportInputs = make(map[string][]byte)
		for _, name := range []string{"glossary", "flow", "template"} {
			input, ok := profile.RegistryInputs[name]
			limit := int64(64 << 20)
			if name == "template" {
				limit = 1 << 20
			}
			if !ok || input.Path == "" || input.Size < 1 || input.Size > limit {
				return fmt.Errorf("invalid registry status %s input", name)
			}
			body, err := readInput(input.Path, limit)
			if err != nil || int64(len(body)) != input.Size || fmt.Sprintf("%x", sha256.Sum256(body)) != input.SHA256 || !utf8.Valid(body) {
				return fmt.Errorf("registry status %s input hash/size/UTF-8 mismatch: %v", name, err)
			}
			if name != "template" && !json.Valid(body) {
				return fmt.Errorf("registry status %s must be JSON", name)
			}
			reportInputs[name] = body
		}
	}
	checked := []checkedJSON{{raw: data}, {raw: registryRecipeData, updates: true, text: author || adding || exporting || summarizing}}
	if summarizing {
		checked = append(checked, checkedJSON{raw: reportInputs["glossary"], text: true}, checkedJSON{raw: reportInputs["flow"], text: true, records: true})
		for _, entry := range entries {
			for _, field := range append(slices.Clone(profile.RegistryColumns), "en", "character", "event") {
				raw := bytes.TrimSpace(entry[field])
				if len(raw) != 0 && raw[0] == '"' {
					checked = append(checked, checkedJSON{raw: raw, text: true})
				}
			}
		}
	}
	if exporting {
		for _, entry := range entries {
			for _, column := range profile.RegistryColumns {
				raw := bytes.TrimSpace(entry[column])
				if len(raw) != 0 && raw[0] == '"' {
					checked = append(checked, checkedJSON{raw: raw, text: true})
				}
			}
		}
	}
	if author || adding {
		textFields := []string{"en"}
		if adding {
			textFields = append(textFields, "jp")
		}
		for _, id := range ids {
			key, err := number(id)
			for _, field := range textFields {
				if _, touchesText := profile.RegistryUpdates[id][field]; touchesText && err == nil && byID[key] != nil {
					// Check selected old text before decoding can repair a lone surrogate.
					checked = append(checked, checkedJSON{raw: byID[key][field], text: true})
				}
			}
		}
	}
	for _, input := range checked {
		if err := checkJSON(input); err != nil {
			return err
		}
	}

	if derived {
		base, baseErr := number(profile.ISOELFOffset)
		delta, deltaErr := number(profile.ELFVMADelta)
		if baseErr != nil || deltaErr != nil || profile.SourceSize <= 0 || base >= uint64(profile.SourceSize) {
			return fmt.Errorf("invalid markup source address profile")
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, source); err != nil {
			return err
		}
		if fmt.Sprintf("%x", hash.Sum(nil)) != profile.SourceSHA256 {
			return fmt.Errorf("markup source hash mismatch")
		}
		glyphData, err := os.ReadFile(options.GlyphmapPath)
		if err != nil {
			return err
		}
		if fmt.Sprintf("%x", sha256.Sum256(glyphData)) != profile.GlyphmapSHA256 || !utf8.Valid(glyphData) {
			return fmt.Errorf("markup glyphmap hash/UTF-8 mismatch")
		}
		var rawGlyphs map[string]string
		if err := json.Unmarshal(glyphData, &rawGlyphs); err != nil || rawGlyphs == nil {
			return fmt.Errorf("markup glyphmap must be an object of glyph strings")
		}
		glyphs := make(map[uint16]string)
		// The reference decoder looks up canonical decimal keys only.
		for key, value := range rawGlyphs {
			word, err := strconv.ParseUint(key, 10, 16)
			if err == nil && key == strconv.FormatUint(word, 10) {
				glyphs[uint16(word)] = value
			}
		}
		shapes := struct {
			TotalDrafted    int                       `json:"total_drafted"`
			StructExcluded  int                       `json:"struct_table_field_excluded"`
			MultiExcluded   int                       `json:"multi_site_excluded"`
			DecodeFailed    int                       `json:"decode_failed"`
			DecodeFailedIDs []string                  `json:"decode_failed_ids"`
			ShapeCounts     map[string]int            `json:"shape_counts"`
			ShapeExamples   map[string][]string       `json:"shape_examples"`
			PerRefType      map[string]map[string]int `json:"per_ref_type_shape"`
			HLOnly          map[string]int            `json:"hl_only_stats"`
		}{DecodeFailedIDs: []string{}, ShapeCounts: map[string]int{}, ShapeExamples: map[string][]string{}, PerRefType: map[string]map[string]int{}, HLOnly: map[string]int{"n_entries": 0, "all_clean_wrap": 0, "total_hl_codes": 0, "total_clean_pairs": 0}}
		clusters := struct {
			Total         int                 `json:"total"`
			MacroCounts   map[string]int      `json:"macro_shape_counts"`
			MacroExamples map[string][]string `json:"macro_shape_examples"`
			PenFamilies   map[string]int      `json:"pen0_subfamily_counts"`
			Payloads      map[string]int      `json:"param8_payload_counts"`
			Entries       []map[string]any    `json:"entries"`
		}{MacroCounts: map[string]int{}, MacroExamples: map[string][]string{}, PenFamilies: map[string]int{}, Payloads: map[string]int{}, Entries: []map[string]any{}}
		profile.RegistryUpdates = make(map[string]map[string]json.RawMessage)
		// Samples and detailed rows retain registry order; byID remains the update index.
		for _, entry := range entries {
			var idText string
			_ = json.Unmarshal(entry["id"], &idText)
			id, _ := number(idText)
			var status, refType, english string
			_ = json.Unmarshal(entry["status"], &status)
			_ = json.Unmarshal(entry["ref_type"], &refType)
			if status != "drafted" {
				continue
			}
			shapes.TotalDrafted++
			if refType == "struct_table_field" {
				shapes.StructExcluded++
				continue
			}
			var sites []map[string]json.RawMessage
			if raw := entry["ref_sites"]; raw != nil {
				if err := json.Unmarshal(raw, &sites); err != nil {
					return fmt.Errorf("%#x: invalid reference sites", id)
				}
			}
			if len(sites) == 1 {
				if sites[0] == nil {
					return fmt.Errorf("%#x: reference site must be an object", id)
				}
				if _, structField := sites[0]["struct_vma"]; structField {
					shapes.StructExcluded++
					continue
				}
			} else {
				shapes.MultiExcluded++
				continue
			}
			var buffer []byte
			if offset := base + id; offset >= delta {
				offset -= delta
				if offset < uint64(profile.SourceSize) {
					// Leading controls plus 4096 body iterations, each at most ten bytes.
					buffer = make([]byte, min(uint64(4096*2+4096*10), uint64(profile.SourceSize)-offset))
					if _, err := source.ReadAt(buffer, int64(offset)); err != nil {
						return err
					}
				}
			}
			var englishErr error
			if raw := entry["en"]; raw != nil {
				englishErr = json.Unmarshal(raw, &english)
			}
			options := TextScanOptions{Decode: true, Glyphs: glyphs}
			if !reportOnly {
				options.English = &english
			}
			shape, err := controls(buffer, options)
			if err != nil {
				shapes.DecodeFailed++
				shapes.DecodeFailedIDs = append(shapes.DecodeFailedIDs, idText)
				continue
			}
			if reportOnly {
				if englishErr != nil {
					return fmt.Errorf("%#x: English must be a string or null", id)
				}
				if raw := entry["ref_type"]; raw != nil {
					if err := json.Unmarshal(raw, &refType); err != nil {
						return fmt.Errorf("%#x: reference type must be a string or null", id)
					}
				}
				key := strings.Join(shape.Kinds, "+")
				hasMarkup := strings.Contains(english, "{{")
				if key == "" {
					key = "clean"
					if hasMarkup {
						key = "en_markup_only"
					}
				} else if hasMarkup {
					key += "(+en_markup)"
				}
				shapes.ShapeCounts[key]++
				if len(shapes.ShapeExamples[key]) < 6 {
					shapes.ShapeExamples[key] = append(shapes.ShapeExamples[key], idText)
				}
				if refType == "" {
					refType = "none"
				}
				if shapes.PerRefType[refType] == nil {
					shapes.PerRefType[refType] = map[string]int{}
				}
				shapes.PerRefType[refType][key]++
				if len(shape.Kinds) == 1 && shape.Kinds[0] == "hl" {
					shapes.HLOnly["n_entries"]++
					shapes.HLOnly["total_hl_codes"] += shape.HLCount
					shapes.HLOnly["total_clean_pairs"] += shape.HLCleanPairs
					if shape.HLCount == 2*shape.HLCleanPairs {
						shapes.HLOnly["all_clean_wrap"]++
					}
				}
				if shape.Targets == 0 {
					continue
				}
				macro := "multi-adjacent (2+ clusters, no text between - rare)"
				switch {
				case shape.Clusters == 1 && !shape.TextBeforeFirst:
					macro = "delayed-prologue (control cluster leads content, nothing before it)"
				case shape.Clusters == 1 && !shape.TextAfterLast:
					macro = "trailing-tag (control cluster is the last thing, nothing after)"
				case shape.Clusters == 1:
					macro = "single-mid-sentence-cluster (text both before and after)"
				case shape.Clusters > 1 && shape.TextBetweenClusters:
					macro = "multi-scattered (2+ clusters, real text between them)"
				}
				clusters.Total++
				clusters.MacroCounts[macro]++
				if len(clusters.MacroExamples[macro]) < 8 {
					clusters.MacroExamples[macro] = append(clusters.MacroExamples[macro], idText)
				}
				clusters.Entries = append(clusters.Entries, map[string]any{"id": idText, "chapter": entry["chapter"], "event": entry["event"], "ref_type": entry["ref_type"], "jp": entry["jp"], "kinds_present": shape.Kinds, "shape_key": strings.Join(shape.Kinds, "+"), "macro_shape": macro, "n_clusters": shape.Clusters, "n_target_tokens": shape.Targets, "has_text_before_first": shape.TextBeforeFirst, "has_text_after_last": shape.TextAfterLast, "has_text_between_clusters": shape.TextBetweenClusters, "en_has_markup": hasMarkup})
				for _, token := range shape.Tokens[shape.ContentStart:] {
					if token.Kind == "pen0" {
						family := fmt.Sprintf("unknown(0x%04x)", token.Word)
						switch {
						case token.Word >= 0xe800 && token.Word <= 0xefff:
							family = "wrap(0xE8xx-0xEFxx, same shape as hl)"
						case token.Word >= 0x4801 && token.Word <= 0x4fff:
							family = "pen-table-coord(0x48xx-0x4Fxx)"
						case token.Word >= 0xb800 && token.Word <= 0xbfff:
							family = "pen-X-set(0xB8xx)"
						case token.Word >= 0xc800 && token.Word <= 0xcfff:
							family = "pen-Y-set(0xC8xx)"
						case token.Word >= 0xd000 && token.Word <= 0xd7ff:
							family = "pen-Y-add(0xD0xx-0xD7xx)"
						case token.Word >= 0xd801 && token.Word <= 0xdfff:
							family = "type27-other(0xD8xx-0xDFxx)"
						}
						clusters.PenFamilies[family]++
					} else if token.Kind == "param8" {
						family := "glyph-decodable"
						for i := 0; i < len(token.Payload); i += 2 {
							word := binary.LittleEndian.Uint16(token.Payload[i:])
							if _, known := glyphs[word]; word != 0 && !known {
								family = "opaque-binary"
								break
							}
						}
						clusters.Payloads[family]++
					}
				}
				continue
			}
			if shape.Targets == 0 {
				continue
			}
			if englishErr != nil {
				return fmt.Errorf("%#x: English must be a string or null", id)
			}
			value, err := json.Marshal(map[string]any{"bucket": "icon_pen0_midcontent_2026-09-08", "kinds_present": shape.Kinds, "readiness": shape.Readiness, "n_target_tokens": shape.Targets, "n_clusters": shape.Clusters, "tagged": "2026-09-08"})
			if err != nil {
				return err
			}
			profile.RegistryUpdates[fmt.Sprintf("0x%x", id)] = map[string]json.RawMessage{"midcontent_markup_shape": value}
		}
		if _, err := source.Seek(0, io.SeekStart); err != nil {
			return err
		}
		hash.Reset()
		if _, err := io.Copy(hash, source); err != nil {
			return err
		}
		if info, err := source.Stat(); err != nil || info.Size() != profile.SourceSize || fmt.Sprintf("%x", hash.Sum(nil)) != profile.SourceSHA256 {
			return fmt.Errorf("markup source changed during analysis")
		}
		if reportOnly {
			encoder := json.NewEncoder(stdout)
			encoder.SetIndent("", "  ")
			encoder.SetEscapeHTML(false)
			return encoder.Encode(map[string]any{"operation": profile.Operation, "source_sha256": profile.SourceSHA256, "registry_sha256": profile.ScopeSHA256, "glyphmap_sha256": profile.GlyphmapSHA256, "updated": profile.Updated, "shapes": shapes, "clusters": clusters})
		}
		ids = slices.Sorted(maps.Keys(profile.RegistryUpdates))
	}
	allowed := map[string]bool{"status": true, "ref_type": true, "ref_sites": true, "preamble_words": true, "inline_codes": true, "jp_capacity_u16": true, "landing_vma": true, "landing_zone_id": true, "patch_ref": true, "discovered_by": true}
	switch {
	case author:
		allowed = map[string]bool{"en": true, "note": true}
	case derived:
		allowed = map[string]bool{"midcontent_markup_shape": true}
	}
	statuses := []string{"drafted", "zone_pending", "patched", "decode_verified", "emulator_confirmed"}
	seen := make(map[uint64]bool)
	added, alreadyPresent := []string{}, []string{}
	for _, id := range ids {
		key, err := number(id)
		entry := byID[key]
		if err != nil || !adding && entry == nil || seen[key] || profile.RegistryUpdates[id] == nil {
			return fmt.Errorf("invalid, missing or duplicate update ID %q", id)
		}
		seen[key] = true
		if adding {
			incoming := profile.RegistryUpdates[id]
			if _, hasID := incoming["id"]; hasID {
				return fmt.Errorf("%s: addition ID belongs in the table key only", id)
			}
			text := make(map[string]string)
			for _, field := range []string{"jp", "en", "status", "source_pool"} {
				var value string
				if raw := incoming[field]; raw == nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &value) != nil {
					return fmt.Errorf("%s: addition requires string %s", id, field)
				}
				text[field] = value
			}
			if text["source_pool"] == "" {
				return fmt.Errorf("%s: additions require a source pool", id)
			}
			canonicalID := fmt.Sprintf("0x%x", key)
			if entry != nil {
				for _, field := range []string{"jp", "en"} {
					var old string
					if raw := entry[field]; raw == nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &old) != nil || old != text[field] {
						return fmt.Errorf("%s: addition conflicts with existing %s; use its field owner", id, field)
					}
				}
				alreadyPresent = append(alreadyPresent, canonicalID)
				continue
			}
			if text["status"] != "drafted" {
				return fmt.Errorf("%s: new additions require drafted status", id)
			}
			entry = maps.Clone(incoming)
			entry["id"], _ = json.Marshal(canonicalID)
			byID[key] = entry
			added = append(added, canonicalID)
			continue
		}
		fields := slices.Sorted(maps.Keys(profile.RegistryUpdates[id]))
		if author && len(fields) == 0 {
			return fmt.Errorf("%s: author update requires en or note", id)
		}
		for _, field := range fields {
			value := profile.RegistryUpdates[id][field]
			if !allowed[field] {
				return fmt.Errorf("%s: field %q is not allowed for %s", id, field, profile.Operation)
			}
			if author {
				var text string
				if bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, &text) != nil || field == "en" && text == "" {
					return fmt.Errorf("%s: author %s requires a string; English cannot be empty", id, field)
				}
				if field == "en" {
					var old, status string
					_ = json.Unmarshal(entry[field], &old)
					_ = json.Unmarshal(entry["status"], &status)
					if text != old && status != "drafted" && status != "zone_pending" {
						return fmt.Errorf("%s: changed English requires a known unlocked status", id)
					}
				}
			}
			if field == "status" {
				var status string
				oldStatus := "drafted"
				if old, ok := entry[field]; ok {
					oldStatus = ""
					_ = json.Unmarshal(old, &oldStatus)
				}
				if err := json.Unmarshal(value, &status); err != nil || slices.Index(statuses, status) < 0 || slices.Index(statuses, status) < slices.Index(statuses, oldStatus) {
					return fmt.Errorf("%s: invalid or backward status update", id)
				}
			}
			entry[field] = value
		}
	}
	if adding && len(added) != 0 {
		entries = nil
		for _, id := range slices.Sorted(maps.Keys(byID)) {
			entries = append(entries, byID[id])
		}
	}
	var encoded bytes.Buffer
	var summary map[string]any
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	switch {
	case summarizing:
		var glossary map[string]json.RawMessage
		var glossaryEntries []map[string]json.RawMessage
		var todos []json.RawMessage
		var flow []map[string]json.RawMessage
		if err := json.Unmarshal(reportInputs["glossary"], &glossary); err != nil || glossary == nil {
			return fmt.Errorf("status glossary must be an object")
		}
		for _, field := range []string{"entries", "todos"} {
			var target any = &glossaryEntries
			if field == "todos" {
				target = &todos
			}
			if raw, present := glossary[field]; present && (bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, target) != nil) {
				return fmt.Errorf("status glossary %s must be an array when present", field)
			}
		}
		if err := json.Unmarshal(reportInputs["flow"], &flow); err != nil || flow == nil {
			return fmt.Errorf("status flow must be an array of objects")
		}
		flowVMAs := make(map[string]bool)
		for _, step := range flow {
			if step == nil {
				return fmt.Errorf("status flow steps must be objects")
			}
			var vma *string
			if raw, present := step["vma"]; present && json.Unmarshal(raw, &vma) != nil {
				return fmt.Errorf("status flow VMAs must be strings or null")
			}
			if vma != nil && *vma != "" {
				flowVMAs[*vma] = true // Exact spellings, not normalized addresses.
			}
		}
		emptyEN, missingTags := []string{}, []string{}
		for _, entry := range entries {
			var id string
			_ = json.Unmarshal(entry["id"], &id)
			missing := false
			for _, field := range []string{"en", "chapter", "character", "event"} {
				var value *string
				if raw, present := entry[field]; present && json.Unmarshal(raw, &value) != nil {
					return fmt.Errorf("%s: status %s must be a string or null", id, field)
				}
				if value == nil || *value == "" {
					if field == "en" {
						emptyEN = append(emptyEN, id)
					} else {
						missing = true
					}
				}
			}
			if missing {
				missingTags = append(missingTags, id)
			}
		}
		escape := strings.NewReplacer("&", "&amp;", "\\", "\\\\", "|", "\\|", "\r\n", "<br>", "\r", "<br>", "\n", "<br>", "*", "\\*", "_", "\\_", "`", "\\`", "[", "\\[", "]", "\\]", "<", "&lt;", ">", "&gt;")
		groups, provenance := make(map[string][]RegistryCount), make(map[string][]RegistryCount)
		unknownStatuses := []RegistryCount{}
		for _, collection := range []struct {
			rows       []map[string]json.RawMessage
			fields     []string
			output     map[string][]RegistryCount
			provenance bool
		}{{entries, profile.RegistryColumns, groups, false}, {glossaryEntries, []string{"provenance"}, provenance, true}} {
			for _, field := range collection.fields {
				type groupKey struct {
					value string
					null  bool
				}
				counts := make(map[groupKey]int)
				firstSeen := []groupKey{}
				for _, entry := range collection.rows {
					if entry == nil {
						return fmt.Errorf("status count entries must be objects")
					}
					raw, present := entry[field]
					var value *string
					if present && json.Unmarshal(raw, &value) != nil {
						return fmt.Errorf("status group %s must contain strings or null", field)
					}
					if !present || value == nil && !collection.provenance && field != "status" {
						fallback := "unknown"
						value = &fallback
					}
					key := groupKey{null: value == nil}
					if value != nil {
						key.value = *value
					}
					if counts[key] == 0 {
						firstSeen = append(firstSeen, key)
					}
					counts[key]++
				}
				keys := firstSeen
				switch {
				case !collection.provenance && field == "status":
					keys = []groupKey{}
					for _, status := range statuses {
						key := groupKey{value: status}
						if counts[key] != 0 {
							keys = append(keys, key)
						}
					}
					for _, key := range firstSeen {
						if key.null || !slices.Contains(statuses, key.value) {
							keys = append(keys, key)
						}
					}
				case !collection.provenance:
					labels := make([]string, 0, len(counts))
					for _, key := range firstSeen {
						labels = append(labels, key.value)
					}
					slices.Sort(labels)
					keys = []groupKey{}
					for _, label := range labels {
						keys = append(keys, groupKey{value: label})
					}
				}
				rows := []RegistryCount{}
				for _, key := range keys {
					row := RegistryCount{Count: counts[key], Display: "*null*"}
					if !key.null {
						value := key.value
						row.Value, row.Display = &value, escape.Replace(value)
						if value == "" {
							row.Display = "*empty string*"
						}
					}
					rows = append(rows, row)
					if !collection.provenance && field == "status" && (key.null || !slices.Contains(statuses, key.value)) {
						unknownStatuses = append(unknownStatuses, row)
					}
				}
				collection.output[field] = rows
			}
		}
		schema, present := glossary["schema_version"]
		if !present {
			schema = json.RawMessage(`"?"`)
		}
		schema = bytes.TrimSpace(schema)
		if len(schema) == 0 || schema[0] == '{' || schema[0] == '[' {
			return fmt.Errorf("glossary schema_version must be a scalar")
		}
		schemaDisplay := string(schema)
		if schema[0] == '"' {
			_ = json.Unmarshal(schema, &schemaDisplay)
		}
		summary = map[string]any{"registry_entries": len(entries), "groups": groups, "group_order": profile.RegistryColumns,
			"empty_en_ids": emptyEN, "missing_tag_ids": missingTags, "unknown_statuses": unknownStatuses,
			"flow_steps": len(flow), "flow_unique_vmas": len(flowVMAs), "glossary_schema": schema, "glossary_schema_present": present,
			"glossary_schema_display": escape.Replace(schemaDisplay), "glossary_entries": len(glossaryEntries), "glossary_provenance": provenance["provenance"], "glossary_open_todos": len(todos), "generated": profile.Updated}
		view, err := template.New("registry-status").Option("missingkey=error").Parse(string(reportInputs["template"]))
		if err != nil {
			return err
		}
		if err := view.Execute(&encoded, summary); err != nil {
			return err
		}
		if encoded.Len() > 64<<20 {
			return fmt.Errorf("registry status output exceeds 64 MiB")
		}
	case exporting:
		orderedIDs := slices.Sorted(maps.Keys(byID))
		for row := 0; row <= len(orderedIDs); row++ {
			for index, column := range profile.RegistryColumns {
				cell := column // The first record contains column names.
				if row > 0 {
					raw := bytes.TrimSpace(byID[orderedIDs[row-1]][column])
					switch {
					case len(raw) == 0 || bytes.Equal(raw, []byte("null")) || bytes.Equal(raw, []byte("false")):
						cell = ""
					case raw[0] == '"':
						if err := json.Unmarshal(raw, &cell); err != nil {
							return err
						}
					case bytes.Equal(raw, []byte("true")):
						cell = "True"
					default:
						var integer big.Int
						if _, ok := integer.SetString(string(raw), 10); !ok {
							return fmt.Errorf("0x%x: export column %q requires a string, integer, boolean or null", orderedIDs[row-1], column)
						}
						cell = ""
						if integer.Sign() != 0 {
							cell = integer.String()
						}
					}
				}
				if index > 0 {
					encoded.WriteByte(',')
				}
				// Go's CSV CRLF mode rewrites embedded newlines; preserve cell text.
				if strings.ContainsAny(cell, ",\"\r\n") || len(profile.RegistryColumns) == 1 && cell == "" {
					encoded.WriteByte('"')
					encoded.WriteString(strings.ReplaceAll(cell, "\"", "\"\""))
					encoded.WriteByte('"')
				} else {
					encoded.WriteString(cell)
				}
			}
			encoded.WriteString("\r\n")
			if encoded.Len() > 64<<20 {
				return fmt.Errorf("registry CSV exceeds 64 MiB")
			}
		}
	case adding && len(added) == 0:
		encoded.Write(data)
	default:
		if err := encoder.Encode(entries); err != nil {
			return err
		}
		document["entries"] = bytes.Clone(encoded.Bytes())
		encoded.Reset()
		document["last_updated"], _ = json.Marshal(profile.Updated)
		if err := encoder.Encode(document); err != nil {
			return err
		}
	}
	if exporting || summarizing {
		if _, err := registrySource.Seek(0, io.SeekStart); err != nil {
			return err
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, registrySource); err != nil {
			return err
		}
		if after, err := registrySource.Stat(); err != nil || after.Size() != registryInfo.Size() || after.ModTime() != registryInfo.ModTime() || fmt.Sprintf("%x", hash.Sum(nil)) != registryHash {
			return fmt.Errorf("registry source changed during export")
		}
		for _, name := range []string{"glossary", "flow", "template"} {
			if input, exists := profile.RegistryInputs[name]; exists {
				current, err := readInput(input.Path, input.Size)
				if err != nil || !bytes.Equal(current, reportInputs[name]) {
					return fmt.Errorf("registry status %s changed during analysis", name)
				}
			}
		}
	}
	outputHash := fmt.Sprintf("%x", sha256.Sum256(encoded.Bytes()))
	if options.Apply {
		if err := writeNewFile(options.Output, bytes.NewReader(encoded.Bytes()), int64(encoded.Len()), outputHash, 0o600); err != nil {
			return err
		}
	}
	report := map[string]any{"operation": profile.Operation, "applied": options.Apply, "source_sha256": profile.SourceSHA256, "output_sha256": outputHash, "updated": profile.Updated, "updates": profile.RegistryUpdates}
	if exporting {
		report = map[string]any{"operation": profile.Operation, "applied": options.Apply, "source_sha256": profile.SourceSHA256, "output_sha256": outputHash, "columns": profile.RegistryColumns, "rows": len(entries), "limits": "Registry plan projection only, not installed disc content or full progress/glossary/flow status. Selected arrays, objects and floats are refused; false and integer zero retain historical empty-cell behavior."}
	}
	if summarizing {
		report = map[string]any{"operation": profile.Operation, "applied": options.Apply, "source_sha256": profile.SourceSHA256, "output_sha256": outputHash, "inputs": profile.RegistryInputs, "summary": summary,
			"limits": "Registry/glossary/flow plan facts, not installed content or gameplay. Markdown template and explicit date are pinned inputs; layout/escaping and extra provenance visibility are redesigned, not historical Markdown byte parity. Selected text/group fields require strings or null."}
	}
	if adding {
		delete(report, "updates")
		report["added_ids"], report["already_present_ids"] = added, alreadyPresent
		report["updated"] = document["last_updated"]
		report["limits"] = "Reviewed draft data only. Existing identical JP/EN preserves all old metadata; all-present batches preserve source bytes/date. No glyph, speaker, marker, fit, reference-topology or patch-readiness validation."
	}
	if derived {
		report["registry_sha256"], report["glyphmap_sha256"] = profile.ScopeSHA256, profile.GlyphmapSHA256
	}
	if options.Apply {
		report["output"] = options.Output
	}
	encoder = json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
