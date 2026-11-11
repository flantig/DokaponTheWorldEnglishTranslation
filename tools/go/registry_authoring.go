package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math/big"
	"os"
	"reflect"
	"regexp"
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
// Reconciliation preflights both documents, then shares EN/note mutation and
// serialization. Its ZIP is complete on successful return, not atomically visible.
// Unchanged pair members retain their original bytes/date; old scripts rewrote both.
// Human source joins stay pure; this owner refreshes selected metadata while
// preserving locked/drifted wording. Unrelated rows need not have complete tags.
// Optional imports validate one declared lexical policy before that same merge.
// Converted marker metadata is historical transcription, never payload-width proof.
// CSV grammar belongs to encoding/csv; source spans preserve quoted CRLF values.
// Full-sweep drafts retain kind-order/schema/apostrophe gates. Pinned text hashes
// and bijective occurrence tables replace the old free-note warning bypass;
// their kind/code identity is lexical, never proof of opaque parameter payloads.
// CSV export projects ordered flat scalar columns; it shares the same source
// guards and publisher. It reports registry plans, never installed disc truth.
// Status reports pin glossary, flow and a plain text/template separately. Counts
// preserve null/missing distinctions and source-order diagnostic IDs; templates
// own presentation, never source reads or custom functions.
func authorRegistry(source *os.File, tables []Recipes, registryRecipeData []byte, options RegistryOptions, stdout io.Writer) error {
	profile := tables[0]
	var err error
	reconciling := profile.Operation == "registry_reconcile"
	human := profile.Operation == "registry_human"
	author := profile.Operation == "registry_author" || reconciling
	adding := profile.Operation == "registry_add"
	importing := adding && profile.RegistryImport != nil
	fullSweep := importing && profile.RegistryImport.Policy == "full_sweep"
	exporting := profile.Operation == "registry_export"
	summarizing := profile.Operation == "registry_status"
	reportOnly := profile.Operation == "text_shapes"
	derived := profile.Operation == "registry_markup" || reportOnly
	if reportOnly && options.Apply {
		return fmt.Errorf("text reports are read-only; use stdout for the combined report")
	}
	if len(tables) != 1 || profile.Evidence == "" ||
		!derived && (options.RegistryPath != "" || options.GlyphmapPath != "" || !exporting && !summarizing && !importing && !reconciling && !human && len(profile.RegistryUpdates) == 0) ||
		derived && (options.RegistryPath == "" || options.GlyphmapPath == "" || profile.RegistryUpdates != nil) {
		return fmt.Errorf("registry operation requires one reviewed table and its declared inputs")
	}
	if author || adding || exporting || summarizing || human {
		var fields map[string]json.RawMessage
		required := []string{"operation", "source_size", "source_sha256", "evidence", "updated", "registry_updates"}
		if reconciling || human {
			required = []string{"operation", "source_size", "source_sha256", "evidence", "updated", "registry_inputs"}
		} else if importing {
			required = []string{"operation", "source_size", "source_sha256", "evidence", "updated", "registry_import", "registry_inputs"}
		} else if exporting {
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
		if importing {
			if _, present := fields["registry_updates"]; present {
				return fmt.Errorf("registry import cannot also contain registry_updates")
			}
			var declaration map[string]json.RawMessage
			_ = json.Unmarshal(fields["registry_import"], &declaration)
			if _, present := declaration["discovered_by"]; present && profile.RegistryImport.Policy != "csv_drafts" {
				return fmt.Errorf("discovered_by belongs only to the CSV import declaration")
			}
			if _, present := declaration["marker_orders"]; present && !fullSweep {
				return fmt.Errorf("marker_orders belongs only to the full_sweep import declaration")
			}
		}
		if importing || reconciling || human {
			inputFields := []string{"path", "size", "sha256"}
			if err := checkJSON(checkedJSON{raw: fields["registry_inputs"], allObjects: true, text: true, nonNull: true, fieldsByDepth: map[int][]string{2: inputFields}, aliasesByDepth: map[int][]string{2: inputFields}, requiredByDepth: map[int][]string{2: inputFields}}); err != nil {
				return err
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
	if summarizing || importing || reconciling || human {
		accepted.RegistryInputs = profile.RegistryInputs
	}
	if importing {
		accepted.RegistryImport = profile.RegistryImport
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
	if (reconciling || human || fullSweep) && (options.ProfilePath == "" || len(registryRecipeData) > 1<<20) {
		return fmt.Errorf("registry operation requires one bounded profile path")
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
	var registryInputs map[string][]byte
	var inputNames []string
	var importSummary map[string]any
	var glossaryDocument map[string]json.RawMessage
	var glossaryEntries []map[string]json.RawMessage
	var correctionOutcomes, glossaryOutcomes []map[string]string
	var glossaryChanged bool
	var humanChanged bool
	var humanOutcomes []map[string]any
	if summarizing || importing || reconciling || human {
		inputNames = []string{"glossary", "flow", "template"}
		owner := "registry status"
		if human {
			owner = "registry human authoring"
			inputNames = []string{"decoded", "flow", "authored"}
		} else if reconciling {
			owner = "registry reconciliation"
			inputNames = []string{"glossary", "corrections", "glossary_proposals"}
		} else if importing {
			owner = "registry import"
			declaration := profile.RegistryImport
			switch declaration.Policy {
			case "json_kinds", "json_codes", "converted_markers", "full_sweep":
				if declaration.DiscoveredBy != "" {
					return fmt.Errorf("JSON import provenance belongs to its records")
				}
			case "csv_drafts":
				// The shared label is copied twice per row, so bound it before projection.
				if declaration.DiscoveredBy == "" || len(declaration.DiscoveredBy) > 512 {
					return fmt.Errorf("CSV import requires discovered_by between 1..512 UTF-8 bytes")
				}
			default:
				return fmt.Errorf("unknown registry import policy %q", declaration.Policy)
			}
			if len(declaration.Batches) < 1 || len(declaration.Batches) > 64 || declaration.Glyphmap == "" {
				return fmt.Errorf("registry import requires 1..64 batches and a distinct glyphmap resource")
			}
			inputNames = append(slices.Clone(declaration.Batches), declaration.Glyphmap)
			if fullSweep {
				if declaration.MarkerOrders == "" {
					return fmt.Errorf("full_sweep requires a pinned marker_orders resource")
				}
				inputNames = append(inputNames, declaration.MarkerOrders)
			}
			for i, name := range inputNames {
				if name == "" || len(name) > 256 || slices.Contains(inputNames[:i], name) {
					return fmt.Errorf("registry import resource names must be bounded, nonempty and unique")
				}
			}
		}
		if summarizing && len(profile.RegistryInputs) != 3 {
			return fmt.Errorf("registry status requires pinned glossary, flow and template inputs")
		}
		if (importing || reconciling || human) && len(profile.RegistryInputs) != len(inputNames) {
			return fmt.Errorf("%s requires exactly its declared inputs", owner)
		}
		for _, field := range []string{"status", "source_pool", "chapter", "tier"} {
			if summarizing && !slices.Contains(profile.RegistryColumns, field) {
				return fmt.Errorf("registry status requires group %q", field)
			}
		}
		registryInputs = make(map[string][]byte)
		var batchBytes int64
		for _, name := range inputNames {
			input, ok := profile.RegistryInputs[name]
			limit := int64(64 << 20)
			if summarizing && name == "template" {
				limit = 1 << 20
			}
			if fullSweep && name == profile.RegistryImport.MarkerOrders {
				limit = 1 << 20
			}
			if !ok || input.Path == "" || input.Size < 1 || input.Size > limit {
				return fmt.Errorf("invalid %s %s input", owner, name)
			}
			if importing && name != profile.RegistryImport.Glyphmap || reconciling && name != "glossary" || human {
				batchBytes += input.Size
				if batchBytes > 64<<20 {
					return fmt.Errorf("%s batches exceed 64 MiB in total", owner)
				}
			}
			body, err := readInput(input.Path, limit)
			if err != nil || int64(len(body)) != input.Size || fmt.Sprintf("%x", sha256.Sum256(body)) != input.SHA256 || !utf8.Valid(body) {
				return fmt.Errorf("%s %s input hash/size/UTF-8 mismatch: %v", owner, name, err)
			}
			jsonResource := name != "template"
			if importing {
				jsonResource = name == profile.RegistryImport.Glyphmap || profile.RegistryImport.Policy != "csv_drafts"
			}
			if jsonResource && !json.Valid(body) {
				return fmt.Errorf("%s %s must be JSON", owner, name)
			}
			registryInputs[name] = body
		}
	}
	if importing {
		declaration := profile.RegistryImport
		policy := declaration.Policy
		type importRow struct {
			fields map[string]json.RawMessage
			batch  string
			record int
			id     string
		}
		var rows []importRow
		batchCounts := make(map[string]int)
		glyphData := registryInputs[declaration.Glyphmap]
		if !bytes.HasPrefix(bytes.TrimSpace(glyphData), []byte("{")) {
			return fmt.Errorf("registry import glyphmap must be a JSON object")
		}
		if err := checkJSON(checkedJSON{raw: glyphData, allObjects: true, text: true}); err != nil {
			return err
		}
		glyphs, _, err := glyphMaps(glyphData, false)
		if err != nil {
			return fmt.Errorf("registry import glyphmap: %w", err)
		}
		reviewedOrders := make(map[string]RegistryMarkerOrder)
		usedReviewIDs := []string{}
		if fullSweep {
			body := registryInputs[declaration.MarkerOrders]
			fields := []string{"jp_sha256", "en_sha256", "en_sources_jp"}
			if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
				return fmt.Errorf("marker_orders requires an ID-keyed object")
			}
			if err := checkJSON(checkedJSON{raw: body, allObjects: true, text: true, nonNull: true, fieldsByDepth: map[int][]string{2: fields}, requiredByDepth: map[int][]string{2: fields}}); err != nil {
				return err
			}
			decoder := json.NewDecoder(bytes.NewReader(body))
			_, _ = decoder.Token()
			for decoder.More() {
				if len(reviewedOrders) == 65536 {
					return fmt.Errorf("marker_orders exceeds 65536 records")
				}
				token, err := decoder.Token()
				if err != nil {
					return err
				}
				id := token.(string) // Complete JSON and the object opener were checked.
				key, err := number(id)
				canonicalID := fmt.Sprintf("0x%x", key)
				if _, present := reviewedOrders[canonicalID]; err != nil || present {
					return fmt.Errorf("invalid or duplicate normalized marker order ID %q", id)
				}
				var order RegistryMarkerOrder
				if err := decoder.Decode(&order); err != nil || len(order.JPSHA256) != 64 || len(order.ENSHA256) != 64 || len(order.ENSourcesJP) < 1 || len(order.ENSourcesJP) > 65536 {
					return fmt.Errorf("marker order %q requires two SHA256 strings and 1..65536 integer positions", id)
				}
				reviewedOrders[canonicalID] = order
			}
		}
		csvFields := strings.Fields("id jp en chapter character event tier mode source_pool note")
		ownedFields := append(slices.Clone(csvFields), "status", "ref_type", "discovered_by", "standalone_codes", "param_blocks")
		for _, batch := range declaration.Batches {
			body := registryInputs[batch]
			before := len(rows)
			if policy == "csv_drafts" {
				// The standard reader owns grammar; raw spans retain quoted CRLF metadata.
				reader := csv.NewReader(bytes.NewReader(body))
				reader.FieldsPerRecord = -1
				var headers []string
				lineNumber, lineStart := 1, 0
				for recordNumber := 0; ; recordNumber++ {
					record, err := reader.Read()
					if err == io.EOF {
						break
					}
					if err != nil {
						return fmt.Errorf("%s record %d: invalid CSV: %w", batch, recordNumber+1, err)
					}
					if len(record) > 256 || recordNumber > 0 && len(record) != len(headers) {
						return fmt.Errorf("%s record %d: CSV column count differs from its bounded header", batch, recordNumber+1)
					}
					positions := make([]int, len(record))
					for i := range record {
						line, column := reader.FieldPos(i)
						if recordNumber == 0 && i == 0 && line != 1 {
							return fmt.Errorf("%s: CSV header must lead the file", batch)
						}
						for lineNumber < line {
							next := bytes.IndexByte(body[lineStart:], '\n')
							if next < 0 {
								return fmt.Errorf("%s: CSV field coordinates exceed source", batch)
							}
							lineStart += next + 1
							lineNumber++
						}
						positions[i] = lineStart + column - 1
					}
					end := int(reader.InputOffset())
					if end > 0 && body[end-1] == '\n' {
						end--
					}
					if end > 0 && body[end-1] == '\r' {
						end--
					}
					for i := range record {
						fieldEnd := end
						if i+1 < len(record) {
							fieldEnd = positions[i+1] - 1
						}
						if positions[i] < 0 || fieldEnd < positions[i] || fieldEnd > len(body) {
							return fmt.Errorf("%s: invalid CSV source span", batch)
						}
						raw := string(body[positions[i]:fieldEnd])
						if strings.HasPrefix(raw, "\"") {
							if len(raw) < 2 || !strings.HasSuffix(raw, "\"") {
								return fmt.Errorf("%s: CSV quoted span differs from parser", batch)
							}
							raw = strings.ReplaceAll(raw[1:len(raw)-1], "\"\"", "\"")
						} else if strings.ContainsAny(raw, "\r\n") {
							return fmt.Errorf("%s: unquoted CSV newline", batch)
						}
						if strings.ReplaceAll(raw, "\r\n", "\n") != record[i] {
							return fmt.Errorf("%s: CSV source value differs beyond newline normalization", batch)
						}
						record[i] = raw
					}
					if recordNumber == 0 {
						headers = record
						for i, name := range headers {
							if name == "" || strings.ContainsRune(name, '\ufeff') || slices.Contains(headers[:i], name) {
								return fmt.Errorf("%s: empty, BOM or duplicate CSV header", batch)
							}
						}
						for _, name := range csvFields {
							if !slices.Contains(headers, name) {
								return fmt.Errorf("%s: missing CSV column %s", batch, name)
							}
						}
						continue
					}
					if len(rows) == 65536 {
						return fmt.Errorf("registry import exceeds 65536 records")
					}
					cells := make(map[string]string, len(headers))
					for i, name := range headers {
						cells[name] = record[i]
					}
					fields := make(map[string]json.RawMessage)
					for _, name := range strings.Fields("id jp en chapter character tier source_pool") {
						fields[name], _ = json.Marshal(cells[name])
					}
					fields["event"] = json.RawMessage("null")
					if cells["event"] != "" {
						fields["event"], _ = json.Marshal(cells["event"])
					}
					if cells["mode"] != "" {
						fields["mode"], _ = json.Marshal(cells["mode"])
					}
					note := "[" + declaration.DiscoveredBy + "]"
					if cells["note"] != "" {
						note = cells["note"] + " " + note
					}
					fields["note"], _ = json.Marshal(note)
					fields["discovered_by"], _ = json.Marshal(declaration.DiscoveredBy)
					fields["status"], fields["ref_type"] = json.RawMessage(`"drafted"`), json.RawMessage(`"unknown"`)
					fields["ref_sites"] = json.RawMessage("[]")
					fields["landing_vma"], fields["patch_ref"] = json.RawMessage("null"), json.RawMessage("null")
					rows = append(rows, importRow{fields: fields, batch: batch, record: recordNumber})
				}
				if headers == nil {
					return fmt.Errorf("%s: CSV requires a header", batch)
				}
			} else {
				if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) {
					return fmt.Errorf("%s: JSON import must be a bare array", batch)
				}
				if err := checkJSON(checkedJSON{raw: body, records: true, aliasesByDepth: map[int][]string{2: ownedFields}}); err != nil {
					return err
				}
				decoder := json.NewDecoder(bytes.NewReader(body))
				_, _ = decoder.Token() // Complete JSON and the array opener were checked above.
				for record := 1; decoder.More(); record++ {
					if len(rows) == 65536 {
						return fmt.Errorf("registry import exceeds 65536 records")
					}
					var fields map[string]json.RawMessage
					if err := decoder.Decode(&fields); err != nil || fields == nil {
						return fmt.Errorf("%s record %d: expected a JSON object", batch, record)
					}
					rows = append(rows, importRow{fields: fields, batch: batch, record: record})
				}
			}
			batchCounts[batch] = len(rows) - before
		}
		// Check the complete ID cohort before collapsing it into the shared keyed merge.
		importedIDs := make(map[uint64]bool)
		for i := range rows {
			row := &rows[i]
			var id string
			if err := json.Unmarshal(row.fields["id"], &id); err != nil {
				return fmt.Errorf("%s record %d: import requires a string id", row.batch, row.record)
			}
			key, err := number(id)
			if err != nil || importedIDs[key] {
				return fmt.Errorf("%s record %d: invalid or duplicate normalized import id %q", row.batch, row.record, id)
			}
			importedIDs[key], row.id = true, fmt.Sprintf("0x%x", key)
		}
		required := strings.Fields("id jp en status source_pool")
		if policy == "json_kinds" || policy == "json_codes" || fullSweep {
			required = strings.Fields("id jp en chapter character tier status source_pool")
			if policy == "json_kinds" || fullSweep {
				required = append(required, "ref_type", "discovered_by")
			}
		}
		markerPattern := regexp.MustCompile(`\{\{(HL|PARAM):(0x[0-9a-fA-F]{4})\}\}`)
		if policy == "json_codes" {
			markerPattern = regexp.MustCompile(`\{\{(HL|PARAM):(0x[0-9a-fA-F]+)\}\}`)
		}
		angleMarkers := regexp.MustCompile(`<<(HL|PARAM):(0x[0-9a-fA-F]{4})>>`)
		speakers := regexp.MustCompile(`\[spk (0x[0-9a-fA-F]{4})\]`)
		closedSpeakers := regexp.MustCompile(`\[spk [^\]]*\]`)
		rawEchoes := regexp.MustCompile(`<0x[0-9a-fA-F]+>`)
		for _, row := range rows {
			for _, field := range required {
				raw := bytes.TrimSpace(row.fields[field])
				missing := len(raw) == 0
				if !missing && (policy == "json_kinds" || policy == "json_codes" || fullSweep) {
					switch raw[0] {
					case 'n', 'f':
						missing = true
					case '"':
						var value string
						_ = json.Unmarshal(raw, &value)
						missing = value == ""
					case '[', '{':
						missing = len(bytes.TrimSpace(raw[1:len(raw)-1])) == 0
					case 't':
					default:
						// Integers stay exact; floating-point truthiness follows the source loader.
						value := string(raw)
						if strings.ContainsAny(value, ".eE") {
							number, _ := strconv.ParseFloat(value, 64)
							missing = number == 0
						} else {
							missing = strings.Trim(value, "-0") == ""
						}
					}
				}
				if missing {
					return fmt.Errorf("%s: missing required import field %s", row.id, field)
				}
			}
			var texts [2]string
			var observations [2][][]string
			for side, field := range []string{"jp", "en"} {
				if err := checkJSON(checkedJSON{raw: row.fields[field], text: true}); err != nil {
					return err
				}
				if bytes.Equal(bytes.TrimSpace(row.fields[field]), []byte("null")) || json.Unmarshal(row.fields[field], &texts[side]) != nil {
					return fmt.Errorf("%s: import %s requires a string", row.id, field)
				}
				if policy == "converted_markers" {
					var converted strings.Builder
					standalone, params := []string{}, []map[string]string{}
					at := 0
					for _, match := range angleMarkers.FindAllStringSubmatchIndex(texts[side], -1) {
						kind := texts[side][match[2]:match[3]]
						code := strings.ToLower(texts[side][match[4]:match[5]])
						converted.WriteString(texts[side][at:match[0]])
						converted.WriteString("{{" + kind + ":" + code + "}}")
						at = match[1]
						if kind == "HL" {
							standalone = append(standalone, code)
						} else {
							params = append(params, map[string]string{"code": code})
						}
					}
					converted.WriteString(texts[side][at:])
					texts[side] = converted.String()
					metadata := map[string]json.RawMessage{}
					metadata["standalone_codes"], _ = json.Marshal(standalone)
					metadata["param_blocks"], _ = json.Marshal(params)
					for name, value := range metadata {
						if side == 0 {
							row.fields[name] = value
						} else if !bytes.Equal(row.fields[name], value) {
							return fmt.Errorf("%s: converted marker metadata differs", row.id)
						}
					}
					row.fields[field], _ = json.Marshal(texts[side])
				}
				if len(closedSpeakers.FindAllString(texts[side], -1)) != len(speakers.FindAllString(texts[side], -1)) {
					return fmt.Errorf("%s: malformed import speaker tag in %s", row.id, field)
				}
				observations[side] = markerPattern.FindAllStringSubmatch(texts[side], -1)

			}
			jpPages, enPages := strings.Split(texts[0], "//"), strings.Split(texts[1], "//")
			if len(jpPages) != len(enPages) {
				return fmt.Errorf("%s: import page count differs", row.id)
			}
			for i := range jpPages {
				var tags [2]string
				for side, page := range []string{jpPages[i], enPages[i]} {
					if at := speakers.FindStringSubmatchIndex(page); at != nil && at[0] == 0 {
						tags[side] = strings.ToLower(page[at[2]:at[3]])
					}
				}
				if tags[0] != tags[1] {
					return fmt.Errorf("%s: import page speaker differs", row.id)
				}
			}
			var sequences [2][]string
			for side, tokens := range observations {
				for _, token := range tokens {
					value := token[1]
					if policy == "json_codes" {
						value = token[2] // Original spelling, family-independent and case-sensitive.
					}
					sequences[side] = append(sequences[side], value)
				}
				if policy == "json_codes" {
					slices.Sort(sequences[side])
				}
			}
			if order, reviewed := reviewedOrders[row.id]; reviewed {
				if fmt.Sprintf("%x", sha256.Sum256([]byte(texts[0]))) != order.JPSHA256 || fmt.Sprintf("%x", sha256.Sum256([]byte(texts[1]))) != order.ENSHA256 {
					return fmt.Errorf("%s: reviewed marker wording hash differs", row.id)
				}
				if len(order.ENSourcesJP) != len(observations[0]) || len(observations[0]) != len(observations[1]) {
					return fmt.Errorf("%s: marker order must cover both complete tapes", row.id)
				}
				seenSources := make([]bool, len(observations[0]))
				for enIndex, sourcePosition := range order.ENSourcesJP {
					jpIndex := sourcePosition - 1
					if jpIndex < 0 || jpIndex >= len(seenSources) || seenSources[jpIndex] {
						return fmt.Errorf("%s: marker order requires a one-based bijection", row.id)
					}
					if observations[0][jpIndex][1] != observations[1][enIndex][1] || observations[0][jpIndex][2] != observations[1][enIndex][2] {
						return fmt.Errorf("%s: reviewed marker kind or code differs", row.id)
					}
					seenSources[jpIndex] = true
				}
				delete(reviewedOrders, row.id)
				usedReviewIDs = append(usedReviewIDs, row.id)
			} else if !slices.Equal(sequences[0], sequences[1]) {
				return fmt.Errorf("%s: declared import marker policy differs; notes do not authorize a bypass", row.id)
			}
			for side, field := range []string{"jp", "en"} {
				stripped := speakers.ReplaceAllString(texts[side], "")
				stripped = markerPattern.ReplaceAllString(stripped, "")
				if policy != "csv_drafts" {
					stripped = rawEchoes.ReplaceAllString(stripped, "")
				}
				stripped = strings.ReplaceAll(strings.ReplaceAll(stripped, "//", ""), "|", "")
				if policy != "json_codes" && strings.ContainsAny(stripped, "‘’`") {
					return fmt.Errorf("%s: import %s requires straight apostrophes", row.id, field)
				}
				for _, char := range stripped {
					if _, known := glyphs[char]; char != ' ' && !known {
						return fmt.Errorf("%s: import %s glyph %q is missing", row.id, field, char)
					}
				}
			}
		}
		if len(reviewedOrders) != 0 {
			return fmt.Errorf("marker_orders contains %d unused reviewed records", len(reviewedOrders))
		}
		profile.RegistryUpdates = make(map[string]map[string]json.RawMessage, len(rows))
		for _, row := range rows {
			fields := maps.Clone(row.fields)
			delete(fields, "id")
			profile.RegistryUpdates[row.id] = fields
		}
		ids = slices.Sorted(maps.Keys(profile.RegistryUpdates))
		limits := "Lexical draft admission only, not byte-source occurrence/payload identity, native fit, references or patch readiness. Canonical Go ID spelling and drafted-only new rows remain enforced. Per-pool construction/ownership/headline and reviewed occurrence exceptions remain separate facts; note text grants no waiver."
		importSummary = map[string]any{"policy": policy, "batches": declaration.Batches, "counts": batchCounts, "records": len(rows), "inputs": profile.RegistryInputs, "limits": limits}
		if fullSweep {
			importSummary["reviewed_marker_ids"] = usedReviewIDs
			importSummary["limits"] = limits + " Full-sweep preserves its ten-field and apostrophe gates. Supplied mappings pin both texts and a complete one-based English-to-Japanese kind/code bijection, even when kinds already agree. Equal codes do not prove opaque payload identity."
		}
	}
	checked := []checkedJSON{{raw: data}, {raw: registryRecipeData, updates: true, text: author || adding || exporting || summarizing || human}}
	if summarizing {
		checked = append(checked, checkedJSON{raw: registryInputs["glossary"], text: true}, checkedJSON{raw: registryInputs["flow"], text: true, records: true})
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
	case human:
		allowed = map[string]bool{"jp": true, "en": true, "chapter": true, "character": true, "event": true, "tier": true, "note": true}
	case derived:
		allowed = map[string]bool{"midcontent_markup_shape": true}
	}
	statuses := []string{"drafted", "zone_pending", "patched", "decode_verified", "emulator_confirmed"}
	if human {
		batch, err := resolveHumanEntries(registryInputs)
		if err != nil {
			return err
		}
		if len(entries) > 65536 {
			return fmt.Errorf("human registry exceeds 65536 existing entries")
		}
		profile.RegistryUpdates = make(map[string]map[string]json.RawMessage)
		humanOutcomes = []map[string]any{}
		resultCount := len(entries)
		for _, key := range slices.Sorted(maps.Keys(batch.Entries)) {
			row := batch.Entries[key]
			id := fmt.Sprintf("0x%x", key)
			entry := byID[key]
			values := map[string]string{"jp": row.JP, "en": row.EN, "chapter": row.Chapter, "character": row.Character, "event": row.Event, "tier": row.Tier, "note": row.Note}
			incoming := make(map[string]json.RawMessage)
			matching := make(map[string]bool)
			for _, field := range []string{"jp", "en", "chapter", "character", "event", "tier", "note"} {
				raw := bytes.TrimSpace(entry[field])
				var old string
				if len(raw) != 0 && raw[0] == '"' {
					if err := checkJSON(checkedJSON{raw: raw, text: true}); err != nil {
						return err
					}
					matching[field] = json.Unmarshal(raw, &old) == nil && old == values[field]
				}
				if field != "jp" && field != "en" {
					incoming[field], _ = json.Marshal(values[field])
				}
			}
			drifted := []string{}
			for _, field := range []string{"jp", "en"} {
				if !matching[field] {
					drifted = append(drifted, field)
				}
			}
			wording := "matching"
			var status string
			_ = json.Unmarshal(entry["status"], &status)
			switch {
			case entry == nil:
				if resultCount == 65536 {
					return fmt.Errorf("human result exceeds 65536 registry entries")
				}
				resultCount++
				wording = "new"
				pool := "text_bank"
				if row.Chapter == "menu" {
					pool = "menu_labels"
				}
				incoming["source_pool"], _ = json.Marshal(pool)
				incoming["discovered_by"], _ = json.Marshal(batch.DiscoveredBy)
				incoming["status"] = json.RawMessage(`"drafted"`)
				incoming["landing_vma"], incoming["patch_ref"] = json.RawMessage("null"), json.RawMessage("null")
			case slices.Contains(statuses[2:], status):
				wording = "locked"
			case len(drifted) != 0 && !batch.OverwriteDrift:
				wording = "drift_held"
			case len(drifted) != 0:
				if !slices.Contains(statuses[:2], status) {
					return fmt.Errorf("%s: changed human wording requires a known unlocked status", id)
				}
				wording = "replaced"
			}
			if wording == "new" || wording == "replaced" {
				for _, field := range []string{"jp", "en"} {
					incoming[field], _ = json.Marshal(values[field])
				}
			}
			changed := false
			for field := range incoming {
				if !matching[field] {
					changed = true
				}
			}
			humanChanged = humanChanged || changed
			profile.RegistryUpdates[id] = incoming
			humanOutcomes = append(humanOutcomes, map[string]any{"id": id, "wording": wording, "drifted_fields": drifted, "changed": changed})
		}
		ids = slices.Sorted(maps.Keys(profile.RegistryUpdates))
	}
	if reconciling {
		correctionOutcomes, glossaryOutcomes = []map[string]string{}, []map[string]string{}
		var corrections []RegistryCorrection
		var proposals []GlossaryProposal
		total := 0
		for _, name := range []string{"corrections", "glossary_proposals"} {
			body := registryInputs[name]
			fields := []string{"id", "old_en", "new_en", "note_suffix"}
			if name == "glossary_proposals" {
				fields = []string{"jp", "en", "provenance", "source", "usage_note"}
			}
			if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) {
				return fmt.Errorf("reconciliation %s must be a bare array", name)
			}
			if err := checkJSON(checkedJSON{raw: body, text: true, allObjects: true, nonNull: true, fieldsByDepth: map[int][]string{2: fields}, requiredByDepth: map[int][]string{2: fields}}); err != nil {
				return err
			}
			decoder := json.NewDecoder(bytes.NewReader(body))
			_, _ = decoder.Token()
			for decoder.More() {
				if total == 65536 {
					return fmt.Errorf("reconciliation exceeds 65536 authored records")
				}
				total++
				if name == "corrections" {
					var row RegistryCorrection
					if err := decoder.Decode(&row); err != nil || row.ID == "" || row.NewEN == "" || row.NoteSuffix == "" {
						return fmt.Errorf("correction requires string fields and nonempty id/new_en/note_suffix: %v", err)
					}
					corrections = append(corrections, row)
				} else {
					var row GlossaryProposal
					if err := decoder.Decode(&row); err != nil || row.JP == "" || row.EN == "" || row.Provenance == "" || row.Source == "" || row.UsageNote == "" {
						return fmt.Errorf("glossary proposal requires five nonempty strings: %v", err)
					}
					proposals = append(proposals, row)
				}
			}
		}
		correctionIDs := make(map[uint64]bool)
		for _, row := range corrections {
			id, err := number(row.ID)
			if err != nil || byID[id] == nil || correctionIDs[id] {
				return fmt.Errorf("missing or duplicate normalized correction ID %q", row.ID)
			}
			correctionIDs[id] = true
		}
		glossaryData := registryInputs["glossary"]
		if err := checkJSON(checkedJSON{raw: glossaryData, aliasesByDepth: map[int][]string{1: {"entries"}}}); err != nil {
			return err
		}
		if json.Unmarshal(glossaryData, &glossaryDocument) != nil || glossaryDocument == nil || !bytes.HasPrefix(bytes.TrimSpace(glossaryDocument["entries"]), []byte("[")) {
			return fmt.Errorf("glossary requires an object with an entries array")
		}
		if err := checkJSON(checkedJSON{raw: glossaryDocument["entries"], records: true, aliasesByDepth: map[int][]string{2: {"jp", "en"}}}); err != nil {
			return err
		}
		glossaryByJP := make(map[string]string)
		decoder := json.NewDecoder(bytes.NewReader(glossaryDocument["entries"]))
		_, _ = decoder.Token()
		for decoder.More() {
			if len(glossaryEntries) == 65536 {
				return fmt.Errorf("glossary exceeds 65536 existing entries")
			}
			var entry map[string]json.RawMessage
			if err := decoder.Decode(&entry); err != nil || entry == nil {
				return fmt.Errorf("glossary entries must be objects: %v", err)
			}
			var values [2]string
			for i, field := range []string{"jp", "en"} {
				raw := bytes.TrimSpace(entry[field])
				if err := checkJSON(checkedJSON{raw: raw, text: true}); err != nil {
					return err
				}
				if len(raw) == 0 || bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &values[i]) != nil || field == "jp" && values[i] == "" {
					return fmt.Errorf("existing glossary requires string JP/EN and nonempty JP")
				}
			}
			if _, duplicate := glossaryByJP[values[0]]; duplicate {
				return fmt.Errorf("duplicate existing glossary JP %q", values[0])
			}
			glossaryByJP[values[0]] = values[1]
			glossaryEntries = append(glossaryEntries, entry)
		}
		proposedJP := make(map[string]bool)
		for _, row := range proposals {
			if proposedJP[row.JP] {
				return fmt.Errorf("duplicate proposed glossary JP %q", row.JP)
			}
			proposedJP[row.JP] = true
		}
		// Plan the complete pair before the shared mutation loop touches registry maps.
		profile.RegistryUpdates = make(map[string]map[string]json.RawMessage)
		for _, row := range corrections {
			id, _ := number(row.ID)
			entry := byID[id]
			canonicalID := fmt.Sprintf("0x%x", id)
			raw := bytes.TrimSpace(entry["en"])
			if err := checkJSON(checkedJSON{raw: raw, text: true}); err != nil {
				return err
			}
			var current string
			if len(raw) == 0 || bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &current) != nil {
				return fmt.Errorf("%s: correction requires string current EN", canonicalID)
			}
			outcome := "eligible"
			switch {
			case current == row.NewEN:
				outcome = "already_applied"
			case current != row.OldEN:
				return fmt.Errorf("%s: stale correction old_en", canonicalID)
			default:
				var status string
				_ = json.Unmarshal(entry["status"], &status)
				if slices.Contains(statuses[2:], status) {
					outcome = "held"
				} else if !slices.Contains(statuses[:2], status) {
					return fmt.Errorf("%s: correction change requires a known unlocked status", canonicalID)
				}
			}
			correctionOutcomes = append(correctionOutcomes, map[string]string{"id": canonicalID, "outcome": outcome})
			if outcome != "eligible" {
				continue
			}
			note := ""
			if raw := bytes.TrimSpace(entry["note"]); len(raw) != 0 && !bytes.Equal(raw, []byte("null")) {
				if err := checkJSON(checkedJSON{raw: raw, text: true}); err != nil {
					return err
				}
				if json.Unmarshal(raw, &note) != nil {
					return fmt.Errorf("%s: correction note must be a string or null", canonicalID)
				}
			}
			en, _ := json.Marshal(row.NewEN)
			annotation, _ := json.Marshal(note + row.NoteSuffix)
			profile.RegistryUpdates[canonicalID] = map[string]json.RawMessage{"en": en, "note": annotation}
		}
		for _, row := range proposals {
			outcome := "eligible"
			if current, present := glossaryByJP[row.JP]; present {
				if current != row.EN {
					return fmt.Errorf("glossary JP %q has conflicting EN", row.JP)
				}
				outcome = "already_present"
			} else {
				if len(glossaryEntries) == 65536 {
					return fmt.Errorf("resulting glossary exceeds 65536 entries")
				}
				fields := make(map[string]json.RawMessage)
				for name, value := range map[string]string{"jp": row.JP, "en": row.EN, "provenance": row.Provenance, "source": row.Source, "usage_note": row.UsageNote} {
					fields[name], _ = json.Marshal(value)
				}
				glossaryEntries = append(glossaryEntries, fields)
				glossaryChanged = true
			}
			glossaryOutcomes = append(glossaryOutcomes, map[string]string{"jp": row.JP, "outcome": outcome})
		}
		ids = slices.Sorted(maps.Keys(profile.RegistryUpdates))
	}
	seen := make(map[uint64]bool)
	added, alreadyPresent := []string{}, []string{}
	for _, id := range ids {
		key, err := number(id)
		entry := byID[key]
		if err != nil || !adding && !human && entry == nil || seen[key] || profile.RegistryUpdates[id] == nil {
			return fmt.Errorf("invalid, missing or duplicate update ID %q", id)
		}
		seen[key] = true
		if adding || human && entry == nil {
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
			if author || human {
				var text string
				if bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, &text) != nil || field == "en" && text == "" {
					return fmt.Errorf("%s: author %s requires a string; English cannot be empty", id, field)
				}
				if field == "en" || field == "jp" {
					var old, status string
					_ = json.Unmarshal(entry[field], &old)
					_ = json.Unmarshal(entry["status"], &status)
					if text != old && !slices.Contains(statuses[:2], status) {
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
	if adding && len(added) != 0 || human && humanChanged {
		entries = nil
		for _, id := range slices.Sorted(maps.Keys(byID)) {
			entries = append(entries, byID[id])
		}
	}
	var encoded bytes.Buffer
	var summary map[string]any
	var pairMembers []map[string]any
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	switch {
	case summarizing:
		var glossary map[string]json.RawMessage
		var glossaryEntries []map[string]json.RawMessage
		var todos []json.RawMessage
		var flow []map[string]json.RawMessage
		if err := json.Unmarshal(registryInputs["glossary"], &glossary); err != nil || glossary == nil {
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
		if err := json.Unmarshal(registryInputs["flow"], &flow); err != nil || flow == nil {
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
		view, err := template.New("registry-status").Option("missingkey=error").Parse(string(registryInputs["template"]))
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
	case adding && len(added) == 0 || human && !humanChanged:
		encoded.Write(data)
	default:
		type registryDocument struct {
			name      string
			fields    map[string]json.RawMessage
			entries   []map[string]json.RawMessage
			unchanged []byte
		}
		documents := []registryDocument{{name: "registry.json", fields: document, entries: entries}}
		var bundle bytes.Buffer
		var archive *zip.Writer
		if reconciling {
			if len(ids) == 0 {
				documents[0].unchanged = data
			}
			glossary := registryDocument{name: "glossary.json", fields: glossaryDocument, entries: glossaryEntries}
			if !glossaryChanged {
				glossary.unchanged = registryInputs["glossary"]
			}
			documents = append(documents, glossary)
			archive = zip.NewWriter(&bundle)
		}
		for _, member := range documents {
			encoded.Reset()
			if member.unchanged != nil {
				encoded.Write(member.unchanged)
			} else {
				if err := encoder.Encode(member.entries); err != nil {
					return err
				}
				if encoded.Len() > 64<<20 {
					return fmt.Errorf("registry compact entries exceed 64 MiB")
				}
				member.fields["entries"] = bytes.Clone(encoded.Bytes())
				encoded.Reset()
				member.fields["last_updated"], _ = json.Marshal(profile.Updated)
				if err := encoder.Encode(member.fields); err != nil {
					return err
				}
				if encoded.Len() > 64<<20 {
					return fmt.Errorf("registry compact document exceeds 64 MiB")
				}
				// Check inherited metadata as well as updates before indentation expands it.
				if err := checkJSON(checkedJSON{raw: encoded.Bytes(), maxPrettyBytes: 64 << 20}); err != nil {
					return err
				}
				var pretty bytes.Buffer
				if err := json.Indent(&pretty, encoded.Bytes(), "", "  "); err != nil {
					return err
				}
				if pretty.Len() > 64<<20 {
					return fmt.Errorf("registry formatted document exceeds 64 MiB")
				}
				encoded = pretty
			}
			if reconciling {
				file, err := archive.CreateHeader(&zip.FileHeader{Name: member.name, Method: zip.Store})
				if err != nil {
					return err
				}
				if _, err := file.Write(encoded.Bytes()); err != nil {
					return err
				}
				pairMembers = append(pairMembers, map[string]any{"name": member.name, "size": encoded.Len(), "sha256": fmt.Sprintf("%x", sha256.Sum256(encoded.Bytes())), "changed": member.unchanged == nil})
			}
		}
		if reconciling {
			if err := archive.Close(); err != nil {
				return err
			}
			// Two bounded members need room for fixed ZIP headers and the central directory.
			if bundle.Len() > 128<<20+1024 {
				return fmt.Errorf("registry pair archive exceeds its byte budget")
			}
			encoded = bundle
		}
	}
	if exporting || summarizing || importing || reconciling || human {
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
		for _, name := range inputNames {
			if input, exists := profile.RegistryInputs[name]; exists {
				current, err := readInput(input.Path, input.Size)
				if err != nil || !bytes.Equal(current, registryInputs[name]) {
					if importing {
						return fmt.Errorf("registry import %s changed during analysis", name)
					}
					return fmt.Errorf("registry status %s changed during analysis", name)
				}
			}
		}
	}
	if reconciling || human || fullSweep {
		current, err := readInput(options.ProfilePath, 1<<20)
		if err != nil || !bytes.Equal(current, registryRecipeData) {
			return fmt.Errorf("reconciliation profile changed before publication: %v", err)
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
	if importing {
		report["import"] = importSummary
		report["limits"] = "Declared lexical draft admission only. Existing field ownership, canonical IDs and all-present source bytes are preserved; byte-source/native/reference/patch readiness is not established."
	}
	if reconciling {
		if options.Apply {
			for _, rows := range [][]map[string]string{correctionOutcomes, glossaryOutcomes} {
				for _, row := range rows {
					if row["outcome"] == "eligible" {
						row["outcome"] = "applied"
					}
				}
			}
		}
		report = map[string]any{"operation": profile.Operation, "applied": options.Apply, "source_sha256": profile.SourceSHA256, "profile_sha256": fmt.Sprintf("%x", sha256.Sum256(registryRecipeData)), "inputs": profile.RegistryInputs, "output_sha256": outputHash, "members": pairMembers, "corrections": correctionOutcomes, "glossary": glossaryOutcomes,
			"limits": "Reviewed registry/glossary snapshots in one complete verified ZIP on successful return; not atomic pathname visibility or installation. Unchanged members preserve source bytes/date, a deliberate redesign from legacy date rewrites. No human drift/force/source construction, lexical/native/reference or patch-readiness claim."}
	}
	if human {
		report = map[string]any{"operation": profile.Operation, "applied": options.Apply, "source_sha256": profile.SourceSHA256, "profile_sha256": fmt.Sprintf("%x", sha256.Sum256(registryRecipeData)), "inputs": profile.RegistryInputs, "output_sha256": outputHash, "changed": humanChanged, "rows": humanOutcomes,
			"limits": "Selected human rows only. Locked wording and default drift are preserved while metadata refreshes; forced wording changes require a known unlocked status. Unchanged documents preserve exact source bytes/date. Unrelated incomplete metadata is preserved, a deliberate redesign from the old whole-registry refusal. Source joins do not establish glyph, native fit, reference or patch readiness."}
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
