package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
)

// auditStreams compares pinned reference/observed file windows through controls.
// Decoder style is explicit: overlapping grammars can interpret identical bytes
// differently. Through-END equality never hides a changed selected-window tail.
// Inputs are fully hashed and rechecked before any JSON is published; no writes,
// native rendering are performed. An optional family binds
// every declared observed site to the complete explicit window, including tails;
// this proves stored reference values, not that those readers execute. Canonical
// rows encode pinned registry EN against original context with an explicit policy;
// failed generation/comparison remains unknown, and generated spans are buffer offsets.
// Explicit review can request machine-only bookkeeping suggestions; matching bytes
// never clear an editorial hold or authorize publication, native fit or gameplay.
// Inline landings name the mapped field itself, never one of its glyph words.
// Optional line limits project decoded page structure against the declared reference;
// they do not measure native font fit or affect bookkeeping suggestions.
func auditStreams(profilePath string, stdout io.Writer) error {
	profileInfo, err := os.Stat(profilePath)
	if err != nil {
		return err
	}
	profileData, err := readInput(profilePath, 1<<20)
	if err != nil {
		return err
	}
	// encoding/json accepts case-folded field aliases; close typed names before
	// decoding. Depth2 holds dynamic source/ID keys; depth3 has pins or entries.
	if err := checkJSON(checkedJSON{raw: profileData, text: true, allObjects: true, nonNullByDepth: map[int][]string{1: {"sentinel"}, 3: {"canonical", "read_pins", "review", "line_limit"}, 4: {"wrap", "columns", "rows", "authoring", "action", "reason"}, 5: {"words", "end_offset", "sha256", "roles"}, 7: {"Kind", "Word", "Offset"}}, fieldsByDepth: map[int][]string{
		1: {"evidence", "sources", "entries", "observed_family", "sentinel"},
		3: {"path", "size", "sha256", "reference", "observed", "decoder", "canonical", "read_pins", "review", "line_limit"},
		4: {"start", "end", "wrap", "columns", "rows", "authoring", "reference", "observed", "action", "reason"},
		5: {"words", "end_offset", "sha256", "roles"},
		7: {"Kind", "Word", "Offset", "Payload"},
	}, requiredByDepth: map[int][]string{5: {"words", "end_offset", "sha256", "roles"}, 7: {"Kind", "Word", "Offset"}}}); err != nil {
		return fmt.Errorf("stream audit profile: %w", err)
	}
	var profile StreamAuditProfile
	decoder := json.NewDecoder(bytes.NewReader(profileData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return err
	}
	if profile.Sentinel != nil {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(profileData, &fields); err != nil {
			return err
		}
		if err := checkJSON(checkedJSON{raw: fields["sentinel"], text: true, allObjects: true, nonNull: true, fieldsByDepth: map[int][]string{1: {"retail_elf_size", "loader_vmas", "window_bases", "window_sizes"}}}); err != nil {
			return fmt.Errorf("stream audit sentinel: %w", err)
		}
		if profile.ObservedFamily == "" {
			return fmt.Errorf("sentinel audit requires a declared observed reference family")
		}
	}
	inputNames := []string{"reference", "observed", "glyphmap"}
	streamNames := []string{"reference", "observed"}
	inputCount := "three"
	if profile.ObservedFamily != "" {
		inputCount = "four"
		inputNames = append(inputNames, "registry")
		streamNames = append(streamNames, "registry")
		if profile.Sources["observed"].Size > 64<<20 || profile.Sources["registry"].Size > 64<<20 {
			return fmt.Errorf("reference-bound audit requires an observed ELF and registry within 64 MiB each")
		}
	}
	if profile.Evidence == "" || len(profile.Sources) != len(inputNames) || len(profile.Entries) < 1 || len(profile.Entries) > 4096 {
		return fmt.Errorf("stream audit requires evidence, %s pinned inputs and 1..4096 entries", inputCount)
	}
	for _, name := range inputNames {
		input, exists := profile.Sources[name]
		pin, err := hex.DecodeString(input.SHA256)
		if !exists || input.Path == "" || input.Size < 1 || err != nil || len(pin) != sha256.Size {
			return fmt.Errorf("invalid stream audit %s pin", name)
		}
		if !filepath.IsAbs(input.Path) {
			input.Path = filepath.Join(filepath.Dir(profilePath), input.Path)
		}
		profile.Sources[name] = input
	}
	glyphInput := profile.Sources["glyphmap"]
	if glyphInput.Size > 4<<20 {
		return fmt.Errorf("stream audit glyphmap exceeds 4 MiB")
	}
	glyphInfo, err := os.Stat(glyphInput.Path)
	if err != nil {
		return err
	}
	glyphData, err := readInput(glyphInput.Path, glyphInput.Size)
	if err != nil || int64(len(glyphData)) != glyphInput.Size || fmt.Sprintf("%x", sha256.Sum256(glyphData)) != glyphInput.SHA256 {
		return fmt.Errorf("stream audit glyphmap size/hash mismatch: %v", err)
	}
	if err := checkJSON(checkedJSON{raw: glyphData, text: true, allObjects: true}); err != nil {
		return fmt.Errorf("stream audit glyphmap: %w", err)
	}
	if bytes.TrimSpace(glyphData)[0] != '{' {
		return fmt.Errorf("stream audit glyphmap must be an object")
	}
	encodingGlyphs, glyphs, err := glyphMaps(glyphData, true)
	if err != nil {
		return err
	}
	inputs := make([]struct {
		pin    RegistryInput
		file   *os.File
		before os.FileInfo
	}, len(streamNames))
	for i, name := range streamNames {
		inputs[i].pin = profile.Sources[name]
		inputs[i].file, err = os.Open(inputs[i].pin.Path)
		if err != nil {
			return err
		}
		defer inputs[i].file.Close()
		inputs[i].before, err = inputs[i].file.Stat()
		if err != nil || !inputs[i].before.Mode().IsRegular() || inputs[i].before.Size() != inputs[i].pin.Size {
			return fmt.Errorf("stream audit %s source size/type mismatch", name)
		}
	}
	canonical := false
	reconciling := false
	fixedEntries := 0
	names := make(map[uint64]string)
	for text := range profile.Entries {
		id, err := number(text)
		if err != nil || names[id] != "" {
			return fmt.Errorf("invalid or duplicate stream audit ID %q", text)
		}
		names[id] = text
		if profile.Entries[text].Decoder == "fixed16" {
			fixedEntries++
		}
		entry := profile.Entries[text]
		if entry.LineLimit != nil && (*entry.LineLimit < 1 || *entry.LineLimit > 4096 || entry.Decoder != "narrative" && entry.Decoder != "positional") {
			return fmt.Errorf("%s: structural line_limit requires narrative or positional decoder and 1..4096 lines", text)
		}
		if entry.Review != nil {
			reconciling = true
			if profile.ObservedFamily == "" || entry.Review.Action != "allow" && entry.Review.Action != "hold" || strings.TrimSpace(entry.Review.Reason) == "" {
				return fmt.Errorf("%s: review requires a bound family, allow/hold action and nonblank reason", text)
			}
		}
		if entry.Decoder == "pinned_raw" {
			if len(entry.ReadPins) != 2 || entry.Canonical != nil {
				return fmt.Errorf("%s: pinned raw audit requires two side pins and no canonical generation", text)
			}
			for _, name := range []string{"reference", "observed"} {
				if _, exists := entry.ReadPins[name]; !exists {
					return fmt.Errorf("%s: pinned raw audit requires exact reference/observed side keys", text)
				}
			}
		} else if entry.ReadPins != nil {
			return fmt.Errorf("%s: read pins require explicit pinned_raw decoder", text)
		}
		policy := profile.Entries[text].Canonical
		if policy == nil {
			continue
		}
		canonical = true
		if profile.ObservedFamily == "" || profile.Entries[text].Decoder != "narrative" && profile.Entries[text].Decoder != "fixed16" {
			return fmt.Errorf("%s: canonical audit requires a bound narrative or fixed16 entry", text)
		}
		if policy.Authoring != "" && policy.Authoring != "markers" && policy.Authoring != "plain" && policy.Authoring != "ordered" {
			return fmt.Errorf("%s: canonical authoring must be markers, plain or ordered", text)
		}
		if profile.Entries[text].Decoder == "fixed16" && (policy.Wrap != "none" || policy.Authoring != "") {
			return fmt.Errorf("%s: fixed16 canonical policy requires no wrapping or source authoring", text)
		}
		switch policy.Wrap {
		case "none":
			if policy.Columns != 0 || policy.Rows != 0 {
				return fmt.Errorf("%s: no-wrap canonical policy cannot have character budgets", text)
			}
		case "characters":
			if policy.Columns < 1 || policy.Rows < 1 || policy.Columns > 4096 || policy.Rows > 4096 {
				return fmt.Errorf("%s: canonical character budgets require columns/rows within 1..4096", text)
			}
		default:
			return fmt.Errorf("%s: canonical wrap must be none or characters", text)
		}
	}

	if profile.ObservedFamily != "" && fixedEntries != 0 && fixedEntries != len(profile.Entries) {
		return fmt.Errorf("bound audit cannot mix inline fields and pointer streams")
	}
	inline := fixedEntries == len(profile.Entries)
	if profile.Sentinel != nil && fixedEntries != 0 {
		return fmt.Errorf("sentinel transport cannot own inline fixed fields")
	}

	// Share the bound inputs with canonical generation and the later strict binding check.
	var documents [2][]byte
	if profile.ObservedFamily != "" {
		for i, input := range inputs[1:] {
			documents[i], err = io.ReadAll(io.NewSectionReader(input.file, 0, input.pin.Size))
			if err != nil {
				return err
			}
		}
	}
	wording := make(map[uint64]string)
	statuses := make(map[uint64]*string)
	inlinePointerKeys := make(map[uint64]bool)
	if canonical || reconciling {
		var registry struct {
			Entries []json.RawMessage `json:"entries"`
		}
		if err := json.Unmarshal(documents[1], &registry); err != nil {
			return err
		}
		for _, raw := range registry.Entries {
			var entry struct {
				ID     string                       `json:"id"`
				EN     *string                      `json:"en"`
				Status json.RawMessage              `json:"status"`
				Sites  []map[string]json.RawMessage `json:"ref_sites"`
			}
			if err := json.Unmarshal(raw, &entry); err != nil {
				return err
			}
			id, err := number(entry.ID)
			if err != nil {
				return err
			}
			if entry.EN != nil {
				wording[id] = *entry.EN
			}
			if _, selected := names[id]; reconciling && selected {
				if err := checkJSON(checkedJSON{raw: raw, aliasesByDepth: map[int][]string{1: {"status"}}}); err != nil {
					return err
				}
				var status *string
				if json.Unmarshal(entry.Status, &status) == nil {
					statuses[id] = status
				}
				if inline {
					for _, site := range entry.Sites {
						if _, present := site["pointer_vma"]; present {
							inlinePointerKeys[id] = true
						}
					}
				}
			}
		}
	}

	report := StreamAuditReport{Operation: "stream_audit", ProfileSHA256: fmt.Sprintf("%x", sha256.Sum256(profileData)), Sources: profile.Sources,
		Limits: "Read-only facts at declared file windows; IDs are attribution, not verified live-reference bindings. No canonical wording, substitutions, rendering, safe placement or gameplay proof. Decoder style is explicit, never autodetected. Complete span bytes include tails; semantic comparisons are null on decode failure. Payload bytes use JSON base64.", Rows: []StreamAuditRow{}}
	rowBytes := 0
	for _, id := range slices.Sorted(maps.Keys(names)) {
		text := names[id]
		entry := profile.Entries[text]
		if entry.Decoder != "narrative" && entry.Decoder != "positional" && entry.Decoder != "fixed16" && entry.Decoder != "pinned_raw" {
			return fmt.Errorf("%s: stream audit decoder must be narrative, positional, fixed16 or pinned_raw", text)
		}
		row := StreamAuditRow{ID: text, Decoder: entry.Decoder, Status: "decode_failed"}
		if entry.LineLimit != nil {
			row.Structure = &StreamAuditStructure{LineLimit: *entry.LineLimit}
		}
		var spans [3][]byte
		var controlsAt, sequence [3][]TextToken
		sides := []*StreamAuditSide{&row.Reference, &row.Observed}
		if entry.Canonical != nil {
			row.Canonical = &StreamAuditSide{}
			sides = append(sides, row.Canonical)
		}
		for i, side := range sides {
			if i == 2 {
				english, hasWording := wording[id]
				switch {
				case !hasWording || english == "" && entry.Decoder != "fixed16":
					side.Error = "missing canonical registry EN"
				case len(english) > 64<<10:
					side.Error = "canonical registry EN exceeds 64 KiB"
				case row.Reference.Error != "":
					side.Error = "canonical source context: " + row.Reference.Error
				case entry.Decoder == "fixed16":
					encoded, encodeErr := encode(english, nil, encodingGlyphs, TextEncodeOptions{})
					if encodeErr != nil {
						side.Error = encodeErr.Error()
					} else if len(encoded) > 16 {
						side.Error = "canonical fixed16 wording exceeds16bytes"
					} else {
						spans[i] = append(encoded, make([]byte, 16-len(encoded))...)
					}
				default:
					source, sourceErr := controls(spans[0], TextScanOptions{Decode: true, Glyphs: glyphs, English: &english})
					if sourceErr != nil {
						side.Error = sourceErr.Error()
						break
					}
					if entry.Canonical.Authoring == "ordered" && source.Tokens[len(source.Tokens)-1].Offset+2 != len(spans[0]) {
						side.Error = "ordered source range must end at its physical END"
						break
					}
					spans[i], sourceErr = encode(english, nil, encodingGlyphs, TextEncodeOptions{Terminated: true, Source: &source, Columns: entry.Canonical.Columns, Rows: entry.Canonical.Rows, SourceAuthoring: entry.Canonical.Authoring})
					if sourceErr != nil {
						side.Error = sourceErr.Error()
					} else if len(spans[i]) > 64<<10 {
						side.Error = "canonical encoded stream exceeds 64 KiB"
					}
				}
				if side.Error != "" {
					continue
				}
				side.Span = AddressRange{Start: "0x0", End: fmt.Sprintf("0x%x", len(spans[i]))}
			} else {
				side.Span = entry.Reference
				if i == 1 {
					side.Span = entry.Observed
				}
				start, startErr := number(side.Span.Start)
				end, endErr := number(side.Span.End)
				if startErr != nil || endErr != nil || start >= end || start%2 != 0 || end%2 != 0 || end > uint64(inputs[i].pin.Size) || end-start > 64<<10 {
					return fmt.Errorf("%s: invalid bounded even stream audit file window", text)
				}
				if entry.Decoder == "fixed16" && end-start != 16 {
					return fmt.Errorf("%s: fixed16 requires exact16byte source/observed windows", text)
				}
				spans[i] = make([]byte, end-start)
				if _, err := inputs[i].file.ReadAt(spans[i], int64(start)); err != nil {
					return err
				}
			}
			side.SpanSHA256 = fmt.Sprintf("%x", sha256.Sum256(spans[i]))
			scan := TextScanOptions{Decode: true, Glyphs: glyphs, PositionalLabels: entry.Decoder == "positional"}
			if entry.Decoder == "fixed16" {
				scan.FixedWords = 8
			}
			if entry.Decoder == "pinned_raw" {
				name := []string{"reference", "observed"}[i]
				pin := entry.ReadPins[name]
				scan.ReadPin = &pin
			}
			shape, err := controls(spans[i], scan)
			if err != nil {
				side.Error = err.Error()
				continue
			}
			consumed := shape.Tokens[len(shape.Tokens)-1].Offset + 2
			trailing := len(spans[i]) - consumed
			side.ConsumedBytes, side.TrailingBytes, side.Tokens = &consumed, &trailing, shape.Tokens
			side.StreamSHA256 = fmt.Sprintf("%x", sha256.Sum256(spans[i][:consumed]))
			side.GlyphWords, side.ArgumentWords, side.OpaquePayloads = []uint16{}, []uint16{}, []TextToken{}
			controlsAt[i], sequence[i] = []TextToken{}, []TextToken{}
			var glyphText strings.Builder
			pages, lineCounts := [][]int{}, []int{0}
			hasHDR := false
			for _, token := range shape.Tokens {
				if row.Structure != nil && i < 2 {
					switch token.Kind {
					case "hdr":
						hasHDR = true
					case "page", "end":
						for len(lineCounts) > 1 && lineCounts[len(lineCounts)-1] == 0 {
							lineCounts = lineCounts[:len(lineCounts)-1]
						}
						pages = append(pages, lineCounts)
						lineCounts = []int{0}
					case "line":
						lineCounts = append(lineCounts, 0)
					case "glyph", "hl", "icon", "param8":
						// Match source report token counts: SPACE/padding is ignored,
						// but a nonzero blank glyph and an opaque argument each count once.
						lineCounts[len(lineCounts)-1]++
					}
				}
				if token.Kind == "glyph" || token.Kind == "space" {
					value := glyphs[token.Word]
					if token.Kind == "space" {
						value = " "
					}
					if glyphText.Len()+len(value) > 64<<10 {
						return fmt.Errorf("%s: expanded glyph text exceeds 64 KiB", text)
					}
					glyphText.WriteString(value)
					side.GlyphWords = append(side.GlyphWords, token.Word)
					continue
				}
				controlsAt[i] = append(controlsAt[i], token)
				token.Offset = 0
				sequence[i] = append(sequence[i], token)
				if token.Kind == "icon" || token.Kind == "param8" || token.Kind == "rawarg" {
					side.ArgumentWords = append(side.ArgumentWords, token.Word)
				}
				if token.Kind == "param8" {
					side.OpaquePayloads = append(side.OpaquePayloads, token)
				}
			}
			side.GlyphText = glyphText.String()
			if row.Structure != nil {
				switch i {
				case 0:
					row.Structure.ReferencePages = pages
				case 1:
					row.Structure.ObservedPages, row.Structure.ObservedHasHDR = pages, &hasHDR
				}
			}
		}
		if structure := row.Structure; structure != nil && structure.ObservedHasHDR != nil {
			structure.ObservedOverLimitPages = []int{}
			var totalLines [2]int
			for side, pages := range [][][]int{structure.ReferencePages, structure.ObservedPages} {
				nonemptyIndex := 0
				for _, page := range pages {
					visible := 0
					for _, count := range page {
						visible += count
					}
					if visible == 0 {
						continue
					}
					totalLines[side] += len(page)
					if side == 1 && *structure.ObservedHasHDR && len(page) > structure.LineLimit {
						structure.ObservedOverLimitPages = append(structure.ObservedOverLimitPages, nonemptyIndex)
					}
					nonemptyIndex++
				}
			}
			if *structure.ObservedHasHDR || structure.ReferencePages != nil {
				advisory := !*structure.ObservedHasHDR && totalLines[0] > 0 && totalLines[1] > totalLines[0]
				structure.HeaderlessLineGrowthAdvisory = &advisory
			}
		}
		row.SpanBytesEqual = bytes.Equal(spans[0], spans[1])
		if !row.SpanBytesEqual {
			at := 0
			for at < min(len(spans[0]), len(spans[1])) && spans[0][at] == spans[1][at] {
				at++
			}
			row.FirstDifference = &at
		}
		for _, a := range []int{0, 2} {
			if a >= len(sides) || sides[a].Error != "" || row.Observed.Error != "" {
				continue
			}
			comparison := &StreamAuditComparison{
				StreamBytesEqual: bytes.Equal(spans[a][:*sides[a].ConsumedBytes], spans[1][:*row.Observed.ConsumedBytes]),
				GlyphWordsEqual:  slices.Equal(sides[a].GlyphWords, row.Observed.GlyphWords), GlyphTextEqual: sides[a].GlyphText == row.Observed.GlyphText,
				ControlTokensEqual: reflect.DeepEqual(controlsAt[a], controlsAt[1]), ControlSequenceEqual: reflect.DeepEqual(sequence[a], sequence[1]),
				ArgumentWordsEqual: slices.Equal(sides[a].ArgumentWords, row.Observed.ArgumentWords), OpaquePayloadsEqual: reflect.DeepEqual(sides[a].OpaquePayloads, row.Observed.OpaquePayloads)}
			if a == 0 {
				row.Status = "compared"
				row.Comparison = comparison
			} else {
				row.CanonicalComparison = comparison
			}
		}

		encoded, err := json.Marshal(row)
		if err != nil {
			return err
		}
		rowBytes += len(encoded)
		if rowBytes > 64<<20 {
			return fmt.Errorf("stream audit rows exceed 64 MiB")
		}
		report.Rows = append(report.Rows, row)
	}
	if profile.ObservedFamily != "" {
		// Window bounds and decoder facts are already checked above. Reuse the
		// actual reference and ELF owners before publishing any comparison.
		observed := inputs[1].pin
		operation := "reference_observed"
		if inline {
			operation = "reference_inline16"
		}
		facts, err := references(documents[0], documents[1], nil, nil, Recipes{Operation: operation, SourceSize: observed.Size, SourceSHA256: observed.SHA256,
			ScopeSHA256: inputs[2].pin.SHA256, RegistryPatchRef: profile.ObservedFamily, Evidence: profile.Evidence})
		if err != nil {
			return err
		}
		rows := facts.Queries[profile.ObservedFamily]
		if len(rows) != len(names) {
			return fmt.Errorf("bound family and paired audit require the same IDs")
		}
		ranges := make(map[string]AddressRange)
		for _, row := range rows {
			id, _ := number(row.ID)
			text, exists := names[id]
			if !exists || len(row.ObservedSites) == 0 || !inline && len(row.ObservedTargets) != 1 {
				return fmt.Errorf("%s: bound audit requires matching IDs and convergent declared sites", row.ID)
			}
			for _, site := range row.ObservedSites {
				if site.Error != "" || !inline && site.Target == nil {
					return fmt.Errorf("%s: every bound reference site must be readable and valid", row.ID)
				}
			}
			span := profile.Entries[text].Observed
			start, _ := number(span.Start)
			end, _ := number(span.End)
			var target uint64
			if inline {
				if len(row.ObservedSites) != 1 || len(row.ObservedSites[0].Geometry.VMAs) != 4 || end-start != 16 {
					return fmt.Errorf("%s: inline16 requires one complete16byte field", text)
				}
				target = row.ObservedSites[0].Geometry.VMAs[0]
			} else {
				target = uint64(row.ObservedTargets[0])
			}
			ranges[text] = AddressRange{Start: fmt.Sprintf("0x%x", target), End: fmt.Sprintf("0x%x", target+end-start)}
		}
		mapped, err := inspect(bytes.NewReader(documents[0]), nil, &Recipes{Operation: "elf_layout", SourceSize: observed.Size, SourceSHA256: observed.SHA256, Evidence: profile.Evidence, AddressRanges: ranges, Sentinel: profile.Sentinel})
		if err != nil {
			return err
		}
		for text, pieces := range mapped.ELFMappings {
			span := profile.Entries[text].Observed
			start, _ := number(span.Start)
			end, _ := number(span.End)
			if len(pieces) != 1 {
				return fmt.Errorf("%s: complete bound window must match one file-backed target range", text)
			}
			piece := pieces[0]
			switch piece.Storage {
			case "file_backed":
			case "sentinel_blob":
				if mapped.Sentinel == nil {
					return fmt.Errorf("%s: sentinel mapping requires independently verified allocation facts", text)
				}
			default:
				return fmt.Errorf("%s: complete bound window must match one file-backed target range", text)
			}
			if piece.FileRange == nil || *piece.FileRange != [2]uint64{start, end} {
				return fmt.Errorf("%s: complete bound window must match one file-backed target range", text)
			}
		}
		if inline {
			original := inputs[0].pin
			if original.Size > 64<<20 {
				return fmt.Errorf("inline16 reference ELF exceeds64MiB")
			}
			data, err := io.ReadAll(io.NewSectionReader(inputs[0].file, 0, original.Size))
			if err != nil {
				return err
			}
			baseline, err := inspect(bytes.NewReader(data), nil, &Recipes{Operation: "elf_layout", SourceSize: original.Size, SourceSHA256: original.SHA256, Evidence: profile.Evidence, AddressRanges: ranges})
			if err != nil {
				return err
			}
			for text, pieces := range baseline.ELFMappings {
				span := profile.Entries[text].Reference
				start, _ := number(span.Start)
				end, _ := number(span.End)
				if len(pieces) != 1 || pieces[0].Storage != "file_backed" || pieces[0].FileRange == nil || *pieces[0].FileRange != [2]uint64{start, end} {
					return fmt.Errorf("%s: inline16 original field window differs from declared struct mapping", text)
				}
			}
			report.ReferenceMappings = baseline.ELFMappings
		}
		report.SentinelAllocation = mapped.Sentinel
		report.ObservedReferences, report.ObservedMappings = &facts, mapped.ELFMappings
		report.Limits = strings.Replace(report.Limits, "IDs are attribution, not verified live-reference bindings.", "Selected IDs bind every declared site to a complete observed window; stored reference values do not prove live readers.", 1)
		if reconciling {
			for i := range report.Rows {
				row := &report.Rows[i]
				id, _ := number(row.ID)
				decision := &StreamAuditReconciliation{CurrentStatus: statuses[id], Review: profile.Entries[row.ID].Review, Status: "held", Reasons: []string{}}
				row.Reconciliation = decision
				switch {
				case decision.Review == nil:
					decision.Reasons = append(decision.Reasons, "review_missing")
				case decision.Review.Action == "hold":
					decision.Reasons = append(decision.Reasons, "review_hold")
				}
				switch {
				case decision.CurrentStatus == nil:
					decision.Reasons = append(decision.Reasons, "status_unknown")
				case *decision.CurrentStatus != "drafted" && *decision.CurrentStatus != "patched":
					decision.Reasons = append(decision.Reasons, "status_not_eligible")
				}
				switch {
				case row.CanonicalComparison == nil:
					decision.Reasons = append(decision.Reasons, "canonical_unknown")
				case !row.CanonicalComparison.StreamBytesEqual:
					decision.Reasons = append(decision.Reasons, "canonical_mismatch")
				}
				if row.Observed.TrailingBytes == nil || *row.Observed.TrailingBytes != 0 {
					decision.Reasons = append(decision.Reasons, "trailing_bytes")
				}
				// Source policy excludes the key itself, including empty/null values.
				if inlinePointerKeys[id] {
					decision.Reasons = append(decision.Reasons, "inline_pointer_key_present")
				}
				if len(decision.Reasons) != 0 {
					continue
				}
				if *decision.CurrentStatus == "patched" {
					decision.Status = "unchanged"
					decision.Reasons = append(decision.Reasons, "already_patched_landing_not_reconciled")
					continue
				}
				decision.Status = "proposed"
				decision.ProposedMachineFields = map[string]string{"status": "patched", "landing_vma": ranges[row.ID].Start}
			}
			report.Limits += " Reconciliation is advisory bookkeeping for explicit current-pin review, not native fit, live/display ownership or patch authority. Only drafted rows with exact canonical bytes, zero observed tail and complete binding can propose status/landing. Pointer streams use observed targets; inline16 uses the field location proved in both files, never a stored pointer. Human EN/JP/note and patch_ref remain untouched. Unchanged means no status promotion; landing metadata is not reconciled. Any later publisher must independently recheck pinned registry/source identity and field ownership."
		}
	}
	if report.SentinelAllocation != nil {
		report.Limits += " Sentinel observed mappings use a separately proved installed dispatch/loader/physical-trailer intersection; declared full windows including tails must fit. sentinel_blob has no program header. Reference target_mapping remains ordinary ELF-only; observed_mappings identifies actual external transport. Retail EOF remains a pinned layout assumption; no runtime liveness, allocation changes or patch authority."
	}
	for _, entry := range profile.Entries {
		if entry.Decoder == "pinned_raw" {
			report.Limits += " Pinned raw roles are exact one-word audited interpretations under full-span identity, count and explicit END-offset guards. Raw arguments retain order; raw controls stay distinct. This establishes no runtime ABI, authoring/native fit or patch authority; default inline-payload grammar is unchanged."
			break
		}
	}
	for _, entry := range profile.Entries {
		if entry.LineLimit != nil {
			report.Limits += " Structural facts count decoded token lines under an explicit line_limit, not font advances, physical fit or gameplay. Full page arrays retain empty pages; overflow indices count only nonempty pages. Headerless line growth compares the declared reference window, never an inferred registry address; an unreadable baseline remains unknown. These diagnostics do not change reconciliation or authorize writes."
			break
		}
	}
	if fixedEntries != 0 {
		report.Limits += " Fixed16 decodes exactlyeight plain glyph words without END. Zero is SPACE/padding; literal canonical wording preserves spaces/metacharacters and intentional empty, then zero-pads exactly16bytes. No write or reader-execution authority."
	}
	if inline && profile.ObservedFamily != "" {
		report.Limits += " Bound inline fields contain no pointer targets; declared field geometry and full16byte original/observed file mappings are verified."
	}
	if canonical {
		report.Limits = strings.Replace(report.Limits, "No canonical wording, substitutions, rendering, safe placement or gameplay proof.", "Canonical fields derive pinned registry EN through the existing source-context encoder and explicit wrapping policy. Canonical spans are zero-based generated buffers, not file windows. Canonical comparison is omitted if generation or observed decoding fails. Original comparison/status remain independent; matching original bytes alone does not mean untranslated. No substitutions, native rendering, safe placement, visual fit or gameplay proof.", 1)
	}

	if inline {
		report.Limits = strings.Replace(report.Limits, "Canonical fields derive pinned registry EN through the existing source-context encoder and explicit wrapping policy.", "Canonical fixed16 fields derive pinned registry EN through literal glyph encoding and exact16byte padding.", 1)
	}

	for _, input := range inputs {
		if _, err := input.file.Seek(0, io.SeekStart); err != nil {
			return err
		}
		hash := sha256.New()
		n, err := io.Copy(hash, input.file)
		after, statErr := input.file.Stat()
		pathInfo, pathErr := os.Stat(input.pin.Path)
		if err != nil || statErr != nil || pathErr != nil || n != input.pin.Size || after.Size() != input.pin.Size || after.ModTime() != input.before.ModTime() || !os.SameFile(input.before, pathInfo) || fmt.Sprintf("%x", hash.Sum(nil)) != input.pin.SHA256 {
			return fmt.Errorf("stream audit source changed or hash mismatch: %s", input.pin.Path)
		}
	}
	for _, input := range []struct {
		path   string
		data   []byte
		limit  int64
		before os.FileInfo
	}{{profilePath, profileData, 1 << 20, profileInfo}, {glyphInput.Path, glyphData, glyphInput.Size, glyphInfo}} {
		current, err := readInput(input.path, input.limit)
		after, statErr := os.Stat(input.path)
		if err != nil || statErr != nil || !bytes.Equal(current, input.data) || !os.SameFile(input.before, after) || input.before.ModTime() != after.ModTime() {
			return fmt.Errorf("stream audit input changed: %s", input.path)
		}
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return err
	}
	if encoded.Len() > 64<<20 {
		return fmt.Errorf("stream audit JSON exceeds 64 MiB")
	}
	_, err = io.Copy(stdout, &encoded)
	return err
}
