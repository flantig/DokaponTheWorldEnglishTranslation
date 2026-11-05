package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"unicode/utf8"
)

// previewFit reports new wording against declared native pen limits without planning edits.
// Exact LINE constraints preserve menu separators and cannot be combined with wrapping.
// Unsupported scale/position/substitution remains unknown; a report never authorizes a patch.
func previewFit(sourcePath, registryPath, glyphPath, profilePath string, stdout io.Writer) error {
	inputs := []struct {
		path  string
		limit int64
		data  []byte
	}{{profilePath, 1 << 20, nil}, {registryPath, 64 << 20, nil}, {glyphPath, 4 << 20, nil}}
	for i := range inputs {
		data, err := readInput(inputs[i].path, inputs[i].limit)
		if err != nil {
			return err
		}
		if !utf8.Valid(data) {
			return fmt.Errorf("fit input must be UTF-8: %s", inputs[i].path)
		}
		inputs[i].data = data
	}
	if err := checkJSON(checkedJSON{raw: inputs[0].data, allObjects: true, aliasesByDepth: map[int][]string{3: {"required_line_breaks"}}}); err != nil {
		return fmt.Errorf("fit profile: %w", err)
	}
	var profile FitProfile
	decoder := json.NewDecoder(bytes.NewReader(inputs[0].data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return fmt.Errorf("fit profile: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("fit profile must contain one JSON object")
	}
	if profile.SourceSize < 12 || len(profile.Entries) < 1 || len(profile.Entries) > 4096 || len(profile.Boxes) < 1 || profile.Font.Columns != 0 || profile.Font.Rows != 0 {
		return fmt.Errorf("fit requires source font facts, explicit entries and consumer boxes without character budgets")
	}
	for _, pin := range []string{profile.SourceSHA256, profile.GlyphmapSHA256} {
		decoded, err := hex.DecodeString(pin)
		if err != nil || len(decoded) != sha256.Size {
			return fmt.Errorf("invalid fit SHA-256 pin")
		}
	}
	if fmt.Sprintf("%x", sha256.Sum256(inputs[2].data)) != profile.GlyphmapSHA256 {
		return fmt.Errorf("fit glyphmap hash mismatch")
	}
	for name, box := range profile.Boxes {
		if name == "" || box.MaxWidth < 1 || box.MaxWidth > 1<<24 || box.MaxLines < 1 || box.MaxLines > maxStreamBytes/2 || box.Evidence == "" || box.MaxBytes != 0 && (box.MaxBytes < 2 || box.MaxBytes > maxStreamBytes || box.MaxBytes%2 != 0) {
			return fmt.Errorf("invalid fit consumer box %q", name)
		}
		if box.RequiredLineBreaks != nil && (*box.RequiredLineBreaks < 0 || *box.RequiredLineBreaks >= maxStreamBytes/2 || box.Wrap) {
			return fmt.Errorf("fit consumer box %q requires a LINE count in [0, %d) without wrapping", name, maxStreamBytes/2)
		}
	}
	var registry Registry
	if err := json.Unmarshal(inputs[1].data, &registry); err != nil || registry.Entries == nil {
		return fmt.Errorf("fit registry must contain an entries array")
	}
	byID := make(map[uint64]RegistryEntry)
	for _, entry := range registry.Entries {
		id, err := number(entry.ID)
		if _, duplicate := byID[id]; err != nil || duplicate {
			return fmt.Errorf("invalid or duplicate fit registry ID %q", entry.ID)
		}
		byID[id] = entry
	}
	ids, seen := make([]string, 0, len(profile.Entries)), make(map[uint64]bool)
	for text, selection := range profile.Entries {
		id, err := number(text)
		_, exists := byID[id]
		if err != nil || seen[id] || !exists || profile.Boxes[selection.Box].Evidence == "" {
			return fmt.Errorf("invalid, duplicate or missing fit entry/profile %q", text)
		}
		if (selection.Authoring != "") != (selection.Source != nil) || selection.Authoring != "" && selection.Authoring != "markers" && selection.Authoring != "plain" && selection.Authoring != "ordered" {
			return fmt.Errorf("%s: fit source range and markers/plain/ordered authoring must be supplied together", text)
		}
		if selection.Source != nil {
			start, startErr := number(selection.Source.Start)
			end, endErr := number(selection.Source.End)
			if startErr != nil || endErr != nil || start%2 != 0 || end%2 != 0 || end <= start || end-start > maxStreamBytes {
				return fmt.Errorf("%s: fit source needs an aligned bounded ELF-relative range", text)
			}
		}
		seen[id], ids = true, append(ids, text)
	}
	sort.Slice(ids, func(i, j int) bool { a, _ := number(ids[i]); b, _ := number(ids[j]); return a < b })
	glyphs, forwardGlyphs, err := glyphMaps(inputs[2].data, true)
	if err != nil || len(glyphs) == 0 {
		return fmt.Errorf("invalid fit glyph map: %v", err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	before, err := source.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() != profile.SourceSize {
		return fmt.Errorf("fit source size/type mismatch")
	}
	extent := fileSpan{size: profile.SourceSize}
	if profile.ISOFile != "" {
		extent, err = isoFileExtent(source, profile.SourceSize, profile.ISOFile)
		if err != nil {
			return err
		}
	}
	if extent.size < 12 || extent.size > 64<<20 {
		return fmt.Errorf("fit native font source must be a bounded ELF")
	}
	elf := io.NewSectionReader(source, extent.offset, extent.size)
	for text, selection := range profile.Entries {
		if selection.Source != nil {
			end, _ := number(selection.Source.End)
			if end > uint64(extent.size) {
				return fmt.Errorf("%s: fit source range exceeds selected ELF extent", text)
			}
		}
	}
	native, err := inspect(elf, nil, &Recipes{Operation: "font_metrics", SourceSize: extent.size, ELFVMADelta: profile.ELFVMADelta, Layout: &profile.Font})
	if err != nil {
		return err
	}
	report := FitReport{Operation: "text_fit", SourceSHA256: profile.SourceSHA256,
		RegistrySHA256: fmt.Sprintf("%x", sha256.Sum256(inputs[1].data)), GlyphmapSHA256: profile.GlyphmapSHA256,
		ProfileSHA256: fmt.Sprintf("%x", sha256.Sum256(inputs[0].data)), Measurement: "native_pen_advances",
		Limits: "Read-only measurements against declared consumer limits. No visual ink/scale/position, source-control, reference or patch approval. Unsupported semantics remain unknown.", Boxes: profile.Boxes, Entries: []FitRow{}}
	for _, text := range ids {
		id, _ := number(text)
		selection := profile.Entries[text]
		box := profile.Boxes[selection.Box]
		row := FitRow{ID: text, Box: selection.Box, English: byID[id].EN, Status: "unsupported"}
		var encoded []byte
		if len(row.English) > maxStreamBytes*4 {
			err = fmt.Errorf("wording exceeds authoring byte limit")
		} else {
			options := TextEncodeOptions{Terminated: true, SourceAuthoring: selection.Authoring}
			if selection.Source != nil {
				start, _ := number(selection.Source.Start)
				end, _ := number(selection.Source.End)
				data := make([]byte, int(end-start))
				if _, err := elf.ReadAt(data, int64(start)); err != nil {
					return fmt.Errorf("%s: fit source read: %w", text, err)
				}
				shape, decodeErr := controls(data, TextScanOptions{Decode: true, Glyphs: forwardGlyphs, English: &row.English})
				if decodeErr != nil || shape.Tokens[len(shape.Tokens)-1].Offset+2 != len(data) {
					row.Diagnostics = []string{fmt.Sprintf("source grammar or physical END differs: %v", decodeErr)}
					report.Entries = append(report.Entries, row)
					continue
				}
				options.Source = &shape
			}
			if box.Wrap {
				options.NativeWidth, options.Rows, options.Advances = box.MaxWidth, box.MaxLines, native.Advances
				options.NumericBounds = selection.NumericBounds
				if !box.AllowPages {
					// Keep all wrapped lines on the original page; validation reports excess height.
					options.Rows = maxStreamBytes
				}
			}
			encoded, err = encode(row.English, nil, glyphs, options)
		}
		if err != nil || len(encoded) > maxStreamBytes {
			row.Diagnostics = []string{fmt.Sprintf("encoding unavailable or too large: %v", err)}
			report.Entries = append(report.Entries, row)
			continue
		}
		row.EncodedHex, row.EncodedSHA256, row.Bytes = hex.EncodeToString(encoded), fmt.Sprintf("%x", sha256.Sum256(encoded)), len(encoded)
		shape, err := controls(encoded, TextScanOptions{Terminated: true, Advances: native.Advances, NumericBounds: selection.NumericBounds})
		if err != nil {
			row.Diagnostics = []string{err.Error()}
			report.Entries = append(report.Entries, row)
			continue
		}
		row.Width, row.Lines, row.LineWidths, row.Status = shape.Width, shape.Lines, shape.LineWidths, "within_profile"
		if shape.Width > box.MaxWidth {
			row.Diagnostics = append(row.Diagnostics, fmt.Sprintf("line width %d exceeds %d", shape.Width, box.MaxWidth))
		}
		if shape.Lines > box.MaxLines {
			row.Diagnostics = append(row.Diagnostics, fmt.Sprintf("page lines %d exceed %d", shape.Lines, box.MaxLines))
		}
		if shape.Pages && !box.AllowPages {
			row.Diagnostics = append(row.Diagnostics, "PAGE is not permitted by this consumer profile")
		}
		if box.MaxBytes != 0 && len(encoded) > box.MaxBytes {
			row.Diagnostics = append(row.Diagnostics, fmt.Sprintf("encoded bytes %d exceed copy limit %d", len(encoded), box.MaxBytes))
		}
		lineCountMismatch := false
		if box.RequiredLineBreaks != nil {
			lineBreaks := 0
			for _, page := range shape.LineWidths {
				lineBreaks += len(page) - 1
			}
			row.LineBreaks = &lineBreaks
			lineCountMismatch = lineBreaks != *box.RequiredLineBreaks
			if lineCountMismatch {
				row.Diagnostics = append(row.Diagnostics, fmt.Sprintf("LINE count %d must equal %d", lineBreaks, *box.RequiredLineBreaks))
			}
		}
		switch {
		case lineCountMismatch:
			row.Status = "row_count_mismatch"
		case len(row.Diagnostics) != 0:
			row.Status = "overflow"
		}
		report.Entries = append(report.Entries, row)
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, source); err != nil {
		return err
	}
	if after, err := source.Stat(); err != nil || after.Size() != before.Size() || after.ModTime() != before.ModTime() || fmt.Sprintf("%x", hash.Sum(nil)) != profile.SourceSHA256 {
		return fmt.Errorf("fit source changed or hash mismatch")
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(report)
}
