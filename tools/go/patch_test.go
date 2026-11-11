package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io"
	"io/fs"
	"maps"
	"math"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const assetManifestFixtureSHA = "731f163716b6d016521c92647bca72d9c2482b201f3ecad644577f7551110a97"

// SHA-256 of fixture IDs, landing VMAs, site counts and sorted pointer VMAs.
const placedPointerScope = "7d77255083cdafb7a27525d573a4379f12fb01de2d8ee826ff6080f0dd63334c"

func fixture(t *testing.T, operation string) (Recipes, Registry, []byte, []byte) {
	t.Helper()
	glyphs := []byte(`{"1":"A","2":"B","3":"C","4":"あ"}`)
	image := bytes.Repeat([]byte{0xcc}, 64)
	copy(image[16:], []byte{4, 0, 0, 0xf8})
	recipes := Recipes{
		Operation: "same_length_stream", SourceSize: int64(len(image)),
		SourceSHA256:   fmt.Sprintf("%x", sha256.Sum256(image)),
		GlyphmapSHA256: fmt.Sprintf("%x", sha256.Sum256(glyphs)),
		ISOELFOffset:   "0x0", ELFVMADelta: "0x0",
		Entries: map[string]Recipe{"0x10": {ExpectedHex: "040000f8", Evidence: "synthetic bounded field"}},
	}
	var registry Registry
	if err := json.Unmarshal([]byte(`{"entries":[{"id":"0x10","en":"A"}]}`), &registry); err != nil {
		t.Fatal(err)
	}
	if operation == "guarded_words" || operation == "guarded_words_reverse" {
		recipes.Operation, recipes.Evidence = "guarded_words", "synthetic documented word block"
		recipes.Values = map[string]string{"allocation": "0x12345678"}
		recipes.Entries = map[string]Recipe{"0x20": {
			ExpectedHex: "cccccccccccccccc",
			Words:       []Word{{Hex: "0x3c050000", Assembly: "lui $a1, hi(allocation)"}, {Hex: "0x34a50000", Assembly: "ori $a1, $a1, lo(allocation)"}},
			Fixups:      map[string]WordFixup{"0x0": {Value: "allocation", Shift: 16, Bits: 16}, "0x4": {Value: "allocation", Bits: 16}},
		}}
		registry.Entries = nil
		if operation == "guarded_words_reverse" {
			recipes.OutputSHA256 = recipes.SourceSHA256
			copy(image[32:40], []byte{0x34, 0x12, 5, 0x3c, 0x78, 0x56, 0xa5, 0x34})
			recipes.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
			recipes.Values = nil
			recipes.Entries = map[string]Recipe{"0x20": {
				ExpectedHex: "3412053c7856a534",
				Words:       []Word{{Hex: "0xcccccccc", Assembly: ".word original fixture bytes"}, {Hex: "0xcccccccc", Assembly: ".word original fixture bytes"}},
			}}
		}
	}
	if operation == "stream_slot" {
		recipes.Operation = operation
		old := []byte{0, 0x28, 1, 0, 1, 0, 0, 8, 2, 0, 2, 0, 0, 0x10, 0, 0xf8}
		target := []byte{0, 0x28, 1, 0, 0, 8, 2, 0, 0, 0x10, 0, 0xf8}
		copy(image[16:32], old)
		recipes.Entries["0x10"] = Recipe{ExpectedHex: hex.EncodeToString(old), EncodedSHA256: fmt.Sprintf("%x", sha256.Sum256(target)), Evidence: "synthetic full owned slot; no native extent or fit claim"}
		registry.Entries[0].EN = "<2800>A|B//"
		registry.Entries[0].JP = json.RawMessage(`"<2800>AA|BB//"`)
		recipes.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
	}
	if operation == "stream_append" || operation == "stream_source" || operation == "stream_read" || strings.HasPrefix(operation, "stream_reflow") || operation == "stream_grow" || operation == "stream_allocate" || strings.HasPrefix(operation, "stream_derived") {
		image = make([]byte, 8192)
		recipes.Operation, recipes.Evidence = "stream_append", "synthetic initialized profile; no emulator claim"
		recipes.ISOELFOffset = "0x800"
		recipes.Stream = &Stream{
			RetailELFSize: 0x310, ELFRecordOffset: "0x100", ZeroRecordOffset: "0x140", ZeroEnd: "0x2000",
			LoaderVMAs: []string{"0x10", "0x14", "0x18", "0x1c"}, WindowLUIVMAs: []string{"0x20", "0x24"},
			WindowSRLWords:  map[string]string{"0x28": "0x00084ac2", "0x2c": "0x00084ac2", "0x30": "0x00084ac2", "0x34": "0x00084ac2", "0x38": "0x00084ac2", "0x3c": "0x00084ac2", "0x40": "0x00084ac2"},
			AllowedPointers: []AddressRange{{Start: "0x200", End: "0x20c"}}, AllowedLandings: []AddressRange{{Start: "0x04000000", End: "0x04000800"}},
		}
		for _, record := range []struct{ offset, lba, size int }{{0x100, 1, 4096}, {0x140, 3, 2048}} {
			image[record.offset] = 34
			binary.LittleEndian.PutUint32(image[record.offset+2:], uint32(record.lba))
			binary.BigEndian.PutUint32(image[record.offset+6:], uint32(record.lba))
			binary.LittleEndian.PutUint32(image[record.offset+10:], uint32(record.size))
			binary.BigEndian.PutUint32(image[record.offset+14:], uint32(record.size))
		}
		for vma, word := range map[int]uint32{0x10: 0x3c050000, 0x14: 0x34a50800, 0x18: 0x240e0001, 0x1c: 0x240e0001, 0x20: 0x3c090001, 0x24: 0x3c090001, 0x28: 0x00084ac2, 0x2c: 0x00084ac2, 0x30: 0x00084ac2, 0x34: 0x00084ac2, 0x38: 0x00084ac2, 0x3c: 0x00084ac2, 0x40: 0x00084ac2, 0x200: 0x100, 0x204: 0x100, 0x208: 0x110} {
			binary.LittleEndian.PutUint32(image[0x800+vma:], word)
		}
		for _, vma := range []int{0x100, 0x110} {
			copy(image[0x800+vma:], []byte{4, 0, 0, 0xf8})
		}
		// The old blob contains a registry-ID-shaped word; discovery must exclude it.
		copy(image[0x1000:], []byte{0, 1, 0, 0, 0, 0xf8})
		recipes.Entries = map[string]Recipe{"0x110": {ExpectedHex: "040000f8"}, "0x100": {ExpectedHex: "040000f8"}}
		if err := json.Unmarshal([]byte(`{"entries":[{"id":"0x100","en":"AB","ref_type":"pointer_array","ref_sites":[{"pointer_vma":"0x204"},{"pointer_vma":"0x200"}]},{"id":"0x110","en":"C","ref_type":"pointer_array","ref_sites":[{"pointer_vma":"0x208"}]}]}`), &registry); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(operation, "stream_reflow") || strings.HasPrefix(operation, "stream_derived_context") {
			image = append(image, make([]byte, 4096)...)
			copy(image[0x2000:0x2800], image[0x1000:0x1800])
			clear(image[0xb10:0x2000])
			recipes.Stream.RetailELFSize, recipes.Stream.ZeroEnd = 0x13a0, "0x3000"
			recipes.Layout = &Layout{FontTableVMA: "0x400", UnflooredGlyphVMA: "0x74", UnflooredGlyph: "0x1b"}
			binary.LittleEndian.PutUint16(image[0x874:], 0x1b)
			recipes.Layout.SpaceWords = make(map[string]string)
			for i := 0; i < 8; i++ {
				vma := 0x50 + i*4
				word := uint32(0x3c024160)
				if i >= 6 {
					word = 0x3c034160
				}
				recipes.Layout.SpaceWords[fmt.Sprintf("0x%x", vma)] = fmt.Sprintf("0x%x", word)
				binary.LittleEndian.PutUint32(image[0x800+vma:], word)
			}
			for page := 0; page < 3; page++ {
				binary.LittleEndian.PutUint32(image[0xc00+page*4:], uint32(0x410+page*441*3))
			}
			for glyph := 0; glyph < 3*441; glyph++ {
				image[0xc10+glyph*3+1] = 7
			}
			image[0xc13], image[0xc14], image[0xc17] = 9, 10, 25
			image[0xc10+442*3], image[0xc10+442*3+1] = 255, 0
			image[0xc10+883*3], image[0xc10+883*3+1] = 2, 4
			binary.LittleEndian.PutUint32(image[0x10a:], 8192)
			binary.BigEndian.PutUint32(image[0x10e:], 8192)
			binary.LittleEndian.PutUint32(image[0x142:], 5)
			binary.BigEndian.PutUint32(image[0x146:], 5)
			entry := recipes.Entries["0x100"]
			entry.ExpectedHex = "040004000008040000f8"
			recipes.Entries["0x100"] = entry
			copy(image[0x900:], []byte{4, 0, 4, 0, 0, 8, 4, 0, 0, 0xf8})
		}
		if operation == "stream_reflow_format" || operation == "stream_reflow_numeric" {
			recipes.SourceContext = true
			recipes.Layout.Columns, recipes.Layout.Rows = 1, 2
			registry.Entries[0].EN = "A B"
			first := []byte{1, 0, 0, 8, 2, 0, 0, 0xf8}
			if operation == "stream_reflow_numeric" {
				recipes.Layout.Rows = 3
				registry.Entries[0].EN = "A {{PARAM:0x7000}} B"
				row := recipes.Entries["0x100"]
				row.ExpectedHex, row.NumericBounds, row.MaxLines, row.MaxWidth = "04000070040000f8", []*NumericRange{{Min: 1, Max: 10}}, 3, 100
				recipes.Entries["0x100"] = row
				copy(image[0x900:], []byte{4, 0, 0, 0x70, 4, 0, 0, 0xf8})
				first = []byte{1, 0, 0, 8, 0, 0x70, 0, 8, 2, 0, 0, 0xf8}
			}
			for id, encoded := range map[string][]byte{"0x100": first, "0x110": {3, 0, 0, 0xf8}} {
				row := recipes.Entries[id]
				row.MaxNewBytes, row.EncodedSHA256 = len(encoded), fmt.Sprintf("%x", sha256.Sum256(encoded))
				recipes.Entries[id] = row
			}
		}
		if operation == "stream_reflow_labels" {
			row := recipes.Entries["0x100"]
			row.ExpectedHex, row.LabelRuns = "00b800b0040000d800a0f6b8040000f8", 2
			old, err := hex.DecodeString(row.ExpectedHex)
			if err != nil {
				t.Fatal(err)
			}
			copy(image[0x900:], old)
			encoded := []byte{0, 0xb8, 0, 0xb0, 1, 0, 2, 0, 0, 0xd8, 0, 0xa0, 0xf6, 0xb8, 3, 0, 0, 0xf8}
			row.MaxNewBytes, row.EncodedSHA256 = len(encoded), fmt.Sprintf("%x", sha256.Sum256(encoded))
			recipes.Entries["0x100"], registry.Entries[0].EN = row, "AB / C"
		}
		if operation == "stream_reflow_bound" || operation == "stream_reflow_pin" || operation == "stream_reflow_byte_limit" {
			row := recipes.Entries["0x100"]
			row.MaxNewBytes = 6
			if operation != "stream_reflow_byte_limit" {
				row.EncodedSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte{1, 0, 2, 0, 0, 0xf8}))
			}
			if operation == "stream_reflow_bound" {
				row.ExpectedHex, row.MaxWidth = "040000f8", 41
				copy(image[0x900:], []byte{4, 0, 0, 0xf8})
			}
			recipes.Entries["0x100"] = row
		}
		if operation == "stream_grow" || operation == "stream_allocate" {
			old := image
			image = make([]byte, 0x20000)
			copy(image[0x10000:], old[0x800:])
			copy(image[0x11000:0x12000], bytes.Repeat([]byte{0xcc}, 4096))
			recipes.Operation, recipes.ISOELFOffset, recipes.Entries = "stream_grow", "0x10000", nil
			recipes.Growth = &Growth{FromSectors: 1, ToSectors: 3, LoaderRange: AddressRange{Start: "0x10", End: "0x44"}}
			recipes.Stream.ELFRecordOffset, recipes.Stream.ZeroRecordOffset, recipes.Stream.ZeroEnd = "0x8844", "0x8872", "0x20000"
			copy(image[0x8000:], []byte{1, 'C', 'D', '0', '0', '1', 1})
			binary.LittleEndian.PutUint32(image[0x8050:], 64)
			binary.BigEndian.PutUint32(image[0x8054:], 64)
			binary.LittleEndian.PutUint16(image[0x8080:], 2048)
			binary.BigEndian.PutUint16(image[0x8082:], 2048)
			binary.LittleEndian.PutUint32(image[0x8084:], 10)
			binary.BigEndian.PutUint32(image[0x8088:], 10)
			binary.LittleEndian.PutUint32(image[0x808c:], 20)
			binary.BigEndian.PutUint32(image[0x8094:], 21)
			copy(image[0xa000:], []byte{1, 0, 17, 0, 0, 0, 1, 0, 0, 0})
			copy(image[0xa800:], []byte{1, 0, 0, 0, 0, 17, 0, 1, 0, 0})
			for _, record := range []struct {
				offset, lba, size int
				name              string
				directory         bool
			}{{0x809c, 17, 2048, "\x00", true}, {0x8800, 17, 2048, "\x00", true}, {0x8822, 17, 2048, "\x01", true}, {0x8844, 32, 4096, "SLPM_657.50;1", false}, {0x8872, 34, 0xf000, "ZERO.BIN;1", false}, {0x889e, 18, 2048, "SUB", true}, {0x9000, 18, 2048, "\x00", true}, {0x9022, 17, 2048, "\x01", true}, {0x9044, 19, 2048, "OTHER;1", false}} {
				o := record.offset
				image[o] = byte(33 + len(record.name) + (1 - len(record.name)%2))
				binary.LittleEndian.PutUint32(image[o+2:], uint32(record.lba))
				binary.BigEndian.PutUint32(image[o+6:], uint32(record.lba))
				binary.LittleEndian.PutUint32(image[o+10:], uint32(record.size))
				binary.BigEndian.PutUint32(image[o+14:], uint32(record.size))
				image[o+28], image[o+31], image[o+32] = 1, 1, byte(len(record.name))
				if record.directory {
					image[o+25] = 2
				}
				copy(image[o+33:], record.name)
			}
		}
		if operation == "stream_allocate" {
			recipes.Operation = operation
			recipes.Growth = &Growth{ToSectors: 3}
			recipes.Stream.LoaderVMAs, recipes.Stream.WindowLUIVMAs, recipes.Stream.WindowSRLWords = nil, nil, nil
			recipes.Stream.AllowedPointers, recipes.Stream.AllowedLandings = nil, nil
			for offset, value := range map[int]uint32{0x884e: 0x310, 0x8874: 33, 0x887c: 0xf800} {
				binary.LittleEndian.PutUint32(image[offset:], value)
				binary.BigEndian.PutUint32(image[offset+4:], value)
			}
			copy(image[0x10800:0x12000], bytes.Repeat([]byte{0xcc}, 0x1800))
		}
		if operation == "stream_source" || operation == "stream_read" {
			row := recipes.Entries["0x100"]
			row.MaxNewBytes, row.ReadBytes = 18, 18
			registry.Entries[0].EN = "AAAAAAA"
			if operation == "stream_source" {
				row.SourcePointer = "0x04000000"
				copy(image[0x1000:], []byte{4, 0, 0, 0xf8, 0, 0})
				copy(image[0x900:0x910], bytes.Repeat([]byte{0xcc}, 16))
				binary.LittleEndian.PutUint32(image[0xa00:], 0x04000000)
				binary.LittleEndian.PutUint32(image[0xa04:], 0x04000000)
				registry.Entries[0].RefType = "struct_table_field"
				for i := range registry.Entries[0].RefSites {
					site := &registry.Entries[0].RefSites[i]
					vma, _ := number(site.PointerVMA)
					site.StructVMA, site.FieldOffset = "0x1f0", fmt.Sprintf("0x%x", vma-0x1f0)
				}
			}
			recipes.Entries["0x100"] = row
		}
		if strings.HasPrefix(operation, "stream_derived") {
			for id := range recipes.Entries {
				recipes.Entries[id] = Recipe{}
			}
			if operation == "stream_derived_header" {
				copy(image[0x900:], []byte{0, 0x28, 4, 0, 0, 0xf8})
			}
			if strings.HasPrefix(operation, "stream_derived_context") {
				recipes.SourceContext = true
				copy(image[0x900:], []byte{0, 0x28, 0x98, 0x39, 4, 0, 4, 0, 4, 0, 4, 0, 0, 0x10, 0, 0xf8})
				if operation == "stream_derived_context_explicit" {
					recipes.Entries["0x100"] = Recipe{ExpectedHex: "002898390400040004000400001000f8"}
				}
			}
		}
		recipes.SourceSize = int64(len(image))
		recipes.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
	}
	return recipes, registry, glyphs, image
}

func TestPlanAndCopy(t *testing.T) {
	{
		profile, registry, glyphs, image := fixture(t, "stream_reflow_format")
		baseline, err := plan([]Recipes{profile}, registry, glyphs, bytes.NewReader(image))
		if err != nil {
			t.Fatal(err)
		}
		for id, row := range profile.Entries {
			row.Authoring = "ordered"
			profile.Entries[id] = row
		}
		edits, err := plan([]Recipes{profile}, registry, glyphs, bytes.NewReader(image))
		if err != nil || !reflect.DeepEqual(edits, baseline) {
			t.Fatal("ordered measurable plan changed the complete reviewed edit list", err)
		}
		dir := t.TempDir()
		sourcePath, outputPath := filepath.Join(dir, "source.iso"), filepath.Join(dir, "ordered.iso")
		if err := os.WriteFile(sourcePath, image, 0600); err != nil {
			t.Fatal(err)
		}
		source, err := os.Open(sourcePath)
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		if _, err := patchCopy(source, outputPath, []Recipes{profile}, edits, registry, glyphs); err != nil {
			t.Fatal("ordered guarded copy", err)
		}
		want := bytes.Clone(image)
		for _, edit := range baseline {
			copy(want[edit.Offset:], edit.New)
		}
		got, err := os.ReadFile(outputPath)
		preserved, sourceErr := os.ReadFile(sourcePath)
		if err != nil || sourceErr != nil || !bytes.Equal(got, want) || !bytes.Equal(preserved, image) {
			t.Fatal("ordered copy changed bytes outside the reviewed edits or its source", err, sourceErr)
		}
	}
	// A typed slot and code words share one source-bound transaction in either direction.
	for _, reverse := range []bool{false, true} {
		for _, wordsFirst := range []bool{false, true} {
			slot, registry, glyphs, original := fixture(t, "stream_slot")
			target := bytes.Clone(original)
			copy(target[16:32], []byte{0, 0x28, 1, 0, 0, 8, 2, 0, 0, 0x10, 0, 0xf8, 0, 0, 0, 0})
			clear(target[40:44])
			words := slot
			words.Operation = "guarded_words"
			words.Entries = map[string]Recipe{"0x28": {ExpectedHex: "cccccccc", Evidence: "independent code restoration", Words: []Word{{Hex: "0x0", Assembly: "nop"}}}}
			input, want := original, target
			if reverse {
				input, want = target, original
				slot.WordingField = "jp"
				row := slot.Entries["0x10"]
				row.ExpectedHex = hex.EncodeToString(target[16:32])
				row.EncodedSHA256 = fmt.Sprintf("%x", sha256.Sum256(original[16:32]))
				slot.Entries["0x10"] = row
				words.Entries["0x28"] = Recipe{ExpectedHex: "00000000", Evidence: "independently stated predecessor code bytes", Words: []Word{{Hex: "0xcccccccc", Assembly: ".word original fixture bytes"}}}
			}
			slot.SourceSHA256, slot.OutputSHA256 = fmt.Sprintf("%x", sha256.Sum256(input)), fmt.Sprintf("%x", sha256.Sum256(want))
			words.SourceSHA256, words.OutputSHA256 = slot.SourceSHA256, slot.OutputSHA256
			tables := []Recipes{slot, words}
			if wordsFirst {
				tables[0], tables[1] = tables[1], tables[0]
			}
			edits, err := plan(tables, registry, glyphs, bytes.NewReader(input))
			if err != nil || len(edits) != 2 || edits[0].Operation != "stream_slot" || len(edits[0].New) != 16 {
				t.Fatalf("mixed slot reverse=%v wordsFirst=%v: %v", reverse, wordsFirst, err)
			}
			dir := t.TempDir()
			sourcePath, output := filepath.Join(dir, "source.bin"), filepath.Join(dir, "output.bin")
			if err := os.WriteFile(sourcePath, input, 0600); err != nil {
				t.Fatal(err)
			}
			source, err := os.Open(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			digest, err := patchCopy(source, output, tables, edits, registry, glyphs)
			if err != nil || digest != slot.OutputSHA256 {
				t.Fatalf("mixed slot copy reverse=%v wordsFirst=%v: %v", reverse, wordsFirst, err)
			}
			got, err := os.ReadFile(output)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("mixed slot changed outside its full expected image", err)
			}
			for _, mutation := range []string{"first missing", "last missing", "conflict", "late target mismatch"} {
				bad := slices.Clone(tables)
				switch mutation {
				case "first missing":
					bad[0].OutputSHA256 = ""
				case "last missing":
					bad[1].OutputSHA256 = ""
				case "conflict":
					bad[1].OutputSHA256 = strings.Repeat("0", 64)
				case "late target mismatch":
					for i := range bad {
						bad[i].OutputSHA256 = strings.Repeat("0", 64)
					}
				}
				refused := filepath.Join(dir, mutation+".bin")
				if _, err := patchCopy(source, refused, bad, edits, registry, glyphs); err == nil {
					t.Fatalf("mixed slot accepted %s", mutation)
				}
				if _, err := os.Stat(refused); !os.IsNotExist(err) {
					t.Fatal("failed mixed slot retained output", err)
				}
			}
			got, err = os.ReadFile(sourcePath)
			if err != nil || !bytes.Equal(got, input) {
				t.Fatal("mixed slot changed source", err)
			}
		}
	}
	{
		r, registry, glyphs, source := fixture(t, "stream_reflow")
		// The native comma bypasses the floor: source6 cannot admit replacement13.
		source[0xc10+27*3], source[0xc10+27*3+1] = 2, 3
		copy(source[0x900:], []byte{27, 0, 0, 0xf8})
		row := r.Entries["0x100"]
		row.ExpectedHex = "1b0000f8"
		r.Entries["0x100"] = row
		registry.Entries[0].EN = "A"
		r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(source))
		state, err := inspect(bytes.NewReader(source), nil, &r)
		if err != nil || state.Advances[27] != 6 || state.Advances[1] != 13 || state.Advances[0] != 14 {
			t.Fatal("native exception or ordinary/SPACE advances differ", err)
		}
		if _, err := plan([]Recipes{r}, registry, glyphs, bytes.NewReader(source)); err == nil || !strings.Contains(err.Error(), "reflow exceeds reviewed width/height") {
			t.Fatal("relative width admitted a wider replacement", err)
		}
		// A relocated source fact can name another glyph; no comma is hardcoded.
		r.Layout.UnflooredGlyphVMA, r.Layout.UnflooredGlyph = "0x76", "0x373"
		binary.LittleEndian.PutUint16(source[0x876:], 883)
		state, err = inspect(bytes.NewReader(source), nil, &r)
		if err != nil || state.Advances[883] != 7 || state.Advances[27] != 20 || state.Advances[0] != 14 {
			t.Fatal("source-defined advance exception was not honored", err)
		}
	}
	{
		r, registry, glyphs, image := fixture(t, "stream_source")
		clear(image[0x1000:0x1800])
		copy(image[0x1020:], []byte{4, 0, 0, 0xf8})
		copy(image[0x920:], []byte{4, 0, 0, 0xf8})
		binary.LittleEndian.PutUint32(image[0xa00:], 0x04000020)
		binary.LittleEndian.PutUint32(image[0xa04:], 0x04000020)
		binary.LittleEndian.PutUint32(image[0xa0c:], 0x120)
		entry := registry.Entries[1]
		entry.ID = "0x120"
		entry.RefSites = slices.Clone(entry.RefSites)
		entry.RefSites[0].PointerVMA = "0x20c"
		registry.Entries = append(registry.Entries, entry)
		r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
		first, reader, last := r, r, r
		first.Entries = map[string]Recipe{"0x110": r.Entries["0x110"]}
		row := r.Entries["0x100"]
		row.SourcePointer, row.ReadBytes = "0x04000020", 64
		reader.Entries = map[string]Recipe{"0x100": row}
		last.Entries = map[string]Recipe{"0x120": r.Entries["0x110"]}
		for _, scope := range []struct {
			table      *Recipes
			start, end string
		}{
			{&first, "0x208", "0x20c"},
			{&reader, "0x200", "0x208"},
			{&last, "0x20c", "0x210"},
		} {
			profile := *r.Stream
			profile.AllowedPointers = []AddressRange{{Start: scope.start, End: scope.end}}
			scope.table.Stream = &profile
		}
		tables := []Recipes{first, reader, last}
		before := bytes.Clone(image)
		edits, err := plan(tables, registry, glyphs, bytes.NewReader(image))
		if err != nil || len(edits) != 8 {
			t.Fatalf("cross-table read reservation: %v", err)
		}
		want := bytes.Clone(image)
		for offset, target := range map[int]uint32{0xa00: 0x04000070, 0xa04: 0x04000070, 0xa08: 0x04000060, 0xa0c: 0x040000c0} {
			binary.LittleEndian.PutUint32(want[offset:], target)
		}
		copy(want[0x1060:], []byte{3, 0, 0, 0xf8})
		copy(want[0x1070:], []byte{1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0xf8})
		copy(want[0x10be:], []byte{0, 0xf8})
		copy(want[0x10c0:], []byte{3, 0, 0, 0xf8})
		dir := t.TempDir()
		path, output := filepath.Join(dir, "source.iso"), filepath.Join(dir, "reservations.iso")
		if err := os.WriteFile(path, image, 0600); err != nil {
			t.Fatal(err)
		}
		source, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		digest, err := patchCopy(source, output, tables, edits, registry, glyphs)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := os.ReadFile(output)
		if err != nil || !bytes.Equal(actual, want) || digest != fmt.Sprintf("%x", sha256.Sum256(want)) {
			t.Fatalf("old read span/new bookend/next allocation lifetime: %v", err)
		}
		for i := range tables {
			tables[i].SourceSHA256 = digest
		}
		done, err := plan(tables, registry, glyphs, bytes.NewReader(actual))
		if err != nil || len(done) != 5 {
			t.Fatalf("completed reservation composition: %v", err)
		}
		for _, edit := range done {
			if !bytes.Equal(edit.Old, edit.New) || edit.Operation != "stream_pointer" && edit.Operation != "stream_padding" {
				t.Fatal("completed reservation moved or reallocated data")
			}
		}
		original, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(original, before) {
			t.Fatal("reservation composition changed source")
		}
	}
	for _, numericFirst := range []bool{false, true} {
		r, registry, glyphs, image := fixture(t, "stream_reflow_numeric")
		literal, numeric := r, r
		numeric.Entries = map[string]Recipe{"0x100": r.Entries["0x100"]}
		literal.Entries = map[string]Recipe{"0x110": r.Entries["0x110"]}
		literal.SourceContext = false
		layout := *r.Layout
		layout.Columns, layout.Rows = 0, 0
		literal.Layout = &layout
		registry.Entries[1].EN = "C  C"
		literalBytes := []byte{3, 0, 0, 0, 0, 0, 3, 0, 0, 0xf8}
		row := literal.Entries["0x110"]
		row.MaxNewBytes, row.MaxWidth, row.EncodedSHA256 = len(literalBytes), 100, fmt.Sprintf("%x", sha256.Sum256(literalBytes))
		literal.Entries["0x110"] = row
		literalTarget, numericTarget := uint32(0x04000010), uint32(0x04000020)
		if numericFirst {
			literalTarget, numericTarget = numericTarget, literalTarget
		}
		literalProfile, numericProfile := *r.Stream, *r.Stream
		literalProfile.AllowedPointers = []AddressRange{{Start: "0x208", End: "0x20c"}}
		numericProfile.AllowedPointers = []AddressRange{{Start: "0x200", End: "0x208"}}
		literalProfile.AllowedLandings = []AddressRange{{Start: fmt.Sprintf("0x%x", literalTarget), End: fmt.Sprintf("0x%x", literalTarget+16)}}
		numericProfile.AllowedLandings = []AddressRange{{Start: fmt.Sprintf("0x%x", numericTarget), End: fmt.Sprintf("0x%x", numericTarget+16)}}
		literal.Stream, numeric.Stream = &literalProfile, &numericProfile
		tables := []Recipes{literal, numeric}
		if numericFirst {
			tables = []Recipes{numeric, literal}
		}
		before := bytes.Clone(image)
		edits, err := plan(tables, registry, glyphs, bytes.NewReader(image))
		if err != nil || len(edits) != 5 {
			t.Fatalf("append composition numericFirst=%v: %v", numericFirst, err)
		}
		again, err := plan(tables, registry, glyphs, bytes.NewReader(image))
		if err != nil || !reflect.DeepEqual(edits, again) || !bytes.Equal(before, image) {
			t.Fatalf("composition changed source or repeated allocation order: %v", err)
		}
		want := bytes.Clone(image)
		for offset, target := range map[int]uint32{0xa00: numericTarget, 0xa04: numericTarget, 0xa08: literalTarget} {
			binary.LittleEndian.PutUint32(want[offset:], target)
		}
		copy(want[0x2000+literalTarget-0x04000000:], literalBytes)
		copy(want[0x2000+numericTarget-0x04000000:], []byte{1, 0, 0, 8, 0, 0x70, 0, 8, 2, 0, 0, 0xf8})
		dir := t.TempDir()
		path, output := filepath.Join(dir, "source.iso"), filepath.Join(dir, "composed.iso")
		if err := os.WriteFile(path, image, 0600); err != nil {
			t.Fatal(err)
		}
		source, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		digest, err := patchCopy(source, output, tables, edits, registry, glyphs)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := os.ReadFile(output)
		if err != nil || !bytes.Equal(actual, want) || digest != fmt.Sprintf("%x", sha256.Sum256(want)) {
			t.Fatalf("composed copy differs from independent whole-image golden: %v", err)
		}
		for i := range tables {
			tables[i].SourceSHA256 = digest
		}
		done, err := plan(tables, registry, glyphs, bytes.NewReader(actual))
		if err != nil || len(done) != 3 {
			t.Fatalf("completed composition allocated again: %v", err)
		}
		for _, edit := range done {
			if edit.Operation != "stream_pointer" || !bytes.Equal(edit.Old, edit.New) {
				t.Fatal("completed composition changed references or allocated payloads")
			}
		}
		for i := range tables {
			tables[i].SourceSHA256 = r.SourceSHA256
		}
		tableDir := filepath.Join(dir, "recipes")
		if err := os.Mkdir(tableDir, 0700); err != nil {
			t.Fatal(err)
		}
		for i, table := range tables {
			data, err := json.Marshal(table)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(tableDir, fmt.Sprintf("%02d.json", i)), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		registryData, err := json.Marshal(registry)
		if err != nil {
			t.Fatal(err)
		}
		registryPath, glyphPath := filepath.Join(dir, "registry.json"), filepath.Join(dir, "glyphs.json")
		for path, data := range map[string][]byte{registryPath: registryData, glyphPath: glyphs} {
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		cliOutput := filepath.Join(dir, "cli-composed.iso")
		args := []string{"--source", path, "--registry", registryPath, "--glyphmap", glyphPath, "--recipes", tableDir}
		if err := run(args, io.Discard); err != nil {
			t.Fatal(err)
		}
		var directoryReport, repeatedReport bytes.Buffer
		if err := run(args, &directoryReport); err != nil {
			t.Fatal(err)
		}
		repeated := slices.Clone(args[:len(args)-2])
		for i := range tables {
			repeated = append(repeated, "--recipes", filepath.Join(tableDir, fmt.Sprintf("%02d.json", i)))
		}
		if err := run(repeated, &repeatedReport); err != nil || !bytes.Equal(repeatedReport.Bytes(), directoryReport.Bytes()) {
			t.Fatalf("repeated recipe selections changed composition: %v", err)
		}
		if _, err := os.Stat(cliOutput); !os.IsNotExist(err) {
			t.Fatal("composition preview created output")
		}
		if err := run(append(args, "--apply", "--output", cliOutput), io.Discard); err != nil {
			t.Fatal(err)
		}
		actual, err = os.ReadFile(cliOutput)
		if err != nil || !bytes.Equal(actual, want) {
			t.Fatalf("composed CLI differs from independent image golden: %v", err)
		}
		forged := filepath.Join(dir, "forged.iso")
		if _, err := patchCopy(source, forged, tables, edits[:len(edits)-1], registry, glyphs); err == nil {
			t.Fatal("writer accepted incomplete multi-table transaction")
		}
		if _, err := os.Stat(forged); !os.IsNotExist(err) {
			t.Fatal("invalid composed transaction created output")
		}
		original, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(original, before) {
			t.Fatal("composed copy or refusal changed source")
		}
	}
	for _, operation := range []string{"same_length_stream", "same_length_page", "same_length_controls", "exact_control_stream", "fixed_field", "fixed_field_noop", "stream_append", "stream_source", "stream_read", "stream_derived", "stream_derived_header", "stream_derived_context", "stream_derived_context_explicit", "stream_reflow", "stream_reflow_labels", "stream_reflow_format", "stream_reflow_numeric", "stream_reflow_bound", "stream_reflow_pin", "stream_reflow_byte_limit", "stream_grow", "stream_allocate", "guarded_words", "guarded_words_reverse", "stream_slot"} {
		r, registry, glyphs, image := fixture(t, operation)
		stream := operation == "stream_append" || operation == "stream_source" || operation == "stream_read" || strings.HasPrefix(operation, "stream_reflow") || strings.HasPrefix(operation, "stream_derived")
		firstPayload, secondPayload := 0x10, 0x20
		if operation == "stream_reflow_labels" {
			secondPayload = 0x30
		}
		bounded := operation == "stream_source" || operation == "stream_read"
		if bounded {
			secondPayload = 0x30
			if operation == "stream_source" {
				firstPayload, secondPayload = 0x20, 0x40
			}
		}
		blobOffset := 0x1000
		if strings.HasPrefix(operation, "stream_reflow") || strings.HasPrefix(operation, "stream_derived_context") {
			blobOffset = 0x2000
		}
		expected := []byte{1, 0, 0, 0xf8}
		expectedCount, expectedOffset := 1, int64(16)
		if stream {
			expectedCount, expectedOffset = 5, 0xa00
			expected = []byte{byte(firstPayload), 0, 0, 4}
			if bounded {
				expectedCount = 6
			}
		} else if operation == "stream_grow" || operation == "stream_allocate" {
			expectedCount, expectedOffset, expected = 7, 0x884e, []byte{0, 0x20, 0, 0, 0, 0, 0x20, 0}
			if operation == "stream_allocate" {
				expectedCount = 4
			}
		} else if operation == "guarded_words" {
			expectedOffset, expected = 32, []byte{0x34, 0x12, 5, 0x3c, 0x78, 0x56, 0xa5, 0x34}
		} else if operation == "guarded_words_reverse" {
			expectedOffset, expected = 32, bytes.Repeat([]byte{0xcc}, 8)
		} else if operation == "same_length_page" {
			registry.Entries[0].EN = "A//B"
			recipe := r.Entries["0x10"]
			recipe.ExpectedHex = "04000010040000f8"
			r.Entries["0x10"] = recipe
			copy(image[16:24], []byte{4, 0, 0, 0x10, 4, 0, 0, 0xf8})
			r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
			expected = []byte{1, 0, 0, 0x10, 2, 0, 0, 0xf8}
		} else if operation == "same_length_controls" {
			registry.Entries[0].EN = "[spk 0x3800]A<7000>//[spk 0x3801]<0x8800>|<3802>{{PARAM:0xa000}}<d829>"
			recipe := r.Entries["0x10"]
			recipe.ExpectedHex = "0038040000700010013800880008023800a029d800f8"
			r.Entries["0x10"] = recipe
			old, err := hex.DecodeString(recipe.ExpectedHex)
			if err != nil {
				t.Fatal(err)
			}
			copy(image[16:], old)
			r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
			expected = []byte{0, 0x38, 1, 0, 0, 0x70, 0, 0x10, 1, 0x38, 0, 0x88, 0, 8, 2, 0x38, 0, 0xa0, 0x29, 0xd8, 0, 0xf8}
		} else if operation == "stream_slot" {
			expected = []byte{0, 0x28, 1, 0, 0, 8, 2, 0, 0, 0x10, 0, 0xf8, 0, 0, 0, 0}
		} else if operation == "exact_control_stream" {
			r.Operation, registry.Entries[0].EN = operation, "<b992>B<e850>C"
			old := []byte{0x92, 0xb9, 1, 0, 0x50, 0xe8, 2, 0, 0, 0xf8}
			expected = []byte{0x92, 0xb9, 2, 0, 0x50, 0xe8, 3, 0, 0, 0xf8}
			row := r.Entries["0x10"]
			row.ExpectedHex = hex.EncodeToString(old)
			row.EncodedSHA256 = fmt.Sprintf("%x", sha256.Sum256(expected))
			r.Entries["0x10"] = row
			copy(image[16:], old)
			r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
		} else if operation != "same_length_stream" {
			r.Operation = "fixed_field"
			recipe := r.Entries["0x10"]
			recipe.ExpectedHex = "04000000"
			r.Entries["0x10"] = recipe
			image[18], image[19], expected[3] = 0, 0, 0
			r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
			if operation == "fixed_field_noop" {
				registry.Entries[0].EN, expected[0] = "あ", 4
			}
		}
		want := bytes.Clone(image)
		if stream {
			copy(want[blobOffset+firstPayload:], []byte{1, 0, 2, 0, 0, 0xf8})
			if operation == "stream_reflow_labels" {
				copy(want[blobOffset+firstPayload:], []byte{0, 0xb8, 0, 0xb0, 1, 0, 2, 0, 0, 0xd8, 0, 0xa0, 0xf6, 0xb8, 3, 0, 0, 0xf8})
			}
			if operation == "stream_reflow_format" {
				copy(want[blobOffset+firstPayload:], []byte{1, 0, 0, 8, 2, 0, 0, 0xf8})
			}
			if operation == "stream_reflow_numeric" {
				copy(want[blobOffset+firstPayload:], []byte{1, 0, 0, 8, 0, 0x70, 0, 8, 2, 0, 0, 0xf8})
			}
			if bounded {
				copy(want[blobOffset+firstPayload:], append(bytes.Repeat([]byte{1, 0}, 7), 0, 0xf8))
			}
			if operation == "stream_derived_header" {
				copy(want[blobOffset+0x10:], []byte{0, 0x28, 1, 0, 2, 0, 0, 0xf8})
			}
			if strings.HasPrefix(operation, "stream_derived_context") {
				copy(want[blobOffset+firstPayload:], []byte{0, 0x28, 0x98, 0x39, 1, 0, 2, 0, 0, 0x10, 0, 0xf8})
			}
			if bounded {
				binary.LittleEndian.PutUint16(want[blobOffset+secondPayload-2:], 0xf800)
			}
			copy(want[blobOffset+secondPayload:], []byte{3, 0, 0, 0xf8})
			copy(want[0xa00:], []byte{byte(firstPayload), 0, 0, 4, byte(firstPayload), 0, 0, 4, byte(secondPayload), 0, 0, 4})
		} else if operation == "stream_grow" || operation == "stream_allocate" {
			for offset, replacement := range map[int][]byte{
				0x10014: {0, 0x18, 0xa5, 0x34}, 0x10018: {3, 0, 0x0e, 0x24}, 0x1001c: {3, 0, 0x0e, 0x24},
				0x884e: {0, 0x20, 0, 0, 0, 0, 0x20, 0},
				0x8874: {0x24, 0, 0, 0, 0, 0, 0, 0x24, 0, 0xe0, 0, 0, 0, 0, 0xe0, 0},
			} {
				if operation != "stream_allocate" || offset < 0x10000 {
					copy(want[offset:], replacement)
				}
			}
			clear(want[0x11000:0x12000])
			if operation == "stream_allocate" {
				clear(want[0x10800:0x11000])
			}
		} else {
			copy(want[expectedOffset:], expected)
		}
		edits, err := plan([]Recipes{r}, registry, glyphs, bytes.NewReader(image))
		if err != nil {
			t.Fatal(err)
		}
		if r.Layout != nil {
			parsed, err := inspect(bytes.NewReader(image), nil, &r)
			if err != nil || parsed.Advances[0] != 14 || parsed.Advances[1] != 13 || parsed.Advances[2] != 28 || parsed.Advances[442] != 3 || parsed.Advances[883] != 20 {
				t.Fatalf("font page/advance decoding: %v", err)
			}
		}
		if len(edits) != expectedCount || edits[0].Offset != expectedOffset || !bytes.Equal(edits[0].New, expected) {
			t.Fatalf("wrong plan: %+v", edits)
		}
		states, err := inspect(bytes.NewReader(image), edits, nil)
		wantState := "pending"
		if bytes.Equal(edits[0].Old, edits[0].New) {
			wantState = "already patched"
		}
		if err != nil || states.States[0] != wantState {
			t.Fatalf("initial: %v %v", states, err)
		}
		dir := t.TempDir()
		sourcePath := filepath.Join(dir, "source.iso")
		output := filepath.Join(dir, "copy.iso")
		if err := os.WriteFile(sourcePath, image, 0600); err != nil {
			t.Fatal(err)
		}
		source, err := os.Open(sourcePath)
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		digest, err := patchCopy(source, output, []Recipes{r}, edits, registry, glyphs)
		if err != nil {
			t.Fatal(err)
		}
		patched, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(patched, want) || digest != fmt.Sprintf("%x", sha256.Sum256(want)) {
			t.Fatal("copy changed bytes outside plan or wrong digest")
		}
		if operation == "guarded_words_reverse" {
			_, _, _, original := fixture(t, "guarded_words")
			if !bytes.Equal(patched, original) || digest != r.OutputSHA256 {
				t.Fatal("reverse did not restore the exact predecessor")
			}
			for _, mutation := range []string{"source pin", "output pin", "outside edit", "old bytes", "short pin", "nonhex pin", "missing composed pin", "other operation"} {
				candidate, input := r, bytes.Clone(image)
				tables := []Recipes{candidate}
				switch mutation {
				case "source pin":
					candidate.SourceSHA256 = strings.Repeat("0", 64)
				case "output pin":
					candidate.OutputSHA256 = strings.Repeat("0", 64)
				case "outside edit":
					input[0] ^= 1
					candidate.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(input))
				case "old bytes":
					row := r.Entries["0x20"]
					row.ExpectedHex = "0000000000000000"
					candidate.Entries = map[string]Recipe{"0x20": row}
				case "short pin":
					candidate.OutputSHA256 = strings.Repeat("a", 63)
				case "nonhex pin":
					candidate.OutputSHA256 = strings.Repeat("g", 64)
				case "missing composed pin":
					tables = append(tables, r)
					tables[1].OutputSHA256 = ""
				case "other operation":
					candidate.Operation = "same_length_stream"
				}
				tables[0] = candidate
				inputPath, refusedPath := filepath.Join(dir, mutation+"-input.iso"), filepath.Join(dir, mutation+"-output.iso")
				if err := os.WriteFile(inputPath, input, 0600); err != nil {
					t.Fatal(err)
				}
				inputFile, err := os.Open(inputPath)
				if err != nil {
					t.Fatal(err)
				}
				proposal, refusal := plan(tables, registry, glyphs, inputFile)
				if refusal == nil {
					_, refusal = patchCopy(inputFile, refusedPath, tables, proposal, registry, glyphs)
				}
				inputFile.Close()
				preserved, err := os.ReadFile(inputPath)
				if refusal == nil || err != nil || !bytes.Equal(preserved, input) {
					t.Fatal("invalid reverse admitted or changed its input", mutation, refusal, err)
				}
				if _, err := os.Stat(refusedPath); !os.IsNotExist(err) {
					t.Fatal("invalid reverse retained an output", mutation, err)
				}
			}
		}
		states, err = inspect(bytes.NewReader(patched), edits, nil)
		if err != nil || states.States[0] != "already patched" {
			t.Fatalf("idempotent inspection: %v %v", states, err)
		}
		if stream {
			doneRecipe := r
			doneRecipe.SourceSHA256 = digest
			done, err := plan([]Recipes{doneRecipe}, registry, glyphs, bytes.NewReader(patched))
			wantDone := 3
			if bounded {
				wantDone++
			}
			if err != nil || len(done) != wantDone {
				t.Fatalf("idempotent append plan: %v", err)
			}
			for _, edit := range done {
				if edit.Operation != "stream_pointer" && edit.Operation != "stream_padding" || !bytes.Equal(edit.Old, edit.New) {
					t.Fatal("idempotent append allocated or changed bytes")
				}
			}
			mixed := bytes.Clone(image)
			copy(mixed[blobOffset+firstPayload:blobOffset+secondPayload], want[blobOffset+firstPayload:blobOffset+secondPayload])
			copy(mixed[0xa00:], []byte{byte(firstPayload), 0, 0, 4, byte(firstPayload), 0, 0, 4})
			mixedRecipe := r
			mixedRecipe.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(mixed))
			mixedEdits, err := plan([]Recipes{mixedRecipe}, registry, glyphs, bytes.NewReader(mixed))
			wantMixed := 4
			if bounded {
				wantMixed++
			}
			if err != nil || len(mixedEdits) != wantMixed || mixedEdits[wantMixed-1].ID != "0x110" || mixedEdits[wantMixed-1].Offset != int64(blobOffset+secondPayload) || mixedEdits[wantMixed-1].Operation != "stream_payload" || !bytes.Equal(mixedEdits[wantMixed-1].New, []byte{3, 0, 0, 0xf8}) {
				t.Fatalf("mixed done/pending append: %v", err)
			}
			for _, edit := range mixedEdits[:2] {
				if !bytes.Equal(edit.Old, edit.New) {
					t.Fatal("reallocated done stream in mixed append")
				}
			}
		}
		if operation == "stream_grow" || operation == "stream_allocate" {
			// This disc masters directories with partial final sectors; declared sizes need not be 2048 multiples.
			partialDirectories := bytes.Clone(image)
			for _, offset := range []int{0x80a6, 0x880a, 0x882c, 0x902c} {
				binary.LittleEndian.PutUint32(partialDirectories[offset:], 0xc4)
				binary.BigEndian.PutUint32(partialDirectories[offset+4:], 0xc4)
			}
			for _, offset := range []int{0x88a8, 0x900a} {
				binary.LittleEndian.PutUint32(partialDirectories[offset:], 0x70)
				binary.BigEndian.PutUint32(partialDirectories[offset+4:], 0x70)
			}
			if partialPlan, err := plan([]Recipes{r}, registry, glyphs, bytes.NewReader(partialDirectories)); err != nil || len(partialPlan) != expectedCount {
				t.Fatalf("partial final directory sectors: %v", err)
			}
			metadataCount := 6
			if operation == "stream_allocate" {
				metadataCount = 2
				patched[0x11800] = 0xaa
			}
			doneRecipe := r
			doneRecipe.SourceSHA256 = digest
			done, err := plan([]Recipes{doneRecipe}, registry, glyphs, bytes.NewReader(patched))
			if err != nil || len(done) != metadataCount {
				t.Fatalf("idempotent growth: %v", err)
			}
			for _, edit := range done {
				if !bytes.Equal(edit.Old, edit.New) {
					t.Fatal("growth replan changed existing content")
				}
			}
			if operation == "stream_grow" {
				partial := bytes.Clone(want)
				copy(partial[0x10010:0x10020], image[0x10010:0x10020])
				partial[0x11800] = 0xaa
				partialEdits, err := plan([]Recipes{r}, registry, glyphs, bytes.NewReader(partial))
				if err != nil || len(partialEdits) != 6 {
					t.Fatalf("disc-grown loader-old state: %v", err)
				}
				for _, edit := range partialEdits {
					if edit.Offset >= 0x10800 {
						t.Fatal("partial growth overwrites already allocated blob")
					}
				}
			}
			for _, mutation := range []string{"omit tail", "tail target", "directory target", "loader target", "foreign role", "padding omission"} {
				bad := slices.Clone(edits)
				switch mutation {
				case "omit tail":
					bad = bad[:len(bad)-1]
				case "tail target":
					bad[len(bad)-1].New = bytes.Repeat([]byte{1}, len(bad[len(bad)-1].New))
				case "directory target":
					bad[0].New = bytes.Repeat([]byte{0}, 8)
				case "loader target":
					bad[2].New = []byte{0, 0, 0, 0}
				case "padding omission":
					if operation == "stream_allocate" {
						bad = append(bad[:2], bad[3:]...)
					} else {
						bad = bad[:2]
					}
				case "foreign role":
					bad[0].Operation = "fixed_field"
				}
				invalid := filepath.Join(dir, "forged-growth.iso")
				if _, err := patchCopy(source, invalid, []Recipes{r}, bad, registry, glyphs); err == nil {
					t.Fatalf("writer accepted %s", mutation)
				}
				if _, err := os.Stat(invalid); !os.IsNotExist(err) {
					t.Fatal("created forged growth output")
				}
			}
		}
		if operation == "stream_allocate" {
			for _, sectors := range []uint32{3, 31} {
				adjacent := bytes.Clone(image)
				// Disc-only reservation has no loader safety margin; exactly adjacent extents are preserved.
				if sectors == 3 {
					binary.LittleEndian.PutUint32(adjacent[0x9046:], 36)
					binary.BigEndian.PutUint32(adjacent[0x904a:], 36)
				}
				candidate := r
				growth := *r.Growth
				growth.ToSectors = sectors
				candidate.Growth = &growth
				if got, err := plan([]Recipes{candidate}, registry, glyphs, bytes.NewReader(adjacent)); err != nil || len(got) != 4 {
					t.Fatalf("allocation boundary %d: %v", sectors, err)
				}
			}
			word, _, _, _ := fixture(t, "guarded_words")
			word.SourceSHA256, word.SourceSize, word.ISOELFOffset = r.SourceSHA256, r.SourceSize, r.ISOELFOffset
			row := word.Entries["0x20"]
			row.ExpectedHex = "0100093c0100093c"
			word.Entries["0x20"] = row
			for _, tables := range [][]Recipes{{r, word}, {word, r}} {
				combined, err := plan(tables, registry, glyphs, bytes.NewReader(image))
				if err != nil || len(combined) != 5 {
					t.Fatalf("allocation/word composition: %v", err)
				}
				combinedPath := filepath.Join(dir, fmt.Sprintf("allocation-words-%s.iso", tables[0].Operation))
				if _, err := patchCopy(source, combinedPath, tables, combined, registry, glyphs); err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(combinedPath)
				combinedWant := bytes.Clone(want)
				copy(combinedWant[0x10020:], []byte{0x34, 0x12, 5, 0x3c, 0x78, 0x56, 0xa5, 0x34})
				if err != nil || !bytes.Equal(got, combinedWant) {
					t.Fatal("allocation composition changed unrelated image bytes")
				}
			}
			for _, offset := range []int{0x9044, 0x8000, 0xa000, 0x97fc} {
				for _, metadataInsideELF := range []bool{false, true} {
					candidate, payload, hostile := r, word, bytes.Clone(image)
					profile := *r.Stream
					if metadataInsideELF {
						// A hostile profile can place ISO metadata inside its declared ELF; bounds alone are insufficient.
						candidate.ISOELFOffset, profile.RetailELFSize = "0x8000", 0x8310
						for at, value := range map[int]uint32{0x8846: 16, 0x884e: 0x8310} {
							binary.LittleEndian.PutUint32(hostile[at:], value)
							binary.BigEndian.PutUint32(hostile[at+4:], value)
						}
					}
					candidate.Stream = &profile
					candidate.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(hostile))
					payload.SourceSHA256, payload.ISOELFOffset = candidate.SourceSHA256, "0x0"
					payload.Values = nil
					old := hostile[offset : offset+12]
					forged := bytes.Clone(old)
					binary.LittleEndian.PutUint32(forged[2:], 35)
					binary.BigEndian.PutUint32(forged[6:], 35)
					block := Recipe{ExpectedHex: hex.EncodeToString(old)}
					for at := 0; at < len(forged); at += 4 {
						block.Words = append(block.Words, Word{Hex: fmt.Sprintf("0x%x", binary.LittleEndian.Uint32(forged[at:])), Assembly: "forge directory extent to overlap reserved sector35"})
					}
					payload.Entries = map[string]Recipe{fmt.Sprintf("0x%x", offset): block}
					if _, err := plan([]Recipes{candidate, payload}, registry, glyphs, bytes.NewReader(hostile)); err == nil || metadataInsideELF && !strings.Contains(err.Error(), "ISO metadata") {
						t.Fatalf("composed metadata edit %#x insideELF=%v: %v", offset, metadataInsideELF, err)
					}
				}
			}

			word.Entries = map[string]Recipe{"0x800": row}
			if _, err := plan([]Recipes{r, word}, registry, glyphs, bytes.NewReader(image)); err == nil {
				t.Fatal("allocation accepted overlapping word block")
			}
		}
		if operation == "guarded_words" {
			template := r.Entries["0x20"]
			for value, golden := range map[string]string{"0x0": "0000053c0000a534", "0xffff": "0000053cffffa534", "0x10000": "0100053c0000a534", "0xffffffff": "ffff053cffffa534"} {
				r.Values["allocation"] = value
				got, err := plan([]Recipes{r}, registry, glyphs, nil)
				if err != nil || len(got) != 1 || hex.EncodeToString(got[0].New) != golden {
					t.Fatalf("word value %s: %v", value, err)
				}
			}
			r.Values["allocation"] = "0x12345678"
			textRecipe, textRegistry, _, _ := fixture(t, "same_length_stream")
			combined, err := plan([]Recipes{r, textRecipe}, textRegistry, glyphs, nil)
			if err != nil || len(combined) != 2 || combined[0].Offset != 16 || combined[1].Offset != 32 {
				t.Fatalf("word/text composition: %v", err)
			}
			combinedPath := filepath.Join(dir, "combined.iso")
			if _, err := patchCopy(source, combinedPath, []Recipes{r, textRecipe}, combined, textRegistry, glyphs); err != nil {
				t.Fatal(err)
			}
			combinedImage, err := os.ReadFile(combinedPath)
			combinedWant := bytes.Clone(want)
			copy(combinedWant[16:], []byte{1, 0, 0, 0xf8})
			if err != nil || !bytes.Equal(combinedImage, combinedWant) {
				t.Fatal("composed words/text changed bytes outside expected spans")
			}
			for _, mutation := range []string{"missing block", "changed word", "changed role", "changed offset"} {
				bad := slices.Clone(edits)
				switch mutation {
				case "missing block":
					bad = nil
				case "changed word":
					bad[0].New = bytes.Repeat([]byte{0}, len(bad[0].New))
				case "changed role":
					bad[0].Operation = "fixed_field"
				case "changed offset":
					bad[0].Offset = 36
				}
				invalid := filepath.Join(dir, "forged-word.iso")
				if _, err := patchCopy(source, invalid, []Recipes{r}, bad, registry, glyphs); err == nil {
					t.Fatalf("writer accepted%s", mutation)
				}
				if _, err := os.Stat(invalid); !os.IsNotExist(err) {
					t.Fatal("created forged word output")
				}
			}
			// A complete word can also be a named value; no opcode or bits are silently retained.
			row := r.Entries["0x20"]
			row.ExpectedHex = "cccccccc"
			row.Words = []Word{{Hex: "0x0", Assembly: ".word allocation"}}
			row.Fixups = map[string]WordFixup{"0x0": {Value: "allocation", Bits: 32}}
			r.Entries["0x20"] = row
			whole, err := plan([]Recipes{r}, registry, glyphs, nil)
			if err != nil || len(whole) != 1 || hex.EncodeToString(whole[0].New) != "78563412" {
				t.Fatalf("whole-word fixup: %v", err)
			}
			r.Values["allocation"] = "0xffffffff"
			for _, field := range []struct {
				bits, shift, lsb uint
				hex              string
			}{{28, 4, 0, "ffffff0f"}, {32, 31, 0, "01000000"}, {1, 31, 0, "01000000"}, {16, 16, 0, "ffff0000"}, {5, 0, 6, "c0070000"}, {1, 0, 31, "00000080"}, {16, 0, 16, "0000ffff"}} {
				row.Fixups["0x0"] = WordFixup{Value: "allocation", Bits: field.bits, Shift: field.shift, LSB: field.lsb}
				r.Entries["0x20"] = row
				got, err := plan([]Recipes{r}, registry, glyphs, nil)
				if err != nil || len(got) != 1 || hex.EncodeToString(got[0].New) != field.hex {
					t.Fatalf("fixup width%d shift%d: %v", field.bits, field.shift, err)
				}
			}
			r.Values["allocation"] = "0x12345678"
			r.WordBlocks = map[string]Recipe{"allocation_hi": {Words: slices.Clone(template.Words[:1]), Fixups: map[string]WordFixup{"0x0": template.Fixups["0x0"]}}}
			row = template
			row.Use, row.Words = "allocation_hi", slices.Clone(template.Words[1:])
			row.Fixups = map[string]WordFixup{"0x4": template.Fixups["0x4"]}
			r.Entries["0x20"] = row
			shared, err := plan([]Recipes{r}, registry, glyphs, nil)
			if err != nil || len(shared) != 1 || !bytes.Equal(shared[0].New, expected) {
				t.Fatalf("shared prefix bytes: %v", err)
			}
			sharedPath := filepath.Join(dir, "shared-prefix.iso")
			if _, err := patchCopy(source, sharedPath, []Recipes{r}, shared, registry, glyphs); err != nil {
				t.Fatal(err)
			}
			sharedImage, err := os.ReadFile(sharedPath)
			if err != nil || !bytes.Equal(sharedImage, want) {
				t.Fatal("shared prefix changed unrelated bytes")
			}
			prefixOnly := r
			prefixOnly.WordBlocks = map[string]Recipe{"complete": template}
			block := prefixOnly.WordBlocks["complete"]
			block.ExpectedHex = ""
			prefixOnly.WordBlocks["complete"] = block
			prefixOnly.Entries = map[string]Recipe{"0x20": {ExpectedHex: template.ExpectedHex, Use: "complete"}}
			if got, err := plan([]Recipes{prefixOnly}, registry, glyphs, nil); err != nil || len(got) != 1 || !bytes.Equal(got[0].New, expected) {
				t.Fatalf("complete shared word block: %v", err)
			}
			r.WordBlocks = nil
			r.Entries["0x20"] = template
		}
		for _, path := range []string{sourcePath, output} {
			before, _ := os.ReadFile(path)
			if _, err := patchCopy(source, path, []Recipes{r}, edits, registry, glyphs); err == nil {
				t.Fatal("overwrote existing path")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("existing path changed")
			}
		}
		for _, kind := range []string{"symlink", "hardlink"} {
			path := filepath.Join(dir, kind)
			if kind == "symlink" {
				err = os.Symlink(sourcePath, path)
			} else {
				err = os.Link(sourcePath, path)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := patchCopy(source, path, []Recipes{r}, edits, registry, glyphs); err == nil {
				t.Fatal("accepted existing alias")
			}
		}
		original, _ := os.ReadFile(sourcePath)
		if !bytes.Equal(original, image) {
			t.Fatal("source changed")
		}
	}
	{
		r, registry, glyphs, image := fixture(t, "stream_append")
		r.Placement = "registry_landing"
		r.ScopeSHA256 = placedPointerScope
		r.Stream.AllowedPointers = nil
		registry.Entries[0].LandingVMA = "0x04000030"
		registry.Entries[1].LandingVMA = "0x04000010"
		edits, err := plan([]Recipes{r}, registry, glyphs, bytes.NewReader(image))
		if err != nil || len(edits) != 5 {
			t.Fatalf("canonical landing plan: %v", err)
		}
		payloads := map[string]int64{}
		for _, edit := range edits {
			if edit.Operation == "stream_payload" {
				payloads[edit.ID] = edit.Offset
			}
		}
		if !reflect.DeepEqual(payloads, map[string]int64{"0x100": 0x1030, "0x110": 0x1010}) {
			t.Fatalf("canonical landings ignored: %v", payloads)
		}
		dir := t.TempDir()
		input, output := filepath.Join(dir, "source.iso"), filepath.Join(dir, "placed.iso")
		if err := os.WriteFile(input, image, 0600); err != nil {
			t.Fatal(err)
		}
		source, err := os.Open(input)
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		if _, err := patchCopy(source, output, []Recipes{r}, edits, registry, glyphs); err != nil {
			t.Fatal(err)
		}
		want := bytes.Clone(image)
		copy(want[0x1010:], []byte{3, 0, 0, 0xf8})
		copy(want[0x1030:], []byte{1, 0, 2, 0, 0, 0xf8})
		for offset, value := range map[int]uint32{0xa00: 0x04000030, 0xa04: 0x04000030, 0xa08: 0x04000010} {
			binary.LittleEndian.PutUint32(want[offset:], value)
		}
		got, err := os.ReadFile(output)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("canonical landing copy differs from independently built image: %v", err)
		}
	}
	for _, mode := range []string{"line", "page"} {
		t.Run("reviewed "+mode+" reflow", func(t *testing.T) {
			r, registry, glyphs, image := fixture(t, "stream_reflow_bound")
			row := r.Entries["0x100"]
			row.LinePageReflow, row.MaxNewBytes, row.MaxWidth, row.MaxLines = true, 8, 100, 2
			encoded := []byte{1, 0, 0, 8, 2, 0, 0, 0xf8}
			registry.Entries[0].EN = "A|B"
			if mode == "page" {
				encoded[3], registry.Entries[0].EN = 0x10, "A//B"
			}
			row.EncodedSHA256 = fmt.Sprintf("%x", sha256.Sum256(encoded))
			r.Entries["0x100"] = row
			edits, err := plan([]Recipes{r}, registry, glyphs, bytes.NewReader(image))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, edit := range edits {
				if edit.ID == "0x100" && edit.Operation == "stream_payload" {
					found = bytes.Equal(edit.New, encoded)
				}
			}
			if !found {
				t.Fatal("reviewed reflow did not produce the pinned payload")
			}
			if mode == "page" {
				for _, change := range []string{"disabled", "missing pin", "missing bound", "too narrow"} {
					invalid := r
					invalid.Entries = maps.Clone(r.Entries)
					bad := row
					switch change {
					case "disabled":
						bad.LinePageReflow = false
					case "missing pin":
						bad.EncodedSHA256 = ""
					case "missing bound":
						bad.MaxNewBytes = 0
					case "too narrow":
						bad.MaxWidth = 1
					}
					invalid.Entries["0x100"] = bad
					if rejected, err := plan([]Recipes{invalid}, registry, glyphs, bytes.NewReader(image)); err == nil || rejected != nil {
						t.Fatalf("accepted %s reflow without its reviewed contract", change)
					}
				}
				for _, boundary := range []string{"preserved pause", "removed pause", "added pause", "changed pause"} {
					t.Run(boundary, func(t *testing.T) {
						old := []byte{4, 0, 0, 0x10, 0, 0xf8}
						target := []byte{1, 0, 0, 8, 2, 0, 0, 0x10, 0, 0xf8}
						wording := "A|B//"
						switch boundary {
						case "removed pause":
							target, wording = target[:6], "A|B"
							target = append(target, 0, 0xf8)
						case "added pause":
							old = []byte{4, 0, 0, 0xf8}
						case "changed pause":
							target[7], wording = 8, "A|B|"
						}
						bounded := r
						bounded.Entries = maps.Clone(r.Entries)
						bad := row
						bad.ExpectedHex, bad.MaxNewBytes, bad.MaxLines = hex.EncodeToString(old), len(target), 3
						bad.EncodedSHA256 = fmt.Sprintf("%x", sha256.Sum256(target))
						bounded.Entries["0x100"] = bad
						boundedImage := bytes.Clone(image)
						copy(boundedImage[0x900:], old)
						bounded.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(boundedImage))
						boundedRegistry := registry
						boundedRegistry.Entries = slices.Clone(registry.Entries)
						boundedRegistry.Entries[0].EN = wording
						edits, err := plan([]Recipes{bounded}, boundedRegistry, glyphs, bytes.NewReader(boundedImage))
						if boundary == "preserved pause" {
							if err != nil || len(edits) == 0 {
								t.Fatalf("refused preserved trailing pause: %v", err)
							}
						} else if err == nil || edits != nil || !strings.Contains(err.Error(), "changed ordered controls") {
							t.Fatalf("accepted %s during reflow: %v", boundary, err)
						}
					})
				}
				altered := bytes.Clone(image)
				copy(altered[0x900:], []byte{4, 0, 1, 0xb0, 0, 0xf8})
				invalid := r
				invalid.Entries = maps.Clone(r.Entries)
				bad := row
				bad.ExpectedHex = "040001b000f8"
				invalid.Entries["0x100"] = bad
				invalid.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(altered))
				if _, err := plan([]Recipes{invalid}, registry, glyphs, bytes.NewReader(altered)); err == nil || !strings.Contains(err.Error(), "changed ordered controls") {
					t.Fatalf("reflow accepted a changed highlight control: %v", err)
				}
				inside := bytes.Clone(image)
				old := []byte{1, 0, 1, 0xb0, 2, 0, 8, 0xb0, 0, 0xf8}
				copy(inside[0x900:], old)
				invalid = r
				invalid.Entries = maps.Clone(r.Entries)
				bad = row
				bad.ExpectedHex = hex.EncodeToString(old)
				bad.MaxNewBytes = 12
				bad.EncodedSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte{1, 0, 1, 0xb0, 0, 0x10, 2, 0, 8, 0xb0, 0, 0xf8}))
				invalid.Entries["0x100"] = bad
				invalid.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(inside))
				registry.Entries[0].EN = "A{{HL:0xb001}}//B{{HL:0xb008}}"
				if _, err := plan([]Recipes{invalid}, registry, glyphs, bytes.NewReader(inside)); err == nil || !strings.Contains(err.Error(), "PAGE within active highlight") {
					t.Fatalf("reflow accepted PAGE inside an active highlight: %v", err)
				}
			}
		})
	}
	for _, mode := range []string{"aligned read extent", "tail within current alignment", "separate subsequent table", "late completed read span", "variable source pointer", "exact encoded copy bound"} {
		t.Run(mode, func(t *testing.T) {
			r, reg, glyphs, image := fixture(t, "stream_source")
			switch mode {
			case "aligned read extent":
				row := r.Entries["0x100"]
				row.ReadBytes = 32
				r.Entries["0x100"] = row
			case "tail within current alignment":
				row := r.Entries["0x100"]
				row.MaxNewBytes, row.ReadBytes = 8, 8
				r.Entries["0x100"] = row
				reg.Entries[0].EN = "AB"
			case "separate subsequent table":
				delete(r.Entries, "0x110")
			case "late completed read span":
				row := r.Entries["0x110"]
				row.MaxNewBytes, row.ReadBytes = 18, 18
				r.Entries["0x110"] = row
				reg.Entries[1].EN = "CCCCCCC"
				copy(image[0x1020:], append(bytes.Repeat([]byte{3, 0}, 7), 0, 0xf8))
				binary.LittleEndian.PutUint32(image[0xa08:], 0x04000020)
				binary.LittleEndian.PutUint16(image[0x103e:], 0xf800)
			case "variable source pointer":
				row := r.Entries["0x100"]
				row.MaxNewBytes, row.ReadBytes = 0, 0
				r.Entries["0x100"] = row
				reg.Entries[0].RefType = "pointer_array"
				for i := range reg.Entries[0].RefSites {
					reg.Entries[0].RefSites[i].StructVMA, reg.Entries[0].RefSites[i].FieldOffset = "", ""
				}
			case "exact encoded copy bound":
				reg.Entries[0].EN = "AAAAAAAA"
			}
			edits, err := plan([]Recipes{r}, reg, glyphs, bytes.NewReader(image))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "aligned read extent" {
				if len(edits) != 6 || len(edits[4].New) != 32 || !bytes.Equal(edits[4].New[:16], make([]byte, 16)) || binary.LittleEndian.Uint16(edits[4].New[30:]) != 0xf800 || edits[5].Offset != 0x1050 {
					t.Fatal("aligned read marker is not outside the fullconsumer span")
				}
			} else if mode == "tail within current alignment" {
				if len(edits) != 6 || len(edits[4].New) != 2 || !bytes.Equal(edits[4].New, []byte{0, 0}) || edits[5].Offset != 0x1020 {
					t.Fatal("unnecessary reservation marker or wrong within-slot padding")
				}
			} else if mode == "separate subsequent table" {
				for _, edit := range edits {
					copy(image[edit.Offset:], edit.New)
				}
				r.Entries = map[string]Recipe{"0x110": {ExpectedHex: "040000f8"}}
				next, err := plan([]Recipes{r}, reg, glyphs, bytes.NewReader(image))
				if err != nil || !bytes.Equal(next[0].New, []byte{0x40, 0, 0, 4}) {
					t.Fatalf("next table reused a reserved fixed-read tail: %v", err)
				}
			} else if mode == "late completed read span" {
				if !bytes.Equal(edits[0].New, []byte{0x40, 0, 0, 4}) || !bytes.Equal(edits[2].Old, edits[2].New) {
					t.Fatal("pending row reused the later completed row's fixed-read tail")
				}
			} else if mode == "variable source pointer" {
				if !bytes.Equal(edits[0].New, []byte{0x10, 0, 0, 4}) || len(edits) != 5 {
					t.Fatal("variable-length source was treated as fixed-copy")
				}
			} else if len(edits) != 5 || len(edits[3].New) != 18 || edits[4].Offset != 0x1040 {
				t.Fatal("exact18-byte encoding/copy bound was not accepted")
			}
		})
	}

	for _, mode := range []string{"code pairs", "layout bound", "layout encoding pin", "refuse layout negative width", "refuse layout no pin", "refuse layout malformed pin", "refuse layout short pin", "refuse layout no bytes", "refuse layout missing font", "refuse layout width", "refuse layout bytes", "refuse layout oversized bytes", "refuse layout canonical change", "refuse layout font drift", "refuse layout extra line", "refuse layout page", "shared upper", "signed target", "signed source", "mixed data", "refuse omitted scope", "refuse omitted pair", "refuse wrong upper", "refuse wrong lower", "refuse register", "refuse partial", "refuse outside", "refuse alignment", "refuse reverse", "refuse duplicate", "refuse raw alias", "refuse mixed shape", "refuse foreign code fields"} {
		t.Run(mode, func(t *testing.T) {
			operation, blobOffset := "stream_append", 0x1000
			if strings.Contains(mode, "layout") {
				operation, blobOffset = "stream_reflow_bound", 0x2000
				if mode == "layout encoding pin" {
					operation = "stream_reflow_pin"
				}
			}
			r, reg, glyphs, image := fixture(t, operation)
			delete(r.Entries, "0x110")
			reg.Entries = reg.Entries[:1]
			reg.Entries[0] = RegistryEntry{}
			clear(image[0xa00:0xa30])
			r.Stream.AllowedPointers[0].End = "0x240"
			if err := json.Unmarshal([]byte(`{"id":"0x100","en":"AB","ref_type":"code_immediate","ref_sites":[{"lui_vma":"0x200","addiu_vma":"0x20c","reg":"$a0"},{"lui_vma":"0x210","addiu_vma":"0x218","reg":"$s3"}]}`), &reg.Entries[0]); err != nil {
				t.Fatal(err)
			}
			for vma, word := range map[int]uint32{0x200: 0x3c040000, 0x208: 0x0c000040, 0x20c: 0x24840100, 0x210: 0x3c130000, 0x214: 0x0c000040, 0x218: 0x26730100} {
				binary.LittleEndian.PutUint32(image[0x800+vma:], word)
			}
			scopeHex := "0001000002000000000200000c02000004100200001802000013"
			target, expectedCount := uint32(0x04000010), 5
			if mode == "shared upper" {
				reg.Entries[0].RefSites[1].LUIVMA, reg.Entries[0].RefSites[1].Register = "0x200", "$a0"
				binary.LittleEndian.PutUint32(image[0xa10:], 0)
				binary.LittleEndian.PutUint32(image[0xa18:], 0x24840100)
				scopeHex, expectedCount = "0001000002000000000200000c02000004000200001802000004", 4
			}
			if mode == "signed target" || mode == "signed source" {
				image = append(image, make([]byte, 0x10000)...)
				r.Stream.ZeroEnd, r.Stream.AllowedLandings[0].End = "0x12000", "0x04010000"
				for offset, value := range map[int]uint32{0x10a: 0x10800, 0x142: 0x22, 0x14a: 0x1000} {
					binary.LittleEndian.PutUint32(image[offset:], value)
					binary.BigEndian.PutUint32(image[offset+4:], value)
				}
				for offset, value := range map[int]uint32{0x810: 0x3c050001, 0x814: 0x34a50000, 0x818: 0x240e0020, 0x81c: 0x240e0020} {
					binary.LittleEndian.PutUint32(image[offset:], value)
				}
				for vma := range r.Stream.WindowSRLWords {
					r.Stream.WindowSRLWords[vma] = "0x00084c02"
					at, _ := number(vma)
					binary.LittleEndian.PutUint32(image[0x800+at:], 0x00084c02)
				}
				binary.LittleEndian.PutUint16(image[0x8ffe:], 0xf800)
				target = 0x04008000
				if mode == "signed source" {
					row := r.Entries["0x100"]
					row.SourcePointer = "0x04008000"
					r.Entries["0x100"] = row
					copy(image[0x9000:], []byte{4, 0, 0, 0xf8})
					for offset, value := range map[int]uint32{0xa00: 0x3c040401, 0xa0c: 0x24848000, 0xa10: 0x3c130401, 0xa18: 0x26738000} {
						binary.LittleEndian.PutUint32(image[offset:], value)
					}
					target = 0x04008010
				}
			}
			if mode == "mixed data" || mode == "refuse foreign code fields" {
				r.Entries["0x110"] = Recipe{ExpectedHex: "040000f8"}
				var entry RegistryEntry
				if err := json.Unmarshal([]byte(`{"id":"0x110","en":"C","ref_type":"pointer_array","ref_sites":[{"pointer_vma":"0x230"}]}`), &entry); err != nil {
					t.Fatal(err)
				}
				reg.Entries = append(reg.Entries, entry)
				binary.LittleEndian.PutUint32(image[0xa30:], 0x110)
				expectedCount = 7
				if mode == "refuse foreign code fields" {
					reg.Entries[1].RefSites[0].LUIVMA = "0x200"
				}
			}
			scope, err := hex.DecodeString(scopeHex)
			if err != nil {
				t.Fatal(err)
			}
			r.ScopeSHA256 = fmt.Sprintf("%x", sha256.Sum256(scope))
			row := r.Entries["0x100"]
			switch mode {
			case "refuse layout negative width":
				row.MaxWidth = -1
			case "refuse layout no pin":
				row.EncodedSHA256 = ""
			case "refuse layout malformed pin":
				row.EncodedSHA256 = "invalid"
			case "refuse layout short pin":
				row.EncodedSHA256 = "00"
			case "refuse layout no bytes":
				row.MaxNewBytes = 0
			case "refuse layout missing font":
				r.Layout = nil
			case "refuse layout width":
				row.MaxWidth = 40
			case "refuse layout bytes":
				row.MaxNewBytes = 4
			case "refuse layout oversized bytes":
				row.MaxNewBytes = maxStreamBytes + 2
			case "refuse layout canonical change":
				reg.Entries[0].EN = "AC"
			case "refuse layout font drift":
				image[0xc17]++
			case "refuse layout extra line", "refuse layout page":
				reg.Entries[0].EN = "A|B"
				encoded := []byte{1, 0, 0, 8, 2, 0, 0, 0xf8}
				if mode == "refuse layout page" {
					reg.Entries[0].EN, encoded[3] = "A//B", 0x10
				}
				row.MaxNewBytes, row.MaxWidth = 8, 100
				row.EncodedSHA256 = fmt.Sprintf("%x", sha256.Sum256(encoded))
			case "refuse omitted scope":
				r.ScopeSHA256 = ""
			case "refuse omitted pair":
				reg.Entries[0].RefSites = reg.Entries[0].RefSites[:1]
			case "refuse wrong upper":
				binary.LittleEndian.PutUint32(image[0xa00:], 0x3c050000)
			case "refuse wrong lower":
				binary.LittleEndian.PutUint32(image[0xa0c:], 0x34840100)
			case "refuse register":
				reg.Entries[0].RefSites[0].Register = "$zero"
			case "refuse partial":
				binary.LittleEndian.PutUint32(image[0xa18:], 0x26730110)
			case "refuse outside":
				r.Stream.AllowedPointers[0].Start = "0x204"
			case "refuse alignment":
				reg.Entries[0].RefSites[0].ADDIUVMA = "0x20e"
			case "refuse reverse":
				reg.Entries[0].RefSites[0].LUIVMA = "0x21c"
			case "refuse duplicate":
				reg.Entries[0].RefSites[1] = reg.Entries[0].RefSites[0]
			case "refuse raw alias":
				binary.LittleEndian.PutUint32(image[0xa2c:], 0x100)
			case "refuse mixed shape":
				reg.Entries[0].RefSites[0].PointerVMA = "0x200"
			}
			r.Entries["0x100"] = row
			r.SourceSize, r.SourceSHA256 = int64(len(image)), fmt.Sprintf("%x", sha256.Sum256(image))
			before := bytes.Clone(image)
			edits, err := plan([]Recipes{r}, reg, glyphs, bytes.NewReader(image))
			if strings.HasPrefix(mode, "refuse ") {
				if err == nil || !bytes.Equal(image, before) {
					t.Fatalf("accepted code-reference mutation or changed source: %v", err)
				}
				return
			}
			if err != nil || len(edits) != expectedCount {
				t.Fatalf("code plan: count%d err%v", len(edits), err)
			}
			want := bytes.Clone(image)
			for vma, word := range map[int]uint32{0x200: 0x3c040000 | ((target + 0x8000) >> 16), 0x20c: 0x24840000 | target&0xffff, 0x210: 0x3c130000 | ((target + 0x8000) >> 16), 0x218: 0x26730000 | target&0xffff} {
				if mode == "shared upper" && vma == 0x210 {
					continue
				}
				if mode == "shared upper" && vma == 0x218 {
					word = 0x24840000 | target&0xffff
				}
				binary.LittleEndian.PutUint32(want[0x800+vma:], word)
			}
			copy(want[blobOffset+int(uint64(target)-sentinelBase):], []byte{1, 0, 2, 0, 0, 0xf8})
			if mode == "mixed data" {
				binary.LittleEndian.PutUint32(want[0xa30:], 0x04000020)
				copy(want[0x1020:], []byte{3, 0, 0, 0xf8})
			}
			dir := t.TempDir()
			path, output := filepath.Join(dir, "source.iso"), filepath.Join(dir, "copy.iso")
			if err := os.WriteFile(path, image, 0600); err != nil {
				t.Fatal(err)
			}
			source, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			digest, err := patchCopy(source, output, []Recipes{r}, edits, reg, glyphs)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := os.ReadFile(output)
			if err != nil || !bytes.Equal(actual, want) {
				t.Fatalf("code copy changed delay/context/source bytes or wrong target: %v", err)
			}
			r.SourceSHA256 = digest
			done, err := plan([]Recipes{r}, reg, glyphs, bytes.NewReader(actual))
			if err != nil {
				t.Fatal(err)
			}
			for _, edit := range done {
				if !bytes.Equal(edit.Old, edit.New) || edit.Operation != "guarded_words" && edit.Operation != "stream_pointer" {
					t.Fatal("completed code references allocated or changed bytes")
				}
			}
			original, _ := os.ReadFile(path)
			if !bytes.Equal(original, before) {
				t.Fatal("code copy changed source")
			}
		})
	}
	t.Run("source-pinned fixed-field table reuse", func(t *testing.T) {
		base, registry, glyphs, original := fixture(t, "same_length_stream")
		clear(original[16:32])
		binary.LittleEndian.PutUint16(original[16:], 4)
		base.Operation = "fixed_field"
		base.Entries["0x10"] = Recipe{ExpectedHex: hex.EncodeToString(original[16:32]), Evidence: "synthetic fixed field"}
		base.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(original))
		stage := bytes.Clone(original)
		stage[40] ^= 1 // Outside the guarded field; its full-image identity still changes.
		stageHash := fmt.Sprintf("%x", sha256.Sum256(stage))
		dir := t.TempDir()
		aliasDir := filepath.Join(dir, "stage")
		if err := os.Mkdir(aliasDir, 0700); err != nil {
			t.Fatal(err)
		}
		basePath, aliasPath := filepath.Join(dir, "base.json"), filepath.Join(aliasDir, "alias.json")
		baseData, _ := json.Marshal(base)
		if err := os.WriteFile(basePath, baseData, 0600); err != nil {
			t.Fatal(err)
		}
		alias := map[string]any{"operation": "reuse_table", "base_recipe": "../base.json", "base_sha256": fmt.Sprintf("%x", sha256.Sum256(baseData)), "source_sha256": stageHash, "source_size": len(stage), "evidence": "unchanged fixed-field preimage on staged source"}
		aliasData, err := json.Marshal(alias)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(aliasPath, aliasData, 0600); err != nil {
			t.Fatal(err)
		}
		sourcePath, registryPath, glyphPath := filepath.Join(dir, "stage.iso"), filepath.Join(dir, "registry.json"), filepath.Join(dir, "glyphs.json")
		registryData, _ := json.Marshal(registry)
		for path, data := range map[string][]byte{sourcePath: stage, registryPath: registryData, glyphPath: glyphs} {
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		args := []string{"--source", sourcePath, "--registry", registryPath, "--glyphmap", glyphPath, "--recipes", aliasPath}
		var preview bytes.Buffer
		if err := run(args, &preview); err != nil || !bytes.Contains(preview.Bytes(), []byte(stageHash)) {
			t.Fatalf("source-pinned reuse dry run: %v", err)
		}
		output := filepath.Join(dir, "output.iso")
		if err := run(append(append([]string{}, args...), "--apply", "--output", output), io.Discard); err != nil {
			t.Fatalf("source-pinned reuse apply: %v", err)
		}
		patched, err := os.ReadFile(output)
		if err != nil || patched[16] != 1 || patched[40] != stage[40] || stage[16] != 4 {
			t.Fatalf("reused table changed wrong bytes: %v", err)
		}
		for _, name := range []string{"wrong base pin", "wrong source pin", "extra override",
			"base reference_flow", "base Reference_Flow", "base reference_flow null", "base Reference_Flow null",
			"base register_flow", "base Register_Flow", "base regiſter_flow", "base register_flow null", "base Register_Flow null", "base regiſter_flow null",
			"base sentinel", "base Sentinel", "base sentinel null", "base Sentinel null"} {
			t.Run(name, func(t *testing.T) {
				switch name {
				case "wrong base pin":
					alias["base_sha256"] = strings.Repeat("0", 64)
				case "wrong source pin":
					alias["source_sha256"] = strings.Repeat("0", 64)
				case "extra override":
					alias["entries"] = map[string]any{}
				default:
					field := strings.TrimPrefix(name, "base ")
					value := json.RawMessage(`{}`)
					if strings.HasSuffix(field, " null") {
						field = strings.TrimSuffix(field, " null")
						value = json.RawMessage(`null`)
					}
					var baseFields map[string]json.RawMessage
					if err := json.Unmarshal(baseData, &baseFields); err != nil {
						t.Fatal(err)
					}
					baseFields[field] = value
					badBase, err := json.Marshal(baseFields)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(basePath, badBase, 0600); err != nil {
						t.Fatal(err)
					}
					alias["base_sha256"] = fmt.Sprintf("%x", sha256.Sum256(badBase))
				}
				aliasData, err := json.Marshal(alias)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(aliasPath, aliasData, 0600); err != nil {
					t.Fatal(err)
				}
				preview.Reset()
				runErr := run(args, &preview)
				if runErr == nil || preview.Len() != 0 {
					t.Fatal("accepted invalid table reuse or published stdout", runErr)
				}
				if strings.HasPrefix(name, "base ") && !strings.Contains(runErr.Error(), "report request") {
					t.Fatal("report request escaped the source-table base guard", runErr)
				}
				if err := os.WriteFile(basePath, baseData, 0600); err != nil {
					t.Fatal(err)
				}
				delete(alias, "entries")
				alias["base_sha256"] = fmt.Sprintf("%x", sha256.Sum256(baseData))
				alias["source_sha256"] = stageHash
			})
		}
		stray := base
		stray.BaseRecipe = "../base.json"
		strayData, err := json.Marshal(stray)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(basePath, strayData, 0600); err != nil {
			t.Fatal(err)
		}
		if err := run(append(append([]string{}, args[:len(args)-1]...), basePath), io.Discard); err == nil || !strings.Contains(err.Error(), "source-table alias fields") {
			t.Fatalf("accepted stray alias fields: %v", err)
		}
	})
	t.Run("named CMB member bundle", func(t *testing.T) {
		_, _, _, image := fixture(t, "stream_allocate")
		const archiveOffset = 19 * isoSector
		const memberOffset = archiveOffset + 97 // fixed-size members need not be word-aligned
		old, replacement := []byte("old data"), []byte("new data")
		binary.LittleEndian.PutUint32(image[archiveOffset:], 96)
		binary.LittleEndian.PutUint32(image[archiveOffset+4:], 1)
		name := "asset\\one.txd"
		copy(image[archiveOffset+8:], name)
		binary.LittleEndian.PutUint32(image[archiveOffset+88:], 1)
		binary.LittleEndian.PutUint32(image[archiveOffset+92:], uint32(len(old)))
		copy(image[memberOffset:], old)
		var packed bytes.Buffer
		writer := zip.NewWriter(&packed)
		memberKey := "SUB/OTHER/asset/one.txd"
		entry, err := writer.Create(memberKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(replacement); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		bundlePath, sourcePath, outputPath := filepath.Join(dir, "bundle.zip"), filepath.Join(dir, "source.iso"), filepath.Join(dir, "output.iso")
		if err := os.WriteFile(bundlePath, packed.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sourcePath, image, 0600); err != nil {
			t.Fatal(err)
		}
		recipe := Recipes{
			Operation: "cmb_member_replace", SourceSize: int64(len(image)), SourceSHA256: fmt.Sprintf("%x", sha256.Sum256(image)),
			BundlePath: bundlePath, BundleSHA256: fmt.Sprintf("%x", sha256.Sum256(packed.Bytes())),
			TargetReferenceSHA256: strings.Repeat("a", 64), Evidence: "synthetic named member",
			Archives: map[string]CMBArchive{"SUB/OTHER": {
				SourceISOOffset: archiveOffset, Size: isoSector,
				IndexSHA256: fmt.Sprintf("%x", sha256.Sum256(image[archiveOffset:archiveOffset+96])),
				Members: map[string]BundleMember{name: {
					Size: int64(len(old)), SourceSHA256: fmt.Sprintf("%x", sha256.Sum256(old)),
					TargetSHA256: fmt.Sprintf("%x", sha256.Sum256(replacement)), BundleKey: memberKey,
				}},
			}},
		}
		edits, err := plan([]Recipes{recipe}, Registry{}, nil, bytes.NewReader(image))
		if err != nil || len(edits) != 1 || edits[0].Offset != memberOffset || !bytes.Equal(edits[0].New, replacement) {
			t.Fatalf("named CMB plan: %v, %+v", err, edits)
		}
		foreign := recipe
		foreign.Sentinel = &SentinelLayout{RetailELFSize: 1920}
		if _, err := plan([]Recipes{foreign}, Registry{}, nil, bytes.NewReader(image)); err == nil {
			t.Fatal("sentinel report facts reached valid named CMB transaction")
		}
		source, err := os.Open(sourcePath)
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		if _, err := patchCopy(source, outputPath, []Recipes{recipe}, edits, Registry{}, nil); err != nil {
			t.Fatal(err)
		}
		actual, err := os.ReadFile(outputPath)
		if err != nil || !bytes.Equal(actual[memberOffset:memberOffset+len(old)], replacement) || !bytes.Equal(image[memberOffset:memberOffset+len(old)], old) {
			t.Fatalf("named CMB copy/source changed: %v", err)
		}
		recipeDir := filepath.Join(dir, "recipes")
		if err := os.Mkdir(recipeDir, 0700); err != nil {
			t.Fatal(err)
		}
		cliRecipe := recipe
		cliRecipe.BundlePath = "../bundle.zip"
		recipeBytes, err := json.Marshal(cliRecipe)
		if err != nil {
			t.Fatal(err)
		}
		recipePath := filepath.Join(recipeDir, "cmb.json")
		if err := os.WriteFile(recipePath, recipeBytes, 0600); err != nil {
			t.Fatal(err)
		}
		args := []string{"--source", sourcePath, "--recipes", recipePath}
		var preview bytes.Buffer
		if err := run(args, &preview); err != nil || !bytes.Contains(preview.Bytes(), []byte(`"asset_member"`)) || bytes.Contains(preview.Bytes(), []byte(`"new_hex"`)) {
			t.Fatalf("CMB CLI dry run or compact report: %v", err)
		}
		cliOutput := filepath.Join(dir, "cli-output.iso")
		if err := run(append(append([]string{}, args...), "--apply", "--output", cliOutput), io.Discard); err != nil {
			t.Fatalf("CMB CLI apply: %v", err)
		}
		cliBytes, err := os.ReadFile(cliOutput)
		if err != nil || !bytes.Equal(cliBytes, actual) {
			t.Fatalf("CMB CLI output mismatch: %v", err)
		}
		t.Run("source-pinned bundle reuse", func(t *testing.T) {
			stage := bytes.Clone(image)
			stage[0x40]++
			want := bytes.Clone(actual)
			want[0x40]++
			stagePath := filepath.Join(dir, "bundle-stage.iso")
			if err := os.WriteFile(stagePath, stage, 0600); err != nil {
				t.Fatal(err)
			}
			aliasDir := filepath.Join(dir, "stages")
			if err := os.Mkdir(aliasDir, 0700); err != nil {
				t.Fatal(err)
			}
			aliasPath := filepath.Join(aliasDir, "assets.json")
			alias := map[string]any{
				"operation": "reuse_table", "base_recipe": "../recipes/cmb.json",
				"base_sha256":   fmt.Sprintf("%x", sha256.Sum256(recipeBytes)),
				"source_sha256": fmt.Sprintf("%x", sha256.Sum256(stage)), "source_size": len(stage),
				"output_sha256": fmt.Sprintf("%x", sha256.Sum256(want)), "evidence": "same member preimages on a separately pinned source",
			}
			data, err := json.Marshal(alias)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(aliasPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(dir, "reused-bundle.iso")
			args := []string{"--source", stagePath, "--recipes", aliasPath, "--apply", "--output", output}
			if err := run(args, io.Discard); err != nil {
				t.Fatalf("source-pinned bundle/relative base ZIP resolution: %v", err)
			}
			got, err := os.ReadFile(output)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("bundle alias output differs: %v", err)
			}
			for i, change := range []string{"base pin", "row override", "missing output", "wrong output", "wrong source", "size"} {
				invalid := maps.Clone(alias)
				switch change {
				case "base pin":
					invalid["base_sha256"] = strings.Repeat("0", 64)
				case "row override":
					invalid["archives"] = recipe.Archives
				case "missing output":
					delete(invalid, "output_sha256")
				case "wrong output":
					invalid["output_sha256"] = strings.Repeat("0", 64)
				case "wrong source":
					invalid["source_sha256"] = strings.Repeat("0", 64)
				case "size":
					invalid["source_size"] = len(stage) - 1
				}
				data, err := json.Marshal(invalid)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(aliasPath, data, 0600); err != nil {
					t.Fatal(err)
				}
				refused := filepath.Join(dir, fmt.Sprintf("bundle-alias-refused-%d.iso", i))
				if err := run(append(slices.Clone(args[:len(args)-1]), refused), io.Discard); err == nil {
					t.Fatalf("bundle alias accepted %s", change)
				}
				if _, err := os.Stat(refused); !os.IsNotExist(err) {
					t.Fatalf("bundle alias %s left an output", change)
				}
			}
		})
		for _, mutation := range []struct {
			name   string
			change func(*Recipes, []byte)
		}{
			{"root extended attributes", func(_ *Recipes, b []byte) { b[0x809c+1] = 1 }},
			{"root interleave", func(_ *Recipes, b []byte) { b[0x809c+26] = 1 }},
			{"file extended attributes", func(_ *Recipes, b []byte) { b[0x9044+1] = 1 }},
			{"file unit size", func(_ *Recipes, b []byte) { b[0x9044+26] = 1 }},
			{"file interleave gap", func(_ *Recipes, b []byte) { b[0x9044+27] = 1 }},
			{"file volume sequence endian", func(_ *Recipes, b []byte) { b[0x9044+28] = 2 }},
			{"archive extent", func(r *Recipes, _ []byte) {
				a := r.Archives["SUB/OTHER"]
				a.SourceISOOffset++
				r.Archives["SUB/OTHER"] = a
			}},
			{"index hash", func(r *Recipes, _ []byte) {
				a := r.Archives["SUB/OTHER"]
				a.IndexSHA256 = strings.Repeat("0", 64)
				r.Archives["SUB/OTHER"] = a
			}},
			{"source member", func(_ *Recipes, b []byte) { b[memberOffset]++ }},
			{"target hash", func(r *Recipes, _ []byte) {
				a := r.Archives["SUB/OTHER"]
				m := a.Members[name]
				m.TargetSHA256 = strings.Repeat("0", 64)
				a.Members[name] = m
				r.Archives["SUB/OTHER"] = a
			}},
			{"bundle hash", func(r *Recipes, _ []byte) { r.BundleSHA256 = strings.Repeat("0", 64) }},
			{"bundle key", func(r *Recipes, _ []byte) {
				a := r.Archives["SUB/OTHER"]
				m := a.Members[name]
				m.BundleKey += "-wrong"
				a.Members[name] = m
				r.Archives["SUB/OTHER"] = a
			}},
			{"size change", func(r *Recipes, _ []byte) {
				a := r.Archives["SUB/OTHER"]
				m := a.Members[name]
				m.Size++
				a.Members[name] = m
				r.Archives["SUB/OTHER"] = a
			}},
			{"invalid index", func(r *Recipes, b []byte) {
				binary.LittleEndian.PutUint32(b[archiveOffset+4:], 0)
				a := r.Archives["SUB/OTHER"]
				a.IndexSHA256 = fmt.Sprintf("%x", sha256.Sum256(b[archiveOffset:archiveOffset+96]))
				r.Archives["SUB/OTHER"] = a
			}},
			{"duplicate CMB name", func(r *Recipes, b []byte) {
				binary.LittleEndian.PutUint32(b[archiveOffset:], 184)
				binary.LittleEndian.PutUint32(b[archiveOffset+4:], 2)
				copy(b[archiveOffset+96:], b[archiveOffset+8:archiveOffset+96])
				a := r.Archives["SUB/OTHER"]
				a.IndexSHA256 = fmt.Sprintf("%x", sha256.Sum256(b[archiveOffset:archiveOffset+184]))
				r.Archives["SUB/OTHER"] = a
			}},
		} {
			t.Run(mutation.name, func(t *testing.T) {
				candidate := recipe
				candidate.Archives = map[string]CMBArchive{"SUB/OTHER": recipe.Archives["SUB/OTHER"]}
				a := candidate.Archives["SUB/OTHER"]
				a.Members = map[string]BundleMember{name: a.Members[name]}
				candidate.Archives["SUB/OTHER"] = a
				altered := bytes.Clone(image)
				mutation.change(&candidate, altered)
				if got, err := plan([]Recipes{candidate}, Registry{}, nil, bytes.NewReader(altered)); err == nil || got != nil {
					t.Fatal("accepted malformed member plan")
				}
			})
		}
		bad := recipe
		bad.SourceSHA256 = strings.Repeat("0", 64)
		refused := filepath.Join(dir, "refused.iso")
		if _, err := patchCopy(source, refused, []Recipes{bad}, edits, Registry{}, nil); err == nil {
			t.Fatal("accepted wrong source image hash")
		}
		if _, err := os.Stat(refused); !os.IsNotExist(err) {
			t.Fatal("refusal created output")
		}
		broken := bytes.Clone(packed.Bytes()[:len(packed.Bytes())/2])
		brokenPath := filepath.Join(dir, "broken.zip")
		if err := os.WriteFile(brokenPath, broken, 0600); err != nil {
			t.Fatal(err)
		}
		bad.BundlePath, bad.BundleSHA256, bad.SourceSHA256 = brokenPath, fmt.Sprintf("%x", sha256.Sum256(broken)), recipe.SourceSHA256
		if got, err := plan([]Recipes{bad}, Registry{}, nil, bytes.NewReader(image)); err == nil || got != nil {
			t.Fatal("accepted malformed bundle member")
		}
		for i, names := range [][]string{{memberKey, memberKey}, {memberKey, "unreferenced.txd"}} {
			var extra bytes.Buffer
			writer := zip.NewWriter(&extra)
			for _, key := range names {
				entry, err := writer.Create(key)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := entry.Write(replacement); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, fmt.Sprintf("extra-%d.zip", i))
			if err := os.WriteFile(path, extra.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			bad.BundlePath, bad.BundleSHA256 = path, fmt.Sprintf("%x", sha256.Sum256(extra.Bytes()))
			if got, err := plan([]Recipes{bad}, Registry{}, nil, bytes.NewReader(image)); err == nil || got != nil {
				t.Fatalf("accepted duplicate or unreferenced ZIP entry %q", names[1])
			}
		}
		t.Run("whole ISO file", func(t *testing.T) {
			wholeOld := bytes.Clone(image[archiveOffset : archiveOffset+isoSector])
			wholeNew := bytes.Clone(wholeOld)
			copy(wholeNew[memberOffset-archiveOffset:], replacement)
			want := bytes.Clone(image)
			copy(want[archiveOffset:], wholeNew)
			var wholePacked bytes.Buffer
			writer := zip.NewWriter(&wholePacked)
			entry, err := writer.Create("SUB/OTHER")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := entry.Write(wholeNew); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			wholePath := filepath.Join(dir, "whole.zip")
			if err := os.WriteFile(wholePath, wholePacked.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			whole := recipe
			whole.Operation, whole.Archives = "iso_file_replace", nil
			whole.BundlePath, whole.BundleSHA256 = wholePath, fmt.Sprintf("%x", sha256.Sum256(wholePacked.Bytes()))
			whole.OutputSHA256 = fmt.Sprintf("%x", sha256.Sum256(want))
			whole.Files = map[string]ISOFile{"SUB/OTHER": {SourceISOOffset: archiveOffset, BundleMember: BundleMember{
				Size: isoSector, SourceSHA256: fmt.Sprintf("%x", sha256.Sum256(wholeOld)),
				TargetSHA256: fmt.Sprintf("%x", sha256.Sum256(wholeNew)), BundleKey: "SUB/OTHER",
			}}}
			fileEdits, err := plan([]Recipes{whole}, Registry{}, nil, bytes.NewReader(image))
			if err != nil || len(fileEdits) != 1 || fileEdits[0].Offset != archiveOffset || !bytes.Equal(fileEdits[0].Old, wholeOld) || !bytes.Equal(fileEdits[0].New, wholeNew) {
				t.Fatalf("whole named file plan: %v", err)
			}
			wholeOutput := filepath.Join(dir, "whole-output.iso")
			if digest, err := patchCopy(source, wholeOutput, []Recipes{whole}, fileEdits, Registry{}, nil); err != nil || digest != whole.OutputSHA256 {
				t.Fatalf("whole named file copy: %s, %v", digest, err)
			}
			actual, err := os.ReadFile(wholeOutput)
			if err != nil || !bytes.Equal(actual, want) {
				t.Fatalf("whole output differs outside the intended replacement: %v", err)
			}
			unchanged, err := os.ReadFile(sourcePath)
			if err != nil || !bytes.Equal(unchanged, image) {
				t.Fatalf("whole replacement changed the source: %v", err)
			}
			wholeRecipePath := filepath.Join(recipeDir, "whole.json")
			wholeData, err := json.Marshal(whole)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(wholeRecipePath, wholeData, 0600); err != nil {
				t.Fatal(err)
			}
			preview.Reset()
			if err := run([]string{"--source", sourcePath, "--recipes", wholeRecipePath}, &preview); err != nil || !bytes.Contains(preview.Bytes(), []byte(`"iso_file"`)) || bytes.Contains(preview.Bytes(), []byte(`"new_hex"`)) {
				t.Fatalf("whole-file CLI/report: %v", err)
			}
			for _, mutation := range []string{"name", "extent", "size", "source hash", "target hash", "bundle key", "bundle hash", "missing output hash", "malformed output hash", "mixed archives", "wrong operation", "wording selector", "sentinel transport", "draft import"} {
				t.Run(mutation, func(t *testing.T) {
					invalid := whole
					invalid.Files = maps.Clone(whole.Files)
					file := invalid.Files["SUB/OTHER"]
					switch mutation {
					case "name":
						delete(invalid.Files, "SUB/OTHER")
						invalid.Files["SUB/MISSING"] = file
					case "extent":
						file.SourceISOOffset++
					case "size":
						file.Size++
					case "source hash":
						file.SourceSHA256 = strings.Repeat("0", 64)
					case "target hash":
						file.TargetSHA256 = strings.Repeat("0", 64)
					case "bundle key":
						file.BundleKey = "missing"
					case "bundle hash":
						invalid.BundleSHA256 = strings.Repeat("0", 64)
					case "missing output hash":
						invalid.OutputSHA256 = ""
					case "malformed output hash":
						invalid.OutputSHA256 = "not a digest"
					case "mixed archives":
						invalid.Archives = recipe.Archives
					case "wording selector":
						invalid.WordingField = "jp"
					case "draft import":
						invalid.RegistryImport = &RegistryImportSpec{}
					case "sentinel transport":
						invalid.Sentinel = &SentinelLayout{RetailELFSize: 1920}
					case "wrong operation":
						invalid.Operation = "guarded_words"
					}
					if mutation != "name" {
						invalid.Files["SUB/OTHER"] = file
					}
					if got, err := plan([]Recipes{invalid}, Registry{}, nil, bytes.NewReader(image)); err == nil || got != nil {
						t.Fatalf("whole replacement accepted %s", mutation)
					}
				})
			}
			invalid := whole
			invalid.OutputSHA256 = strings.Repeat("0", 64)
			mismatchOutput := filepath.Join(dir, "wrong-final-hash.iso")
			if _, err := patchCopy(source, mismatchOutput, []Recipes{invalid}, fileEdits, Registry{}, nil); err == nil || !strings.Contains(err.Error(), "output hash mismatch") {
				t.Fatalf("accepted wrong final output digest: %v", err)
			}
			if _, err := os.Stat(mismatchOutput); !os.IsNotExist(err) {
				t.Fatal("output hash mismatch left a new image behind")
			}
			if err := validateEdits(append(slices.Clone(fileEdits), fileEdits[0]), int64(len(image))); err == nil {
				t.Fatal("accepted overlapping named-file edits")
			}
		})
	})

}

func TestPlanRefusals(t *testing.T) {
	for _, name := range []string{"registry import", "unknown authoring", "missing context", "independent prefix", "missing preimage", "missing encoding pin", "missing byte bound", "physical END", "body setup", "opaque payload", "scale prefix"} {
		r, registry, glyphs, image := fixture(t, "stream_reflow_format")
		row := r.Entries["0x100"]
		row.Authoring = "ordered"
		wantError := ""
		switch name {
		case "registry import":
			r.RegistryImport = &RegistryImportSpec{}
			wantError = "registry updates"
		case "unknown authoring":
			row.Authoring = "automatic"
		case "missing context":
			r.SourceContext = false
		case "independent prefix":
			row.PrefixWords = []string{"0x2800"}
		case "missing preimage":
			row.ExpectedHex = ""
		case "missing encoding pin":
			row.EncodedSHA256 = ""
		case "missing byte bound":
			row.MaxNewBytes = 0
		case "physical END":
			row.ExpectedHex = "040000f80000"
			data, _ := hex.DecodeString(row.ExpectedHex)
			copy(image[0x900:], data)
			wantError = "physical END"
		case "body setup", "opaque payload", "scale prefix":
			r.Layout.Columns, r.Layout.Rows = 0, 0
			row.MaxWidth, row.MaxLines = 100, 3
			var expected string
			switch name {
			case "body setup":
				row.ExpectedHex, registry.Entries[0].EN, expected = "04000140040000f8", "A{{STATE:0x4001}}B", "01000140020000f8"
				wantError = "unsupported control word"
			case "opaque payload":
				row.ExpectedHex, registry.Entries[0].EN, expected = "040000b0111100f800102222040000f8", "A{{PARAM:0xb000}}B", "010000b0111100f800102222020000f8"
				wantError = "unsupported control word"
			case "scale prefix":
				row.ExpectedHex, registry.Entries[0].EN, expected = "32e8040000f8", "{{INIT:0xe832}}A", "32e8010000f8"
				wantError = "layout needs"
			}
			old, _ := hex.DecodeString(row.ExpectedHex)
			next, _ := hex.DecodeString(expected)
			copy(image[0x900:], old)
			row.MaxNewBytes, row.EncodedSHA256 = len(next), fmt.Sprintf("%x", sha256.Sum256(next))
		}
		r.Entries["0x100"] = row
		r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
		before := bytes.Clone(image)
		if edits, err := plan([]Recipes{r}, registry, glyphs, bytes.NewReader(image)); err == nil || edits != nil || wantError != "" && !strings.Contains(err.Error(), wantError) || !bytes.Equal(image, before) {
			t.Fatal("ordered authoring bypassed a planner or native guard", name, err)
		}
	}
	for _, mode := range []string{"struct base", "struct offset", "both struct coordinates"} {
		r, registry, glyphs, image := fixture(t, "stream_append")
		if mode != "struct offset" {
			registry.Entries[0].RefSites[0].StructVMA = "0x1f0"
		}
		if mode != "struct base" {
			registry.Entries[0].RefSites[0].FieldOffset = "0x10"
		}
		if edits, err := plan([]Recipes{r}, registry, glyphs, bytes.NewReader(image)); err == nil || edits != nil || !strings.Contains(err.Error(), "struct coordinates require") {
			t.Fatal("append accepted unused struct metadata on data array", mode, err)
		}
	}
	{
		r, reg, glyphs, source := fixture(t, "stream_slot")
		for _, raw := range []json.RawMessage{nil, json.RawMessage(`null`), json.RawMessage(`""`), json.RawMessage(`3`), json.RawMessage(`{}`), json.RawMessage(`[]`), {34, 255, 34}} {
			reg.Entries[0].JP = raw
			r.WordingField = ""
			if _, err := plan([]Recipes{r}, reg, glyphs, bytes.NewReader(source)); err != nil {
				t.Fatalf("unselected JP changed English behavior: %s %v", raw, err)
			}
			r.WordingField = "jp"
			if _, err := plan([]Recipes{r}, reg, glyphs, bytes.NewReader(source)); err == nil {
				t.Fatalf("selected invalid JP fell back to English: %s", raw)
			}
		}
		reg.Entries[0].JP = json.RawMessage(`"<2800>A|B//"`)
		reg.Entries[0].EN = ""
		if _, err := plan([]Recipes{r}, reg, glyphs, bytes.NewReader(source)); err != nil {
			t.Fatal("JP selection incorrectly required English", err)
		}
		for _, selector := range []string{"en", "JP", "other"} {
			r.WordingField = selector
			if _, err := plan([]Recipes{r}, reg, glyphs, bytes.NewReader(source)); err == nil {
				t.Fatalf("accepted unknown explicit wording selector %q", selector)
			}
		}
		for _, operation := range []string{"same_length_stream", "fixed_field", "guarded_words", "stream_append", "registry_merge", "reference_candidates", "cmb_member_replace", "iso_file_replace"} {
			r.Operation, r.WordingField = operation, "jp"
			if _, err := plan([]Recipes{r}, reg, glyphs, bytes.NewReader(source)); err == nil {
				t.Fatalf("accepted JP selector on %s", operation)
			}
		}
	}
	{
		old := []byte{0, 0x28, 1, 0, 0, 0x70, 0, 8, 2, 0, 0, 0x10, 0, 0xf8, 0, 0}
		next := []byte{0, 0x28, 1, 0, 0, 0x70, 0, 8, 2, 0, 0, 0x10, 0, 0xf8, 0, 0}
		for _, mutation := range []string{"tail", "missing END", "partial word", "empty", "overlong", "argument", "argument moved", "break order", "setup", "param8", "opaque"} {
			bad := bytes.Clone(next)
			switch mutation {
			case "tail":
				bad[len(bad)-1] = 1
			case "missing END":
				clear(bad[12:14])
			case "partial word":
				bad = bad[:len(bad)-1]
			case "empty":
				bad = nil
			case "overlong":
				bad = append(bad, make([]byte, maxStreamBytes)...)
			case "argument":
				bad[4] = 1
			case "argument moved":
				copy(bad[2:6], []byte{0, 0x70, 1, 0})
			case "break order":
				bad[7], bad[11] = 0x10, 8
			case "setup":
				bad[2], bad[3] = 0x0a, 0xa8
			case "param8":
				bad[4], bad[5] = 0, 0x48
			case "opaque":
				bad[4], bad[5] = 0x92, 0xb9
			}
			if err := validateEdits([]Edit{{ID: "0x10", Offset: 16, Old: old, New: bad, Operation: "stream_slot"}}, int64(16+len(bad))); err == nil {
				t.Fatalf("slot accepted %s", mutation)
			}
		}
		for _, word := range []uint16{0xa80a, 0x4001, 0xb992, 0x4800, 0xb000, 0xd800} {
			left := binary.LittleEndian.AppendUint16(nil, word)
			left = append(left, 1, 0, 0, 0xf8, 0, 0)
			right := bytes.Clone(left)
			right[2] = 2
			if err := validateEdits([]Edit{{ID: "0x10", Offset: 16, Old: left, New: right, Operation: "stream_slot"}}, 64); err == nil {
				t.Fatalf("slot accepted unchanged unsupported control %#x", word)
			}
		}
		for _, size := range []int{maxStreamBytes - 2, maxStreamBytes, maxStreamBytes + 2} {
			left, right := make([]byte, size), make([]byte, size)
			copy(left, []byte{1, 0, 0, 0xf8})
			copy(right, []byte{2, 0, 0, 0xf8})
			if err := validateEdits([]Edit{{ID: "0x10", Offset: 16, Old: left, New: right, Operation: "stream_slot"}}, int64(16+size)); (err != nil) != (size > maxStreamBytes) {
				t.Fatalf("slot size boundary %d: %v", size, err)
			}
		}
		badTail := bytes.Clone(old)
		badTail[len(badTail)-1] = 1
		for _, pair := range [][2][]byte{{badTail, next}, {old, badTail}} {
			if err := validateEdits([]Edit{{ID: "0x10", Offset: 16, Old: pair[0], New: pair[1], Operation: "stream_slot"}}, 64); err == nil {
				t.Fatal("slot failed to validate both source and target tails")
			}
		}
		for _, operation := range []string{"same_length_stream", "exact_control_stream", "fixed_field"} {
			if err := validateEdits([]Edit{{ID: "0x10", Offset: 16, Old: old, New: next, Operation: operation}}, 64); err == nil {
				t.Fatalf("slot relaxed existing %s", operation)
			}
		}
		if _, err := controls(next, TextScanOptions{Padded: true, Terminated: true}); err == nil {
			t.Fatal("slot accepted padding without token validation")
		}
		r, registry, glyphs, image := fixture(t, "stream_slot")
		for _, mutation := range []string{"missing encoding", "changed encoding", "over capacity", "unknown control", "changed controls"} {
			bad := r
			bad.Entries = maps.Clone(r.Entries)
			row := bad.Entries["0x10"]
			text := registry.Entries[0].EN
			switch mutation {
			case "missing encoding":
				row.EncodedSHA256 = ""
			case "changed encoding":
				row.EncodedSHA256 = strings.Repeat("0", 64)
			case "over capacity":
				text = "<2800>" + strings.Repeat("A", 8) + "|B//"
				active := append([]byte{0, 0x28}, bytes.Repeat([]byte{1, 0}, 8)...)
				active = append(active, 0, 8, 2, 0, 0, 0x10, 0, 0xf8)
				row.EncodedSHA256 = fmt.Sprintf("%x", sha256.Sum256(active))
			case "unknown control":
				text = "<2800><a80a>A|B//"
				row.EncodedSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte{0, 0x28, 0x0a, 0xa8, 1, 0, 0, 8, 2, 0, 0, 0x10, 0, 0xf8}))
			case "changed controls":
				text = "<2800>A//B|"
				row.EncodedSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte{0, 0x28, 1, 0, 0, 0x10, 2, 0, 0, 8, 0, 0xf8}))
			}
			bad.Entries["0x10"] = row
			reg := Registry{Entries: slices.Clone(registry.Entries)}
			reg.Entries[0].EN = text
			if _, err := plan([]Recipes{bad}, reg, glyphs, bytes.NewReader(image)); err == nil {
				t.Fatalf("slot planner accepted %s", mutation)
			}
		}
	}
	for _, mode := range []string{"non-append", "missing landing", "unaligned landing", "overlapping landings", "installed neighbor overlap", "unselected neighbor overlap", "conflicting current landing", "changed scope", "duplicated pointer ranges"} {
		r, registry, glyphs, image := fixture(t, "stream_append")
		r.Placement = "registry_landing"
		r.ScopeSHA256 = placedPointerScope
		r.Stream.AllowedPointers = nil
		registry.Entries[0].LandingVMA = "0x04000030"
		registry.Entries[1].LandingVMA = "0x04000010"
		switch mode {
		case "non-append":
			r, registry, glyphs, image = fixture(t, "same_length_stream")
			r.Placement = "registry_landing"
		case "missing landing":
			registry.Entries[0].LandingVMA = ""
		case "unaligned landing":
			registry.Entries[0].LandingVMA = "0x04000031"
		case "overlapping landings":
			registry.Entries[0].LandingVMA = "0x04000010"
		case "installed neighbor overlap":
			registry.Entries[0].EN = " C"
			registry.Entries[1].EN = strings.Repeat("A", 16)
			binary.LittleEndian.PutUint32(image[0xa00:], 0x04000030)
			binary.LittleEndian.PutUint32(image[0xa04:], 0x04000030)
			copy(image[0x1030:], []byte{0, 0, 3, 0, 0, 0xf8})
			r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
		case "unselected neighbor overlap":
			r.Entries = map[string]Recipe{"0x110": r.Entries["0x110"]}
			registry.Entries[1].LandingVMA = "0x04000030"
			binary.LittleEndian.PutUint32(image[0xa00:], 0x04000030)
			binary.LittleEndian.PutUint32(image[0xa04:], 0x04000030)
			copy(image[0x1030:], []byte{0, 0, 0, 0, 3, 0, 0, 0xf8})
			scope := make([]byte, 0, 16)
			for _, word := range []uint32{0x110, 0x04000030, 1, 0x208} {
				scope = binary.LittleEndian.AppendUint32(scope, word)
			}
			r.ScopeSHA256 = fmt.Sprintf("%x", sha256.Sum256(scope))
			r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
		case "conflicting current landing":
			binary.LittleEndian.PutUint32(image[0xa00:], 0x04000020)
			binary.LittleEndian.PutUint32(image[0xa04:], 0x04000020)
			r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
		case "changed scope":
			registry.Entries[0].LandingVMA = "0x04000040"
		case "duplicated pointer ranges":
			r.Stream.AllowedPointers = []AddressRange{{Start: "0x200", End: "0x20c"}}
		}
		if edits, err := plan([]Recipes{r}, registry, glyphs, bytes.NewReader(image)); err == nil || edits != nil {
			t.Fatalf("accepted %s canonical landing: %+v, %v", mode, edits, err)
		}
	}
	{
		old := []byte{0x92, 0xb9, 1, 0, 0x50, 0xe8, 2, 0, 0, 0xf8}
		newBytes := []byte{0x92, 0xb9, 2, 0, 0x50, 0xe8, 3, 0, 0, 0xf8}
		for _, mode := range []string{"missing preimage", "missing pin", "changed pin", "prefix", "plain stream"} {
			r, registry, glyphs, image := fixture(t, "same_length_stream")
			r.Operation, registry.Entries[0].EN = "exact_control_stream", "<b992>B<e850>C"
			copy(image[16:], old)
			r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
			row := r.Entries["0x10"]
			row.ExpectedHex, row.EncodedSHA256 = hex.EncodeToString(old), fmt.Sprintf("%x", sha256.Sum256(newBytes))
			switch mode {
			case "missing preimage":
				row.ExpectedHex = ""
			case "missing pin":
				row.EncodedSHA256 = ""
			case "changed pin":
				row.EncodedSHA256 = strings.Repeat("0", 64)
			case "prefix":
				row.PrefixWords = []string{"0x2800"}
			case "plain stream":
				r.Operation = "same_length_stream"
			}
			r.Entries["0x10"] = row
			if edits, err := plan([]Recipes{r}, registry, glyphs, bytes.NewReader(image)); err == nil || edits != nil {
				t.Fatalf("accepted exact-control %s: %+v, %v", mode, edits, err)
			}
		}
		for _, variant := range [][]byte{
			{0x92, 0xb9, 2, 0, 0x51, 0xe8, 3, 0, 0, 0xf8}, // changed control
			{0x92, 0xb9, 2, 0, 3, 0, 0x50, 0xe8, 0, 0xf8}, // moved control
			{0x92, 0xb9, 2, 0, 0, 0xf8, 3, 0, 0, 0xf8},    // early END
			{0x92, 0xb9, 2, 0, 0x50, 0xe8, 3, 0, 4, 0},    // missing END
		} {
			if err := validateEdits([]Edit{{ID: "0x10", Offset: 16, Old: old, New: variant, Operation: "exact_control_stream"}}, 64); err == nil {
				t.Fatalf("accepted changed exact-control stream %x", variant)
			}
		}
		if _, err := controls(old, TextScanOptions{Terminated: true, ExactControls: true, Decode: true}); err == nil {
			t.Fatal("exact-control validation accepted decoder mode")
		}
	}
	for _, mode := range []string{"negative count", "oversized count", "missing count", "too few runs", "too many runs", "missing template", "missing encoding pin", "changed encoding pin", "missing byte cap", "short byte cap", "narrative context", "columns", "rows", "numeric arguments", "prefix", "flowing width", "flowing lines", "missing layout", "changed wording", "swapped labels", "empty label", "raw delimiter", "markup", "changed source", "hidden glyph", "after END"} {
		r, registry, glyphs, image := fixture(t, "stream_reflow_labels")
		row := r.Entries["0x100"]
		switch mode {
		case "negative count":
			row.LabelRuns = -1
		case "oversized count":
			row.LabelRuns = 4097
		case "missing count":
			row.LabelRuns = 0
		case "too few runs":
			row.LabelRuns = 1
		case "too many runs":
			row.LabelRuns = 3
		case "missing template":
			row.ExpectedHex = ""
		case "missing encoding pin":
			row.EncodedSHA256 = ""
		case "changed encoding pin":
			row.EncodedSHA256 = strings.Repeat("0", 64)
		case "missing byte cap":
			row.MaxNewBytes = 0
		case "short byte cap":
			row.MaxNewBytes = 16
		case "narrative context":
			r.SourceContext = true
		case "columns":
			r.Layout.Columns = 10
		case "rows":
			r.Layout.Rows = 2
		case "numeric arguments":
			row.NumericBounds = []*NumericRange{{Min: 1, Max: 2}}
		case "prefix":
			row.PrefixWords = []string{"0x2800"}
		case "flowing width":
			row.MaxWidth = 100
		case "flowing lines":
			row.MaxLines = 1
		case "missing layout":
			r.Layout = nil
		case "changed wording":
			registry.Entries[0].EN = "A / C"
		case "swapped labels":
			registry.Entries[0].EN = "C / AB"
		case "empty label":
			registry.Entries[0].EN = " / C"
		case "raw delimiter":
			registry.Entries[0].EN = "A/B / C"
		case "markup":
			registry.Entries[0].EN = "AB / {{PARAM:0xa000}}"
		case "changed source":
			image[0x900] = 1
		case "hidden glyph":
			binary.LittleEndian.PutUint16(image[0x908:], 4)
			row.ExpectedHex = hex.EncodeToString(image[0x900:0x910])
		case "after END":
			row.ExpectedHex += "0100"
		}
		r.Entries["0x100"] = row
		r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
		before := bytes.Clone(image)
		if edits, err := plan([]Recipes{r}, registry, glyphs, bytes.NewReader(image)); err == nil || edits != nil {
			t.Fatalf("accepted positional label %s: %+v, %v", mode, edits, err)
		}
		if !bytes.Equal(image, before) {
			t.Fatalf("positional refusal changed source: %s", mode)
		}
	}
	{
		forward := map[uint16]string{1: "A"}
		source := []byte{0, 0xb0, 1, 0, 0, 0xf8}
		shape, err := controls(source, TextScanOptions{Decode: true, Glyphs: forward, PositionalLabels: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := controls(source, TextScanOptions{Decode: true, Glyphs: forward}); err == nil {
			t.Fatal("positional decoding weakened default inline-PARAM8 grammar")
		}
		for _, mode := range []string{"no count", "negative count", "no source", "narrative source", "fixed field", "prefix", "wrapping", "payload", "no END"} {
			copyShape := shape
			copyShape.Tokens = slices.Clone(shape.Tokens)
			options := TextEncodeOptions{Terminated: true, Source: &copyShape, LabelRuns: 1}
			var prefix []string
			switch mode {
			case "no count":
				options.LabelRuns = 0
			case "negative count":
				options.LabelRuns = -1
			case "no source":
				options.Source = nil
			case "narrative source":
				copyShape.PositionalLabels = false
			case "fixed field":
				options.Terminated = false
			case "prefix":
				prefix = []string{"0x2800"}
			case "wrapping":
				options.Columns, options.Rows = 2, 1
			case "payload":
				copyShape.Tokens[0].Payload = make([]byte, 8)
			case "no END":
				copyShape.Tokens = copyShape.Tokens[:len(copyShape.Tokens)-1]
			}
			if got, err := encode("A", prefix, map[rune]uint16{'A': 1}, options); err == nil || got != nil {
				t.Fatalf("accepted positional encoder %s: %x, %v", mode, got, err)
			}
		}
		for _, mode := range []string{"advances", "HDR", "English", "numeric", "unterminated", "PAGE", "speaker", "setup", "PARAM8", "colour", "unknown glyph", "no END", "odd word", "tail"} {
			data := bytes.Clone(source)
			options := TextScanOptions{Terminated: true, PositionalLabels: true}
			switch mode {
			case "advances":
				options.Advances = map[uint16]int{1: 10}
			case "HDR":
				options.RequireHDR = true
			case "English":
				text := "A"
				options.English = &text
			case "numeric":
				options.NumericBounds = []*NumericRange{{Min: 1, Max: 2}}
			case "unterminated":
				options.Terminated = false
			case "PAGE":
				data[1] = 0x10
			case "speaker":
				data[1] = 0x38
			case "setup":
				data[1] = 0x40
			case "PARAM8":
				data[1] = 0x48
			case "colour":
				data[0] = 10
			case "unknown glyph":
				options.Terminated, options.Decode, options.Glyphs = false, true, forward
				data[2] = 2
			case "no END":
				data = data[:len(data)-2]
			case "odd word":
				data = data[:len(data)-1]
			case "tail":
				data = append(data, 1, 0)
			}
			if got, err := controls(data, options); err == nil || !reflect.DeepEqual(got, TextShape{}) {
				t.Fatalf("accepted positional scan %s: %+v, %v", mode, got, err)
			}
		}
	}
	for _, mode := range []string{"duplicate ID", "other pointer scope", "other landing scope", "mapping", "native window", "native font", "native spacing", "missing layout", "source pin", "glyph pin", "mixed words", "mixed growth", "incomplete sites", "unbounded number", "encoding pin"} {
		r, registry, glyphs, image := fixture(t, "stream_reflow_numeric")
		literal, numeric := r, r
		literal.SourceContext = false
		layout := *r.Layout
		layout.Columns, layout.Rows = 0, 0
		literal.Layout = &layout
		literal.Entries = map[string]Recipe{"0x110": r.Entries["0x110"]}
		numeric.Entries = map[string]Recipe{"0x100": r.Entries["0x100"]}
		literalProfile, numericProfile := *r.Stream, *r.Stream
		literalProfile.AllowedPointers = []AddressRange{{Start: "0x208", End: "0x20c"}}
		numericProfile.AllowedPointers = []AddressRange{{Start: "0x200", End: "0x208"}}
		literal.Stream, numeric.Stream = &literalProfile, &numericProfile
		message := ""
		switch mode {
		case "duplicate ID":
			numeric.Entries["00000110"] = literal.Entries["0x110"]
			message = "duplicate recipe ID"
		case "other pointer scope":
			literal.Stream.AllowedPointers = []AddressRange{{Start: "0x200", End: "0x208"}}
			numeric.Stream.AllowedPointers = []AddressRange{{Start: "0x200", End: "0x20c"}}
			message = "reference outside reviewed consumer ranges"
		case "other landing scope":
			literal.Stream.AllowedLandings = []AddressRange{{Start: "0x04000020", End: "0x04000030"}}
			numeric.Stream.AllowedLandings = []AddressRange{{Start: "0x04000010", End: "0x04000030"}}
			message = "target outside reviewed landing/capacity"
		case "mapping":
			numeric.ISOELFOffset = "0x1000"
			message = "incompatible native mapping"
		case "native window":
			numeric.Stream.LoaderVMAs = slices.Clone(numeric.Stream.LoaderVMAs)
			numeric.Stream.LoaderVMAs[0] = "0x44"
			message = "incompatible native stream profiles"
		case "native font":
			numeric.Layout.FontTableVMA = "0x404"
			message = "incompatible native font profiles"
		case "native spacing":
			words := make(map[string]string)
			for key, value := range numeric.Layout.SpaceWords {
				words[key] = value
			}
			words["0x50"] = "0x3c0241c0"
			numeric.Layout.SpaceWords = words
			message = "incompatible native font profiles"
		case "missing layout":
			numeric.SourceContext, numeric.Layout = false, nil
			message = "incompatible native mapping or layout"
		case "source pin":
			numeric.SourceSHA256 = strings.Repeat("0", 64)
			message = "incompatible source or glyphmap pins"
		case "glyph pin":
			numeric.GlyphmapSHA256 = strings.Repeat("0", 64)
			message = "incompatible source or glyphmap pins"
		case "mixed words":
			numeric.Operation, numeric.SourceContext, numeric.Stream, numeric.Layout = "guarded_words", false, nil, nil
			numeric.Entries = map[string]Recipe{"0x120": {ExpectedHex: "00000000", Words: []Word{{Hex: "0x0", Assembly: "nop"}}}}
			message = "append composes only with other append tables"
		case "mixed growth":
			numeric.Operation, numeric.SourceContext, numeric.Layout, numeric.Entries = "stream_grow", false, nil, nil
			numeric.Growth = &Growth{FromSectors: 1, ToSectors: 2}
			message = "growth requires one table"
		case "incomplete sites":
			registry.Entries[0].RefSites = registry.Entries[0].RefSites[1:]
			message = "incomplete raw pointer coverage"
		case "unbounded number":
			row := numeric.Entries["0x100"]
			row.NumericBounds = nil
			numeric.Entries["0x100"] = row
			message = "layout needs substitution/position semantics for 0x7000"
		case "encoding pin":
			row := numeric.Entries["0x100"]
			row.EncodedSHA256 = strings.Repeat("0", 64)
			numeric.Entries["0x100"] = row
			message = "canonical encoding differs from reviewed layout"
		}
		tables := []Recipes{literal, numeric}
		before := bytes.Clone(image)
		edits, err := plan(tables, registry, glyphs, bytes.NewReader(image))
		if err == nil || !strings.Contains(err.Error(), message) || edits != nil || !bytes.Equal(image, before) {
			t.Fatalf("composition refusal %s: %v", mode, err)
		}
		dir := t.TempDir()
		path, output := filepath.Join(dir, "source.iso"), filepath.Join(dir, "must-not-exist.iso")
		if err := os.WriteFile(path, image, 0600); err != nil {
			t.Fatal(err)
		}
		source, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		if _, err := patchCopy(source, output, tables, nil, registry, glyphs); err == nil || !strings.Contains(err.Error(), message) {
			t.Fatalf("composition writer refusal %s: %v", mode, err)
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatalf("composition refusal %s created output", mode)
		}
		original, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(original, before) {
			t.Fatalf("composition refusal %s changed source", mode)
		}
	}
	for _, mode := range []string{"unbounded", "null bound", "reversed", "too positive", "too negative", "unused bound", "native height", "short height", "negative height", "oversized height", "short copy", "short width", "missing pin", "missing layout", "other number format", "nested string"} {
		r, reg, glyphs, image := fixture(t, "stream_reflow_numeric")
		row := r.Entries["0x100"]
		switch mode {
		case "unbounded":
			row.NumericBounds = nil
		case "null bound":
			row.NumericBounds[0] = nil
		case "reversed":
			row.NumericBounds[0] = &NumericRange{Min: 11, Max: 10}
		case "too positive":
			row.NumericBounds[0].Max = 1000000000
		case "too negative":
			row.NumericBounds[0].Min = -1000000000
		case "unused bound":
			row.NumericBounds = append(row.NumericBounds, &NumericRange{})
		case "native height":
			row.MaxLines = 0
		case "short height":
			row.MaxLines = 2
		case "negative height":
			row.MaxLines = -1
		case "oversized height":
			row.MaxLines = maxStreamBytes/2 + 1
		case "short copy":
			row.MaxNewBytes -= 2
		case "short width":
			row.MaxWidth = 1
		case "missing pin":
			row.EncodedSHA256 = ""
		case "missing layout":
			r.Layout = nil
		case "other number format", "nested string":
			word := uint16(0x8800)
			if mode == "nested string" {
				word = 0xa000
			}
			binary.LittleEndian.PutUint16(image[0x902:], word)
			row.ExpectedHex = hex.EncodeToString(image[0x900:0x908])
			reg.Entries[0].EN = fmt.Sprintf("A {{PARAM:0x%04x}} B", word)
		}
		r.Entries["0x100"] = row
		r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
		before := bytes.Clone(image)
		if edits, err := plan([]Recipes{r}, reg, glyphs, bytes.NewReader(image)); err == nil || edits != nil {
			t.Errorf("numeric layout %s: expected complete refusal: %v", mode, err)
		}
		if !bytes.Equal(image, before) {
			t.Fatalf("numeric layout %s: source mutated", mode)
		}
	}
	for _, mode := range []string{"missing columns", "missing rows", "negative columns", "negative rows", "literal context", "unreviewed row", "missing byte limit", "unformatted pin", "changed wording"} {
		r, reg, glyphs, image := fixture(t, "stream_reflow_format")
		row := r.Entries["0x100"]
		switch mode {
		case "missing columns":
			r.Layout.Columns = 0
		case "missing rows":
			r.Layout.Rows = 0
		case "negative columns":
			r.Layout.Columns = -1
		case "negative rows":
			r.Layout.Rows = -1
		case "literal context":
			r.SourceContext = false
		case "unreviewed row":
			other := r.Entries["0x110"]
			other.EncodedSHA256 = ""
			r.Entries["0x110"] = other
		case "missing byte limit":
			row.MaxNewBytes = 0
		case "unformatted pin":
			row.EncodedSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte{1, 0, 0, 0, 2, 0, 0, 0xf8}))
		case "changed wording":
			reg.Entries[0].EN = "A C"
		}
		r.Entries["0x100"] = row
		before := bytes.Clone(image)
		if edits, err := plan([]Recipes{r}, reg, glyphs, bytes.NewReader(image)); err == nil || edits != nil {
			t.Errorf("character formatting %s: expected complete refusal: %v", mode, err)
		}
		if !bytes.Equal(image, before) {
			t.Fatalf("character formatting %s: source mutated", mode)
		}
	}
	for _, check := range []string{"missing layout", "unbounded value", "width", "pause", "speaker", "prefix", "glyph aliases"} {
		r, reg, glyphs, image := fixture(t, "stream_derived_context")
		wantError := ""
		switch check {
		case "missing layout":
			r.Layout = nil
			wantError = "requires stream append with measured layout"
		case "unbounded value":
			copy(image[0x900:], []byte{0, 0x28, 0x98, 0x39, 4, 0, 0, 0x90, 0, 0x10, 0, 0xf8})
			reg.Entries[0].EN = "AB{{PARAM:0x9000}}"
			wantError = "layout needs substitution/position semantics"
		case "width":
			reg.Entries[0].EN = strings.Repeat("B", 20)
			wantError = "reflow exceeds reviewed"
		case "pause":
			reg.Entries[0].EN = "AB//"
			wantError = "changed ordered controls"
		case "speaker":
			reg.Entries[0].EN = "[spk 0x39d3]AB"
			wantError = "changed ordered controls"
		case "prefix":
			row := r.Entries["0x100"]
			row.PrefixWords = []string{"0x2800"}
			r.Entries["0x100"] = row
			wantError = "without an independent prefix"
		case "glyph aliases":
			glyphs = []byte(`{"1":"A","0x1":"B","2":"B","3":"C","4":"あ"}`)
			r.GlyphmapSHA256 = fmt.Sprintf("%x", sha256.Sum256(glyphs))
			wantError = "conflicting source glyph aliases"
		}
		r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
		before := bytes.Clone(image)
		if _, err := plan([]Recipes{r}, reg, glyphs, bytes.NewReader(image)); err == nil || !strings.Contains(err.Error(), wantError) {
			t.Fatalf("source-context %s: %v; want %s", check, err, wantError)
		}
		if !bytes.Equal(image, before) {
			t.Fatalf("source-context refusal changed source: %s", check)
		}
	}

	for _, space := range []int{14, 24} {
		r, reg, glyphs, image := fixture(t, "stream_reflow")
		for text := range r.Layout.SpaceWords {
			vma, _ := number(text)
			word := binary.LittleEndian.Uint32(image[0x800+vma:]) & 0xffff0000
			word |= map[int]uint32{14: 0x4160, 24: 0x41c0}[space]
			binary.LittleEndian.PutUint32(image[0x800+vma:], word)
			r.Layout.SpaceWords[text] = fmt.Sprintf("0x%x", word)
		}
		state, err := inspect(bytes.NewReader(image), nil, &r)
		if err != nil || state.Advances[0] != space {
			t.Fatalf("native space%d: %v", space, err)
		}
		reg.Entries[0].EN = "A A"
		_, err = plan([]Recipes{r}, reg, glyphs, bytes.NewReader(image))
		if space == 14 && err != nil || space == 24 && (err == nil || !strings.Contains(err.Error(), "reflow exceeds reviewed")) {
			t.Fatalf("native space%d must change this width40/50 acceptance against JP44: %v", space, err)
		}
		reg.Entries[0].EN = "AB"
		if _, err := plan([]Recipes{r}, reg, glyphs, bytes.NewReader(image)); err != nil {
			t.Fatalf("space-free text must remain valid under native%d: %v", space, err)
		}
	}
	{
		r, reg, glyphs, image := fixture(t, "stream_reflow")
		old := []byte{4, 0, 0, 0x10, 4, 0, 0, 0xf8}
		newText := []byte{1, 0, 0, 0x10, 2, 0, 0, 0x10, 3, 0, 0, 0xf8}
		copy(image[0x900:], old)
		row := r.Entries["0x100"]
		row.ExpectedHex = hex.EncodeToString(old)
		row.EncodedSHA256 = fmt.Sprintf("%x", sha256.Sum256(newText))
		row.MaxNewBytes, row.MaxWidth, row.MaxLines = len(newText), 100, 3
		r.Entries["0x100"] = row
		reg.Entries[0].EN = "A//B//C"
		r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
		edits, err := plan([]Recipes{r}, reg, glyphs, bytes.NewReader(image))
		if err != nil {
			t.Fatalf("text-to-text PAGE reflow already supported: %v", err)
		}
		found := false
		for _, edit := range edits {
			if edit.ID == "0x100" && edit.Operation == "stream_payload" {
				found = bytes.Equal(edit.New, newText)
			}
		}
		if !found {
			t.Fatal("PAGE reflow did not plan exact pinned payload")
		}
		old = []byte{4, 0, 0, 0x10, 0, 0xf8}
		copy(image[0x900:], old)
		row.ExpectedHex = hex.EncodeToString(old)
		r.Entries["0x100"] = row
		r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
		if _, err := plan([]Recipes{r}, reg, glyphs, bytes.NewReader(image)); err == nil || !strings.Contains(err.Error(), "changed ordered controls") {
			t.Fatalf("PAGE before END remains a guarded boundary: %v", err)
		}
		old = []byte{4, 0, 0, 0xf8}
		copy(image[0x900:], old)
		row.ExpectedHex = hex.EncodeToString(old)
		r.Entries["0x100"] = row
		r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
		if _, err := plan([]Recipes{r}, reg, glyphs, bytes.NewReader(image)); err == nil || !strings.Contains(err.Error(), "introduces unsupported pages") {
			t.Fatalf("page reflow cannot introduce the first page: %v", err)
		}
	}
	for _, mutation := range []string{"source pointer", "copy bounds", "explicit width", "explicit height", "numeric bounds", "encoded pin", "block width", "block height", "block numeric bounds", "block encoded pin", "block source", "block copy", "no words", "short old", "empty assembly", "bad word", "overlarge word", "prefix", "missing value", "unused value", "invalid value", "empty value name", "unaligned fixup", "outside fixup", "duplicate fixup", "bad fixup number", "zero width", "large width", "large shift", "nonzero field", "text downgrade", "text words without values", "text fixups without values", "wrong target", "large lsb", "field overflow", "unknown block", "unused block", "nested block", "block old bytes", "block text prefix", "empty block", "empty block name", "block fixup outside prefix", "block fixup alias", "block bad word", "text use", "text blocks"} {
		t.Run("words/"+mutation, func(t *testing.T) {
			r, reg, glyphs, image := fixture(t, "guarded_words")
			row := r.Entries["0x20"]
			fixup := row.Fixups["0x0"]
			switch mutation {
			case "source pointer":
				row.SourcePointer = "0x04000000"
			case "copy bounds":
				row.MaxNewBytes, row.ReadBytes = 18, 18
			case "explicit width":
				row.MaxWidth = 100
			case "explicit height":
				row.MaxLines = 3
			case "numeric bounds":
				row.NumericBounds = []*NumericRange{{Min: 1, Max: 10}}
			case "encoded pin":
				row.EncodedSHA256 = strings.Repeat("0", 64)
			case "large lsb":
				fixup.LSB = 32
				row.Fixups["0x0"] = fixup
			case "field overflow":
				fixup.LSB = 17
				row.Fixups["0x0"] = fixup
			case "unknown block":
				row.Use = "missing"
			case "block width", "block height", "block numeric bounds", "block encoded pin", "block source", "block copy", "unused block", "nested block", "block old bytes", "block text prefix", "empty block", "empty block name", "block fixup outside prefix", "block fixup alias", "block bad word":
				block := Recipe{Words: slices.Clone(row.Words[:1]), Fixups: map[string]WordFixup{"0x0": fixup}}
				row.Use, row.Words = "shared", slices.Clone(row.Words[1:])
				row.Fixups = map[string]WordFixup{"0x4": row.Fixups["0x4"]}
				switch mutation {
				case "block width":
					block.MaxWidth = 100
				case "block height":
					block.MaxLines = 3
				case "block numeric bounds":
					block.NumericBounds = []*NumericRange{{Min: 1, Max: 10}}
				case "block encoded pin":
					block.EncodedSHA256 = strings.Repeat("0", 64)
				case "block source":
					block.SourcePointer = "0x04000000"
				case "block copy":
					block.MaxNewBytes, block.ReadBytes = 18, 18
				case "unused block":
					row.Use = ""
					row.Words = append(slices.Clone(block.Words), row.Words...)
					row.Fixups["0x0"] = fixup
				case "nested block":
					block.Use = "shared"
				case "block old bytes":
					block.ExpectedHex = "cccccccc"
				case "block text prefix":
					block.PrefixWords = []string{"0x2800"}
				case "empty block":
					block.Words = nil
				case "empty block name":
					row.Use = ""
				case "block fixup outside prefix":
					delete(block.Fixups, "0x0")
					block.Fixups["0x4"] = fixup
				case "block fixup alias":
					row.Fixups["0X0000"] = fixup
				case "block bad word":
					block.Words[0].Hex = "0x100000000"
				}
				r.WordBlocks = map[string]Recipe{row.Use: block}
				if mutation == "unused block" {
					r.WordBlocks = map[string]Recipe{"unused": block}
				}
			case "text use", "text blocks":
				r.Operation, r.Values = "fixed_field", nil
				row = Recipe{ExpectedHex: "04000000"}
				reg.Entries = []RegistryEntry{{ID: "0x20", EN: "A"}}
				if mutation == "text use" {
					row.Use = "shared"
				} else {
					r.WordBlocks = map[string]Recipe{"shared": {Words: []Word{{Hex: "0x0", Assembly: "nop"}}}}
				}
			case "no words":
				row.Words = nil
			case "short old":
				row.ExpectedHex = "cccccccc"
			case "empty assembly":
				row.Words[0].Assembly = ""
			case "bad word":
				row.Words[0].Hex = "oops"
			case "overlarge word":
				row.Words[0].Hex = "0x100000000"
			case "prefix":
				row.PrefixWords = []string{"0x2800"}
			case "missing value":
				fixup.Value = "absent"
				row.Fixups["0x0"] = fixup
			case "unused value":
				r.Values["unused"] = "0x0"
			case "invalid value":
				r.Values["allocation"] = "0x100000000"
			case "empty value name":
				r.Values[""] = "0x0"
			case "unaligned fixup":
				delete(row.Fixups, "0x0")
				row.Fixups["0x1"] = fixup
			case "outside fixup":
				delete(row.Fixups, "0x0")
				row.Fixups["0x8"] = fixup
			case "duplicate fixup":
				row.Fixups["0X0000"] = fixup
			case "bad fixup number":
				row.Fixups["-1"] = fixup
			case "zero width":
				fixup.Bits = 0
				row.Fixups["0x0"] = fixup
			case "large width":
				fixup.Bits = 33
				row.Fixups["0x0"] = fixup
			case "large shift":
				fixup.Shift = 32
				row.Fixups["0x0"] = fixup
			case "nonzero field":
				row.Words[0].Hex = "0x3c050001"
			case "text downgrade":
				r.Operation = "fixed_field"
			case "text words without values", "text fixups without values":
				r.Operation, r.Values = "fixed_field", nil
				row.ExpectedHex = "04000000"
				reg.Entries = []RegistryEntry{{ID: "0x20", EN: "A"}}
				if mutation == "text words without values" {
					row.Fixups = nil
				} else {
					row.Words = nil
				}
			case "wrong target":
				delete(r.Entries, "0x20")
				r.Entries["0x22"] = row
			}
			if mutation != "wrong target" {
				r.Entries["0x20"] = row
			}
			if _, err := plan([]Recipes{r}, reg, glyphs, nil); err == nil {
				t.Fatalf("accepted invalid words %s", mutation)
			}
			dir := t.TempDir()
			path, output := filepath.Join(dir, "source.iso"), filepath.Join(dir, "refused.iso")
			if err := os.WriteFile(path, image, 0600); err != nil {
				t.Fatal(err)
			}
			source, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			if _, err := patchCopy(source, output, []Recipes{r}, nil, reg, glyphs); err == nil {
				t.Fatal("writer accepted invalid words")
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("created invalid word output")
			}
			unchanged, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(unchanged, image) {
				t.Fatal("word refusal changed source")
			}
		})
	}
	for _, operation := range []string{"stream_grow", "stream_allocate"} {
		for _, mutation := range []string{"missing growth", "bootstrap", "equal target", "shrink", "signed target", "no margin", "entries", "layout", "mixed tables", "no source", "bad scan range", "omitted loader site", "stray LUI", "stray ORI", "stray ADDIU", "future loader", "torn disc", "oversized disc", "bad PVD", "bad block endian", "short root", "not directory root", "bad record length", "bad name length", "bad record endian", "bad sequence endian", "bad name identity", "missing allocation record", "nested extent overlap", "margin overlap", "extent outside source", "directory alias", "interleaved", "multiextent", "record padding", "duplicate name", "stale operand done", "bad self reference", "bad parent reference", "special file", "missing self", "volume endian", "volume size", "path size endian", "missing path table", "path outside volume", "path table overlap", "optional path overlap", "nonzero padding", "claimed padding", "readiness fields"} {
			if operation == "stream_allocate" && slices.Contains([]string{"signed target", "no margin", "omitted loader site", "stray LUI", "stray ORI", "stray ADDIU", "future loader", "stale operand done", "margin overlap", "optional path overlap"}, mutation) {
				continue
			}
			t.Run(operation+"/"+mutation, func(t *testing.T) {
				r, reg, glyphs, image := fixture(t, operation)
				tables := []Recipes{r}
				reader := io.ReaderAt(bytes.NewReader(image))
				switch mutation {
				case "nonzero padding":
					image[0x10310] = 1
				case "claimed padding":
					binary.LittleEndian.PutUint32(image[0x884e:], 0x800)
					binary.BigEndian.PutUint32(image[0x8852:], 0x800)
				case "readiness fields":
					r.Stream.LoaderVMAs = []string{"0x10"}
				case "missing growth":
					r.Growth = nil
				case "bootstrap":
					if operation == "stream_allocate" {
						r.Growth.FromSectors = 1
					} else {
						r.Growth.FromSectors = 0
					}
				case "equal target":
					r.Growth.ToSectors = r.Growth.FromSectors
				case "shrink":
					r.Growth.FromSectors, r.Growth.ToSectors = 3, 1
				case "signed target":
					r.Growth.ToSectors = 0x8000
				case "no margin":
					r.Growth.ToSectors = 20
				case "entries":
					r.Entries = map[string]Recipe{"0x100": {ExpectedHex: "040000f8"}}
				case "layout":
					r.Layout = &Layout{FontTableVMA: "0x400"}
				case "mixed tables":
					tables = append(tables, r)
				case "no source":
					reader = nil
				case "bad scan range":
					r.Growth.LoaderRange.End = "0x311"
				case "omitted loader site":
					r.Growth.LoaderRange.Start = "0x14"
				case "stray LUI":
					binary.LittleEndian.PutUint32(image[0x10044:], 0x3c060000)
					r.Growth.LoaderRange.End = "0x48"
				case "stray ORI":
					binary.LittleEndian.PutUint32(image[0x10044:], 0x34a50800)
					r.Growth.LoaderRange.End = "0x48"
				case "stray ADDIU":
					binary.LittleEndian.PutUint32(image[0x10044:], 0x24060001)
					r.Growth.LoaderRange.End = "0x48"
				case "future loader":
					binary.LittleEndian.PutUint32(image[0x10014:], 0x34a51800)
					binary.LittleEndian.PutUint32(image[0x10018:], 0x240e0003)
					binary.LittleEndian.PutUint32(image[0x1001c:], 0x240e0003)
				case "torn disc":
					image[0x884e] ^= 1
				case "oversized disc":
					for offset, value := range map[int]uint32{0x884e: 0x8000, 0x8874: 48, 0x887c: 0x8000} {
						binary.LittleEndian.PutUint32(image[offset:], value)
						binary.BigEndian.PutUint32(image[offset+4:], value)
					}
				case "stale operand done":
					for offset, value := range map[int]uint32{0x884e: 0x2000, 0x8874: 36, 0x887c: 0xe000} {
						binary.LittleEndian.PutUint32(image[offset:], value)
						binary.BigEndian.PutUint32(image[offset+4:], value)
					}
					for offset, value := range map[int]uint32{0x10014: 0x34a51800, 0x10018: 0x240e0003, 0x1001c: 0x240e0003, 0x10044: 0x24060001} {
						binary.LittleEndian.PutUint32(image[offset:], value)
					}
					r.Growth.LoaderRange.End = "0x48"
				case "bad self reference":
					binary.LittleEndian.PutUint32(image[0x8802:], 18)
					binary.BigEndian.PutUint32(image[0x8806:], 18)
					image[0x88b7] = 0
					binary.LittleEndian.PutUint32(image[0x9046:], 35)
					binary.BigEndian.PutUint32(image[0x904a:], 35)
				case "bad parent reference":
					binary.LittleEndian.PutUint32(image[0x9024:], 18)
					binary.BigEndian.PutUint32(image[0x9028:], 18)
				case "special file":
					image[0x9019] = 0
				case "missing self":
					image[0x9021] = 'X'
				case "volume endian":
					image[0x8054] ^= 1
				case "volume size":
					binary.LittleEndian.PutUint32(image[0x8050:], 63)
					binary.BigEndian.PutUint32(image[0x8054:], 63)
				case "path size endian":
					image[0x8088] ^= 1
				case "missing path table":
					clear(image[0x808c:0x8090])
				case "path outside volume":
					binary.LittleEndian.PutUint32(image[0x808c:], 64)
				case "path table overlap":
					binary.LittleEndian.PutUint32(image[0x808c:], 35)
					binary.BigEndian.PutUint32(image[0x8094:], 35)
				case "optional path overlap":
					binary.LittleEndian.PutUint32(image[0x8090:], 40)
				case "bad PVD":
					image[0x8001] = 'X'
				case "bad block endian":
					image[0x8082] ^= 1
				case "short root":
					image[0x809c] = 10
				case "not directory root":
					image[0x80b5] = 0
				case "bad record length":
					image[0x9044] = 33
				case "bad name length":
					image[0x9064] = 255
				case "bad record endian":
					image[0x904a] ^= 1
				case "bad sequence endian":
					image[0x9062] ^= 1
				case "bad name identity":
					image[0x8865] = 'X'
				case "missing allocation record":
					r.Stream.ELFRecordOffset = "0x100"
				case "nested extent overlap", "margin overlap", "extent outside source":
					lba := uint32(35)
					if mutation == "margin overlap" {
						lba = 40
					}
					if mutation == "extent outside source" {
						lba = 0xffffffff
					}
					binary.LittleEndian.PutUint32(image[0x9046:], lba)
					binary.BigEndian.PutUint32(image[0x904a:], lba)
				case "directory alias":
					binary.LittleEndian.PutUint32(image[0x88a0:], 17)
					binary.BigEndian.PutUint32(image[0x88a4:], 17)
				case "interleaved":
					image[0x905e] = 1
				case "multiextent":
					image[0x905d] = 128
				case "record padding":
					image[0x90ff] = 1
				case "duplicate name":
					copy(image[0x9065:], []byte{0})
					image[0x9064] = 1
				}
				r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
				tables[0] = r
				if _, err := plan(tables, reg, glyphs, reader); err == nil {
					t.Fatalf("accepted invalid growth %s", mutation)
				}
				dir := t.TempDir()
				path, output := filepath.Join(dir, "source.iso"), filepath.Join(dir, "refused.iso")
				if err := os.WriteFile(path, image, 0600); err != nil {
					t.Fatal(err)
				}
				source, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
				if mutation != "no source" {
					if _, err := patchCopy(source, output, tables, nil, reg, glyphs); err == nil {
						t.Fatal("writer accepted invalid growth")
					}
					if _, err := os.Stat(output); !os.IsNotExist(err) {
						t.Fatal("created invalid growth output")
					}
				}
				unchanged, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(unchanged, image) {
					t.Fatal("source changed during refusal")
				}
			})
		}
	}
	cases := map[string]func(*Recipes, *Registry){
		"non-append source context": func(r *Recipes, _ *Registry) { r.SourceContext = true },
		"wrong operation":           func(r *Recipes, _ *Registry) { r.Operation = "relocate" },
		"no recipes":                func(r *Recipes, _ *Registry) { r.Entries = nil },
		"missing entry":             func(_ *Recipes, r *Registry) { r.Entries = nil },
		"duplicate registry ID":     func(_ *Recipes, r *Registry) { r.Entries = append(r.Entries, r.Entries[0]); r.Entries[1].ID = "0X0010" },
		"invalid ID":                func(_ *Recipes, r *Registry) { r.Entries[0].ID = "bad-id" },
		"ID overflow": func(r *Recipes, reg *Registry) {
			r.Entries = map[string]Recipe{"0xfffffffe": r.Entries["0x10"]}
			reg.Entries[0].ID = "0xfffffffe"
		},
		"invalid recipe ID":    func(r *Recipes, _ *Registry) { r.Entries = map[string]Recipe{"-0x10": r.Entries["0x10"]} },
		"target below mapping": func(r *Recipes, _ *Registry) { r.ELFVMADelta = "0x20" },
		"too long":             func(_ *Recipes, r *Registry) { r.Entries[0].EN = "AB" },
		"missing glyph":        func(_ *Recipes, r *Registry) { r.Entries[0].EN = "?" },
		"control changed":      func(_ *Recipes, r *Registry) { r.Entries[0].EN = "|" },
		"unsupported colour":   func(_ *Recipes, r *Registry) { r.Entries[0].EN = "{{HL:0xb000}}" },
		"added PARAM":          func(_ *Recipes, r *Registry) { r.Entries[0].EN = "{{PARAM:0xa000}}" },
		"midstream speaker":    func(_ *Recipes, r *Registry) { r.Entries[0].EN = "A[spk 0x3a87]" },
		"added page":           func(_ *Recipes, r *Registry) { r.Entries[0].EN = "//" },
		"removed page": func(r *Recipes, reg *Registry) {
			r.Entries["0x10"] = Recipe{ExpectedHex: "04000010040000f8", Evidence: "page-bearing source"}
			reg.Entries[0].EN = "ABC"
		},
		"page replaced by line": func(r *Recipes, reg *Registry) {
			r.Entries["0x10"] = Recipe{ExpectedHex: "04000010040000f8", Evidence: "page-bearing source"}
			reg.Entries[0].EN = "A|B"
		},
		"bad speaker":      func(_ *Recipes, r *Registry) { r.Entries[0].EN = "[spk 0xf800]" },
		"bad source pin":   func(r *Recipes, _ *Registry) { r.SourceSHA256 = "00" },
		"wrong glyph pin":  func(r *Recipes, _ *Registry) { r.GlyphmapSHA256 = strings.Repeat("0", 64) },
		"negative size":    func(r *Recipes, _ *Registry) { r.SourceSize = -1 },
		"bad mapping":      func(r *Recipes, _ *Registry) { r.ISOELFOffset = "bogus" },
		"negative mapping": func(r *Recipes, _ *Registry) { r.ELFVMADelta = "-1" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r, registry, glyphs, _ := fixture(t, "same_length_stream")
			mutate(&r, &registry)
			if _, err := plan([]Recipes{r}, registry, glyphs, nil); err == nil {
				t.Fatal("accepted invalid input")
			}
		})
	}
	for name, value := range map[string]Recipe{
		"empty evidence":  {ExpectedHex: "040000f8"},
		"odd bytes":       {ExpectedHex: "0400f8", Evidence: "test"},
		"bad hex":         {ExpectedHex: "oops", Evidence: "test"},
		"empty stream":    {Evidence: "test"},
		"early END":       {ExpectedHex: "00f80400", Evidence: "test"},
		"no END":          {ExpectedHex: "04000400", Evidence: "test"},
		"unknown control": {ExpectedHex: "002000f8", Evidence: "test"},
		"bad prefix":      {ExpectedHex: "040000f8", PrefixWords: []string{"0xb000"}, Evidence: "test"},
	} {
		t.Run(name, func(t *testing.T) {
			r, registry, glyphs, _ := fixture(t, "same_length_stream")
			r.Entries["0x10"] = value
			if _, err := plan([]Recipes{r}, registry, glyphs, nil); err == nil {
				t.Fatal("accepted invalid recipe")
			}
		})
	}
	for _, text := range []string{"", "ABC", "A|", "{{HL:0xb001}}A", "[spk 0x3a87]A", "A//", "<a000>", "{{PARAM:0xa000}}", "<0001>"} {
		r, reg, glyphs, _ := fixture(t, "same_length_stream")
		r.Operation, reg.Entries[0].EN = "fixed_field", text
		recipe := r.Entries["0x10"]
		recipe.ExpectedHex = "04000000"
		r.Entries["0x10"] = recipe
		if _, err := plan([]Recipes{r}, reg, glyphs, nil); err == nil {
			t.Fatalf("accepted fixed-field overflow/markup: %q", text)
		}
	}
	if got, err := encode("", nil, nil, TextEncodeOptions{ExactControls: true}); err == nil || got != nil {
		t.Fatal("empty literal skipped incompatible opaque policy", got, err)
	}
	// These glyphs deliberately make unsupported control notation encodable as text.
	literalGlyphs := map[rune]uint16{'<': 1, '>': 2, 'a': 3, 'x': 4, '0': 5, 'f': 6, '8': 7}
	for _, text := range []string{"<4800>", "<0xd800>", "<e000>", "<5000>", "<d82e>", "<d831>", "<d836>", "<d839>", "<d83c>", "<d87f>", "<e04b>", "<f800>", "<broken>", "<0xa000", "<a0000>", "<07ff>", "{{PARAM:0xb001}}", "{{HL:0xa000}}", "A<3800>", " <3800>", "<b001><3800>", "A<2800>"} {
		if _, err := encode(text, nil, literalGlyphs, TextEncodeOptions{Terminated: true}); err == nil {
			t.Fatalf("encoded unsupported markup as glyphs: %q", text)
		}
	}
	for _, pair := range [][2]string{
		{"0070008800a000f8", "0088007000a000f8"},
		{"0038010000f8", "0100003800f8"},
		{"010000100138020000f8", "010001380010020000f8"},
	} {
		old, err := hex.DecodeString(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		newBytes, err := hex.DecodeString(pair[1])
		if err != nil {
			t.Fatal(err)
		}
		if err := validateEdits([]Edit{{ID: "0x10", Offset: 16, Old: old, New: newBytes, Operation: "same_length_stream"}}, 64); err == nil {
			t.Fatal("accepted reordered arguments or relocated speaker")
		}
	}
	for _, edit := range []Edit{
		{ID: "0x30", Offset: 16, Old: []byte{0, 0}, New: []byte{0, 0}, Operation: "stream_pointer"},
		{ID: "0x30", Offset: 16, Old: []byte{0}, New: []byte{0}, Operation: "stream_padding"},
		{ID: "0x30", Offset: 16, Old: []byte{1, 0}, New: []byte{0, 0}, Operation: "stream_padding"},
		{ID: "0x30", Offset: 16, Old: []byte{0, 0}, New: []byte{1, 0}, Operation: "stream_padding"},
		{ID: "0x30", Offset: 16, Old: []byte{0x30, 0, 0, 0}, New: []byte{0x31, 0, 0, 0}, Operation: "pointer_check"},
		{ID: "0x30", Offset: 18, Old: []byte{0x30, 0, 0, 0}, New: []byte{0x30, 0, 0, 0}, Operation: "pointer_check"},
		{ID: "0x30", Offset: 16, Old: []byte{0x31, 0, 0, 0}, New: []byte{0x31, 0, 0, 0}, Operation: "pointer_check"},
		{ID: "0x30", Offset: 16, Old: []byte{0x30, 0, 0, 0}, New: []byte{0x30, 0, 0, 0}},
	} {
		if err := validateEdits([]Edit{edit}, 64); err == nil {
			t.Fatal("accepted invalid pointer check or unknown operation")
		}
	}
	for operation, cases := range map[string]map[string]func(*Recipes, *Registry, []byte){
		"stream_source": {
			"missing frozen preimage": func(r *Recipes, _ *Registry, _ []byte) {
				row := r.Entries["0x100"]
				row.ExpectedHex = ""
				r.Entries["0x100"] = row
			},
			"missing explicit origin": func(r *Recipes, _ *Registry, _ []byte) {
				row := r.Entries["0x100"]
				row.SourcePointer = ""
				r.Entries["0x100"] = row
			},
			"bad origin number": func(r *Recipes, _ *Registry, _ []byte) {
				row := r.Entries["0x100"]
				row.SourcePointer = "bad"
				r.Entries["0x100"] = row
			},
			"origin over32bits": func(r *Recipes, _ *Registry, _ []byte) {
				row := r.Entries["0x100"]
				row.SourcePointer = "0x100000000"
				r.Entries["0x100"] = row
			},
			"origin below sentinel": func(r *Recipes, _ *Registry, _ []byte) {
				row := r.Entries["0x100"]
				row.SourcePointer = "0x100"
				r.Entries["0x100"] = row
			},
			"unaligned origin": func(r *Recipes, _ *Registry, _ []byte) {
				row := r.Entries["0x100"]
				row.SourcePointer = "0x04000002"
				r.Entries["0x100"] = row
			},
			"origin outside blob": func(r *Recipes, _ *Registry, _ []byte) {
				row := r.Entries["0x100"]
				row.SourcePointer = "0x04000800"
				r.Entries["0x100"] = row
			},
			"changed JP source":          func(_ *Recipes, _ *Registry, image []byte) { image[0x1000] = 3 },
			"obsolete raw ID reference":  func(_ *Recipes, _ *Registry, image []byte) { binary.LittleEndian.PutUint32(image[0xa10:], 0x100) },
			"source raw word collision":  func(_ *Recipes, _ *Registry, image []byte) { binary.LittleEndian.PutUint32(image[0xa10:], 0x04000000) },
			"mixed source references":    func(_ *Recipes, _ *Registry, image []byte) { binary.LittleEndian.PutUint32(image[0xa00:], 0x04000020) },
			"missing struct base":        func(_ *Recipes, reg *Registry, _ []byte) { reg.Entries[0].RefSites[0].StructVMA = "" },
			"missing struct offset":      func(_ *Recipes, reg *Registry, _ []byte) { reg.Entries[0].RefSites[0].FieldOffset = "" },
			"changed struct coordinates": func(_ *Recipes, reg *Registry, _ []byte) { reg.Entries[0].RefSites[0].FieldOffset = "0x18" },
			"unaligned struct base":      func(_ *Recipes, reg *Registry, _ []byte) { reg.Entries[0].RefSites[0].StructVMA = "0x1f1" },
			"bad struct offset":          func(_ *Recipes, reg *Registry, _ []byte) { reg.Entries[0].RefSites[0].FieldOffset = "nope" },
			"struct without copy contract": func(r *Recipes, _ *Registry, _ []byte) {
				row := r.Entries["0x100"]
				row.MaxNewBytes, row.ReadBytes = 0, 0
				r.Entries["0x100"] = row
			},
			"negative encoded bound": func(r *Recipes, _ *Registry, _ []byte) {
				row := r.Entries["0x100"]
				row.MaxNewBytes = -2
				r.Entries["0x100"] = row
			},
			"negative readable bound": func(r *Recipes, _ *Registry, _ []byte) {
				row := r.Entries["0x100"]
				row.ReadBytes = -2
				r.Entries["0x100"] = row
			},
			"odd encoded bound": func(r *Recipes, _ *Registry, _ []byte) {
				row := r.Entries["0x100"]
				row.MaxNewBytes = 17
				r.Entries["0x100"] = row
			},
			"odd readable bound": func(r *Recipes, _ *Registry, _ []byte) {
				row := r.Entries["0x100"]
				row.ReadBytes = 19
				r.Entries["0x100"] = row
			},
			"oversize readable bound": func(r *Recipes, _ *Registry, _ []byte) {
				row := r.Entries["0x100"]
				row.ReadBytes = 8194
				r.Entries["0x100"] = row
			},
			"encoded bound without read bound": func(r *Recipes, _ *Registry, _ []byte) {
				row := r.Entries["0x100"]
				row.ReadBytes = 0
				r.Entries["0x100"] = row
			},
			"read bound without encoded bound": func(r *Recipes, _ *Registry, _ []byte) {
				row := r.Entries["0x100"]
				row.MaxNewBytes = 0
				r.Entries["0x100"] = row
			},
			"encoded exceeds read bound": func(r *Recipes, _ *Registry, _ []byte) {
				row := r.Entries["0x100"]
				row.MaxNewBytes = 20
				r.Entries["0x100"] = row
			},
			"canonical encoding exceeds copy":             func(_ *Recipes, reg *Registry, _ []byte) { reg.Entries[0].EN = "AAAAAAAAA" },
			"encoded fits but read span exceeds capacity": func(_ *Recipes, _ *Registry, image []byte) { image[0x17e0] = 1 },
			"landing excludes read tail": func(r *Recipes, _ *Registry, _ []byte) {
				r.Stream.AllowedLandings = []AddressRange{{Start: "0x04000020", End: "0x04000030"}}
			},
			"done nonzero read tail": func(_ *Recipes, _ *Registry, image []byte) {
				binary.LittleEndian.PutUint32(image[0xa00:], 0x04000020)
				binary.LittleEndian.PutUint32(image[0xa04:], 0x04000020)
				copy(image[0x1020:], append(bytes.Repeat([]byte{1, 0}, 7), 0, 0xf8))
				image[0x1030] = 1
				binary.LittleEndian.PutUint16(image[0x103e:], 0xf800)
			},
			"done missing reservation bookend": func(_ *Recipes, _ *Registry, image []byte) {
				binary.LittleEndian.PutUint32(image[0xa00:], 0x04000020)
				binary.LittleEndian.PutUint32(image[0xa04:], 0x04000020)
				copy(image[0x1020:], append(bytes.Repeat([]byte{1, 0}, 7), 0, 0xf8))
			},
			"origin readable span crosses blob": func(r *Recipes, _ *Registry, image []byte) {
				row := r.Entries["0x100"]
				row.SourcePointer = "0x040007f0"
				r.Entries["0x100"] = row
				copy(image[0x17f0:], []byte{4, 0, 0, 0xf8})
				binary.LittleEndian.PutUint32(image[0xa00:], 0x040007f0)
				binary.LittleEndian.PutUint32(image[0xa04:], 0x040007f0)
			},
		},
		"stream_append": {
			"derived no END": func(r *Recipes, _ *Registry, image []byte) { r.Entries["0x100"] = Recipe{}; clear(image[0x900:0xb10]) },
			"derived outside ELF": func(r *Recipes, reg *Registry, _ []byte) {
				delete(r.Entries, "0x100")
				r.Entries["0xfffffffe"] = Recipe{}
				reg.Entries[0].ID = "0xfffffffe"
			},
			"derived unsupported source": func(r *Recipes, _ *Registry, image []byte) {
				r.Entries["0x100"] = Recipe{}
				image[0x900], image[0x901] = 0x6e, 0xd8
			},
			"profile absent":   func(r *Recipes, _ *Registry, _ []byte) { r.Stream = nil },
			"retail extent":    func(r *Recipes, _ *Registry, _ []byte) { r.Stream.RetailELFSize = 8192 },
			"directory offset": func(r *Recipes, _ *Registry, _ []byte) { r.Stream.ELFRecordOffset = "0x1fff" },
			"directory endian": func(_ *Recipes, _ *Registry, image []byte) { image[0x106] ^= 1 },
			"directory allocation": func(_ *Recipes, _ *Registry, image []byte) {
				binary.LittleEndian.PutUint32(image[0x10a:], 4095)
				binary.BigEndian.PutUint32(image[0x10e:], 4095)
			},
			"ZERO end":                     func(r *Recipes, _ *Registry, _ []byte) { r.Stream.ZeroEnd = "0x1fff" },
			"padding":                      func(_ *Recipes, _ *Registry, image []byte) { image[0xb10] = 1 },
			"loader opcode":                func(_ *Recipes, _ *Registry, image []byte) { image[0x813] ^= 1 },
			"loader allocation":            func(_ *Recipes, _ *Registry, image []byte) { binary.LittleEndian.PutUint32(image[0x814:], 0x34a51000) },
			"loader count":                 func(_ *Recipes, _ *Registry, image []byte) { binary.LittleEndian.PutUint32(image[0x81c:], 0x240e0002) },
			"LUI window":                   func(_ *Recipes, _ *Registry, image []byte) { binary.LittleEndian.PutUint32(image[0x820:], 0) },
			"SRL window":                   func(_ *Recipes, _ *Registry, image []byte) { binary.LittleEndian.PutUint32(image[0x828:], 0) },
			"SRL reserved rs":              func(_ *Recipes, _ *Registry, image []byte) { binary.LittleEndian.PutUint32(image[0x828:], 0x00284ac2) },
			"SRL zero source":              func(_ *Recipes, _ *Registry, image []byte) { binary.LittleEndian.PutUint32(image[0x828:], 0x00004ac2) },
			"SRL zero destination":         func(_ *Recipes, _ *Registry, image []byte) { binary.LittleEndian.PutUint32(image[0x828:], 0x000802c2) },
			"SRL wrong operands":           func(_ *Recipes, _ *Registry, image []byte) { binary.LittleEndian.PutUint32(image[0x828:], 0x00094ac2) },
			"window excludes live content": func(_ *Recipes, _ *Registry, image []byte) { binary.LittleEndian.PutUint32(image[0x828:], 0x00084842) },
			"duplicate readiness site":     func(r *Recipes, _ *Registry, _ []byte) { r.Stream.WindowLUIVMAs[1] = r.Stream.WindowLUIVMAs[0] },
			"missing readiness site":       func(r *Recipes, _ *Registry, _ []byte) { delete(r.Stream.WindowSRLWords, "0x40") },
			"missing consumer ranges":      func(r *Recipes, _ *Registry, _ []byte) { r.Stream.AllowedPointers = nil },
			"unapproved pointer":           func(r *Recipes, _ *Registry, _ []byte) { r.Stream.AllowedPointers[0].Start = "0x208" },
			"unapproved landing":           func(r *Recipes, _ *Registry, _ []byte) { r.Stream.AllowedLandings[0].Start = "0x04000100" },
			"bad range":                    func(r *Recipes, _ *Registry, _ []byte) { r.Stream.AllowedLandings[0].End = "0x0000" },
			"unsupported sentinel route": func(r *Recipes, _ *Registry, _ []byte) {
				r.Stream.AllowedLandings = []AddressRange{{Start: "0x05000000", End: "0x05000800"}}
			},
			"missing references":   func(_ *Recipes, reg *Registry, _ []byte) { reg.Entries[0].RefSites = nil },
			"duplicate references": func(_ *Recipes, reg *Registry, _ []byte) { reg.Entries[0].RefSites[1] = reg.Entries[0].RefSites[0] },
			"wrong reference type": func(_ *Recipes, reg *Registry, _ []byte) { reg.Entries[0].RefType = "code_immediate" },
			"unaligned reference":  func(_ *Recipes, reg *Registry, _ []byte) { reg.Entries[0].RefSites[0].PointerVMA = "0x202" },
			"reference outside ELF": func(r *Recipes, reg *Registry, _ []byte) {
				r.Stream.AllowedPointers = []AddressRange{{Start: "0x400", End: "0x404"}}
				reg.Entries[0].RefSites[0].PointerVMA = "0x400"
			},
			"incomplete recorded scope":   func(_ *Recipes, reg *Registry, _ []byte) { reg.Entries[0].RefSites = reg.Entries[0].RefSites[:1] },
			"unrecorded original pointer": func(_ *Recipes, _ *Registry, image []byte) { binary.LittleEndian.PutUint32(image[0xa0c:], 0x100) },
			"partial repoint":             func(_ *Recipes, _ *Registry, image []byte) { binary.LittleEndian.PutUint32(image[0xa00:], 0x04000010) },
			"unknown pointer state": func(_ *Recipes, _ *Registry, image []byte) {
				binary.LittleEndian.PutUint32(image[0xa00:], 0x03000000)
				binary.LittleEndian.PutUint32(image[0xa04:], 0x03000000)
			},
			"changed JP":           func(_ *Recipes, _ *Registry, image []byte) { image[0x900] = 3 },
			"changed controls":     func(_ *Recipes, reg *Registry, _ []byte) { reg.Entries[0].EN = "AB|" },
			"added PARAM":          func(_ *Recipes, reg *Registry, _ []byte) { reg.Entries[0].EN = "{{PARAM:0xa000}}" },
			"numeric duplicate ID": func(r *Recipes, _ *Registry, _ []byte) { r.Entries["0X0100"] = r.Entries["0x100"] },
		},
		"stream_reflow": {
			"source context independent prefix": func(r *Recipes, _ *Registry, _ []byte) {
				r.SourceContext = true
				row := r.Entries["0x100"]
				row.PrefixWords = []string{"0x2800"}
				r.Entries["0x100"] = row
			},
			"source context changed marker": func(r *Recipes, reg *Registry, _ []byte) {
				r.SourceContext = true
				reg.Entries[0].EN = "{{PARAM:0x7000}}A"
			},
			"source context new pause":   func(r *Recipes, reg *Registry, _ []byte) { r.SourceContext = true; reg.Entries[0].EN = "A//" },
			"source context new speaker": func(r *Recipes, reg *Registry, _ []byte) { r.SourceContext = true; reg.Entries[0].EN = "[spk 0x3998]A" },

			"missing advance exception":  func(r *Recipes, _ *Registry, _ []byte) { r.Layout.UnflooredGlyph = "" },
			"missing exception source":   func(r *Recipes, _ *Registry, _ []byte) { r.Layout.UnflooredGlyphVMA = "" },
			"unaligned exception source": func(r *Recipes, _ *Registry, _ []byte) { r.Layout.UnflooredGlyphVMA = "0x75" },
			"exception source extent":    func(r *Recipes, _ *Registry, _ []byte) { r.Layout.UnflooredGlyphVMA = "0x2000" },
			"exception source mismatch":  func(_ *Recipes, _ *Registry, image []byte) { binary.LittleEndian.PutUint16(image[0x874:], 0x1c) },
			"exception is SPACE":         func(r *Recipes, _ *Registry, _ []byte) { r.Layout.UnflooredGlyph = "0x0" },
			"exception is control":       func(r *Recipes, _ *Registry, _ []byte) { r.Layout.UnflooredGlyph = "0x800" },
			"exception glyph extent":     func(r *Recipes, _ *Registry, _ []byte) { r.Layout.UnflooredGlyph = "0x52b" },
			"missing native space":       func(r *Recipes, _ *Registry, _ []byte) { r.Layout.SpaceWords = nil },
			"incomplete native space":    func(r *Recipes, _ *Registry, _ []byte) { delete(r.Layout.SpaceWords, "0x50") },
			"changed native space":       func(_ *Recipes, _ *Registry, image []byte) { binary.LittleEndian.PutUint32(image[0x850:], 0x3c0241c0) },
			"mixed native space": func(r *Recipes, _ *Registry, image []byte) {
				r.Layout.SpaceWords["0x50"] = "0x3c0241c0"
				binary.LittleEndian.PutUint32(image[0x850:], 0x3c0241c0)
			},
			"unknown native space": func(r *Recipes, _ *Registry, image []byte) {
				r.Layout.SpaceWords["0x50"] = "0x3c024170"
				binary.LittleEndian.PutUint32(image[0x850:], 0x3c024170)
			},
			"wrong native space opcode": func(r *Recipes, _ *Registry, image []byte) {
				r.Layout.SpaceWords["0x50"] = "0x34024160"
				binary.LittleEndian.PutUint32(image[0x850:], 0x34024160)
			},
			"duplicate native space": func(r *Recipes, _ *Registry, _ []byte) {
				delete(r.Layout.SpaceWords, "0x54")
				r.Layout.SpaceWords["0X0050"] = "0x3c024160"
			},
			"missing font table":   func(r *Recipes, _ *Registry, _ []byte) { r.Layout.FontTableVMA = "" },
			"font table extent":    func(r *Recipes, _ *Registry, _ []byte) { r.Layout.FontTableVMA = "0x2000" },
			"font table alignment": func(r *Recipes, _ *Registry, _ []byte) { r.Layout.FontTableVMA = "0x401" },
			"font page extent":     func(_ *Recipes, _ *Registry, image []byte) { binary.LittleEndian.PutUint32(image[0xc00:], 0x2000) },
			"font changes width":   func(_ *Recipes, _ *Registry, image []byte) { image[0xc14] = 100 },
			"increased width":      func(_ *Recipes, reg *Registry, _ []byte) { reg.Entries[0].EN = "ABC" },
			"increased height":     func(_ *Recipes, reg *Registry, _ []byte) { reg.Entries[0].EN = "A|B|C" },
			"introduced pages":     func(_ *Recipes, reg *Registry, _ []byte) { reg.Entries[0].EN = "A//B" },
			"removed policy":       func(r *Recipes, _ *Registry, _ []byte) { r.Layout = nil },
			"unbounded substitution": func(r *Recipes, reg *Registry, image []byte) {
				entry := r.Entries["0x100"]
				entry.ExpectedHex = "0070040004000008040000f8"
				r.Entries["0x100"] = entry
				copy(image[0x900:], []byte{0, 0x70, 4, 0, 4, 0, 0, 8, 4, 0, 0, 0xf8})
				reg.Entries[0].EN = "<7000>AB"
			},
			"positioned source": func(r *Recipes, reg *Registry, image []byte) {
				entry := r.Entries["0x100"]
				entry.ExpectedHex = "29d8040004000008040000f8"
				r.Entries["0x100"] = entry
				copy(image[0x900:], []byte{0x29, 0xd8, 4, 0, 4, 0, 0, 8, 4, 0, 0, 0xf8})
				reg.Entries[0].EN = "<d829>AB"
			},
			"changed speaker boundary": func(r *Recipes, reg *Registry, image []byte) {
				entry := r.Entries["0x100"]
				entry.ExpectedHex = "00380400000801380400001000f8"
				r.Entries["0x100"] = entry
				copy(image[0x900:], []byte{0, 0x38, 4, 0, 0, 8, 1, 0x38, 4, 0, 0, 0x10, 0, 0xf8})
				reg.Entries[0].EN = "[spk 0x3800]A//[spk 0x3801]B//"
			},
			"lost trailing pause": func(r *Recipes, _ *Registry, image []byte) {
				entry := r.Entries["0x100"]
				entry.ExpectedHex = "0400040000080400001000f8"
				r.Entries["0x100"] = entry
				copy(image[0x900:], []byte{4, 0, 4, 0, 0, 8, 4, 0, 0, 0x10, 0, 0xf8})
			},
			"added empty pause": func(r *Recipes, reg *Registry, image []byte) {
				entry := r.Entries["0x100"]
				entry.ExpectedHex = "0400040000080400001000f8"
				r.Entries["0x100"] = entry
				copy(image[0x900:], []byte{4, 0, 4, 0, 0, 8, 4, 0, 0, 0x10, 0, 0xf8})
				reg.Entries[0].EN = "AB////"
			},
			"color hides trailing pause": func(r *Recipes, reg *Registry, image []byte) {
				entry := r.Entries["0x100"]
				entry.ExpectedHex = "0400040000080400001001b000f8"
				r.Entries["0x100"] = entry
				copy(image[0x900:], []byte{4, 0, 4, 0, 0, 8, 4, 0, 0, 0x10, 1, 0xb0, 0, 0xf8})
				reg.Entries[0].EN = "AB{{HL:0xb001}}"
			},
			"color hides empty page": func(r *Recipes, reg *Registry, image []byte) {
				entry := r.Entries["0x100"]
				entry.ExpectedHex = "0400040000080400001001b0001000f8"
				r.Entries["0x100"] = entry
				copy(image[0x900:], []byte{4, 0, 4, 0, 0, 8, 4, 0, 0, 0x10, 1, 0xb0, 0, 0x10, 0, 0xf8})
				reg.Entries[0].EN = "AB{{HL:0xb001}}//"
			},
			"spaces hide trailing pause": func(r *Recipes, reg *Registry, image []byte) {
				entry := r.Entries["0x100"]
				entry.ExpectedHex = "04000400000804000010000000f8"
				r.Entries["0x100"] = entry
				copy(image[0x900:], []byte{4, 0, 4, 0, 0, 8, 4, 0, 0, 0x10, 0, 0, 0, 0xf8})
				reg.Entries[0].EN = "AB "
			},
			"lost leading empty page": func(r *Recipes, reg *Registry, image []byte) {
				entry := r.Entries["0x100"]
				entry.ExpectedHex = "0010040004000010040000f8"
				r.Entries["0x100"] = entry
				copy(image[0x900:], []byte{0, 0x10, 4, 0, 4, 0, 0, 0x10, 4, 0, 0, 0xf8})
				reg.Entries[0].EN = "A//B"
			},
			"lost internal colored page": func(r *Recipes, reg *Registry, image []byte) {
				entry := r.Entries["0x100"]
				entry.ExpectedHex = "04000400001001b00010040000f8"
				r.Entries["0x100"] = entry
				copy(image[0x900:], []byte{4, 0, 4, 0, 0, 0x10, 1, 0xb0, 0, 0x10, 4, 0, 0, 0xf8})
				reg.Entries[0].EN = "A{{HL:0xb001}}B"
			},
			"spaces hide internal page": func(r *Recipes, reg *Registry, image []byte) {
				entry := r.Entries["0x100"]
				entry.ExpectedHex = "04000400001000000010040000f8"
				r.Entries["0x100"] = entry
				copy(image[0x900:], []byte{4, 0, 4, 0, 0, 0x10, 0, 0, 0, 0x10, 4, 0, 0, 0xf8})
				reg.Entries[0].EN = "A//B"
			},
			"color hides trailing line": func(r *Recipes, reg *Registry, image []byte) {
				entry := r.Entries["0x100"]
				entry.ExpectedHex = "04000400000801b000f8"
				r.Entries["0x100"] = entry
				copy(image[0x900:], []byte{4, 0, 4, 0, 0, 8, 1, 0xb0, 0, 0xf8})
				reg.Entries[0].EN = "AB{{HL:0xb001}}"
			},
			"trailing pause moved to start": func(r *Recipes, reg *Registry, image []byte) {
				entry := r.Entries["0x100"]
				entry.ExpectedHex = "04000400001000f8"
				r.Entries["0x100"] = entry
				copy(image[0x900:], []byte{4, 0, 4, 0, 0, 0x10, 0, 0xf8})
				reg.Entries[0].EN = "//AB"
			},
			"leading pause moved to end": func(r *Recipes, reg *Registry, image []byte) {
				entry := r.Entries["0x100"]
				entry.ExpectedHex = "00100400040000f8"
				r.Entries["0x100"] = entry
				copy(image[0x900:], []byte{0, 0x10, 4, 0, 4, 0, 0, 0xf8})
				reg.Entries[0].EN = "AB//"
			},
		},
	} {
		for name, mutate := range cases {
			t.Run(operation+"/"+name, func(t *testing.T) {
				r, reg, glyphs, image := fixture(t, operation)
				mutate(&r, &reg, image)
				r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
				if _, err := plan([]Recipes{r}, reg, glyphs, bytes.NewReader(image)); err == nil {
					t.Fatal("accepted invalid initialized stream state")
				}
				dir := t.TempDir()
				path, output := filepath.Join(dir, "source.iso"), filepath.Join(dir, "refused.iso")
				if err := os.WriteFile(path, image, 0600); err != nil {
					t.Fatal(err)
				}
				source, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
				if _, err := patchCopy(source, output, []Recipes{r}, nil, reg, glyphs); err == nil {
					t.Fatal("writer accepted invalid initialized state")
				}
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatal("created refused stream output")
				}
			})
		}
	}
	for _, windowBits := range []uint{10, 11} {
		for _, overflow := range []int{0, 1} {
			r, reg, glyphs, image := fixture(t, "stream_append")
			delete(r.Entries, "0x110")
			binary.LittleEndian.PutUint32(image[0x828:], uint32(0x00084802|windowBits<<6))
			reg.Entries[0].EN = strings.Repeat("A", (1<<windowBits-16)/2-1+overflow)
			edits, err := plan([]Recipes{r}, reg, glyphs, bytes.NewReader(image))
			if overflow != 0 {
				if err == nil {
					t.Fatal("accepted append over effective capacity")
				}
			} else if err != nil || len(edits) != 3 || edits[2].Offset+int64(len(edits[2].New)) != 0x1000+int64(1<<windowBits) {
				t.Fatalf("exact capacity append: %v", err)
			}
		}
	}
	for _, endAt := range []int{8190, 8192, -1} {
		t.Run(fmt.Sprintf("derived END boundary %d", endAt), func(t *testing.T) {
			r, reg, glyphs, old := fixture(t, "stream_derived")
			image := make([]byte, 0x6000)
			copy(image, old)
			copy(image[0x3000:0x3800], old[0x1000:0x1800])
			clear(image[0xb00:0x3000])
			r.Stream.RetailELFSize, r.Stream.ZeroEnd = 0x2310, "0x6000"
			for at, value := range map[int]uint32{0x10a: 0x3000, 0x142: 7, 0x14a: 0x2800} {
				binary.LittleEndian.PutUint32(image[at:], value)
				binary.BigEndian.PutUint32(image[at+4:], value)
			}
			binary.LittleEndian.PutUint32(image[0xa00:], 0x300)
			binary.LittleEndian.PutUint32(image[0xa04:], 0x300)
			reg.Entries = reg.Entries[:1]
			reg.Entries[0].ID = "0x300"
			r.Entries = map[string]Recipe{"0x300": {}}
			if endAt >= 0 {
				binary.LittleEndian.PutUint16(image[0xb00+endAt:], 0xf800)
			}
			r.SourceSize = int64(len(image))
			r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
			edits, err := plan([]Recipes{r}, reg, glyphs, bytes.NewReader(image))
			if endAt == 8190 {
				if err != nil || len(edits) != 3 || !bytes.Equal(edits[2].New, []byte{1, 0, 2, 0, 0, 0xf8}) {
					t.Fatalf("refused exact bounded stream: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "no bounded source stream END") {
				t.Fatalf("accepted END outside bound: %v", err)
			}
		})
	}
	r, reg, glyphs, image := fixture(t, "stream_append")
	if _, err := plan([]Recipes{r}, reg, glyphs, nil); err == nil {
		t.Fatal("accepted append without source")
	}
	if _, err := plan([]Recipes{r, r}, reg, glyphs, bytes.NewReader(image)); err == nil {
		t.Fatal("accepted mixed append tables")
	}
	image[0x1010] = 0x55
	edits, err := plan([]Recipes{r}, reg, glyphs, bytes.NewReader(image))
	if err != nil || edits[3].Offset != 0x1020 || edits[4].Offset != 0x1030 {
		t.Fatalf("append overwrote existing unknown live tail: %v", err)
	}
}

func TestOverlapAndNormalizedRecipeIDs(t *testing.T) {
	for _, id := range []string{"0x11", "0X0010"} {
		r, registry, glyphs, _ := fixture(t, "same_length_stream")
		r.Entries[id] = r.Entries["0x10"]
		if id == "0x11" {
			entry := registry.Entries[0]
			entry.ID = id
			registry.Entries = append(registry.Entries, entry)
		}
		_, err := plan([]Recipes{r}, registry, glyphs, nil)
		if err == nil {
			t.Fatal("accepted overlap or duplicate")
		}
		for attempt := 0; attempt < 20; attempt++ {
			if _, next := plan([]Recipes{r}, registry, glyphs, nil); next == nil || next.Error() != err.Error() {
				t.Fatal("nondeterministic overlap or duplicate refusal")
			}
		}
	}
}

func TestUnexpectedAndShortImage(t *testing.T) {
	r, registry, glyphs, image := fixture(t, "same_length_stream")
	edits, err := plan([]Recipes{r}, registry, glyphs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspect(bytes.NewReader(image[:17]), edits, nil); err == nil {
		t.Fatal("accepted truncated image")
	}
	image[16] = 0xff
	if _, err := inspect(bytes.NewReader(image), edits, nil); err == nil {
		t.Fatal("accepted unexpected bytes")
	}
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source.iso")
	output := filepath.Join(dir, "out.iso")
	if err := os.WriteFile(sourcePath, image, 0600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err := patchCopy(source, output, []Recipes{r}, edits, registry, glyphs); err == nil {
		t.Fatal("accepted wrong source hash")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("created output on refusal")
	}
	r.SourceSize++
	if err := verifySource(source, []Recipes{r}, edits, registry, glyphs); err == nil {
		t.Fatal("accepted wrong size")
	}
}

func TestCLIDryRunAndApply(t *testing.T) {
	r, registry, glyphs, sourceImage := fixture(t, "same_length_stream")
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := name
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	jsonFile := func(name string, v any) string {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return write(name, data)
	}
	bundledFixtures := make(map[string]map[string][]byte)
	for _, fixture := range []struct{ Path, SHA256 string }{
		{"testdata/asset-manifest.zip", assetManifestFixtureSHA},
		{"testdata/registry-import-pretty.zip", "dda847089cae84f829fc47f263eec25d08e8c65eee1bfa54470116c9730d535d"},
		{"testdata/sentinel-reader.zip", "991a0772859e89f02ef6d2a62868f33a887369938d769401c9891c4956b19ee1"},
		{"testdata/gp-index-fixture.zip", "434aab918d573df3989c1502011b5202eb5ed2fa06cee5291ca832fbadd04a97"},
		{"testdata/instruction-index-fixture.zip", "6eb077edda6569ef5af3c7844d1189da902bf8773673bdd1f90076f8d9c4fc35"},
		{"testdata/register-flow-fixture.zip", "c747ab1007b8706216264e4f58f848c4e537c6b30af0005e42b82808a7e3b9a2"},
		{"testdata/instruction-ori-fixture.zip", "31d9cdd7193258d89335722b50bab448d8906cc6c35a4cea4e04d82ad71076e7"},
		{"testdata/reference-owner-fixture.zip", "a8a76300aab41a80a3775dd9eedf12391cfbf7ddd9d74567c24d097ba28b905f"},
		{"testdata/truetype-raster.zip", "dfdb85cbc5e431edf404b6b3e7f00118fede5d1c7065d2263dd47cd4478330c3"},
		{"testdata/reconstruction-rows.zip", "1fc8751a5f42731d1f4e78b0582316bda331ac9559d62a1d66e7863638e7f58e"},
		{"testdata/reconstruction-masks.zip", "bfaadb71c12020fa85000ac8893ddb526f54c9b79abbf2439be0bf6d92de6c5d"},
		{"testdata/fixed-permissions.zip", "1fb6e677c7788267302219129e4d690ca595f9ca893133da31296f1818158b4a"},
		{"testdata/asset-contacts.zip", "ab408bdbd0a0a9f30defd3b76af3b9d0159a9b92196dfca924f43df5b1d7492f"},
		{"testdata/asset-specification.zip", "6e06fbbab7112798168698461a754e3daff8d3bdb060b6d24b8494c2d94cb2c1"},
		{"testdata/asset-comparison.zip", "b115ecaccb3ad2d133546651dc31d6bc9092db50fcd65e08b5854cbef13578e6"},
	} {
		data, err := os.ReadFile(fixture.Path)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != fixture.SHA256 {
			t.Fatal("asset oracle bundle", fixture.Path, err)
		}
		archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		files := make(map[string][]byte)
		for _, member := range archive.File {
			reader, err := member.Open()
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(io.LimitReader(reader, 4<<20))
			closeErr := reader.Close()
			if readErr != nil || closeErr != nil {
				t.Fatal(readErr, closeErr)
			}
			files[member.Name] = body
		}
		bundledFixtures[fixture.Path] = files
	}
	for _, bundle := range []struct {
		Path, Member    string
		Cases, Refusals int
	}{{"testdata/gp-index-fixture.zip", "gp-index.json", 13, 39}, {"testdata/instruction-index-fixture.zip", "instruction-index.json", 74, 6}, {"testdata/register-flow-fixture.zip", "register-flow.json", 26, 18}, {"testdata/instruction-ori-fixture.zip", "instruction-ori.json", 4, 0}, {"testdata/reference-owner-fixture.zip", "reference-owner.json", 31, 23}} {
		var indexFixture struct {
			CarrierHex string `json:"carrier_hex"`
			Profile    json.RawMessage
			Cases      []struct {
				Name            string
				ExpectedScope   string                                 `json:"expected_core_scope"`
				OwnerScope      string                                 `json:"expected_scope"`
				RegistryText    string                                 `json:"registry_text"`
				GlyphmapText    string                                 `json:"glyphmap_text"`
				CarrierOverride string                                 `json:"carrier_hex_override"`
				ExpectedFlow    map[string]map[string]ReferenceFlowRow `json:"expected_flow_by_query_by_ID"`
				ExpectedGraph   *RegisterFlowReport                    `json:"expected_register_flow"`
				SourceEdits     []struct {
					Offset int
					Hex    string
				} `json:"source_edits"`
				Profile  json.RawMessage
				Expected struct {
					Instructions *InstructionIndex `json:"instruction_index"`
					Index        *GPIndex          `json:"gp_index"`
					RegisterInfo *ELFRegisterInfo  `json:"register_info"`
				} `json:"expected_core"`
			}
			Refusals []struct {
				Name, Expected  string
				RegistryText    string `json:"registry_text"`
				GlyphmapText    string `json:"glyphmap_text"`
				Profile         json.RawMessage
				ProfileText     string `json:"profile_text"`
				CarrierOverride string `json:"carrier_hex_override"`
				SourceEdits     []struct {
					Offset int
					Hex    string
				} `json:"source_edits"`
				CarrierBaseHex   string       `json:"carrier_base_hex"`
				ProfileFileRange AddressRange `json:"profile_file_range"`
				Extension        *struct {
					Size       int    `json:"set_size"`
					FileOffset int    `json:"code_file_offset"`
					VMA        uint32 `json:"code_vma"`
					Word       uint32 `json:"repeat_word"`
					Count      int    `json:"repeat_count"`
					Span       uint32 `json:"update_code_LOAD_file_and_mem_size"`
				} `json:"source_extension_recipe"`
			}
		}
		if err := json.Unmarshal(bundledFixtures[bundle.Path][bundle.Member], &indexFixture); err != nil || len(indexFixture.Cases) != bundle.Cases || len(indexFixture.Refusals) != bundle.Refusals {
			t.Fatal("independent instruction index fixture", err)
		}
		for _, fixture := range indexFixture.Cases {
			carrier := indexFixture.CarrierHex
			if fixture.CarrierOverride != "" {
				carrier = fixture.CarrierOverride
			}
			body, err := hex.DecodeString(carrier)
			if err != nil {
				t.Fatal(err)
			}
			for _, edit := range fixture.SourceEdits {
				value, err := hex.DecodeString(edit.Hex)
				if err != nil || edit.Offset < 0 || edit.Offset+len(value) > len(body) {
					t.Fatal("GP fixture edit", fixture.Name, err)
				}
				copy(body[edit.Offset:], value)
			}
			caseDir := t.TempDir()
			sourcePath, profilePath := write(filepath.Join(caseDir, "source.elf"), body), write(filepath.Join(caseDir, "profile.json"), fixture.Profile)
			args := []string{"--source", sourcePath, "--recipes", profilePath}
			inputBytes := map[string][]byte{sourcePath: body, profilePath: fixture.Profile}
			registryPin, glyphPin := "", ""
			if bundle.Member == "reference-owner.json" {
				registryPath := write(filepath.Join(caseDir, "registry.json"), []byte(fixture.RegistryText))
				glyphPath := write(filepath.Join(caseDir, "glyphmap.json"), []byte(fixture.GlyphmapText))
				args = append(args, "--registry", registryPath, "--glyphmap", glyphPath)
				inputBytes[registryPath], inputBytes[glyphPath] = []byte(fixture.RegistryText), []byte(fixture.GlyphmapText)
				registryPin, glyphPin = fmt.Sprintf("%x", sha256.Sum256([]byte(fixture.RegistryText))), fmt.Sprintf("%x", sha256.Sum256([]byte(fixture.GlyphmapText)))
			}
			beforeInputs := make(map[string]os.FileInfo, len(inputBytes))
			for path := range inputBytes {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				beforeInputs[path] = info
			}
			var out bytes.Buffer
			var operation struct{ Operation string }
			if err := json.Unmarshal(fixture.Profile, &operation); err != nil {
				t.Fatal(err)
			}
			var got ReferenceReport
			if err := run(args, &out); err != nil || json.Unmarshal(out.Bytes(), &got) != nil || got.Operation != operation.Operation || got.Applied || got.SourceSHA256 != fmt.Sprintf("%x", sha256.Sum256(body)) || got.ProfileSHA256 != fmt.Sprintf("%x", sha256.Sum256(fixture.Profile)) || got.RegistrySHA256 != registryPin || got.GlyphmapSHA256 != glyphPin {
				t.Fatalf("instruction index case %s: %v\n%s", fixture.Name, err, out.String())
			}
			if fixture.Expected.Index != nil && fixture.Expected.Index.MetadataError != "" {
				if got.GPIndex.MetadataError == "" || got.RegisterInfo.Error == "" || got.RegisterInfo.GlobalPointer != nil {
					t.Fatal("GP unknown metadata guessed", fixture.Name, got)
				}
				got.GPIndex.MetadataError, got.RegisterInfo.Error = "unknown", "unknown"
			}
			if bundle.Member == "instruction-ori.json" && fixture.Name == "ori-same-register" {
				rows := got.InstructionIndex.Instructions
				if _, err := referenceTarget(ReferenceGeometry{VMAs: []uint64{rows[0].VMA, rows[1].VMA}, Register: 8}, []uint32{rows[0].Word, rows[1].Word}); err == nil {
					t.Fatal("ORI observation widened canonical patch-pair grammar")
				}
			}
			actualInstructions := got.InstructionIndex
			if bundle.Member == "reference-owner.json" {
				if fixture.OwnerScope != "exact requested row.flow objects and exact authoritative register_flow group only; legacy advisory oracle separate" || got.InstructionIndex == nil || fixture.ExpectedGraph == nil || !reflect.DeepEqual(got.InstructionIndex.RegisterFlow, fixture.ExpectedGraph) {
					t.Fatal("reference owner authoritative graph", fixture.Name, got.InstructionIndex)
				}
				actualFlow := make(map[string]map[string]ReferenceFlowRow)
				legacyQueries := make(map[string][]ReferenceRow, len(got.Queries))
				for name, rows := range got.Queries {
					legacyRows := slices.Clone(rows)
					for i, row := range rows {
						if row.Flow != nil {
							if actualFlow[name] == nil {
								actualFlow[name] = make(map[string]ReferenceFlowRow)
							}
							if _, duplicate := actualFlow[name][row.ID]; duplicate {
								t.Fatal("duplicate reference owner row", fixture.Name, name, row.ID)
							}
							actualFlow[name][row.ID] = *row.Flow
						}
						legacyRows[i].Flow = nil
					}
					legacyQueries[name] = legacyRows
				}
				if !reflect.DeepEqual(actualFlow, fixture.ExpectedFlow) {
					actual, _ := json.Marshal(actualFlow)
					t.Fatalf("reference owner manual policy differs %s: %s", fixture.Name, actual)
				}
				var plainProfile map[string]json.RawMessage
				if err := json.Unmarshal(fixture.Profile, &plainProfile); err != nil {
					t.Fatal(err)
				}
				delete(plainProfile, "reference_flow")
				plainWire, err := json.Marshal(plainProfile)
				if err != nil {
					t.Fatal(err)
				}
				plainArgs := slices.Clone(args)
				plainArgs[3] = write(filepath.Join(caseDir, "plain.json"), plainWire)
				var plainOut bytes.Buffer
				var plain ReferenceReport
				if err := run(plainArgs, &plainOut); err != nil || json.Unmarshal(plainOut.Bytes(), &plain) != nil || !reflect.DeepEqual(legacyQueries, plain.Queries) || !reflect.DeepEqual(got.Summaries, plain.Summaries) {
					t.Fatal("reference owner changed advisory rows or summaries", fixture.Name, err)
				}
				actualInstructions = fixture.Expected.Instructions
			}
			if fixture.ExpectedScope == "register_flow_semantic_group_only" {
				if got.InstructionIndex == nil || fixture.Expected.Instructions == nil || !reflect.DeepEqual(got.InstructionIndex.RegisterFlow, fixture.Expected.Instructions.RegisterFlow) {
					actual, _ := json.Marshal(got.InstructionIndex)
					t.Fatalf("independent register flow differs %s: %s", fixture.Name, actual)
				}
				// The pure graph must leave the existing decoded source facts intact.
				var plainProfile map[string]json.RawMessage
				if err := json.Unmarshal(fixture.Profile, &plainProfile); err != nil {
					t.Fatal(err)
				}
				delete(plainProfile, "register_flow")
				plainWire, err := json.Marshal(plainProfile)
				if err != nil {
					t.Fatal(err)
				}
				var plainOut bytes.Buffer
				var plain ReferenceReport
				if err := run([]string{"--source", sourcePath, "--recipes", write(filepath.Join(caseDir, "plain.json"), plainWire)}, &plainOut); err != nil || json.Unmarshal(plainOut.Bytes(), &plain) != nil {
					t.Fatal("register flow baseline", fixture.Name, err)
				}
				copyIndex := *got.InstructionIndex
				copyIndex.RegisterFlow = nil
				if !reflect.DeepEqual(&copyIndex, plain.InstructionIndex) {
					t.Fatal("register flow changed decoded facts", fixture.Name)
				}
				actualInstructions = fixture.Expected.Instructions
			}
			if !reflect.DeepEqual(actualInstructions, fixture.Expected.Instructions) || !reflect.DeepEqual(got.GPIndex, fixture.Expected.Index) || !reflect.DeepEqual(got.RegisterInfo, fixture.Expected.RegisterInfo) {
				actual, _ := json.Marshal(struct {
					Instructions *InstructionIndex
					Index        *GPIndex
					Metadata     *ELFRegisterInfo
				}{got.InstructionIndex, got.GPIndex, got.RegisterInfo})
				t.Fatalf("independent instruction facts differ %s: %s", fixture.Name, actual)
			}
			for path, expected := range inputBytes {
				after, err := os.ReadFile(path)
				info, statErr := os.Stat(path)
				if err != nil || statErr != nil || !bytes.Equal(after, expected) || !os.SameFile(beforeInputs[path], info) || beforeInputs[path].ModTime() != info.ModTime() {
					t.Fatal("reference report changed input", fixture.Name, path, err, statErr)
				}
			}
			if bundle.Member == "reference-owner.json" && fixture.Name == indexFixture.Cases[0].Name {
				compact, err := json.Marshal(fixture.Profile)
				if err != nil {
					t.Fatal(err)
				}
				for _, cut := range []struct{ Before, After string }{
					{`"reference_flow":`, `"Reference_Flow":`},
					{`"reference_flow":`, `"reference_flow":{},"reference_flow":`},
					{`"entry_vmas":["0x100000"]`, `"entry_vmas":null`},
					{`"entry_vmas":["0x100000"],`, ``},
					{`"max_visited_states":4000`, `"max_visited_states":null`},
					{`"entries":{"0x100400":{}}`, `"entries":{"0x100400":{"benign_reader_pairs":null}}`},
					{`"entries":{"0x100400":{}}`, `"entries":{"0x100400":{"complete":true}}`},
					{`"entries":{"0x100400":{}}`, `"entries":{"0x100400":{"benign_reader_pairs":[{"lui_vma":"0x100004","use_vma":"0x100008"}]}}`},
					{`"entries":{"0x100400":{}}`, `"entries":{"0x100400":{"benign_reader_pairs":[{"lui_vma":"0x100004","use_vma":"0x100008","evidence":"\ud800"}]}}`},
					{`"references":`, `"References":`},
					{`"id_range":`, `"ID_Range":`},
					{`"check_collisions":true`, `"check_collisions":false,"check_collisions":true`},
					{`"skip_words":4`, `"skip_words":null`},
					{`"iso_elf_offset":`, `"ISO_ELF_OFFSET":`},
					{`"operation":"reference_candidates"`, `"operation":"reference_candidates","pointer_state":null`},
					{`"references":`, `"references":{},"references":`},
					{`"queries":{"selected":`, `"queries":{"\ud800":`},
					{`"glyphmap_sha256":`, `"Glyphmap_SHA256":`},
					{`"start":"0x100"`, `"start":null`},
					{`"operation":"reference_candidates"`, `"operation":"reference_candidates","proof":null`},
				} {
					if strings.Count(string(compact), cut.Before) != 1 {
						t.Fatal("reference owner wire cut missing", cut.Before)
					}
					wire := strings.Replace(string(compact), cut.Before, cut.After, 1)
					call := slices.Clone(args)
					call[3] = write(filepath.Join(caseDir, "invalid.json"), []byte(wire))
					out.Reset()
					if err := run(call, &out); err == nil || out.Len() != 0 {
						t.Fatal("reference owner wire refusal", cut.Before, err)
					}
				}
				for _, operation := range []string{"reference_observed", "reference_gp_index", "instruction_index", "elf_layout", "words", "reuse_table"} {
					wire := strings.Replace(string(compact), `"operation":"reference_candidates"`, `"operation":"`+operation+`"`, 1)
					call := slices.Clone(args)
					call[3] = write(filepath.Join(caseDir, "wrong-mode.json"), []byte(wire))
					out.Reset()
					if err := run(call, &out); err == nil || !strings.Contains(err.Error(), "reference_flow") || out.Len() != 0 {
						t.Fatal("reference owner escaped operation boundary", operation, err)
					}
				}
				for _, call := range [][]string{args[:4], args[:6], append(slices.Clone(args[:4]), args[6:]...)} {
					out.Reset()
					if err := run(call, &out); err == nil || out.Len() != 0 {
						t.Fatal("reference owner missing registry or glyphmap", err)
					}
				}
				for _, boundary := range []struct {
					Name  string
					Data  []byte
					Limit int64
					Valid bool
				}{
					{"below-limit", []byte("1234567"), 8, true},
					{"at-limit", []byte("12345678"), 8, true},
					{"above-limit", []byte("123456789"), 8, false},
					{"empty", nil, 8, false},
					{"invalid-zero-limit", []byte("1"), 0, false},
					{"invalid-large-limit", []byte("1"), (128 << 20) + 1, false},
				} {
					path := write(filepath.Join(caseDir, boundary.Name), boundary.Data)
					actual, err := readInput(path, boundary.Limit)
					if boundary.Valid {
						if err != nil || !bytes.Equal(actual, boundary.Data) {
							t.Fatal("bounded input lost a valid boundary", boundary.Name, err)
						}
					} else if err == nil {
						t.Fatal("bounded input accepted invalid boundary", boundary.Name)
					}
				}
				for _, extra := range []int{0, 1} {
					wire := append(slices.Clone(fixture.Profile), bytes.Repeat([]byte(" "), (1<<20)+extra-len(fixture.Profile))...)
					call := slices.Clone(args)
					call[3] = write(filepath.Join(caseDir, "profile-boundary.json"), wire)
					out.Reset()
					err := run(call, &out)
					if extra == 0 {
						var boundaryReport ReferenceReport
						if err != nil || json.Unmarshal(out.Bytes(), &boundaryReport) != nil || boundaryReport.ProfileSHA256 != fmt.Sprintf("%x", sha256.Sum256(wire)) {
							t.Fatal("exact report profile byte limit refused", err)
						}
					} else if err == nil || !strings.Contains(err.Error(), "reference recipe must be bounded") || out.Len() != 0 {
						t.Fatal("report profile byte limit widened", err)
					}
				}
				// Isolate FIFO opens in an owned CLI process so a regression cannot hang the suite.
				cliPath := filepath.Join(caseDir, "input-check-cli")
				buildContext, cancelBuild := context.WithTimeout(context.Background(), 90*time.Second)
				build := exec.CommandContext(buildContext, "go", "build", "-p", "2", "-o", cliPath, ".")
				build.Env = append(os.Environ(), "GOMAXPROCS=2")
				build.WaitDelay = time.Second
				buildOutput, buildErr := build.CombinedOutput()
				cancelBuild()
				if buildErr != nil {
					t.Fatalf("build owned input-check CLI: %v\n%s", buildErr, buildOutput)
				}
				mkfifo, fifoErr := exec.LookPath("mkfifo")
				if fifoErr != nil {
					t.Log("mkfifo unavailable; FIFO variants omitted, directory and size checks still run")
				}
				for _, input := range []struct {
					Name     string
					Argument int
					Limit    int64
				}{
					{"recipe", 3, 128 << 20}, {"glob-recipe", 3, 128 << 20}, {"alias-base", 3, 128 << 20},
					{"source", 1, 0}, {"registry", 5, 64 << 20}, {"glyphmap", 7, 64 << 20},
				} {
					for _, kind := range []string{"directory", "fifo", "oversize"} {
						if kind == "fifo" && fifoErr != nil || kind == "oversize" && input.Limit == 0 {
							continue
						}
						inputDir := t.TempDir()
						path := filepath.Join(inputDir, "input.json")
						switch kind {
						case "directory":
							if err := os.Mkdir(path, 0700); err != nil {
								t.Fatal(err)
							}
						case "fifo":
							fifoContext, cancelFIFO := context.WithTimeout(context.Background(), 3*time.Second)
							output, err := exec.CommandContext(fifoContext, mkfifo, path).CombinedOutput()
							cancelFIFO()
							if err != nil {
								t.Fatalf("create owned FIFO: %v\n%s", err, output)
							}
						case "oversize":
							file, err := os.Create(path)
							if err != nil {
								t.Fatal(err)
							}
							truncateErr := file.Truncate(input.Limit + 1)
							closeErr := file.Close()
							if truncateErr != nil || closeErr != nil {
								t.Fatal(truncateErr, closeErr)
							}
						}
						call := slices.Clone(args)
						call[input.Argument] = path
						if input.Name == "glob-recipe" {
							call[3] = inputDir
						} else if input.Name == "alias-base" {
							alias := map[string]any{"operation": "reuse_table", "base_recipe": "input.json", "base_sha256": strings.Repeat("0", 64), "source_sha256": fmt.Sprintf("%x", sha256.Sum256(body)), "source_size": len(body), "evidence": "owned nonregular or oversized base-input refusal"}
							aliasData, err := json.Marshal(alias)
							if err != nil {
								t.Fatal(err)
							}
							call[3] = write(filepath.Join(inputDir, "alias.json"), aliasData)
						}
						inputContext, cancelInput := context.WithTimeout(context.Background(), 3*time.Second)
						command := exec.CommandContext(inputContext, cliPath, call...)
						command.Env = append(os.Environ(), "GOMAXPROCS=2")
						command.WaitDelay = time.Second
						var stdout, stderr bytes.Buffer
						command.Stdout, command.Stderr = &stdout, &stderr
						runErr := command.Run()
						deadlineErr := inputContext.Err()
						cancelInput()
						if deadlineErr != nil {
							t.Fatal("input blocked before regular-file refusal", input.Name, kind, deadlineErr)
						}
						want := "input must be a bounded regular file"
						if input.Name == "source" {
							want = "source size/type mismatch"
						} else if input.Name == "recipe" && kind == "directory" {
							want = "recipe directory contains no JSON tables"
						}
						if runErr == nil || stdout.Len() != 0 || !strings.Contains(stderr.String(), want) {
							t.Fatal("invalid physical input accepted or wrong refusal", input.Name, kind, runErr, stdout.String(), stderr.String())
						}
					}
				}
			}
			if bundle.Member == "register-flow.json" && fixture.Name == indexFixture.Cases[0].Name {
				compact, err := json.Marshal(fixture.Profile)
				if err != nil {
					t.Fatal(err)
				}
				for _, cut := range []struct{ Before, After string }{
					{`"register_flow":`, `"Register_Flow":`},
					{`"register_flow":`, `"regiſter_flow":`},
					{`"register_flow":`, `"register_flow":{},"register_flow":`},
					{`"entry_vmas":`, `"Entry_Vmas":`},
					{`"entry_vmas":["0x100000"],`, ``},
					{`"entry_vmas":["0x100000"]`, `"entry_vmas":[]`},
					{`"queries":`, `"Queries":`},
					{`"kind":"uses_after",`, ``},
					{`"kind":"uses_after"`, `"kind":null`},
					{`"kind":"uses_after"`, `"kind":"liveness"`},
					{`"register":8,`, ``},
					{`"register":8`, `"Register":8`},
					{`"register":8`, `"register":8,"register":8`},
					{`"register":8`, `"register":-1`},
					{`"vma":"0x100008",`, ``},
					{`"vma":"0x100008"`, `"vma":null`},
					{`"vma":"0x100008"`, `"vma":"0x100009"`},
					{`"context":"normal",`, ``},
					{`"context":"normal"`, `"context":null`},
					{`"context":"normal"`, `"context":"physical"`},
					{`"max_visited_states":3000`, `"max_visited_states":100001`},
					{`"max_visited_states":3000`, `"max_visited_states":null`},
				} {
					if !strings.Contains(string(compact), cut.Before) {
						t.Fatal("register flow wire cut missing", cut.Before)
					}
					wire := strings.Replace(string(compact), cut.Before, cut.After, 1)
					out.Reset()
					if err := run([]string{"--source", sourcePath, "--recipes", write(filepath.Join(caseDir, "invalid.json"), []byte(wire))}, &out); err == nil || out.Len() != 0 {
						t.Fatal("register flow schema refusal", cut.Before, err)
					}
				}
				for _, operation := range []string{"reference_gp_index", "reference_observed", "reference_candidates", "elf_layout", "words", "reuse_table"} {
					wire := strings.Replace(string(compact), `"operation":"instruction_index"`, `"operation":"`+operation+`"`, 1)
					out.Reset()
					if err := run([]string{"--source", sourcePath, "--recipes", write(filepath.Join(caseDir, "wrong-mode.json"), []byte(wire))}, &out); err == nil || !strings.Contains(err.Error(), "register_flow") || out.Len() != 0 {
						t.Fatal("register flow escaped operation boundary", operation, err)
					}
				}
			}
			if bundle.Member == "instruction-index.json" && fixture.Name == indexFixture.Cases[0].Name {
				compact, err := json.Marshal(fixture.Profile)
				if err != nil {
					t.Fatal(err)
				}
				for _, cut := range []struct{ Before, After string }{
					{`"references":{"file_range":{"start":"0x100","end":"0x10c"}}`, `"references":null`},
					{`"file_range":{"start":"0x100","end":"0x10c"}`, `"file_range":null`},
					{`"start":"0x100"`, `"start":null`},
					{`"end":"0x10c"`, `"end":null`},
					{`"start":"0x100",`, ``},
					{`"start":"0x100"`, `"start":"0x101"`},
					{`"end":"0x10c"`, `"end":"0x100"`},
					{`"end":"0x10c"`, `"end":"0x100000000"`},
					{`"references":`, `"References":`},
					{`"references":`, `"referenceſ":`},
					{`"file_range":`, `"File_Range":`},
					{`"file_range":`, `"skip_words":0,"file_range":`},
					{`"operation":"instruction_index"`, `"operation":"instruction_index","address_ranges":{}`},
					{`"operation":"instruction_index"`, `"operation":"instruction_index","scope_sha256":""`},
					{`"operation":"instruction_index"`, `"operation":"instruction_index","glyphmap_sha256":""`},
					{`"operation":"instruction_index"`, `"operation":"instruction_index","operation":"instruction_index"`},
				} {
					if strings.Count(string(compact), cut.Before) != 1 {
						t.Fatal("instruction wire cut", cut.Before)
					}
					bad := strings.Replace(string(compact), cut.Before, cut.After, 1)
					out.Reset()
					if err := run([]string{"--source", sourcePath, "--recipes", write(filepath.Join(caseDir, "invalid.json"), []byte(bad))}, &out); err == nil || out.Len() != 0 {
						t.Fatal("instruction schema refusal", cut.Before, err)
					}
				}
			}
			if fixture.Name == indexFixture.Cases[0].Name {
				for _, flags := range [][]string{{"--registry", sourcePath}, {"--glyphmap", sourcePath}, {"--apply", "--output", filepath.Join(caseDir, "forbidden.out")}, {"--recipes", profilePath}} {
					out.Reset()
					call := append(slices.Clone(args), flags...)
					if err := run(call, &out); err == nil || out.Len() != 0 {
						t.Fatal("GP read-only/composition boundary", flags, err)
					}
				}
				if _, err := os.Stat(filepath.Join(caseDir, "forbidden.out")); !os.IsNotExist(err) {
					t.Fatal("instruction index wrote a patch output", err)
				}
			}
		}
		for _, fixture := range indexFixture.Refusals {
			carrier := indexFixture.CarrierHex
			if fixture.CarrierOverride != "" {
				carrier = fixture.CarrierOverride
			}
			body, err := hex.DecodeString(carrier)
			if err != nil {
				t.Fatal(err)
			}
			for _, edit := range fixture.SourceEdits {
				value, err := hex.DecodeString(edit.Hex)
				if err != nil || edit.Offset < 0 || edit.Offset+len(value) > len(body) {
					t.Fatal("GP refusal edit", fixture.Name, err)
				}
				copy(body[edit.Offset:], value)
			}
			wire := fixture.Profile
			if fixture.ProfileText != "" {
				wire = []byte(fixture.ProfileText)
			}
			if fixture.Extension != nil {
				body, err = hex.DecodeString(fixture.CarrierBaseHex)
				if err != nil {
					t.Fatal(err)
				}
				extension := fixture.Extension
				body = append(body, make([]byte, extension.Size-len(body))...)
				for i := 0; i < extension.Count; i++ {
					binary.LittleEndian.PutUint32(body[extension.FileOffset+4*i:], extension.Word)
				}
				ph := binary.LittleEndian.Uint32(body[28:])
				for offset, value := range map[uint32]uint32{4: uint32(extension.FileOffset), 8: extension.VMA, 12: extension.VMA, 16: extension.Span, 20: extension.Span} {
					binary.LittleEndian.PutUint32(body[ph+offset:], value)
				}
				var profile map[string]any
				if json.Unmarshal(indexFixture.Profile, &profile) != nil {
					t.Fatal("GP budget profile")
				}
				profile["source_size"], profile["source_sha256"] = len(body), fmt.Sprintf("%x", sha256.Sum256(body))
				profile["references"] = map[string]any{"file_range": fixture.ProfileFileRange}
				wire, err = json.Marshal(profile)
				if err != nil {
					t.Fatal(err)
				}
			}
			caseDir := t.TempDir()
			var out bytes.Buffer
			args := []string{"--source", write(filepath.Join(caseDir, "source.elf"), body), "--recipes", write(filepath.Join(caseDir, "profile.json"), wire)}
			if bundle.Member == "reference-owner.json" {
				args = append(args, "--registry", write(filepath.Join(caseDir, "registry.json"), []byte(fixture.RegistryText)), "--glyphmap", write(filepath.Join(caseDir, "glyphmap.json"), []byte(fixture.GlyphmapText)))
			}
			if err := run(args, &out); err == nil || out.Len() != 0 {
				t.Fatal("instruction index refusal accepted", fixture.Name, err)
			}
		}
	}

	permissionFacts, err := os.ReadFile("profiles/permissions/batch-c-panels.json")
	var fixedPermissions RasterReconstruction
	if err != nil || json.Unmarshal(permissionFacts, &fixedPermissions) != nil || len(fixedPermissions.Allow) != 13 {
		t.Fatal("canonical fixed panel permissions", err)
	}
	fixedPermissions.Erases = []RasterErase{{ID: "source-mask-witness", Rect: []int{0, 0, 512, 512}, Method: "flat", Fill: []int{7, 11, 13, 255}}}
	fixedBase := image.NewNRGBA(image.Rect(0, 0, 512, 512))
	fixedResult, _, err := composeCells(fixedBase, nil, RasterFont{}, RasterComposition{Reconstruction: &fixedPermissions})
	fixedMask := bundledFixtures["testdata/fixed-permissions.zip"]["batch-c-panel.mask"]
	if err != nil || len(fixedMask) != 512*512 || fmt.Sprintf("%x", sha256.Sum256(fixedMask)) != "e20ea6eb649851a641193bdd99d206b71b9899e957222aab9cc86ebdd76d733b" {
		t.Fatal("independent original fixed mask", err)
	}
	for at, permitted := range fixedMask {
		want := color.NRGBA{}
		if permitted == 255 {
			want = color.NRGBA{7, 11, 13, 255}
		}
		if fixedResult.NRGBAAt(at%512, at/512) != want || fixedBase.NRGBAAt(at%512, at/512) != (color.NRGBA{}) {
			t.Fatal("fixed permission facts differ from original geometry or mutate source", at)
		}
	}
	type reconstructionWireCut struct{ Name, Before, After, Want string }
	sharedPermissionDir := t.TempDir()
	var sharedPermissionData []byte
	sharedPermissionPath := filepath.Join(sharedPermissionDir, "permissions.json")
	for _, fixture := range []struct {
		Bundle, Profile, TXD, RGBA string
		NativeChanges              int
		Cuts                       []reconstructionWireCut
	}{
		{Bundle: "testdata/reconstruction-rows.zip", Profile: "profiles/textures/help00-reconstruction.json", TXD: "5245d6bb533f0f5173d28251f74d5dddbc83a63e99a5f7bcf213dd5f58e8cd0b", RGBA: "794329ff40074e07597fcb158a4a9d6363721e8ab9f1b73f14ecc9c603cc19c1", NativeChanges: 8260, Cuts: []reconstructionWireCut{
			{"unknown mask", `"lum_lt":180`, `"bogus":1`, `unknown field "bogus"`},
			{"null threshold", `"lum_lt":180`, `"lum_lt":null`, "instead of null"},
			{"null grow", `"grow":1`, `"grow":null`, "instead of null"},
			{"duplicate selector", `"lum_lt":180`, `"lum_lt":1,"lum_lt":180`, "duplicate"},
			{"unpaired step id", `"erase-rows"`, `"\ud800"`, "surrogates"},
			{"case-fold selector collision", `"lum_lt":180`, `"lum_lt":180,"LUM_LT":0`, "noncanonical"},
			{"unicode erase alias", `"erases":`, `"eraſes":`, "noncanonical"},
			{"reconstruction alias", `"reconstruction":`, `"Reconstruction":`, "noncanonical"},
			{"render alias", `"render":`, `"Render":`, "noncanonical"},
			{"order alias", `"order":`, `"Order":`, "noncanonical"},
			{"allow alias", `"allow":`, `"Allow":`, "noncanonical"},
			{"step identity alias", `"id":`, `"ID":`, "noncanonical"},
		}},
		{Bundle: "testdata/reconstruction-masks.zip", Profile: "profiles/textures/help00-color-exclusions.json", TXD: "f493896ae3733dce31357c1c2a6eb48e5d5087c9bae01e17476ca12cb7bf2d0a", RGBA: "571477a174f2b99ab0a8f01ecb17f87556a1fab97951b5b08c752c7d41fe8de4", NativeChanges: 5685, Cuts: []reconstructionWireCut{
			{"unknown clause key", `"not_near":[244,195,110]`, `"bogus":1`, `unknown field "bogus"`},
			{"clause color name", `"not_near":[244,195,110]`, `"not_near":"missing"`, "cannot unmarshal"},
			{"null exclusion", `"not_near":[244,195,110]`, `"not_near":null`, "instead of null"},
			{"empty exclusion", `"not_near":[244,195,110]`, `"not_near":[]`, "requires RGB or RGBA"},
			{"clause alias", `"not_near":[244,195,110]`, `"NOT_NEAR":[244,195,110]`, "noncanonical"},
			{"clause tolerance alias", `"tol":16`, `"TOL":16`, "noncanonical"},
			{"clause tolerance collision", `"tol":16`, `"tol":16,"TOL":0`, "noncanonical"},
			{"duplicate clause key", `"tol":16`, `"tol":0,"tol":16`, "duplicate"},
			{"all alias", `"all":`, `"All":`, "noncanonical"},
			{"duplicate all", `"all":[`, `"all":[],"all":[`, "duplicate"},
			{"null all", `"all":[{"not_near":[244,195,110],"tol":16},{"not_near":[49,137,24],"tol":10}]`, `"all":null`, "instead of null"},
			{"null clause", `"all":[{"not_near":[244,195,110],"tol":16},{"not_near":[49,137,24],"tol":10}]`, `"all":[null]`, "instead of null"},
			{"wrong clause type", `"all":[{"not_near":[244,195,110],"tol":16},{"not_near":[49,137,24],"tol":10}]`, `"all":[17]`, "cannot unmarshal"},
			{"recursive clause held", `"not_near":[244,195,110]`, `"all":[]`, `unknown field "all"`},
			{"OR held", `"not_near":[244,195,110]`, `"any":[]`, `unknown field "any"`},
			{"sat_gt held", `"not_near":[244,195,110]`, `"sat_gt":200`, `unknown field "sat_gt"`},
			{"alpha_gt held", `"not_near":[244,195,110]`, `"alpha_gt":128`, `unknown field "alpha_gt"`},
		}},
	} {
		files := bundledFixtures[fixture.Bundle]
		nativeDir := t.TempDir()
		sourcePath := write(filepath.Join(nativeDir, "original.txd"), bundledFixtures["testdata/truetype-raster.zip"]["native/original.txd"])
		sourceBefore, err := os.Stat(sourcePath)
		if err != nil {
			t.Fatal(err)
		}
		profileData, err := os.ReadFile(fixture.Profile)
		if err != nil {
			t.Fatal(err)
		}
		var profile TextureProfile
		if err := json.Unmarshal(profileData, &profile); err != nil {
			t.Fatal(err)
		}
		var composition RasterComposition
		if json.Unmarshal(files["native/composition.json"], &composition) != nil || profile.Render.Font != "" {
			t.Fatal("separate donor-only recipe table")
		}
		if input := profile.Render.Permissions; input != nil {
			permissionData, err := os.ReadFile(filepath.Join(filepath.Dir(fixture.Profile), input.Path))
			var declared RasterReconstruction
			if err != nil || int64(len(permissionData)) != input.Size || fmt.Sprintf("%x", sha256.Sum256(permissionData)) != input.SHA256 || json.Unmarshal(permissionData, &declared) != nil || !reflect.DeepEqual(declared.Allow, composition.Reconstruction.Allow) || !reflect.DeepEqual(declared.Exclude, composition.Reconstruction.Exclude) || !reflect.DeepEqual(declared.AllowAdd, composition.Reconstruction.AllowAdd) || len(declared.Erases) != 0 {
				t.Fatal("canonical shared permissions differ from original source facts", err)
			}
			var declaredReport bytes.Buffer
			if err := run([]string{"--source", sourcePath, "--texture-profile", fixture.Profile}, &declaredReport); err != nil {
				t.Fatal("declared reusable profile", err)
			}
			var declaredFacts map[string]any
			if json.Unmarshal(declaredReport.Bytes(), &declaredFacts) != nil || declaredFacts["output_sha256"] != fixture.TXD || declaredFacts["permissions_sha256"] != input.SHA256 {
				t.Fatal("declared reusable profile changed the source golden", declaredFacts)
			}
			// Keep the original inline route and its malformed-wire checks covered too.
			profile.Render.Reconstruction.Allow, profile.Render.Reconstruction.Exclude, profile.Render.Reconstruction.AllowAdd = declared.Allow, declared.Exclude, declared.AllowAdd
			profile.Render.Permissions = nil
			profileData, err = json.Marshal(profile)
			if err != nil {
				t.Fatal(err)
			}
		}
		if !reflect.DeepEqual(profile.Render.RasterComposition, composition) {
			t.Fatal("recipe composition differs from independent original facts")
		}
		profilePath := write(filepath.Join(nativeDir, "profile.json"), profileData)
		outputPath := filepath.Join(nativeDir, "authored.txd")
		args := []string{"--source", sourcePath, "--texture-profile", profilePath}
		for _, apply := range []bool{false, true} {
			call := slices.Clone(args)
			if apply {
				call = append(call, "--apply", "--output", outputPath)
			}
			var report bytes.Buffer
			if err := run(call, &report); err != nil {
				t.Fatal("donor-only CLI", apply, err)
			}
			var got map[string]any
			if json.Unmarshal(report.Bytes(), &got) != nil || got["mode"] != "reconstruct" || got["output_sha256"] != fixture.TXD || got["rgba_sha256"] != fixture.RGBA || got["rendered_cells"] != float64(0) || got["reconstruction_steps"] != float64(2) || got["applied"] != apply {
				t.Fatal("donor-only CLI report", apply, got)
			}
			if _, exists := got["font_sha256"]; exists {
				t.Fatal("donor-only path must not invent a font")
			}
			if !apply {
				if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
					t.Fatal("dry reconstruction published output", err)
				}
				continue
			}
			body, err := os.ReadFile(outputPath)
			if err != nil || !bytes.Equal(body, files["native/expected-native.txd"]) {
				t.Fatal("whole native reconstruction projection", err)
			}
			var ledger []struct {
				Offset        int
				Before, After byte
			}
			if json.Unmarshal(files["native/native-byte-ledger.json"], &ledger) != nil || len(ledger) != fixture.NativeChanges {
				t.Fatal("independent native byte ledger")
			}
			source := bundledFixtures["testdata/truetype-raster.zip"]["native/original.txd"]
			changes := make(map[int]byte, len(ledger))
			for _, change := range ledger {
				if change.Offset < 0 || change.Offset >= len(source) || source[change.Offset] != change.Before || change.Before == change.After {
					t.Fatal("native ledger guard", change)
				}
				changes[change.Offset] = change.After
			}
			for at, before := range source {
				after, changed := changes[at]
				if changed && body[at] != after || !changed && body[at] != before {
					t.Fatal("native bytes outside original projection ledger", at)
				}
			}
			_, decoded, err := texture(body, profile.Texture, nil, nil, "", nil)
			if err != nil || !bytes.Equal(decoded.Pix, files["native/expected-native-decoded.raw"]) {
				t.Fatal("whole reconstruction native readback", err)
			}
			allow := files["native/allow.raw"]
			original := bundledFixtures["testdata/reconstruction-rows.zip"]["native/original.raw"]
			if len(allow) != 1024*512 || len(original) != 4*len(allow) {
				t.Fatal("native exact mask dimensions")
			}
			for at, permitted := range allow {
				if permitted == 0 && !bytes.Equal(decoded.Pix[at*4:at*4+4], original[at*4:at*4+4]) {
					t.Fatal("native change outside exact permission", at)
				}
			}
		}
		for _, target := range []string{outputPath, sourcePath} {
			before, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			var report bytes.Buffer
			if err := run(append(slices.Clone(args), "--apply", "--output", target), &report); err == nil || report.Len() != 0 {
				t.Fatal("donor-only overwrite guard", err)
			}
			after, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("donor-only overwrite preservation", err)
			}
		}
		permissionData, err := json.Marshal(map[string][][]int{"allow": composition.Reconstruction.Allow, "exclude": composition.Reconstruction.Exclude, "allow_add": composition.Reconstruction.AllowAdd})
		if err != nil {
			t.Fatal(err)
		}
		if sharedPermissionData == nil {
			sharedPermissionData = bytes.Clone(permissionData)
			write(sharedPermissionPath, sharedPermissionData)
		} else if !bytes.Equal(sharedPermissionData, permissionData) {
			t.Fatal("two independent native recipes no longer share one permission datum")
		}
		var sharedProfile map[string]any
		if json.Unmarshal(profileData, &sharedProfile) != nil {
			t.Fatal("shared permission profile")
		}
		sharedRender := sharedProfile["render"].(map[string]any)
		sharedReconstruction := sharedRender["reconstruction"].(map[string]any)
		for _, key := range []string{"allow", "exclude", "allow_add"} {
			delete(sharedReconstruction, key)
		}
		relativePermissionPath, err := filepath.Rel(nativeDir, sharedPermissionPath)
		if err != nil {
			t.Fatal(err)
		}
		permissionPin := RegistryInput{Path: relativePermissionPath, Size: int64(len(permissionData)), SHA256: fmt.Sprintf("%x", sha256.Sum256(permissionData))}
		sharedRender["permissions"] = permissionPin
		sharedWire, err := json.Marshal(sharedProfile)
		if err != nil {
			t.Fatal(err)
		}
		sharedArgs := []string{"--source", sourcePath, "--texture-profile", write(filepath.Join(nativeDir, "shared-profile.json"), sharedWire)}
		var sharedReport bytes.Buffer
		sharedOutput := filepath.Join(nativeDir, "shared.txd")
		if err := run(append(slices.Clone(sharedArgs), "--apply", "--output", sharedOutput), &sharedReport); err != nil {
			t.Fatal("shared permissions native authoring", err)
		}
		sharedArtifact, err := os.ReadFile(sharedOutput)
		var sharedFacts map[string]any
		if err != nil || !bytes.Equal(sharedArtifact, files["native/expected-native.txd"]) || json.Unmarshal(sharedReport.Bytes(), &sharedFacts) != nil || sharedFacts["permissions_sha256"] != permissionPin.SHA256 {
			t.Fatal("shared permission data changed independently frozen native output", err)
		}
		programPermissions := RasterReconstruction{Exclude: composition.Reconstruction.Exclude, AllowAdd: composition.Reconstruction.AllowAdd, Masks: &RasterPermissionMasks{}}
		for _, rect := range composition.Reconstruction.Allow {
			// Alpha is nonnegative: core fill restores the complete rectangle after closing.
			allPixels := [][]RasterSelection{{{Above: map[string]float64{"alpha": -1}}}}
			coreGrowth := 0
			programPermissions.Masks.Allow = append(programPermissions.Masks.Allow, RasterFootprint{Rect: rect, SampleRect: rect, Any: allPixels, Core: &allPixels, CoreGrow: &coreGrowth, Close: 1, Fill: "core", MinimumSize: 1, Components: &RasterComponentFilter{Connectivity: 8, Seeds: &[][]int{{rect[0], rect[1]}}, Reject: &[][]RasterSelection{{{Above: map[string]float64{"alpha": 255}}}}}, Clip: rect})
			// An eroded label-zero region is contained in the already allowed rectangle.
			programPermissions.Masks.Allow = append(programPermissions.Masks.Allow, RasterFootprint{Rect: rect, Any: [][]RasterSelection{}, Fill: "holes", Components: &RasterComponentFilter{Connectivity: 4, Seeds: &[][]int{{rect[0], rect[1]}}, BackgroundSeed: "label-zero"}, Erode: 1})
		}
		programTable, err := json.Marshal(programPermissions)
		if err != nil {
			t.Fatal(err)
		}
		// The typed reconstruction's required Allow field is omitted in a masks-only table.
		var programFields map[string]json.RawMessage
		_ = json.Unmarshal(programTable, &programFields)
		delete(programFields, "allow")
		programTable, _ = json.Marshal(programFields)
		var programProfile map[string]any
		_ = json.Unmarshal(sharedWire, &programProfile)
		programProfile["render"].(map[string]any)["permissions"] = RegistryInput{Path: write(filepath.Join(nativeDir, "program-table.json"), programTable), Size: int64(len(programTable)), SHA256: fmt.Sprintf("%x", sha256.Sum256(programTable))}
		programWire, _ := json.Marshal(programProfile)
		programArgs := slices.Clone(sharedArgs)
		programArgs[3] = write(filepath.Join(nativeDir, "program-profile.json"), programWire)
		programOutput := filepath.Join(nativeDir, "program.txd")
		sharedReport.Reset()
		if err := run(append(slices.Clone(programArgs), "--apply", "--output", programOutput), &sharedReport); err != nil {
			t.Fatal("mask-program native authoring", err)
		}
		programArtifact, err := os.ReadFile(programOutput)
		if err != nil || !bytes.Equal(programArtifact, files["native/expected-native.txd"]) {
			t.Fatal("mask-program representation changed source native golden", err)
		}
		for _, mutation := range []string{"path", "empty path", "size", "zero size", "large size", "pin", "bad pin", "inline empty", "missing reconstruction", "null without reconstruction"} {
			var bad map[string]any
			_ = json.Unmarshal(sharedWire, &bad)
			render := bad["render"].(map[string]any)
			input := render["permissions"].(map[string]any)
			switch mutation {
			case "path":
				input["path"] = "missing-permissions.json"
			case "empty path":
				input["path"] = " "
			case "size":
				input["size"] = permissionPin.Size + 1
			case "zero size":
				input["size"] = 0
			case "large size":
				input["size"] = (1 << 20) + 1
			case "pin":
				input["sha256"] = strings.Repeat("0", 64)
			case "bad pin":
				input["sha256"] = "bad"
			case "inline empty":
				render["reconstruction"].(map[string]any)["allow"] = []any{}
			case "missing reconstruction", "null without reconstruction":
				delete(render, "reconstruction")
				if mutation == "null without reconstruction" {
					render["permissions"] = nil
				}
			}
			wire, _ := json.Marshal(bad)
			call := slices.Clone(sharedArgs)
			call[3] = write(filepath.Join(nativeDir, "bad-shared-profile.json"), wire)
			sharedReport.Reset()
			if err := run(call, &sharedReport); err == nil || sharedReport.Len() != 0 {
				t.Fatal("shared permission refusal", mutation, err)
			}
		}
		for _, cut := range []reconstructionWireCut{
			{Name: "resource alias", Before: `"permissions":`, After: `"Permissions":`},
			{Name: "resource Unicode alias", Before: `"permissions":`, After: `"permiſſions":`},
			{Name: "resource duplicate", Before: `"permissions":`, After: `"permissions":{},"permissions":`},
			{Name: "path alias", Before: `"path":`, After: `"Path":`},
			{Name: "size alias", Before: `"size":`, After: `"Size":`},
			{Name: "duplicate size", Before: `"size":`, After: `"size":1,"size":`},
		} {
			if strings.Count(string(sharedWire), cut.Before) != 1 {
				t.Fatal("shared resource wire cut is ambiguous", cut.Name)
			}
			call := slices.Clone(sharedArgs)
			call[3] = write(filepath.Join(nativeDir, "bad-shared-wire.json"), []byte(strings.Replace(string(sharedWire), cut.Before, cut.After, 1)))
			sharedReport.Reset()
			if err := run(call, &sharedReport); err == nil || sharedReport.Len() != 0 {
				t.Fatal("shared permission wire refusal", cut.Name, err)
			}
		}
		for _, table := range []string{`null`, `[]`, `{}`, `{"allow":null}`, `{"allow":[]}`, `{"Allow":[[0,0,1,1]]}`, `{"allow":[],"allow":[[0,0,1,1]]}`, `{"allow":[[0,0,1,1]],"erases":[]}`, `{"allow":[[0,0,1,1]],"permissions":{}}`, `{"allow":[[0,0,1,1]],"bogus":0}`, `{"allow":[[0,0,1]]}`, `{"allow":[[-1,0,1,1]]}`, `{"allow":[[0,0,1,1]]} {}`,
			`{"masks":null}`,
			`{"masks":{"Allow":[]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"proof":true}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"grow":0}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none"}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"fill":"none","grow":0}]}}`,
			`{"masks":{"allow":[{"Rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":null,"fill":"none","grow":0}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[{"Above":{"alpha":0}}]],"fill":"none","grow":0}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[{"above":{"ALPHA":0}}]],"fill":"none","grow":0}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"core","grow":0}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"core_grow":0,"fill":"none","grow":0}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"core":null,"fill":"none","grow":0}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"grow":1}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"sample_rect":[],"any":[[]],"fill":"none","grow":0}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"Sample_Rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"components":{}}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"Components":{"connectivity":8}}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"components":{"Connectivity":8}}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"components":{"connectivity":6}}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"components":{"connectivity":4,"connectivity":8}}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"components":{"connectivity":8,"seeds":null}}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"components":{"connectivity":8,"seeds":[[-1,0]]}}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"components":{"connectivity":8,"proof":true}}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"components":{"connectivity":8,"reject":[[{"Above":{"alpha":255}}]]}}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"components":{"connectivity":8,"reject":[[{"above":{"ALPHA":255}}]]}}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"components":{"connectivity":8,"reject":[[{"above":{"alpha":255},"above":{"alpha":256}}]]}}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"components":{"connectivity":8,"reject":[[{"proof":true}]]}}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"Erode":1}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"erode":null}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"erode":0,"erode":1}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"components":{"connectivity":4,"background_seed":"label-zero"}}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"components":{"connectivity":4,"seeds":[[0,0]],"Background_Seed":"label-zero"}}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"components":{"connectivity":4,"seeds":[[0,0]],"background_seed":"all"}}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"components":{"connectivity":4,"seeds":[[0,0]],"background_seed":null}}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"components":{"connectivity":4,"seeds":[[0,0]],"background_seed":"label-zero","reject":[]}}]}}`,
			`{"masks":{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0,"minimum_size":1,"components":{"connectivity":4,"seeds":[[0,0]],"background_seed":"label-zero"}}]}}`,
		} {
			var bad map[string]any
			_ = json.Unmarshal(sharedWire, &bad)
			bad["render"].(map[string]any)["permissions"] = RegistryInput{Path: write(filepath.Join(nativeDir, "bad-table.json"), []byte(table)), Size: int64(len(table)), SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(table)))}
			wire, _ := json.Marshal(bad)
			call := slices.Clone(sharedArgs)
			call[3] = write(filepath.Join(nativeDir, "bad-table-profile.json"), wire)
			sharedReport.Reset()
			if err := run(call, &sharedReport); err == nil || sharedReport.Len() != 0 {
				t.Fatal("shared table grammar refusal", table, err)
			}
		}
		textProfilePath := "profiles/textures/help00-turn-order.json"
		textProfileData, err := os.ReadFile(textProfilePath)
		var textProfile map[string]json.RawMessage
		if err != nil || json.Unmarshal(textProfileData, &textProfile) != nil {
			t.Fatal("valid text renderer for mask ancestor probes", err)
		}
		var textRender map[string]json.RawMessage
		_ = json.Unmarshal(textProfile["render"], &textRender)
		var fontPath string
		_ = json.Unmarshal(textRender["font"], &fontPath)
		fontPath, err = filepath.Abs(filepath.Join(filepath.Dir(textProfilePath), fontPath))
		if err != nil {
			t.Fatal(err)
		}
		textRender["font"], _ = json.Marshal(fontPath)
		delete(textRender, "reconstruction")
		validRender, _ := json.Marshal(textRender)
		textProfile["render"] = validRender
		validTextWire, _ := json.Marshal(textProfile)
		validTextArgs := []string{"--source", sourcePath, "--texture-profile", write(filepath.Join(nativeDir, "valid-text-profile.json"), validTextWire)}
		sharedReport.Reset()
		if err := run(validTextArgs, &sharedReport); err != nil {
			t.Fatal("ancestor refusal baseline must render successfully", err)
		}
		for _, last := range []string{"reconstruction", "Reconstruction", `recon\u0073truction`} {
			for _, request := range []string{`null`, `{"allow":[{"rect":[0,0,1,1],"any":[[]],"fill":"none","grow":0}]}`} {
				shadow := strings.TrimSuffix(string(validRender), "}") + `,"reconstruction":{"masks":` + request + `},"` + last + `":null}`
				textProfile["render"] = json.RawMessage(shadow)
				wire, _ := json.Marshal(textProfile)
				output := filepath.Join(nativeDir, "must-not-render-shadow.txd")
				call := []string{"--source", sourcePath, "--texture-profile", write(filepath.Join(nativeDir, "shadow-text-profile.json"), wire), "--apply", "--output", output}
				sharedReport.Reset()
				if err := run(call, &sharedReport); err == nil || sharedReport.Len() != 0 {
					t.Fatal("inline mask hidden by an aliased ancestor", last, request, err)
				}
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatal("inline mask ancestor shadow created output", err)
				}
			}
		}
		for _, mode := range []string{"", "inventory"} {
			selector := profile.Texture
			if mode == "inventory" {
				selector = ""
			}
			for _, resource := range []string{`null`, `{"path":"missing.json","size":1,"sha256":"` + strings.Repeat("0", 64) + `"}`} {
				for _, last := range []string{"render", "Render", `re\u006eder`} {
					// Exercise raw requests even when decoding leaves no Render value.
					shadow := fmt.Sprintf(`{"operation":%q,"texture":%q,"source_size":%d,"source_sha256":%q,"evidence":"resource shadow refusal","render":{"permissions":%s},"%s":null}`, mode, selector, profile.SourceSize, profile.SourceSHA256, resource, last)
					shadowOutput := filepath.Join(nativeDir, "must-not-export.txd")
					call := []string{"--source", sourcePath, "--texture-profile", write(filepath.Join(nativeDir, "shadow-profile.json"), []byte(shadow))}
					if mode == "" {
						call = append(call, "--apply", "--output", shadowOutput)
					}
					sharedReport.Reset()
					if err := run(call, &sharedReport); err == nil || sharedReport.Len() != 0 {
						t.Fatal("shadowed permission request exported instead of refusing", mode, last, err)
					}
					if _, err := os.Stat(shadowOutput); !os.IsNotExist(err) {
						t.Fatal("shadowed permission request created output", err)
					}
				}
			}
		}
		for _, mutation := range []string{"source pin", "source size", "missing allow", "short allow", "allow outside", "exclude outside", "add outside", "region count", "no steps", "step count", "duplicate id", "empty id", "unknown order", "duplicate order", "missing order", "short rect", "outside rect", "zero rect", "overflow rect", "unknown method", "missing fill", "bad fill", "near length", "near channel", "font conflict", "png conflict", "rectangle conflict", "clause count", "clause near", "clause exclusion", "exclusion channel", "selection work"} {
			var bad TextureProfile
			if json.Unmarshal(profileData, &bad) != nil {
				t.Fatal("donor profile clone")
			}
			r := bad.Render.Reconstruction
			op := &r.Erases[0]
			switch mutation {
			case "source pin":
				bad.SourceSHA256 = strings.Repeat("0", 64)
			case "source size":
				bad.SourceSize++
			case "missing allow":
				r.Allow = nil
			case "short allow":
				r.Allow[0] = []int{0, 0, 1}
			case "allow outside":
				r.Allow[0] = []int{1024, 0, 1, 1}
			case "exclude outside":
				r.Exclude = [][]int{{-1, 0, 1, 1}}
			case "add outside":
				r.AllowAdd = [][]int{{0, 512, 1, 1}}
			case "region count":
				r.Allow = make([][]int, 65)
			case "no steps":
				r.Erases = nil
				bad.Render.Order = nil
			case "step count":
				r.Erases = make([]RasterErase, 65)
			case "duplicate id":
				r.Erases[1].ID = op.ID
			case "empty id":
				op.ID = ""
			case "unknown order":
				bad.Render.Order[0] = "unknown"
			case "duplicate order":
				bad.Render.Order[1] = bad.Render.Order[0]
			case "missing order":
				bad.Render.Order = bad.Render.Order[:1]
			case "short rect":
				op.Rect = op.Rect[:3]
			case "outside rect":
				op.Rect[0] = 1024
			case "zero rect":
				op.Rect[2] = 0
			case "overflow rect":
				op.Rect[0] = int(^uint(0) >> 1)
				op.Rect[2] = int(^uint(0) >> 1)
			case "unknown method":
				op.Method = "bogus"
			case "missing fill":
				op.Method = "flat"
				op.Fill = nil
			case "bad fill":
				op.Method = "flat"
				op.Fill = []int{0, 0, 256}
			case "near length":
				op.Near = []int{1, 2}
			case "near channel":
				op.Near = []int{0, 0, 256}
			case "clause count":
				op.All = make([]RasterSelection, maxRasterSelections+1)
			case "clause near":
				op.All = []RasterSelection{{Near: []int{0, 1}}}
			case "clause exclusion":
				op.All = []RasterSelection{{NotNear: []int{0, 1}}}
			case "exclusion channel":
				op.NotNear = []int{0, 0, 256}
			case "selection work":
				for i := range r.Erases {
					r.Erases[i].Rect = []int{0, 0, 1024, 512}
					r.Erases[i].All = make([]RasterSelection, maxRasterSelections)
				}
			case "font conflict":
				bad.Render.Font = "unread-font.json"
			case "png conflict":
				bad.PNG = "unread.png"
				bad.PNGSHA256 = strings.Repeat("0", 64)
			case "rectangle conflict":
				bad.Rectangles = [][]int{{0, 0, 1, 1}}
			}
			badPath := jsonFile(filepath.Join(nativeDir, "malformed.json"), bad)
			for _, apply := range []bool{false, true} {
				call := []string{"--source", sourcePath, "--texture-profile", badPath}
				missing := filepath.Join(nativeDir, "refused.txd")
				if apply {
					call = append(call, "--apply", "--output", missing)
				}
				var report bytes.Buffer
				if err := run(call, &report); err == nil || report.Len() != 0 {
					t.Fatal("donor-only CLI structured refusal", mutation, apply, err)
				}
				if _, err := os.Stat(missing); !os.IsNotExist(err) {
					t.Fatal("refused reconstruction published", mutation, err)
				}
			}
		}
		compact, err := json.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		for _, cut := range fixture.Cuts {
			if !bytes.Contains(compact, []byte(cut.Before)) {
				t.Fatal("donor JSON mutation did not reach field", cut.Name)
			}
			path := write(filepath.Join(nativeDir, "malformed-wire.json"), bytes.Replace(compact, []byte(cut.Before), []byte(cut.After), 1))
			for _, apply := range []bool{false, true} {
				call := []string{"--source", sourcePath, "--texture-profile", path}
				missing := filepath.Join(nativeDir, "wire-refused.txd")
				if apply {
					call = append(call, "--apply", "--output", missing)
				}
				var report bytes.Buffer
				if err := run(call, &report); err == nil || !strings.Contains(err.Error(), cut.Want) || report.Len() != 0 {
					t.Fatal("donor-only strict wire refusal", cut.Name, apply, err)
				}
				if _, err := os.Stat(missing); !os.IsNotExist(err) {
					t.Fatal("wire refusal published", cut.Name, err)
				}
			}
		}
		sourceAfter, err := os.Stat(sourcePath)
		body, readErr := os.ReadFile(sourcePath)
		if err != nil || readErr != nil || !os.SameFile(sourceBefore, sourceAfter) || sourceBefore.ModTime() != sourceAfter.ModTime() || sourceBefore.Size() != sourceAfter.Size() || !bytes.Equal(body, bundledFixtures["testdata/truetype-raster.zip"]["native/original.txd"]) {
			t.Fatal("reconstruction CLI source identity", err, readErr)
		}
	}
	ttfFixtureDir := t.TempDir()
	for name, data := range bundledFixtures["testdata/truetype-raster.zip"] {
		path := filepath.Join(ttfFixtureDir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		write(path, data)
	}
	var ttfCell BitmapCell
	if json.Unmarshal(bundledFixtures["testdata/truetype-raster.zip"]["op8/cell.json"], &ttfCell) != nil {
		t.Fatal("TTF operation bridge")
	}
	{
		files := bundledFixtures["testdata/truetype-raster.zip"]
		sourcePath := filepath.Join(ttfFixtureDir, "native", "original.txd")
		fontPath := filepath.Join(ttfFixtureDir, "font.json")
		payloadPath := filepath.Join(ttfFixtureDir, "corpus", "NotoSans-CondensedExtraBold.ttf")
		profilePath := filepath.Join(ttfFixtureDir, "profile.json")
		outputPath := filepath.Join(ttfFixtureDir, "authored.txd")
		font := RasterFont{TrueType: &RegistryInput{Path: "corpus/NotoSans-CondensedExtraBold.ttf", Size: 623368, SHA256: "e8411ed0b4635955dcaf8a237930c14f391fb1cd248544131a7dda138e71e197"}, Layout: "RAQM"}
		fontBody, err := json.Marshal(font)
		if err != nil {
			t.Fatal(err)
		}
		write(fontPath, fontBody)
		profile := TextureProfile{SourceSize: 525564, SourceSHA256: "663c2990b13026ba40ceb70b26380b2ba5c06490dae889555ed2d05788ae857e", Texture: "textures\\help_illust00", Evidence: "Original TTF operation then old accepted codec projection; no independent encoder or visual approval", PalettePolicy: "source", Render: &RasterRender{Font: "font.json", FontSHA256: fmt.Sprintf("%x", sha256.Sum256(fontBody)), RasterComposition: RasterComposition{Cells: []BitmapCell{ttfCell}}}}
		jsonFile(profilePath, profile)
		args := []string{"--source", sourcePath, "--texture-profile", profilePath}
		var report bytes.Buffer
		_, fontErr := textMasks(files["corpus/NotoSans-CondensedExtraBold.ttf"], 76, "RAQM", nil)
		if fontErr != nil {
			if !strings.Contains(fontErr.Error(), "-tags nativefonts") {
				t.Fatal("TTF backend", fontErr)
			}
			if err := run(append(slices.Clone(args), "--apply", "--output", outputPath), &report); err == nil || !strings.Contains(err.Error(), "-tags nativefonts") || report.Len() != 0 {
				t.Fatal("TTF disabled CLI refusal", err)
			}
			if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
				t.Fatal("TTF disabled output", err)
			}
		} else {
			opaqueProfile := profile
			opaqueRender := *profile.Render
			opaqueRender.Icons = map[string][]int{"ERASES": {0, 0, 1, 1}, "LUM_LT": {1, 1, 1, 1}, "Reconstruction": {2, 2, 1, 1}, "ALL": {3, 3, 1, 1}, "NOT_NEAR": {4, 4, 1, 1}}
			opaqueRender.Reconstruction = &RasterReconstruction{Allow: [][]int{slices.Clone(ttfCell.Rect)}}
			opaqueRender.Order = []string{ttfCell.ID}
			opaqueProfile.Render = &opaqueRender
			opaquePath := jsonFile(filepath.Join(ttfFixtureDir, "opaque-icon-ids.json"), opaqueProfile)
			var opaqueReport bytes.Buffer
			if err := run([]string{"--source", sourcePath, "--texture-profile", opaquePath}, &opaqueReport); err != nil {
				t.Fatal("icon map identities remain opaque under reconstruction validation", err)
			}
			var opaqueResult map[string]any
			if json.Unmarshal(opaqueReport.Bytes(), &opaqueResult) != nil || opaqueResult["output_sha256"] != fmt.Sprintf("%x", sha256.Sum256(files["native/expected.txd"])) {
				t.Fatal("opaque icon IDs preserve native text result")
			}
			for _, apply := range []bool{false, true} {
				call := slices.Clone(args)
				if apply {
					call = append(call, "--apply", "--output", outputPath)
				}
				report.Reset()
				if err := run(call, &report); err != nil {
					t.Fatal("TTF actual CLI", apply, err)
				}
				var result struct {
					Mode    string
					Output  string `json:"output_sha256"`
					RGBA    string `json:"rgba_sha256"`
					Font    string `json:"font_ttf_sha256"`
					Layout  string `json:"font_layout"`
					Cells   int    `json:"rendered_cells"`
					Applied bool
				}
				if json.Unmarshal(report.Bytes(), &result) != nil || result.Mode != "render_truetype" || result.Output != "624c9f3a0a8c613f47c863ff0f5fd0cfa12c581d9f6bb686bc7035054ccf823e" || result.RGBA != "731c6fa4ce1743fecf6c354d9d01771539f17fd748fd2e84b1cb014792b73065" || result.Font != font.TrueType.SHA256 || result.Layout != "RAQM" || result.Cells != 1 || result.Applied != apply {
					t.Fatal("TTF CLI report", apply, report.String())
				}
				if apply {
					got, err := os.ReadFile(outputPath)
					if err != nil || !bytes.Equal(got, files["native/expected.txd"]) {
						t.Fatal("TTF whole native projection", err)
					}
				} else if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
					t.Fatal("TTF dry run created output", err)
				}
			}
		}
		for _, target := range []string{sourcePath, fontPath, payloadPath, profilePath, outputPath} {
			before, err := os.ReadFile(target)
			if target == outputPath && os.IsNotExist(err) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(target)
			if err != nil {
				t.Fatal(err)
			}
			report.Reset()
			if err := run(append(slices.Clone(args), "--apply", "--output", target), &report); err == nil {
				t.Error("TTF input/existing output overwrite", target)
			}
			after, err := os.ReadFile(target)
			current, statErr := os.Stat(target)
			if err != nil || statErr != nil || !bytes.Equal(before, after) || !os.SameFile(info, current) || info.ModTime() != current.ModTime() {
				t.Fatal("TTF input/existing output preservation", target, err, statErr)
			}
		}
		for _, name := range []string{"empty-path", "missing-font", "zero-size", "oversize", "wrong-size", "invalid-pin", "wrong-pin", "invalid-face", "layout", "bitmap-png", "bitmap-glyphs", "bitmap-em", "bitmap-metrics", "font-null", "font-duplicate", "font-surrogate", "profile-duplicate", "profile-surrogate", "profile-pin", "word-spill"} {
			badFont := font
			input := *font.TrueType
			badFont.TrueType = &input
			badProfile := profile
			render := *profile.Render
			render.Cells = slices.Clone(profile.Render.Cells)
			badProfile.Render = &render
			write(payloadPath, files["corpus/NotoSans-CondensedExtraBold.ttf"])
			switch name {
			case "empty-path":
				input.Path = ""
			case "missing-font":
				input.Path = "absent.ttf"
			case "zero-size":
				input.Size = 0
			case "oversize":
				input.Size = 4<<20 + 1
			case "wrong-size":
				input.Size--
			case "invalid-pin":
				input.SHA256 = "invalid"
			case "wrong-pin":
				input.SHA256 = strings.Repeat("0", 64)
			case "invalid-face":
				body := []byte("not a TrueType face")
				write(payloadPath, body)
				input.Size = int64(len(body))
				input.SHA256 = fmt.Sprintf("%x", sha256.Sum256(body))
			case "layout":
				badFont.Layout = "unknown"
			case "bitmap-png":
				badFont.PNG = "atlas.png"
			case "bitmap-glyphs":
				badFont.Glyphs = map[string]BitmapGlyph{"A": {Advance: 1}}
			case "bitmap-em":
				badFont.Em = 16
			case "bitmap-metrics":
				badFont.Ascent = 16
			case "word-spill":
				render.Cells[0].Group = nil
				render.Cells[0].Runs = ttfCell.Group.Lines[0]
				render.Cells[0].Layout = &BitmapRunLayout{At: []float64{0, 35}, Size: 19, MinSize: 10, MaxWidth: 384, ScaleX: 1, Strokes: &[]BitmapStroke{}, Composite: "float"}
			}
			badBody, err := json.Marshal(badFont)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "font-null":
				badBody = []byte(`{"truetype":null,"layout":"RAQM"}`)
			case "font-duplicate":
				badBody = append(bytes.TrimSuffix(badBody, []byte("}")), []byte(`,"layout":"RAQM"}`)...)
			case "font-surrogate":
				badBody = bytes.Replace(badBody, []byte("corpus/NotoSans-CondensedExtraBold.ttf"), []byte(`\ud800`), 1)
			}
			write(fontPath, badBody)
			render.FontSHA256 = fmt.Sprintf("%x", sha256.Sum256(badBody))
			if name == "profile-pin" {
				render.FontSHA256 = strings.Repeat("0", 64)
			}
			badBody, err = json.Marshal(badProfile)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "profile-duplicate":
				badBody = append(bytes.TrimSuffix(badBody, []byte("}")), []byte(`,"source_size":525564}`)...)
			case "profile-surrogate":
				badBody = bytes.Replace(badBody, []byte("Each day, everyone takes "), []byte(`\ud800`), 1)
			}
			write(profilePath, badBody)
			refused := filepath.Join(ttfFixtureDir, "refused.txd")
			report.Reset()
			if err := run(append(slices.Clone(args), "--apply", "--output", refused), &report); err == nil || report.Len() != 0 {
				t.Error("TTF CLI refusal", name, err, report.String())
			}
			if _, err := os.Stat(refused); !os.IsNotExist(err) {
				t.Fatal("TTF refusal created output", name, err)
			}
		}
		write(fontPath, fontBody)
		write(payloadPath, files["corpus/NotoSans-CondensedExtraBold.ttf"])
		jsonFile(profilePath, profile)
		for path, want := range map[string][]byte{sourcePath: files["native/original.txd"], fontPath: fontBody, payloadPath: files["corpus/NotoSans-CondensedExtraBold.ttf"]} {
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("TTF final input preservation", path, err)
			}
		}
	}
	for _, scenario := range []struct {
		Prefix      string
		Rows, Pages int
	}{{"", 11, 4}, {"pagination/ui25-reversed/", 25, 2}, {"pagination/cross-archive-duplicates/", 11, 4}, {"labels/labels-lf-archive/", 1, 1}, {"labels/labels-lf-entry/", 1, 1}, {"labels/labels-lf-texture/", 1, 1}, {"labels/labels-lf-blank-trailing/", 1, 1}, {"labels/labels-combining-control1/", 1, 1}, {"labels/labels-combining-occlusion7/", 7, 1}, {"scores/odd-evaluated-four-groups/", 4, 4}, {"scores/missing-det-ui-control/", 1, 0}} {
		files := bundledFixtures["testdata/asset-contacts.zip"]
		manifestFile, detFile := scenario.Prefix+"manifest.json", scenario.Prefix+"det.json"
		if scenario.Prefix == "" {
			manifestFile, detFile = "literal-manifest.json", "literal-det.json"
		}
		var original []struct {
			CMB, Entry, Tex, PNG string
			Idx, W, H, Depth     int
			SHA                  *string
		}
		var scores map[string][6]float64
		var facts struct {
			Outputs []struct {
				Path string
				Size [2]int
				SHA  string `json:"sha256"`
			} `json:"complete_pixel_outputs"`
			Projection     []struct{ PNG, Sheet string } `json:"csv_sheet_projection"`
			CSVFields      []map[string]string           `json:"csv_selected_fields"`
			HeaderlessRows []int                         `json:"headerless_rows"`
			CSVLineEnding  string                        `json:"csv_line_ending"`
			Thumbnails     []struct {
				Name   string
				Size   [2]int
				Filter string
				SHA    string `json:"rgba_sha256"`
			}
		}
		if json.Unmarshal(files[manifestFile], &original) != nil || len(original) != scenario.Rows || json.Unmarshal(files[detFile], &scores) != nil || json.Unmarshal(files[scenario.Prefix+"expected-facts.json"], &facts) != nil {
			t.Fatal("original contacts schema")
		}
		for _, v := range facts.Thumbnails {
			source, _, err := decodePNG(files["inputs/"+v.Name+".png"], 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			got, err := resizeRaster(source, 232, 136, "thumbnail-"+strings.ToLower(v.Filter), nil)
			if err != nil {
				t.Fatal(err)
			}
			if got.Bounds().Dx() != v.Size[0] || got.Bounds().Dy() != v.Size[1] || fmt.Sprintf("%x", sha256.Sum256(got.(*image.NRGBA).Pix)) != v.SHA {
				t.Fatal("thumbnail", v.Name)
			}
		}
		contactsDir := t.TempDir()
		fontPath := write(filepath.Join(contactsDir, "DejaVuSans.ttf"), files["DejaVuSans.ttf"])
		fontInput := RegistryInput{Path: fontPath, Size: int64(len(files["DejaVuSans.ttf"])), SHA256: fmt.Sprintf("%x", sha256.Sum256(files["DejaVuSans.ttf"]))}
		manifests := make(map[string]*TextureManifest)
		members := make(map[string]map[string][]byte)
		var archiveOrder []string
		for ordinal, r := range original {
			sourceName := fmt.Sprintf("%03d_%s", ordinal, r.CMB)
			manifest := manifests[sourceName]
			if manifest == nil {
				manifest = &TextureManifest{Archive: r.CMB, Entries: []TextureManifestEntry{}}
				manifests[sourceName] = manifest
				members[sourceName] = make(map[string][]byte)
				archiveOrder = append(archiveOrder, sourceName)
			}
			raw := files[scenario.Prefix+r.PNG]
			pixels, _, err := decodePNG(raw, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			size := [2]int{r.W, r.H}
			discovery := inspectRaster(pixels, r.Entry, r.Tex)
			if score, present := scores[r.PNG]; present {
				if score[0] >= 0 {
					discovery.Status = "measured"
					discovery.Score = &TextureDiscoveryScore{GlyphClusters: int(score[0]), ClusterFraction: score[1], GlyphTiles: int(score[2]), DominantColorFraction: score[3], OpaqueFraction: score[4], TextLineRows: int(score[5])}
				} else {
					discovery.Status, discovery.Score = "unavailable", nil
				}
			} else {
				discovery.Status, discovery.Score = "not_evaluated", nil
			}
			raster := TextureManifestRaster{TextureSpecificationRow: TextureSpecificationRow{NativeOrdinal: 0, Specification: TextureSpecification{Texture: r.Tex}, Header: &TextureHeader{Width: uint32(r.W), Height: uint32(r.H), Depth: uint32(r.Depth)}, DecodedStatus: "decoded", DecodedGeometry: &size}, Discovery: discovery, Preview: r.PNG, PreviewSHA256: fmt.Sprintf("%x", sha256.Sum256(raw))}
			if slices.Contains(facts.HeaderlessRows, ordinal) {
				raster.Header = nil
			}
			if r.SHA != nil && *r.SHA != "" {
				digest := fmt.Sprintf("%x", sha256.Sum256(pixels.Pix))
				raster.RGBASHA256 = &digest
			}
			manifest.Entries = append(manifest.Entries, TextureManifestEntry{Ordinal: r.Idx, Name: r.Entry, Status: "fixture", Rasters: []TextureManifestRaster{raster}})
			members[sourceName][r.PNG] = raw
		}
		var inputs []RegistryInput
		for _, name := range archiveOrder {
			raw, err := json.Marshal(manifests[name])
			if err != nil {
				t.Fatal(err)
			}
			members[name]["manifest.json"] = raw
			names := slices.Sorted(maps.Keys(members[name]))
			var bundle bytes.Buffer
			archive := zip.NewWriter(&bundle)
			for _, member := range names {
				file, err := archive.CreateHeader(&zip.FileHeader{Name: member, Method: zip.Store})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.Write(members[name][member]); err != nil {
					t.Fatal(err)
				}
			}
			if err := archive.Close(); err != nil {
				t.Fatal(err)
			}
			path := write(filepath.Join(contactsDir, name+".zip"), bundle.Bytes())
			inputs = append(inputs, RegistryInput{Path: path, Size: int64(bundle.Len()), SHA256: fmt.Sprintf("%x", sha256.Sum256(bundle.Bytes()))})
		}
		profile := TextureProfile{Operation: "contacts", SourceSize: inputs[0].Size, SourceSHA256: inputs[0].SHA256, Evidence: "Frozen original collection groups/dedup/sort/pixels/link contracts", Contacts: &TextureContacts{Font: fontInput, Sources: inputs[1:]}}
		profilePath := jsonFile(filepath.Join(contactsDir, "profile.json"), map[string]any{"operation": "contacts", "source_size": profile.SourceSize, "source_sha256": profile.SourceSHA256, "evidence": profile.Evidence, "contacts": profile.Contacts})
		args := []string{"--source", inputs[0].Path, "--texture-profile", profilePath}
		output := filepath.Join(contactsDir, "contacts.zip")
		var report bytes.Buffer
		_, fontErr := textMasks(files["DejaVuSans.ttf"], 11, "RAQM", nil)
		if fontErr != nil {
			if !strings.Contains(fontErr.Error(), "-tags nativefonts") {
				t.Fatal("font support", fontErr)
			}
			if err := run(append(slices.Clone(args), "--apply", "--output", output), &report); err == nil || !strings.Contains(err.Error(), "-tags nativefonts") {
				t.Fatal("disabled native font refusal", err)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) || report.Len() != 0 {
				t.Fatal("disabled fonts wrote output", err)
			}
		} else {
			if err := run(args, &report); err != nil {
				t.Fatal("contacts preview", err)
			}
			preview := slices.Clone(report.Bytes())
			report.Reset()
			if err := run(args, &report); err != nil || !bytes.Equal(preview, report.Bytes()) {
				t.Fatal("deterministic contacts", err)
			}
			var result struct {
				Rows      []TextureContactRow
				Pages     []struct{ Path string }
				BundleSHA string `json:"bundle_sha256"`
			}
			if json.Unmarshal(report.Bytes(), &result) != nil || len(result.Rows) != scenario.Rows || len(result.Pages) != scenario.Pages {
				t.Fatalf("contacts row/page accounting rows=%d pages=%d", len(result.Rows), len(result.Pages))
			}
			for ordinal, row := range result.Rows {
				if slices.Contains(facts.HeaderlessRows, ordinal) {
					if row.Raster == nil || row.Raster.Header != nil || row.Raster.DecodedGeometry == nil || *row.Raster.DecodedGeometry != [2]int{original[ordinal].W, original[ordinal].H} {
						t.Fatal("decoded dimensions must not fabricate a native header", ordinal)
					}
				}
				if row.Raster == nil {
					continue
				}
				if score, present := scores[original[ordinal].PNG]; !present {
					if row.Raster.Discovery.Status != "not_evaluated" || row.Raster.Discovery.Score != nil {
						t.Fatal("absent detector result must remain distinct", ordinal)
					}
				} else if score[0] < 0 && (row.Raster.Discovery.Status != "unavailable" || row.Raster.Discovery.Score != nil) {
					t.Fatal("display sentinel must not become a measured score", ordinal)
				}
			}
			for _, expected := range facts.Projection {
				found := false
				for _, row := range result.Rows {
					if row.Raster != nil && strings.HasSuffix(row.Raster.Preview, "/"+expected.PNG) {
						found = true
						if strings.TrimPrefix(row.Sheet, "sheets/") != expected.Sheet {
							t.Fatal("original final page projection", expected.PNG, row.Sheet, expected.Sheet)
						}
					}
				}
				if !found {
					t.Fatal("missing original row", expected.PNG)
				}
			}
			report.Reset()
			if err := run(append(slices.Clone(args), "--apply", "--output", output), &report); err != nil {
				t.Fatal("contacts publication", err)
			}
			published, err := os.ReadFile(output)
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(published)) != result.BundleSHA {
				t.Fatal("contacts bundle identity", err)
			}
			archive, err := zip.NewReader(bytes.NewReader(published), int64(len(published)))
			if err != nil {
				t.Fatal(err)
			}
			pages, inventory := 0, false
			for _, member := range archive.File {
				reader, err := member.Open()
				if err != nil {
					t.Fatal(err)
				}
				raw, readErr := io.ReadAll(io.LimitReader(reader, 4<<20))
				closeErr := reader.Close()
				if readErr != nil || closeErr != nil {
					t.Fatal(readErr, closeErr)
				}
				if member.Name == "inventory.csv" {
					if facts.CSVLineEnding == "LF" && bytes.Contains(raw, []byte("\r\n")) {
						t.Fatal("canonical CSV record endings", scenario.Prefix)
					}
					table, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
					if err != nil || len(table) != scenario.Rows+1 {
						t.Fatal("contacts CSV", err)
					}
					if len(facts.CSVFields) > 0 {
						if len(facts.CSVFields) != len(table)-1 {
							t.Fatal("original CSV row accounting")
						}
						for i, expected := range facts.CSVFields {
							for key, value := range expected {
								column := slices.Index(table[0], key)
								if column < 0 || column >= len(table[i+1]) || strings.TrimPrefix(table[i+1][column], "sheets/") != value {
									t.Fatal("original CSV field", scenario.Prefix, i, key)
								}
							}
						}
					}
					inventory = true
				}
				if !strings.HasPrefix(member.Name, "sheets/") {
					continue
				}
				decoded, _, err := decodePNG(raw, 1<<20)
				if err != nil {
					t.Fatal(err)
				}
				rgb := make([]byte, decoded.Rect.Dx()*decoded.Rect.Dy()*3)
				for i, j := 0, 0; i < len(decoded.Pix); i, j = i+4, j+3 {
					copy(rgb[j:j+3], decoded.Pix[i:i+3])
					if decoded.Pix[i+3] != 255 {
						t.Fatal("contact RGB alpha")
					}
				}
				found := false
				for _, v := range facts.Outputs {
					if v.Path == member.Name {
						found = true
						if fmt.Sprintf("%x", sha256.Sum256(rgb)) != v.SHA {
							t.Fatal("original complete contact page", member.Name)
						}
					}
				}
				if !found || raw[25] != 2 {
					t.Fatal("unexpected/nonRGB contact page", member.Name)
				}
				pages++
			}
			if pages != scenario.Pages || !inventory {
				t.Fatal("missing page/inventory")
			}
			before := sha256.Sum256(published)
			report.Reset()
			if err := run(append(slices.Clone(args), "--apply", "--output", output), &report); err == nil {
				t.Fatal("contacts overwrote output")
			}
			after, err := os.ReadFile(output)
			if err != nil || sha256.Sum256(after) != before {
				t.Fatal("contacts changed existing output", err)
			}
			// The first collection exercises trust boundaries; the others reuse the same lifecycle.
			if scenario.Prefix == "" {
				originalProfile, err := os.ReadFile(profilePath)
				if err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"source-pin", "source-size", "font-pin", "font-size", "font-path", "missing-contacts", "null-contacts", "null-font", "null-source", "font-alias", "source-alias", "source-alias-pair", "source-unknown", "extra-root", "extra-preview", "too-many-sources", "empty-evidence", "wrong-operation", "duplicate-path", "surrogate", "trailing"} {
					var doc map[string]any
					if json.Unmarshal(originalProfile, &doc) != nil {
						t.Fatal("profile fixture")
					}
					contact := doc["contacts"].(map[string]any)
					font := contact["font"].(map[string]any)
					sources := contact["sources"].([]any)
					switch name {
					case "source-pin":
						doc["source_sha256"] = strings.Repeat("0", 64)
					case "source-size":
						doc["source_size"] = float64(inputs[0].Size + 1)
					case "font-pin":
						font["sha256"] = strings.Repeat("0", 64)
					case "font-size":
						font["size"] = float64(fontInput.Size + 1)
					case "font-path":
						font["path"] = "missing.ttf"
					case "missing-contacts":
						delete(doc, "contacts")
					case "null-contacts":
						doc["contacts"] = nil
					case "null-font":
						contact["font"] = nil
					case "null-source":
						sources[0] = nil
					case "font-alias":
						font["Path"] = font["path"]
						delete(font, "path")
					case "source-alias":
						source := sources[0].(map[string]any)
						source["Path"] = source["path"]
						delete(source, "path")
					case "source-alias-pair":
						source := sources[0].(map[string]any)
						source["PaTh"] = source["path"]
					case "source-unknown":
						sources[0].(map[string]any)["unused"] = true
					case "extra-root":
						doc["texture"] = ""
					case "extra-preview":
						doc["preview"] = map[string]any{"scale": 1}
					case "too-many-sources":
						contact["sources"] = make([]RegistryInput, 64)
					case "empty-evidence":
						doc["evidence"] = ""
					case "wrong-operation":
						doc["operation"] = "inventory"
					}
					raw, err := json.Marshal(doc)
					if err != nil {
						t.Fatal(err)
					}
					switch name {
					case "duplicate-path":
						raw = bytes.Replace(raw, []byte(`"path":`), []byte(`"path":"ignored","path":`), 1)
					case "surrogate":
						value, err := json.Marshal(doc["evidence"])
						if err != nil {
							t.Fatal(err)
						}
						raw = bytes.Replace(raw, value, []byte(`"\ud800"`), 1)
					case "trailing":
						raw = append(raw, []byte(`{}`)...)
					}
					write(profilePath, raw)
					failed := filepath.Join(contactsDir, "refused-"+name+".zip")
					report.Reset()
					if err := run(append(slices.Clone(args), "--apply", "--output", failed), &report); err == nil || report.Len() != 0 {
						t.Fatal("contacts profile refusal", name, err)
					}
					if _, err := os.Stat(failed); !os.IsNotExist(err) {
						t.Fatal("profile refusal created output", name, err)
					}
				}
				write(profilePath, originalProfile)
				for _, name := range []string{"not-zip", "missing-manifest", "duplicate-member", "dot-member", "traversal", "backslash", "symlink", "invalid-json", "duplicate-key", "root-alias", "entry-alias", "raster-alias", "missing-preview", "preview-pin", "pixel-pin", "geometry", "invalid-png", "negative-index", "duplicate-index", "score-negative", "unknown-tier", "unknown-tier-undetected", "unknown-status", "inconsistent-score", "unknown-discovery-status", "measured-without-score", "not-evaluated-with-score"} {
					data := members[archiveOrder[0]]
					payloads := maps.Clone(data)
					var manifest TextureManifest
					if json.Unmarshal(data["manifest.json"], &manifest) != nil {
						t.Fatal("manifest fixture")
					}
					row := &manifest.Entries[0].Rasters[0]
					switch name {
					case "missing-manifest":
						delete(payloads, "manifest.json")
					case "dot-member":
						payloads["."] = []byte("bad")
					case "traversal":
						payloads["../bad"] = []byte("bad")
					case "backslash":
						payloads[`bad\member`] = []byte("bad")
					case "symlink":
						payloads["link"] = []byte("destination")
					case "missing-preview":
						delete(payloads, row.Preview)
					case "preview-pin":
						row.PreviewSHA256 = strings.Repeat("0", 64)
					case "pixel-pin":
						digest := strings.Repeat("0", 64)
						row.RGBASHA256 = &digest
					case "geometry":
						size := [2]int{1, 1}
						row.DecodedGeometry = &size
					case "invalid-png":
						payloads[row.Preview] = []byte("not a PNG")
						row.PreviewSHA256 = fmt.Sprintf("%x", sha256.Sum256(payloads[row.Preview]))
					case "negative-index":
						manifest.Entries[0].Ordinal = -1
					case "duplicate-index":
						manifest.Entries = append(manifest.Entries, manifest.Entries[0])
					case "score-negative":
						row.Discovery.Score.GlyphClusters = -1
					case "unknown-tier":
						row.Discovery.Tier = "unknown"
					case "unknown-tier-undetected":
						row.Discovery.Tier = "unknown"
						row.Discovery.Score = nil
						row.Discovery.Status = "unavailable"
					case "unknown-status":
						row.DecodedStatus = "unknown"
					case "inconsistent-score":
						row.Discovery.Status = "unavailable"
					case "unknown-discovery-status":
						row.Discovery.Status = "unknown"
					case "measured-without-score":
						row.Discovery.Status, row.Discovery.Score = "measured", nil
					case "not-evaluated-with-score":
						row.Discovery.Status = "not_evaluated"
					}
					raw, err := json.Marshal(manifest)
					if err != nil {
						t.Fatal(err)
					}
					switch name {
					case "invalid-json":
						raw = []byte(`{`)
					case "duplicate-key":
						raw = bytes.Replace(raw, []byte(`"archive":`), []byte(`"archive":"ignored","archive":`), 1)
					case "root-alias":
						raw = bytes.Replace(raw, []byte(`"archive":`), []byte(`"Archive":`), 1)
					case "entry-alias":
						raw = bytes.Replace(raw, []byte(`"ordinal":`), []byte(`"Ordinal":`), 1)
					case "raster-alias":
						raw = bytes.Replace(raw, []byte(`"preview":`), []byte(`"Preview":`), 1)
					}
					if name != "missing-manifest" {
						payloads["manifest.json"] = raw
					}
					var bundle bytes.Buffer
					archive := zip.NewWriter(&bundle)
					for _, member := range slices.Sorted(maps.Keys(payloads)) {
						header := &zip.FileHeader{Name: member, Method: zip.Store}
						if name == "symlink" && member == "link" {
							header.SetMode(os.ModeSymlink | 0600)
						}
						file, err := archive.CreateHeader(header)
						if err != nil {
							t.Fatal(err)
						}
						if _, err := file.Write(payloads[member]); err != nil {
							t.Fatal(err)
						}
					}
					if name == "duplicate-member" {
						file, err := archive.CreateHeader(&zip.FileHeader{Name: "manifest.json", Method: zip.Store})
						if err != nil {
							t.Fatal(err)
						}
						if _, err := file.Write(raw); err != nil {
							t.Fatal(err)
						}
					}
					if err := archive.Close(); err != nil {
						t.Fatal(err)
					}
					encoded := bundle.Bytes()
					if name == "not-zip" {
						encoded = []byte("not a ZIP archive")
					}
					path := write(filepath.Join(contactsDir, "bad-source.zip"), encoded)
					doc := map[string]any{"operation": "contacts", "source_size": len(encoded), "source_sha256": fmt.Sprintf("%x", sha256.Sum256(encoded)), "evidence": "damaged source refusal", "contacts": profile.Contacts}
					jsonFile(profilePath, doc)
					badArgs := []string{"--source", path, "--texture-profile", profilePath, "--apply", "--output", filepath.Join(contactsDir, "bad-output.zip")}
					report.Reset()
					if err := run(badArgs, &report); err == nil || report.Len() != 0 {
						t.Fatal("contacts source refusal", name, err)
					}
					if _, err := os.Stat(badArgs[len(badArgs)-1]); !os.IsNotExist(err) {
						t.Fatal("source refusal created output", name, err)
					}
				}
				write(profilePath, originalProfile)
				for _, target := range []string{inputs[0].Path, fontPath, profilePath} {
					before, err := os.ReadFile(target)
					if err != nil {
						t.Fatal(err)
					}
					report.Reset()
					if err := run(append(slices.Clone(args), "--apply", "--output", target), &report); err == nil {
						t.Fatal("contacts input overwrite", target)
					}
					after, err := os.ReadFile(target)
					if err != nil || !bytes.Equal(before, after) {
						t.Fatal("contacts input preservation", err)
					}
				}
			}
			for _, input := range append(slices.Clone(inputs), fontInput) {
				data, err := os.ReadFile(input.Path)
				if err != nil || int64(len(data)) != input.Size || fmt.Sprintf("%x", sha256.Sum256(data)) != input.SHA256 {
					t.Fatal("contacts input changed", err)
				}
			}

			var fontOracle struct {
				Masks []struct {
					Name, Text, Engine string
					Font               string `json:"font_file"`
					Size               int
					Dimensions         [2]int `json:"mask_size"`
					Offset             [2]int
					SHA                string `json:"mask_sha256"`
					Advance            int64  `json:"advance_26_6"`
				}
			}
			if json.Unmarshal(files["font-oracles.json"], &fontOracle) != nil || len(fontOracle.Masks) != 56 {
				t.Fatal("font oracle schema")
			}
			ttfDir := filepath.Join(ttfFixtureDir, "phases")
			ttfFont, err := os.ReadFile(filepath.Join(ttfFixtureDir, "corpus", "NotoSans-CondensedExtraBold.ttf"))
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(ttfFont)) != "e8411ed0b4635955dcaf8a237930c14f391fb1cd248544131a7dda138e71e197" {
				t.Fatal("TTF prototype font", err)
			}
			var phases struct {
				Cases []struct {
					Size    int
					Text    string
					Metrics [2]int
					Advance float64
					Phases  []struct {
						Start      float64
						Dimensions [2]int `json:"mask_size"`
						Offset     [2]int
						Raw        string `json:"mask_raw"`
						SHA        string `json:"mask_sha256"`
					}
				}
			}
			facts, err := os.ReadFile(filepath.Join(ttfDir, "facts.json"))
			if err != nil || json.Unmarshal(facts, &phases) != nil || len(phases.Cases) != 14 {
				t.Fatal("TTF phase schema", err)
			}
			for caseNo, vector := range phases.Cases {
				requests := make([]TextRequest, len(vector.Phases))
				for i, phase := range vector.Phases {
					requests[i] = TextRequest{Text: vector.Text, Start: [2]float64{phase.Start, 0}}
				}
				masks, err := textMasks(ttfFont, vector.Size, "RAQM", requests)
				if err != nil || len(masks) != len(requests) {
					t.Fatal("TTF phase batch", caseNo, err)
				}
				for i, phase := range vector.Phases {
					m := masks[i]
					raw, err := os.ReadFile(filepath.Join(ttfDir, phase.Raw))
					if err != nil || fmt.Sprintf("%x", sha256.Sum256(raw)) != phase.SHA {
						t.Fatal("TTF original mask pin", caseNo, i, err)
					}
					if m.Ascent != vector.Metrics[0] || m.Descent != vector.Metrics[1] || m.Advance != int64(math.Round(vector.Advance*64)) || m.Bearing != image.Pt(phase.Offset[0], phase.Offset[1]+m.Ascent) || m.Coverage.Rect.Size() != image.Pt(phase.Dimensions[0], phase.Dimensions[1]) || !bytes.Equal(m.Coverage.Pix, raw) {
						t.Fatal("TTF source metrics/phase/complete mask", caseNo, i, m.Ascent, m.Descent, m.Advance, m.Bearing, m.Coverage.Rect.Size(), vector.Metrics, phase.Offset, phase.Dimensions)
					}
				}
			}
			styledDir := filepath.Join(ttfFixtureDir, "op8")
			base := image.NewNRGBA(image.Rect(0, 0, 512, 512))
			baseData, err := os.ReadFile(filepath.Join(styledDir, "literal-base.rgba"))
			if err != nil || len(baseData) != len(base.Pix) {
				t.Fatal("literal panel", err)
			}
			copy(base.Pix, baseData)
			styledFont := RasterFont{
				TrueType: &RegistryInput{
					Path: "NotoSans-CondensedExtraBold.ttf", Size: int64(len(ttfFont)),
					SHA256: "e8411ed0b4635955dcaf8a237930c14f391fb1cd248544131a7dda138e71e197",
				},
				Layout: "RAQM", TrueTypeData: ttfFont,
			}
			styledCell := ttfCell

			// Explicit no-stroke and omitted scalar-default are different wire contracts.
			for _, strokes := range []*[]BitmapStroke{nil, &[]BitmapStroke{}, &[]BitmapStroke{{Radius: 0.6, Source: "glyph"}}} {
				layout := *styledCell.Layout
				layout.Strokes = strokes
				body, err := json.Marshal(layout)
				if err != nil {
					t.Fatal(err)
				}
				var restored BitmapRunLayout
				if json.Unmarshal(body, &restored) != nil || (restored.Strokes == nil) != (strokes == nil) {
					t.Fatal("stroke presence roundtrip", string(body))
				}
				if strokes != nil && !reflect.DeepEqual(*restored.Strokes, *strokes) {
					t.Fatal("stroke value roundtrip", string(body))
				}
			}
			workspaceDir := filepath.Join(ttfFixtureDir, "workspace")
			workspaceBaseBytes, err := os.ReadFile(filepath.Join(workspaceDir, "literal-base.png"))
			if err != nil {
				t.Fatal(err)
			}
			workspaceImage, err := png.Decode(bytes.NewReader(workspaceBaseBytes))
			if err != nil {
				t.Fatal(err)
			}
			workspaceBase := image.NewNRGBA(workspaceImage.Bounds())
			draw.Draw(workspaceBase, workspaceBase.Rect, workspaceImage, workspaceImage.Bounds().Min, draw.Src)
			workspaceCell := BitmapCell{ID: "original-temporary-crop", Rect: []int{0, 0, 512, 512}, Runs: []BitmapRun{{Text: "A" + strings.Repeat("\u0301", 16), Fill: []int{7, 5, 4, 255}}}, Layout: &BitmapRunLayout{At: []float64{256, 256}, Size: 16, MinSize: 16, MaxWidth: 400, ScaleX: 1, Strokes: &[]BitmapStroke{}, Composite: "float"}}
			workspaceCandidate, _, err := composeCells(workspaceBase, nil, styledFont, RasterComposition{Cells: []BitmapCell{workspaceCell}, Icons: nil})
			if err != nil {
				t.Fatal("original temporary crop", err)
			}
			workspaceExpected, err := os.ReadFile(filepath.Join(workspaceDir, "candidate.u8"))
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(workspaceExpected)) != "6731e6f5816df8cef2e763cebed41f2db080a067b7b1d4e4255c5c5df69b02e1" || !bytes.Equal(workspaceCandidate.Pix, workspaceExpected) {
				t.Fatal("whole original temporary crop", err, fmt.Sprintf("%x", sha256.Sum256(workspaceCandidate.Pix)))
			}
			for _, start := range [][2]float64{{1, 0}, {-1, 0}, {0, 1}, {0, -1}, {math.NaN(), 0}, {0, math.Inf(1)}} {
				if _, err := textMasks(ttfFont, 64, "RAQM", []TextRequest{{Text: "A", Start: start}}); err == nil {
					t.Error("accepted invalid raster phase", start)
				}
			}
			styledCandidate, _, err := composeCells(base, nil, styledFont, RasterComposition{Cells: []BitmapCell{styledCell}, Icons: nil})
			if err != nil {
				t.Fatal("styled TTF reference", err)
			}
			expectedPanel, err := os.ReadFile(filepath.Join(styledDir, "candidate.u8"))
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(expectedPanel)) != "57167614da0568ecceb77504c427c803e33ed2fae9e44b19f22cad41c938c2f6" {
				t.Fatal("original styled panel pin", err)
			}
			if !bytes.Equal(styledCandidate.Pix, expectedPanel) {
				if err := os.WriteFile(filepath.Join(ttfFixtureDir, "styled-failed-candidate.rgba"), styledCandidate.Pix, 0600); err != nil {
					t.Fatal(err)
				}
				t.Fatal("complete original styled TTF panel differs", fmt.Sprintf("%x", sha256.Sum256(styledCandidate.Pix)))
			}
			var implicitLines struct {
				Cases []struct {
					Name     string
					Cell     BitmapCell
					Expected string `json:"expected_rgba"`
					SHA      string `json:"expected_sha256"`
				}
			}
			lfFiles := bundledFixtures["testdata/truetype-raster.zip"]
			if json.Unmarshal(lfFiles["lf/facts.json"], &implicitLines) != nil || len(implicitLines.Cases) != 5 {
				t.Fatal("original implicit LF corpus")
			}
			lfImage, err := png.Decode(bytes.NewReader(lfFiles["lf/base.png"]))
			if err != nil {
				t.Fatal(err)
			}
			lfBase := image.NewNRGBA(lfImage.Bounds())
			draw.Draw(lfBase, lfBase.Rect, lfImage, lfImage.Bounds().Min, draw.Src)
			for _, v := range implicitLines.Cases {
				got, _, err := composeCells(lfBase, nil, styledFont, RasterComposition{Cells: []BitmapCell{v.Cell}, Icons: nil})
				if err != nil {
					t.Fatal("original implicit LF render", v.Name, err)
				}
				want := lfFiles["lf/"+v.Expected]
				if fmt.Sprintf("%x", sha256.Sum256(want)) != v.SHA || !bytes.Equal(got.Pix, want) {
					t.Error("whole original implicit LF", v.Name, fmt.Sprintf("%x", sha256.Sum256(got.Pix)))
				}
			}
			corpusDir := filepath.Join(ttfFixtureDir, "corpus")
			var corpus struct {
				Fonts map[string]struct {
					Filename string
					Bytes    int64
					SHA      string `json:"sha256"`
				}
				Cases []struct {
					Name, Font, Expected string
					Cell                 BitmapCell
					Icons                map[string][]int
					Chosen               float64 `json:"chosen_size"`
				} `json:"style_cases"`
				Masks []struct {
					Name, Font, Text, Layout, Raw string
					Size                          int
					Start                         [2]float64
					Dimensions                    [2]int `json:"size_xy"`
					Bearing                       [2]int
					Advance                       float64
					Metrics                       [2]int `json:"ascent_descent"`
				} `json:"primitive_masks"`
			}
			corpusBody, err := os.ReadFile(filepath.Join(corpusDir, "input.json"))
			if err != nil || json.Unmarshal(corpusBody, &corpus) != nil || len(corpus.Cases) != 8 || len(corpus.Masks) != 6 {
				t.Fatal("new original TTF corpus", err)
			}
			corpusFonts := make(map[string][]byte)
			for name, fact := range corpus.Fonts {
				data, err := os.ReadFile(filepath.Join(corpusDir, fact.Filename))
				if err != nil || int64(len(data)) != fact.Bytes || fmt.Sprintf("%x", sha256.Sum256(data)) != fact.SHA {
					t.Fatal("corpus font pin", name, err)
				}
				corpusFonts[name] = data
			}
			for _, v := range corpus.Masks {
				masks, err := textMasks(corpusFonts[v.Font], v.Size, v.Layout, []TextRequest{{Text: v.Text, Start: v.Start}})
				if err != nil {
					t.Error("signed phase mask", v.Name, err)
					continue
				}
				m := masks[0]
				want, err := os.ReadFile(filepath.Join(corpusDir, v.Raw))
				if err != nil || m.Coverage.Rect.Size() != image.Pt(v.Dimensions[0], v.Dimensions[1]) || m.Bearing != image.Pt(v.Bearing[0], v.Bearing[1]) || m.Ascent != v.Metrics[0] || m.Descent != v.Metrics[1] || m.Advance != int64(math.Round(v.Advance*64)) || !bytes.Equal(m.Coverage.Pix, want) {
					t.Error("whole signed phase mask/metrics", v.Name, err, m.Bearing, m.Coverage.Rect.Size())
				}
			}
			corpusBaseFile, err := os.ReadFile(filepath.Join(corpusDir, "literal-base.png"))
			if err != nil {
				t.Fatal(err)
			}
			corpusImage, err := png.Decode(bytes.NewReader(corpusBaseFile))
			if err != nil {
				t.Fatal(err)
			}
			corpusBase := image.NewNRGBA(corpusImage.Bounds())
			draw.Draw(corpusBase, corpusBase.Rect, corpusImage, corpusImage.Bounds().Min, draw.Src)
			if fmt.Sprintf("%x", sha256.Sum256(corpusBase.Pix)) != "e5016007acb589861ffff9b41fa808e4e1d9554caa00d1f2ab2f2e04128666a5" {
				t.Fatal("corpus original base pin")
			}
			for _, v := range corpus.Cases {
				font := RasterFont{TrueType: &RegistryInput{Path: corpus.Fonts[v.Font].Filename, Size: int64(len(corpusFonts[v.Font])), SHA256: corpus.Fonts[v.Font].SHA}, Layout: "RAQM", TrueTypeData: corpusFonts[v.Font]}
				word, _, err := renderRuns(nil, font, v.Cell, v.Icons)
				if err != nil || word.Size != v.Chosen {
					t.Error("TTF quarterfit", v.Name, err)
					continue
				}
				candidate, _, err := composeCells(corpusBase, nil, font, RasterComposition{Cells: []BitmapCell{v.Cell}, Icons: v.Icons})
				if err != nil {
					t.Error("TTF corpus compositor", v.Name, err)
					continue
				}
				want, err := os.ReadFile(filepath.Join(corpusDir, v.Expected))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(candidate.Pix, want) {
					if err := os.WriteFile(filepath.Join(ttfFixtureDir, v.Name+".rgba"), candidate.Pix, 0600); err != nil {
						t.Fatal(err)
					}
					t.Error("whole original TTF styled corpus", v.Name, fmt.Sprintf("%x", sha256.Sum256(candidate.Pix)))
				}
			}
			for _, v := range fontOracle.Masks {
				masks, err := textMasks(files[v.Font], v.Size, v.Engine, []TextRequest{{Text: v.Text}})
				if err != nil {
					t.Fatal(v.Name, err)
				}
				m := masks[0]
				if [2]int{m.Coverage.Rect.Dx(), m.Coverage.Rect.Dy()} != v.Dimensions || [2]int{m.Bearing.X, m.Bearing.Y} != v.Offset || m.Advance != v.Advance || fmt.Sprintf("%x", sha256.Sum256(m.Coverage.Pix)) != v.SHA {
					t.Fatal("original mask", v.Name)
				}
			}
		}
	}

	{
		files := bundledFixtures["testdata/asset-comparison.zip"]
		type previewVector struct {
			Name, Before, After string
			Layout              string
			Scale               int
			Crop                []int  `json:"crop_xywh"`
			Size                [2]int `json:"output_size"`
			RGBA                string `json:"RGBA_sha256"`
			RGB                 string `json:"RGB_sha256"`
			PNGMode             string `json:"png_mode"`
		}
		var oracle struct {
			Cases    []previewVector `json:"checker_cases"`
			Variants []previewVector `json:"pair_variant_cases"`
			Refusals []struct {
				Name  string
				Scale int
				Crop  []int `json:"crop_xywh"`
			} `json:"source_refusals"`
		}
		if json.Unmarshal(files["expected-facts.json"], &oracle) != nil || len(oracle.Cases) != 17 || len(oracle.Refusals) != 5 || len(oracle.Variants) != 22 {
			t.Fatal("original comparison facts")
		}
		previewDir := t.TempDir()
		sourcePath, afterPath, profilePath := filepath.Join(previewDir, "before.png"), filepath.Join(previewDir, "after.png"), filepath.Join(previewDir, "profile.json")
		args := []string{"--source", sourcePath, "--texture-profile", profilePath}
		fontPath := write(filepath.Join(previewDir, "Aileron.ttf"), files["Aileron-Pillow-default.ttf"])
		fontInput := RegistryInput{Path: fontPath, Size: int64(len(files["Aileron-Pillow-default.ttf"])), SHA256: fmt.Sprintf("%x", sha256.Sum256(files["Aileron-Pillow-default.ttf"]))}
		for _, vector := range append(oracle.Cases, oracle.Variants...) {
			before, after := files["inputs/"+vector.Before+".png"], files["inputs/"+vector.After+".png"]
			layout := map[string]any{"scale": vector.Scale}
			if vector.Layout != "" {
				layout["layout"] = vector.Layout
			}
			if vector.Layout == "weekday" {
				layout["font"] = fontInput
			}
			if vector.Crop != nil {
				layout["crop"] = vector.Crop
			}
			profile := map[string]any{"operation": "comparison", "source_size": len(before), "source_sha256": fmt.Sprintf("%x", sha256.Sum256(before)), "png": afterPath, "png_sha256": fmt.Sprintf("%x", sha256.Sum256(after)), "evidence": "Independent original complete pixel oracle", "preview": layout}
			write(sourcePath, before)
			write(afterPath, after)
			jsonFile(profilePath, profile)
			inputBytes := make(map[string][]byte)
			inputInfo := make(map[string]os.FileInfo)
			inputPaths := []string{sourcePath, afterPath, profilePath}
			if vector.Layout == "weekday" {
				inputPaths = append(inputPaths, fontPath)
			}
			for _, path := range inputPaths {
				inputBytes[path], _ = os.ReadFile(path)
				inputInfo[path], _ = os.Stat(path)
			}
			output := filepath.Join(previewDir, vector.Name+".png")
			var first bytes.Buffer
			if vector.Layout == "weekday" {
				_, fontErr := textMasks(files["Aileron-Pillow-default.ttf"], 10, "BASIC", nil)
				if fontErr != nil {
					if !strings.Contains(fontErr.Error(), "-tags nativefonts") {
						t.Fatal("weekday font support", fontErr)
					}
					if err := run(append(slices.Clone(args), "--apply", "--output", output), &first); err == nil || !strings.Contains(err.Error(), "-tags nativefonts") || first.Len() != 0 {
						t.Fatal("weekday disabled font refusal", err)
					}
					if _, err := os.Stat(output); !os.IsNotExist(err) {
						t.Fatal("disabled weekday wrote output", err)
					}
					continue
				}
			}
			if err := run(args, &first); err != nil {
				t.Fatal("comparison dryrun", vector.Name, err)
			}
			var report struct {
				Mode          string
				PNGMode       string `json:"png_mode"`
				Applied       bool
				Width, Height int
				RGBA          string `json:"rgba_sha256"`
				SHA           string `json:"output_sha256"`
				Bytes         int    `json:"output_bytes"`
			}
			expectedMode := vector.PNGMode
			if expectedMode == "" {
				expectedMode = "RGB"
			}
			if json.Unmarshal(first.Bytes(), &report) != nil || report.Mode != "comparison" || report.PNGMode != expectedMode || report.Applied || report.Width != vector.Size[0] || report.Height != vector.Size[1] || report.RGBA != vector.RGBA {
				t.Fatal("comparison original facts", vector.Name, first.String())
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("comparison dryrun created output", vector.Name, err)
			}
			var repeat, applied bytes.Buffer
			if err := run(args, &repeat); err != nil || !bytes.Equal(first.Bytes(), repeat.Bytes()) {
				t.Fatal("deterministic comparison", vector.Name, err)
			}
			if err := run(append(slices.Clone(args), "--apply", "--output", output), &applied); err != nil {
				t.Fatal("publish comparison", vector.Name, err)
			}
			var appliedReport map[string]any
			if json.Unmarshal(applied.Bytes(), &appliedReport) != nil || appliedReport["applied"] != true || appliedReport["rgba_sha256"] != vector.RGBA || appliedReport["output_sha256"] != report.SHA {
				t.Fatal("comparison apply report", vector.Name, applied.String())
			}
			published, err := os.ReadFile(output)
			colorType := byte(2)
			if vector.PNGMode == "RGBA" {
				colorType = 6
			}
			if err != nil || len(published) != report.Bytes || len(published) < 26 || published[25] != colorType || fmt.Sprintf("%x", sha256.Sum256(published)) != report.SHA {
				t.Fatal("comparison PNG wiremode/publication", vector.Name, err)
			}
			decoded, err := png.Decode(bytes.NewReader(published))
			if err != nil {
				t.Fatal(err)
			}
			rgba := image.NewNRGBA(decoded.Bounds())
			draw.Draw(rgba, rgba.Rect, decoded, decoded.Bounds().Min, draw.Src)
			if fmt.Sprintf("%x", sha256.Sum256(rgba.Pix)) != vector.RGBA {
				t.Fatal("comparison complete original RGBA hash", vector.Name)
			}
			expectedRGBA, present := files["outputs/"+vector.Name+".rgba"]
			if !present && vector.Size[0]*vector.Size[1] <= 1<<20 {
				t.Fatal("missing original RGBA bytes", vector.Name)
			}
			if present && !bytes.Equal(rgba.Pix, expectedRGBA) {
				t.Fatal("comparison complete original RGBA", vector.Name)
			}
			var rgb []byte
			for i := 0; i < len(rgba.Pix); i += 4 {
				if rgba.Pix[i+3] != 255 {
					t.Fatal("comparison nonopaque output", vector.Name, i)
				}
				rgb = append(rgb, rgba.Pix[i:i+3]...)
			}
			if fmt.Sprintf("%x", sha256.Sum256(rgb)) != vector.RGB {
				t.Fatal("comparison complete original RGB hash", vector.Name)
			}
			expectedRGB, present := files["outputs/"+vector.Name+".rgb"]
			if !present && vector.Size[0]*vector.Size[1] <= 1<<20 {
				t.Fatal("missing original RGB bytes", vector.Name)
			}
			if present && !bytes.Equal(rgb, expectedRGB) {
				t.Fatal("comparison complete original RGB", vector.Name)
			}
			for _, target := range append([]string{output}, inputPaths...) {
				var refused bytes.Buffer
				if err := run(append(slices.Clone(args), "--apply", "--output", target), &refused); err == nil || refused.Len() != 0 {
					t.Fatal("comparison overwrite refusal", vector.Name, target, err)
				}
			}
			for path, want := range inputBytes {
				got, _ := os.ReadFile(path)
				info, _ := os.Stat(path)
				if !bytes.Equal(got, want) || !os.SameFile(info, inputInfo[path]) || info.ModTime() != inputInfo[path].ModTime() {
					t.Fatal("comparison input preservation", vector.Name, path)
				}
			}
		}
		var capacity struct {
			Cases []struct {
				Name string
				Size [2]int `json:"output_size"`
				RGBA string `json:"complete_pre_rgb_rgba_sha256"`
				RGB  string `json:"complete_rgb_sha256"`
			} `json:"cases"`
		}
		if json.Unmarshal(files["capacity/facts.json"], &capacity) != nil || len(capacity.Cases) != 2 {
			t.Fatal("original normal capacity facts")
		}
		for _, vector := range capacity.Cases {
			data := files["capacity/"+vector.Name+"-before.png"]
			write(sourcePath, data)
			profile := map[string]any{"operation": "comparison", "source_size": len(data), "source_sha256": fmt.Sprintf("%x", sha256.Sum256(data)), "png": sourcePath, "png_sha256": fmt.Sprintf("%x", sha256.Sum256(data)), "evidence": "Original-only normal capacity, shared source/candidate path", "preview": map[string]any{"scale": 3}}
			jsonFile(profilePath, profile)
			output := filepath.Join(previewDir, "capacity-"+vector.Name+".png")
			var out bytes.Buffer
			if err := run(append(slices.Clone(args), "--apply", "--output", output), &out); err != nil {
				t.Fatal("normal comparison capacity", vector.Name, err)
			}
			var report struct {
				RGBA          string `json:"rgba_sha256"`
				Width, Height int
			}
			if json.Unmarshal(out.Bytes(), &report) != nil || report.RGBA != vector.RGBA || report.Width != vector.Size[0] || report.Height != vector.Size[1] {
				t.Fatal("normal capacity full original RGBA", vector.Name, out.String())
			}
			published, err := os.ReadFile(output)
			if err != nil || len(published) < 26 || published[25] != 2 {
				t.Fatal("normal capacity RGB PNG", vector.Name, err)
			}
			decoded, err := png.Decode(bytes.NewReader(published))
			if err != nil {
				t.Fatal(err)
			}
			rgba := image.NewNRGBA(decoded.Bounds())
			draw.Draw(rgba, rgba.Rect, decoded, decoded.Bounds().Min, draw.Src)
			if fmt.Sprintf("%x", sha256.Sum256(rgba.Pix)) != vector.RGBA {
				t.Fatal("normal capacity complete decoded original RGBA", vector.Name)
			}
			rgbHash := sha256.New()
			row := make([]byte, vector.Size[0]*3)
			for y := 0; y < vector.Size[1]; y++ {
				for x := 0; x < vector.Size[0]; x++ {
					at := rgba.PixOffset(x, y)
					copy(row[3*x:3*x+3], rgba.Pix[at:at+3])
				}
				rgbHash.Write(row)
			}
			if fmt.Sprintf("%x", rgbHash.Sum(nil)) != vector.RGB {
				t.Fatal("normal capacity complete original RGB", vector.Name)
			}
			got, _ := os.ReadFile(sourcePath)
			if !bytes.Equal(got, data) {
				t.Fatal("normal capacity aliased input changed", vector.Name)
			}
		}
		before, after := files["inputs/before.png"], files["inputs/after.png"]
		write(sourcePath, before)
		write(afterPath, after)
		base := map[string]any{"operation": "comparison", "source_size": len(before), "source_sha256": fmt.Sprintf("%x", sha256.Sum256(before)), "png": afterPath, "png_sha256": fmt.Sprintf("%x", sha256.Sum256(after)), "evidence": "literal", "preview": map[string]any{"scale": 1, "crop": []int{0, 0, 9, 3}}}
		for _, bad := range oracle.Refusals {
			candidate := maps.Clone(base)
			layout := map[string]any{"scale": bad.Scale}
			if bad.Crop != nil {
				layout["crop"] = bad.Crop
			}
			candidate["preview"] = layout
			jsonFile(profilePath, candidate)
			var out bytes.Buffer
			if err := run(args, &out); err == nil || out.Len() != 0 {
				t.Fatal("original comparison geometry refusal", bad.Name, err)
			}
		}
		for _, mutation := range []string{"source-pin", "source-size", "source-large", "png-pin", "invalid-pin", "missing-png", "missing-preview", "empty-evidence", "scale-large", "crop-short", "crop-origin", "crop-axis", "crop-area", "canvas-axis", "canvas-area", "native-selector", "native-pixel", "native-palette", "native-rectangles", "native-render", "specification", "archive", "not-comparison", "invalid-before", "invalid-after", "unknown-layout", "flat-font", "flat-scaled-gap-bound", "weekday-no-font", "weekday-crop", "weekday-canvas", "font-empty-path", "font-missing", "font-zero-size", "font-size-mismatch", "font-large", "font-pin", "font-invalid-pin", "font-invalid-bytes"} {
			candidate := maps.Clone(base)
			layout := maps.Clone(base["preview"].(map[string]any))
			candidate["preview"] = layout
			write(sourcePath, before)
			write(afterPath, after)
			font := fontInput
			if strings.HasPrefix(mutation, "font-") || mutation == "weekday-canvas" {
				layout["layout"], layout["font"] = "weekday", &font
				delete(layout, "crop")
			}
			switch mutation {
			case "unknown-layout":
				layout["layout"] = "unknown"
			case "flat-font":
				layout["layout"], layout["font"] = "flat", &font
			case "flat-scaled-gap-bound":
				layout["layout"], layout["scale"], layout["crop"] = "flat", 8192, []int{0, 0, 1, 1}
			case "weekday-no-font":
				layout["layout"] = "weekday"
				delete(layout, "crop")
			case "weekday-crop":
				layout["layout"], layout["font"] = "weekday", &font
			case "weekday-canvas":
				layout["scale"] = 256
			case "font-empty-path":
				font.Path = ""
			case "font-missing":
				font.Path = filepath.Join(previewDir, "missing-font.ttf")
			case "font-zero-size":
				font.Size = 0
			case "font-size-mismatch":
				font.Size++
			case "font-large":
				font.Size = 4<<20 + 1
			case "font-pin":
				font.SHA256 = strings.Repeat("0", 64)
			case "font-invalid-pin":
				font.SHA256 = "bad"
			case "font-invalid-bytes":
				font.Path, font.Size, font.SHA256 = sourcePath, int64(len(before)), fmt.Sprintf("%x", sha256.Sum256(before))
			case "source-pin":
				candidate["source_sha256"] = strings.Repeat("0", 64)
			case "source-size":
				candidate["source_size"] = len(before) + 1
			case "source-large":
				candidate["source_size"] = 64<<20 + 1
			case "png-pin":
				candidate["png_sha256"] = strings.Repeat("0", 64)
			case "invalid-pin":
				candidate["png_sha256"] = "bad"
			case "missing-png":
				delete(candidate, "png")
			case "missing-preview":
				delete(candidate, "preview")
			case "empty-evidence":
				candidate["evidence"] = ""
			case "scale-large":
				layout["scale"] = 16385
			case "crop-short":
				layout["crop"] = []int{0, 0, 9}
			case "crop-origin":
				layout["crop"] = []int{1<<30 + 1, 0, 1, 1}
			case "crop-axis":
				layout["crop"] = []int{0, 0, 4097, 1}
			case "crop-area":
				layout["crop"] = []int{0, 0, 1025, 1025}
			case "canvas-axis":
				layout["crop"] = []int{0, 0, 4096, 1}
				layout["scale"] = 5
			case "canvas-area":
				layout["crop"] = []int{0, 0, 1024, 1024}
				layout["scale"] = 4
			case "native-selector":
				candidate["texture"] = "alpha"
			case "native-pixel":
				candidate["pixel_policy"] = "rgba"
			case "native-palette":
				candidate["palette_policy"] = "exact"
			case "native-rectangles":
				candidate["rectangles"] = [][]int{{0, 0, 1, 1}}
			case "native-render":
				candidate["render"] = map[string]any{"font": "unused"}
			case "specification":
				candidate["specifications"] = map[string]any{}
			case "archive":
				candidate["archive"] = "unused"
			case "not-comparison":
				candidate["operation"] = "inventory"
			case "invalid-before":
				raw := []byte("not a PNG source")
				write(sourcePath, raw)
				candidate["source_size"] = len(raw)
				candidate["source_sha256"] = fmt.Sprintf("%x", sha256.Sum256(raw))
			case "invalid-after":
				raw := []byte("not a PNG candidate")
				write(afterPath, raw)
				candidate["png_sha256"] = fmt.Sprintf("%x", sha256.Sum256(raw))
			}
			jsonFile(profilePath, candidate)
			failed := filepath.Join(previewDir, "failed.png")
			for _, attempt := range [][]string{args, append(slices.Clone(args), "--apply", "--output", failed)} {
				var out bytes.Buffer
				if err := run(attempt, &out); err == nil || out.Len() != 0 {
					t.Fatal("comparison refusal", mutation, err)
				}
				if _, err := os.Lstat(failed); !os.IsNotExist(err) {
					t.Fatal("failed comparison left output", mutation, err)
				}
			}
		}
		write(sourcePath, before)
		write(afterPath, after)
		body, _ := json.Marshal(base)
		for _, change := range [][2]string{
			{`"operation":"comparison"`, `"operation":"comparison","operation":"comparison"`},
			{`"operation":"comparison"`, `"Operation":"comparison"`},
			{`"scale":1`, `"scale":1,"scale":2`},
			{`"scale":1`, `"Scale":1`},
			{`"scale":1`, `"scale":null`},
			{`"scale":1`, `"scale":1.5`},
			{`"scale":1`, `"scale":"1"`},
			{`"scale":1`, `"scale":1,"extra":0`},
			{`"scale":1`, `"scale":1,"layout":null`},
			{`"scale":1`, `"scale":1,"Layout":"flat"`},
			{`"scale":1`, `"scale":1,"layout":"flat","layout":"checker"`},
			{`"scale":1`, `"scale":1,"font":null`},
			{`"scale":1`, `"scale":1,"font":{"Path":"unused","size":1,"sha256":"bad"}`},
			{`"crop":[0,0,9,3]`, `"crop":[null,0,9,3]`},
			{`"preview":{`, `"preview":null,"discarded":{`},
			{`"evidence":"literal"`, `"evidence":"\ud800"`},
		} {
			bad := strings.Replace(string(body), change[0], change[1], 1)
			if bad == string(body) {
				t.Fatal("comparison mutation anchor", change)
			}
			write(profilePath, []byte(bad))
			var out bytes.Buffer
			if err := run(args, &out); err == nil || out.Len() != 0 {
				t.Fatal("comparison owned JSON refusal", change, err)
			}
		}
		for _, key := range []string{"preview", "Preview", "contacts", "Contacts", "archive", "Archive", "index_sha256", "index_ſha256"} {
			legacy := maps.Clone(base)
			delete(legacy, "preview")
			legacy["operation"], legacy["texture"], legacy[key] = "", "alpha", nil
			jsonFile(profilePath, legacy)
			var legacyOut bytes.Buffer
			if err := run(args, &legacyOut); err == nil || !strings.Contains(err.Error(), "unknown field") || legacyOut.Len() != 0 {
				t.Fatal("legacy null field ownership and Unicode folding", key, err)
			}
		}
		base["evidence"] = "null is a valid string"
		jsonFile(profilePath, base)
		for _, badArgs := range [][]string{append(slices.Clone(args), "--apply"), append(slices.Clone(args), "--output", filepath.Join(previewDir, "unrequested.png"))} {
			var out bytes.Buffer
			if err := run(badArgs, &out); err == nil || out.Len() != 0 {
				t.Fatal("comparison apply/output contract", err)
			}
		}
		var valid bytes.Buffer
		if err := run(args, &valid); err != nil {
			t.Fatal("quoted null must remain ordinary text", err)
		}
		for _, budget := range []uint64{0, 26, 27} {
			image, charged, err := decodePNG(before, budget)
			if budget < 27 {
				if err != errPNGPixelBudget || image != nil || charged != 0 {
					t.Fatal("PNG budget refusal", budget, charged, err)
				}
			} else if err != nil || image == nil || charged != 27 {
				t.Fatal("PNG exact work charge", charged, err)
			}
		}
		if image, charged, err := decodePNG(before[:len(before)-12], 27); err == nil || image != nil || charged != 27 {
			t.Fatal("failed PNG payload must charge attempted pixels", charged, err)
		}
	}
	{
		files := bundledFixtures["testdata/asset-manifest.zip"]
		var oracle struct {
			Source struct {
				Bytes    int64
				SHA      string `json:"sha256"`
				IndexSHA string `json:"index_sha256"`
			}
			Entries []struct {
				Ordinal               int      `json:"index_ordinal"`
				Span                  [2]int64 `json:"file_span"`
				Entry, Classification string
				Size                  int64  `json:"source_bytes"`
				SHA                   string `json:"source_sha256"`
				Facts                 struct {
					Geometry *[2]int
					RGBA     string `json:"rgba_sha256"`
					Score    *[6]float64
					Tier     string
					Reasons  []string
				}
				Natives []struct {
					Ordinal  int `json:"native_ordinal"`
					Name     string
					Geometry *[2]int
					RGBA     string `json:"rgba_sha256"`
					Score    *[6]float64
					Tier     string
					Reasons  []string
				} `json:"native_rows"`
			}
			Refusals []struct {
				Name     string
				SHA      string `json:"source_sha256"`
				IndexSHA string `json:"index_sha256"`
			}
		}
		if json.Unmarshal(files["cmb/expected-manifest-facts.json"], &oracle) != nil || len(oracle.Entries) != 9 || len(oracle.Refusals) != 4 {
			t.Fatal("frozen batch facts")
		}
		manifestDir := t.TempDir()
		sourcePath := filepath.Join(manifestDir, "source.cmb")
		profilePath := filepath.Join(manifestDir, "profile.json")
		output := filepath.Join(manifestDir, "previews.zip")
		profile := TextureProfile{Operation: "manifest", SourceSize: oracle.Source.Bytes, SourceSHA256: oracle.Source.SHA, IndexSHA256: oracle.Source.IndexSHA, Archive: "SYNTHETIC", Evidence: "Independent CMB index order, full pixel and discovery oracles", Specifications: map[string]TextureSpecification{"joined-alpha": {Entry: oracle.Entries[1].Entry, Texture: "alpha", JPText: "日本語", ProposedEN: "Example"}}}
		write(sourcePath, files["cmb/mixed.cmb"])
		jsonFile(profilePath, profile)
		before, _ := os.Stat(sourcePath)
		profileBefore, _ := os.Stat(profilePath)
		sourceBytes, _ := os.ReadFile(sourcePath)
		profileBytes, _ := os.ReadFile(profilePath)
		args := []string{"--source", sourcePath, "--texture-profile", profilePath}
		var first bytes.Buffer
		if err := run(args, &first); err != nil {
			t.Fatal("manifest dry run", err)
		}
		var report struct {
			Manifest TextureManifest
			Applied  bool
			SHA      string `json:"bundle_sha256"`
			Size     int    `json:"bundle_size"`
		}
		if json.Unmarshal(first.Bytes(), &report) != nil || report.Applied || len(report.Manifest.Entries) != 9 {
			t.Fatal("complete batch report", first.String())
		}
		decoded, unknown, previews := 0, 0, make(map[string][2]string)
		for i, expected := range oracle.Entries {
			entry := report.Manifest.Entries[i]
			if entry.Ordinal != expected.Ordinal || entry.Name != expected.Entry || entry.SourceSize != expected.Size || entry.SourceSHA256 != expected.SHA || entry.SourceRange != expected.Span {
				t.Fatal("index order/provenance", i, entry, expected)
			}
			count := len(expected.Natives)
			if strings.HasPrefix(expected.Classification, "raw_png") {
				count = 1
			}
			if len(entry.Rasters) != count {
				t.Fatal("all native/error rows", i, len(entry.Rasters), count)
			}
			for j, row := range entry.Rasters {
				geometry, rgba, score, tier, reasons := expected.Facts.Geometry, expected.Facts.RGBA, expected.Facts.Score, expected.Facts.Tier, expected.Facts.Reasons
				if len(expected.Natives) > 0 {
					n := expected.Natives[j]
					geometry, rgba, score, tier, reasons = n.Geometry, n.RGBA, n.Score, n.Tier, n.Reasons
					if row.NativeOrdinal != n.Ordinal || row.Specification.Texture != n.Name {
						t.Fatal("native exact identity", i, j, row)
					}
				} else if row.NativeOrdinal != -1 {
					t.Fatal("raw PNG has no native ordinal", i)
				}
				if !reflect.DeepEqual(row.DecodedGeometry, geometry) || row.Discovery.Tier != tier || !reflect.DeepEqual(row.Discovery.FlagReasons, reasons) {
					t.Fatal("frozen measured facts", i, j, row, geometry, tier, reasons)
				}
				if geometry == nil {
					unknown++
					if row.DecodedStatus != "unavailable" || row.RGBASHA256 != nil || row.Diagnostic == "" || row.Preview != "" {
						t.Fatal("unknown raster remains unknown", i, j, row)
					}
				} else {
					decoded++
					if row.DecodedStatus != "decoded" || row.RGBASHA256 == nil || *row.RGBASHA256 != rgba || row.Preview == "" || row.PreviewSHA256 == "" {
						t.Fatal("literal decoded pixels", i, j, row)
					}
					if _, duplicate := previews[row.Preview]; duplicate {
						t.Fatal("preview name collision", row.Preview)
					}
					previews[row.Preview] = [2]string{rgba, row.PreviewSHA256}
				}
				if score == nil {
					if row.Discovery.Score != nil || row.Discovery.Status != "unavailable" {
						t.Fatal("unknown discovery", i, j, row.Discovery)
					}
				} else {
					s := row.Discovery.Score
					if s == nil {
						t.Fatal("missing discovery", i, j)
					}
					if ([6]float64{float64(s.GlyphClusters), s.ClusterFraction, float64(s.GlyphTiles), s.DominantColorFraction, s.OpaqueFraction, float64(s.TextLineRows)}) != *score {
						t.Fatal("batch source counter oracle", i, j, s, *score)
					}
				}
			}
		}
		if decoded != 6 || unknown != 4 || report.Manifest.Entries[1].Rasters[0].ID != "joined-alpha" || report.Manifest.Entries[1].Rasters[0].Specification != profile.Specifications["joined-alpha"] {
			t.Fatal("complete counts/authored join", decoded, unknown)
		}
		var repeated bytes.Buffer
		if err := run(args, &repeated); err != nil || !bytes.Equal(first.Bytes(), repeated.Bytes()) {
			t.Fatal("deterministic dry manifest", err)
		}
		var applied bytes.Buffer
		if err := run(append(slices.Clone(args), "--apply", "--output", output), &applied); err != nil {
			t.Fatal("publish manifest", err)
		}
		var actual struct {
			Manifest TextureManifest
			Applied  bool
			SHA      string `json:"bundle_sha256"`
		}
		if json.Unmarshal(applied.Bytes(), &actual) != nil || !actual.Applied || !reflect.DeepEqual(actual.Manifest, report.Manifest) || actual.SHA != report.SHA {
			t.Fatal("same publication facts", applied.String())
		}
		published, err := os.ReadFile(output)
		if err != nil || len(published) != report.Size || fmt.Sprintf("%x", sha256.Sum256(published)) != report.SHA {
			t.Fatal("verified bundle", err)
		}
		zipReport, err := zip.NewReader(bytes.NewReader(published), int64(len(published)))
		if err != nil || len(zipReport.File) != 7 {
			t.Fatal("contained seven artifacts", err)
		}
		for _, file := range zipReport.File {
			reader, err := file.Open()
			if err != nil {
				t.Fatal(err)
			}
			raw, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				t.Fatal(err)
			}
			if file.Name == "manifest.json" {
				var stored TextureManifest
				if json.Unmarshal(raw, &stored) != nil || !reflect.DeepEqual(stored, report.Manifest) {
					t.Fatal("stored manifest")
				}
				continue
			}
			want, ok := previews[file.Name]
			if !ok || strings.Contains(file.Name, "..") || filepath.IsAbs(file.Name) {
				t.Fatal("contained preview", file.Name)
			}
			img, err := png.Decode(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			rgba := image.NewNRGBA(img.Bounds())
			draw.Draw(rgba, rgba.Bounds(), img, img.Bounds().Min, draw.Src)
			if fmt.Sprintf("%x", sha256.Sum256(rgba.Pix)) != want[0] || fmt.Sprintf("%x", sha256.Sum256(raw)) != want[1] {
				t.Fatal("complete preview pixel oracle", file.Name)
			}
			delete(previews, file.Name)
		}
		if len(previews) != 0 {
			t.Fatal("missing preview links", previews)
		}
		for _, target := range []string{output, sourcePath, profilePath} {
			var out bytes.Buffer
			if err := run(append(slices.Clone(args), "--apply", "--output", target), &out); err == nil || out.Len() != 0 {
				t.Fatal("overwrite refusal", target, err)
			}
		}
		for _, p := range []string{sourcePath, profilePath} {
			got, _ := os.ReadFile(p)
			info, _ := os.Stat(p)
			want, original := sourceBytes, before
			if p == profilePath {
				want, original = profileBytes, profileBefore
			}
			if !bytes.Equal(got, want) || !os.SameFile(info, original) || info.ModTime() != original.ModTime() {
				t.Fatal("input preservation", p)
			}
		}
		for _, mutation := range []string{"source-pin", "index-pin", "missing-entry", "missing-native", "duplicate-join", "ambiguous-native", "archive-mismatch", "authoring-policy", "empty-id", "oversized-source"} {
			candidate := profile
			candidate.Specifications = maps.Clone(profile.Specifications)
			switch mutation {
			case "source-pin":
				candidate.SourceSHA256 = strings.Repeat("0", 64)
			case "index-pin":
				candidate.IndexSHA256 = strings.Repeat("0", 64)
			case "missing-entry":
				candidate.Specifications["bad"] = TextureSpecification{Entry: "missing", Texture: "alpha"}
			case "missing-native":
				candidate.Specifications["bad"] = TextureSpecification{Entry: oracle.Entries[1].Entry, Texture: "missing"}
			case "duplicate-join":
				candidate.Specifications["bad"] = candidate.Specifications["joined-alpha"]
			case "ambiguous-native":
				candidate.Specifications["bad"] = TextureSpecification{Entry: oracle.Entries[5].Entry, Texture: "alpha"}
			case "archive-mismatch":
				candidate.Specifications["bad"] = TextureSpecification{Entry: oracle.Entries[1].Entry, Texture: "beta", Archive: "OTHER"}
			case "authoring-policy":
				candidate.PixelPolicy = "rgba"
			case "empty-id":
				candidate.Specifications[" "] = TextureSpecification{Entry: oracle.Entries[1].Entry, Texture: "beta"}
			case "oversized-source":
				candidate.SourceSize = 1<<30 + 1
			}
			jsonFile(profilePath, candidate)
			var out bytes.Buffer
			if err := run(args, &out); err == nil || out.Len() != 0 {
				t.Fatal("manifest refusal", mutation, err)
			}
			out.Reset()
			failedOutput := filepath.Join(manifestDir, "failed.zip")
			if err := run(append(slices.Clone(args), "--apply", "--output", failedOutput), &out); err == nil || out.Len() != 0 {
				t.Fatal("no partial batch publication", mutation, err)
			}
			if _, err := os.Lstat(failedOutput); !os.IsNotExist(err) {
				t.Fatal("failed batch left output", mutation, err)
			}
		}
		for _, replacement := range [][2]string{
			{`"operation":"manifest"`, `"operation":"manifest","operation":"manifest"`},
			{`"archive":"SYNTHETIC"`, `"Archive":"SYNTHETIC"`},
			{`"source_sha256":`, `"\u017fource_sha256":`},
			{`"joined-alpha":`, `"joined-alpha":{},"joined-alpha":`},
			{`"jp_text":"日本語"`, `"JP_text":"日本語"`},
			{`"jp_text":"日本語"`, `"jp_text":"\ud800"`},
			{`"jp_text":"日本語"`, `"jp_text":"日本語","unknown":true`},
			{`"archive":"SYNTHETIC"`, `"archive":null`},
			{`"source_size":14380`, `"source_size":null`},
		} {
			raw := bytes.Replace(profileBytes, []byte(replacement[0]), []byte(replacement[1]), 1)
			if bytes.Equal(raw, profileBytes) {
				t.Fatal("ineffective malformed batch profile", replacement)
			}
			write(profilePath, raw)
			var out bytes.Buffer
			if err := run(args, &out); err == nil || out.Len() != 0 {
				t.Fatal("batch JSON ambiguity/domain refusal", replacement, err)
			}
		}
		for _, bad := range oracle.Refusals {
			candidate := profile
			raw := files["cmb/"+bad.Name+".cmb"]
			candidate.SourceSize, candidate.SourceSHA256, candidate.IndexSHA256 = int64(len(raw)), bad.SHA, bad.IndexSHA
			write(sourcePath, raw)
			jsonFile(profilePath, candidate)
			var out bytes.Buffer
			if err := run(args, &out); err == nil || out.Len() != 0 {
				t.Fatal("whole archive refusal", bad.Name, err)
			}
		}
		write(sourcePath, sourceBytes)
		write(profilePath, profileBytes)
		// Charge potential decode work even when storage validation later refuses it.
		many := bytes.Clone(files["cmb/member-01.bin"][:28])
		for i := 0; i < 257; i++ {
			frame := bytes.Clone(files["cmb/member-01.bin"][28:1668])
			clear(frame[40:46])
			copy(frame[40:46], fmt.Sprintf("%05d", i))
			binary.LittleEndian.PutUint32(frame[96:], 1024)
			binary.LittleEndian.PutUint32(frame[100:], 1024)
			many = append(many, frame...)
		}
		binary.LittleEndian.PutUint32(many[4:], uint32(len(many)-12))
		binary.LittleEndian.PutUint16(many[24:], 257)
		container := make([]byte, 96)
		binary.LittleEndian.PutUint32(container, 96)
		binary.LittleEndian.PutUint32(container[4:], 1)
		copy(container[8:], `event\budget.txd`)
		binary.LittleEndian.PutUint32(container[92:], uint32(len(many)))
		container = append(container, many...)
		policy := profile
		policy.Specifications = nil
		policy.SourceSize = int64(len(container))
		policy.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(container))
		policy.IndexSHA256 = fmt.Sprintf("%x", sha256.Sum256(container[:96]))
		write(sourcePath, container)
		jsonFile(profilePath, policy)
		var budget bytes.Buffer
		if err := run(args, &budget); err != nil {
			t.Fatal("bounded failed decodes", err)
		}
		var bounded struct{ Manifest TextureManifest }
		if json.Unmarshal(budget.Bytes(), &bounded) != nil || len(bounded.Manifest.Entries) != 1 || len(bounded.Manifest.Entries[0].Rasters) != 257 {
			t.Fatal("budget must not truncate manifest")
		}
		for i, row := range bounded.Manifest.Entries[0].Rasters {
			if row.DecodedStatus != "unavailable" || row.RGBASHA256 != nil || row.DecodedGeometry != nil || row.Diagnostic == "" {
				t.Fatal("budget fixture unexpected decode", i, row)
			}
			if strings.Contains(row.Diagnostic, "budget exhausted") != (i == 256) {
				t.Fatal("exact attempted-pixel boundary", i, row.Diagnostic)
			}
		}
		var pngOracle struct {
			Cases []struct {
				Name  string
				Size  [2]int `json:"dimensions"`
				Score [6]float64
				PNG   string `json:"PNG_sha256"`
				RGBA  string `json:"RGBA_sha256"`
			}
		}
		if json.Unmarshal(files["png/conversion-oracles.json"], &pngOracle) != nil || len(pngOracle.Cases) != 34 {
			t.Fatal("original PNG conversion vectors")
		}
		container = make([]byte, 8+88*len(pngOracle.Cases))
		binary.LittleEndian.PutUint32(container, uint32(len(container)))
		binary.LittleEndian.PutUint32(container[4:], uint32(len(pngOracle.Cases)))
		base := len(container)
		for i, c := range pngOracle.Cases {
			raw := files["png/"+c.Name+".png"]
			if fmt.Sprintf("%x", sha256.Sum256(raw)) != c.PNG {
				t.Fatal("literal PNG pin", c.Name)
			}
			copy(container[8+88*i:], c.Name+".png")
			binary.LittleEndian.PutUint32(container[8+88*i+80:], uint32(len(container)-base))
			binary.LittleEndian.PutUint32(container[8+88*i+84:], uint32(len(raw)))
			container = append(container, raw...)
		}
		policy.SourceSize = int64(len(container))
		policy.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(container))
		policy.IndexSHA256 = fmt.Sprintf("%x", sha256.Sum256(container[:base]))
		write(sourcePath, container)
		jsonFile(profilePath, policy)
		pngOutput := filepath.Join(manifestDir, "png-types.zip")
		var pngReport bytes.Buffer
		if err := run(append(slices.Clone(args), "--apply", "--output", pngOutput), &pngReport); err != nil {
			t.Fatal("complete PNG conversion lifecycle", err)
		}
		var converted struct{ Manifest TextureManifest }
		if json.Unmarshal(pngReport.Bytes(), &converted) != nil || len(converted.Manifest.Entries) != 34 {
			t.Fatal("PNG conversion accounting")
		}
		pngBytes, _ := os.ReadFile(pngOutput)
		zipPNGs, err := zip.NewReader(bytes.NewReader(pngBytes), int64(len(pngBytes)))
		if err != nil {
			t.Fatal(err)
		}
		encoded := make(map[string][]byte)
		for _, file := range zipPNGs.File {
			reader, err := file.Open()
			if err != nil {
				t.Fatal(err)
			}
			encoded[file.Name], err = io.ReadAll(reader)
			reader.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
		for i, c := range pngOracle.Cases {
			entry := converted.Manifest.Entries[i]
			if len(entry.Rasters) != 1 {
				t.Fatal("one raw PNG row", c.Name, entry)
			}
			row := entry.Rasters[0]
			if row.RGBASHA256 == nil || *row.RGBASHA256 != c.RGBA || row.DecodedGeometry == nil || *row.DecodedGeometry != c.Size || row.PreviewSHA256 != c.PNG || !bytes.Equal(encoded[row.Preview], files["png/"+c.Name+".png"]) {
				t.Fatal("Pillow RGBA/original encoded PNG", c.Name, row)
			}
			s := row.Discovery.Score
			if s == nil || ([6]float64{float64(s.GlyphClusters), s.ClusterFraction, float64(s.GlyphTiles), s.DominantColorFraction, s.OpaqueFraction, float64(s.TextLineRows)}) != c.Score {
				t.Fatal("original PNG six-counter score", c.Name, s, c.Score)
			}
		}
	}
	{
		// Authored facts are joined by exact native identity; failed measurements stay null.
		files := bundledFixtures["testdata/asset-specification.zip"]
		var specs map[string]TextureSpecification
		for _, variant := range []string{"two-native", "zero-width", "unsupported-depth", "metadata-error", "duplicate-name", "duplicate-metadata-error"} {
			raw := files["literal/"+variant+".txd"]
			index, err := indexTextures(raw)
			if err != nil {
				t.Fatal("reused index fixture", variant, err)
			}
			before := sha256.Sum256(raw)
			indexBefore, _ := json.Marshal(map[string]any{"textures": index.Textures, "by_name": index.byName, "chunks": index.chunkCount})
			for _, selector := range []string{"alpha", "beta", "missing"} {
				for _, policy := range []string{"", "rgba", "source", "exact", "invalid"} {
					fresh, plain, plainErr := texture(raw, selector, nil, nil, policy, nil)
					cached, reused, reusedErr := texture(raw, selector, nil, nil, policy, &index)
					if !bytes.Equal(fresh, cached) || !reflect.DeepEqual(plain, reused) || fmt.Sprint(plainErr) != fmt.Sprint(reusedErr) {
						t.Fatal("cached complete bytes/refusal parity", variant, selector, policy, plainErr, reusedErr)
					}
				}
			}
			for _, foreign := range [][]byte{bytes.Clone(raw), raw[1:], raw[:len(raw)-1]} {
				if artifact, raster, err := texture(foreign, "alpha", nil, nil, "", &index); err == nil || artifact != nil || raster != nil || !strings.Contains(err.Error(), "same immutable source view") {
					t.Fatal("foreign prepared index", variant, err)
				}
			}
			if _, _, err := texture(raw, "alpha", nil, nil, "", &TextureIndex{}); err == nil {
				t.Fatal("empty prepared index accepted")
			}
			indexAfter, _ := json.Marshal(map[string]any{"textures": index.Textures, "by_name": index.byName, "chunks": index.chunkCount})
			if sha256.Sum256(raw) != before || !bytes.Equal(indexBefore, indexAfter) {
				t.Fatal("cache reuse mutated source/index", variant)
			}
		}
		var oracle struct {
			TwoNative struct {
				Rows map[string]struct {
					Header TextureHeader
					RGBA   string `json:"rgba_sha256"`
				} `json:"rows"`
			} `json:"two_native"`
		}
		if json.Unmarshal(files["literal/literal-specs.json"], &specs) != nil || json.Unmarshal(files["literal/expected-join-facts.json"], &oracle) != nil || len(specs) != 2 || len(oracle.TwoNative.Rows) != 2 {
			t.Fatal("independent specification facts")
		}
		specDir := t.TempDir()
		sourcePath := filepath.Join(specDir, "source.txd")
		profilePath := filepath.Join(specDir, "profile.json")
		args := []string{"--source", sourcePath, "--texture-profile", profilePath}
		source := files["literal/two-native.txd"]
		profile := TextureProfile{Operation: "specification", SourceSize: int64(len(source)), SourceSHA256: fmt.Sprintf("%x", sha256.Sum256(source)), Evidence: "Independent keyed authored/specification and measured geometry vectors", Specifications: specs}
		for _, variant := range []string{"two-native", "zero-width", "unsupported-depth", "metadata-error"} {
			raw := files["literal/"+variant+".txd"]
			policy := profile
			policy.SourceSize, policy.SourceSHA256 = int64(len(raw)), fmt.Sprintf("%x", sha256.Sum256(raw))
			write(sourcePath, raw)
			jsonFile(profilePath, policy)
			before, err := os.Stat(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			var out, repeat bytes.Buffer
			if err := run(args, &out); err != nil {
				t.Fatal(variant, err)
			}
			if err := run(args, &repeat); err != nil || !bytes.Equal(out.Bytes(), repeat.Bytes()) {
				t.Fatal("specification is not deterministic", variant, err)
			}
			var got struct {
				Mode           string                    `json:"mode"`
				SourceSHA      string                    `json:"source_sha256"`
				CodecSupport   string                    `json:"codec_support"`
				Specifications []TextureSpecificationRow `json:"specifications"`
				Applied        bool                      `json:"applied"`
			}
			if json.Unmarshal(out.Bytes(), &got) != nil || got.Mode != "specification" || got.SourceSHA != policy.SourceSHA256 || got.CodecSupport != "selected_only" || got.Applied || len(got.Specifications) != 2 {
				t.Fatal("specification provenance/report", variant, out.String())
			}
			for i, row := range got.Specifications {
				id := []string{"asset-a", "asset-b"}[i]
				if row.ID != id || row.NativeOrdinal != i || row.Specification != specs[id] {
					t.Fatal("authored facts, exact identity or order changed", variant, row)
				}
				header := oracle.TwoNative.Rows[id].Header
				if i == 1 {
					switch variant {
					case "zero-width":
						header.Width = 0
					case "unsupported-depth":
						header.Depth = 16
					}
				}
				if variant == "metadata-error" && i == 1 {
					if row.Header != nil {
						t.Fatal("unavailable source metadata fabricated", row)
					}
				} else if row.Header == nil || *row.Header != header {
					t.Fatal("parsed metadata changed", variant, row)
				}
				if variant != "two-native" && i == 1 {
					if row.DecodedStatus != "unavailable" || row.DecodedGeometry != nil || row.RGBASHA256 != nil || row.DecodedFormat != "" || row.Diagnostic == "" {
						t.Fatal("unknown decoder geometry/hash claimed", variant, row)
					}
				} else if row.DecodedStatus != "decoded" || row.DecodedGeometry == nil || *row.DecodedGeometry != [2]int{16, 16} || row.RGBASHA256 == nil || *row.RGBASHA256 != oracle.TwoNative.Rows[id].RGBA || row.DecodedFormat != "PSMT8" || row.Diagnostic != "" {
					t.Fatal("independent measured geometry/RGBA mismatch", variant, row)
				}
			}
			after, err := os.Stat(sourcePath)
			preserved, readErr := os.ReadFile(sourcePath)
			if err != nil || readErr != nil || !after.ModTime().Equal(before.ModTime()) || !os.SameFile(before, after) || !bytes.Equal(preserved, raw) {
				t.Fatal("specification changed its source", variant, err, readErr)
			}
		}
		write(sourcePath, source)
		for _, mutation := range []string{"missing", "case", "duplicate", "repeat", "no specs", "empty ID", "blank ID", "long ID", "empty texture", "long texture", "too many", "apply", "output", "selector", "png", "pin", "rectangles", "render", "palette", "pixels", "default", "inventory", "source pin", "source size", "evidence"} {
			bad := profile
			bad.Specifications = maps.Clone(specs)
			badArgs := slices.Clone(args)
			row := specs["asset-a"]
			switch mutation {
			case "missing":
				row.Texture = "missing"
			case "case":
				row.Texture = "Alpha"
			case "duplicate":
				raw := files["literal/duplicate-name.txd"]
				write(sourcePath, raw)
				bad.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(raw))
			case "repeat":
				bad.Specifications["other"] = row
			case "no specs":
				bad.Specifications = nil
			case "empty ID", "blank ID", "long ID":
				delete(bad.Specifications, "asset-a")
				id := ""
				if mutation == "blank ID" {
					id = " \t"
				} else if mutation == "long ID" {
					id = strings.Repeat("a", 257)
				}
				bad.Specifications[id] = row
			case "empty texture":
				row.Texture = ""
			case "long texture":
				row.Texture = strings.Repeat("a", 1025)
			case "too many":
				for i := 0; i < 65; i++ {
					bad.Specifications[fmt.Sprint(i)] = row
				}
			case "apply":
				badArgs = append(badArgs, "--apply", "--output", filepath.Join(specDir, "forbidden"))
			case "output":
				badArgs = append(badArgs, "--output", filepath.Join(specDir, "forbidden"))
			case "selector":
				bad.Texture = "alpha"
			case "png":
				bad.PNG = "candidate.png"
			case "pin":
				bad.PNGSHA256 = profile.SourceSHA256
			case "rectangles":
				bad.Rectangles = [][]int{{0, 0, 1, 1}}
			case "render":
				bad.Render = &RasterRender{}
			case "palette":
				bad.PalettePolicy = "source"
			case "pixels":
				bad.PixelPolicy = "rgba"
			case "default":
				bad.Operation, bad.Texture = "", "alpha"
			case "inventory":
				bad.Operation = "inventory"
			case "source pin":
				bad.SourceSHA256 = strings.Repeat("0", 64)
			case "source size":
				bad.SourceSize--
			case "evidence":
				bad.Evidence = ""
			}
			if mutation == "missing" || mutation == "case" || mutation == "empty texture" || mutation == "long texture" {
				bad.Specifications["asset-a"] = row
			}
			jsonFile(profilePath, bad)
			var out bytes.Buffer
			if err := run(badArgs, &out); err == nil || out.Len() != 0 {
				t.Fatal("invalid specification admitted", mutation, err)
			}
			write(sourcePath, source)
		}
		valid, err := json.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		for _, change := range [][2]string{
			{`"kind":"tutorial"`, `"unknown_kind":"tutorial"`},
			{`"specifications":`, `"SPECIFICATIONS":`},
			{`"texture":"alpha"`, `"TEXTURE":"alpha"`},
			{`"screen_hint":`, `"ſcreen_hint":`},
			{`"kind":"tutorial"`, `"kind":"old","kind":"tutorial"`},
			{`"asset-a":`, `"asset-a":{},"asset-a":`},
			{`"source_sha256":`, `"source_sha256":"old","source_sha256":`},
			{`"日本語"`, `"\ud800"`},
		} {
			bad := bytes.Replace(valid, []byte(change[0]), []byte(change[1]), 1)
			if bytes.Equal(valid, bad) {
				t.Fatal("ineffective specification ambiguity probe", change)
			}
			write(profilePath, bad)
			var out bytes.Buffer
			if err := run(args, &out); err == nil || out.Len() != 0 {
				t.Fatal("ambiguous specification admitted", change, err)
			}
		}
		// Optional authored strings deliberately normalize null/omission to empty.
		optional := profile
		optional.Specifications = maps.Clone(specs)
		row := optional.Specifications["asset-a"]
		row.Notes = ""
		optional.Specifications["asset-a"] = row
		data, _ := json.Marshal(optional)
		write(profilePath, bytes.Replace(data, []byte(`"notes":""`), []byte(`"notes":null`), 1))
		var out bytes.Buffer
		if err := run(args, &out); err != nil {
			t.Fatal("optional null annotation refused", err)
		}
		var normalized struct {
			Specifications []TextureSpecificationRow `json:"specifications"`
		}
		if json.Unmarshal(out.Bytes(), &normalized) != nil || normalized.Specifications[0].Specification.Notes != "" {
			t.Fatal("optional annotation normalization")
		}
		// Independent source oracle: unchanged church_siba frame, newly wrapped dictionary.
		native := files["native/church-siba.txd"]
		policy := profile
		policy.SourceSize, policy.SourceSHA256 = int64(len(native)), fmt.Sprintf("%x", sha256.Sum256(native))
		policy.Specifications = map[string]TextureSpecification{"real-church-siba": {Texture: "church_siba", Kind: "original native source"}}
		write(sourcePath, native)
		jsonFile(profilePath, policy)
		out.Reset()
		if err := run(args, &out); err != nil || json.Unmarshal(out.Bytes(), &normalized) != nil || len(normalized.Specifications) != 1 || normalized.Specifications[0].RGBASHA256 == nil || *normalized.Specifications[0].RGBASHA256 != "50d6b6cf199756a3f883704737d9423e2530c5477de071d28f2436bd5537aeba" {
			t.Fatal("original native specification oracle", err)
		}
		// Bound aggregate potential decode work before any row measurements begin.
		for _, count := range []int{16, 17} {
			many := bytes.Clone(source[:28])
			policy := profile
			policy.Specifications = make(map[string]TextureSpecification)
			for i := 0; i < count; i++ {
				frame := bytes.Clone(source[28:1668])
				name := fmt.Sprintf("n%02d", i)
				clear(frame[44:56])
				copy(frame[44:56], name)
				binary.LittleEndian.PutUint32(frame[96:], 1024)
				binary.LittleEndian.PutUint32(frame[100:], 1024)
				many = append(many, frame...)
				policy.Specifications[name] = TextureSpecification{Texture: name}
			}
			binary.LittleEndian.PutUint32(many[4:], uint32(len(many)-12))
			binary.LittleEndian.PutUint16(many[24:], uint16(count))
			policy.SourceSize, policy.SourceSHA256 = int64(len(many)), fmt.Sprintf("%x", sha256.Sum256(many))
			write(sourcePath, many)
			jsonFile(profilePath, policy)
			out.Reset()
			err := run(args, &out)
			if count == 17 {
				if err == nil || out.Len() != 0 || !strings.Contains(err.Error(), "pixel work budget") {
					t.Fatal("aggregate measurement work bound", err)
				}
			} else if err != nil {
				t.Fatal("exact aggregate work boundary refused", err)
			}
		}
		if files, err := os.ReadDir(specDir); err != nil || len(files) != 2 {
			t.Fatal("specification wrote output files", err)
		}
	}
	{
		observedDir := t.TempDir()
		var oracle struct {
			SourceHex string `json:"source_hex"`
			SourceSHA string `json:"source_sha256"`
			Registry  Registry
			Expected  struct {
				Entries []struct {
					ID        string
					Divergent bool
					Targets   []uint32 `json:"unique_targets_source_order"`
					Sites     []struct {
						VMAs    []uint64 `json:"site_vmas"`
						Words   []uint32
						Target  uint32
						Ordinal int      `json:"site_ordinal"`
						Offsets []uint64 `json:"file_offsets"`
						Mapping struct {
							Storage string
							Offset  uint64 `json:"file_offset"`
						} `json:"target_mapping"`
					}
				} `json:"entries_literal"`
			}
			Invalid []struct {
				Name, ID    string
				Replacement string `json:"replacement_hex_le"`
				FileOffset  int    `json:"file_offset"`
				Site        *ReferenceSite
				RefType     string `json:"ref_type"`
			}
		}
		fixtureData, err := os.ReadFile("testdata/observed-references.json")
		if err != nil || json.Unmarshal(fixtureData, &oracle) != nil || len(oracle.Expected.Entries) != 7 || len(oracle.Invalid) != 16 {
			t.Fatal("independent observed-reference fixture", err)
		}
		source, err := hex.DecodeString(oracle.SourceHex)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(source)) != oracle.SourceSHA {
			t.Fatal("literal observed source pin", err)
		}
		registryData, err := json.Marshal(oracle.Registry)
		if err != nil {
			t.Fatal(err)
		}
		profile := map[string]any{"operation": "reference_observed", "source_size": len(source), "source_sha256": oracle.SourceSHA, "scope_sha256": fmt.Sprintf("%x", sha256.Sum256(registryData)), "evidence": "independent literal observed vectors", "registry_patch_ref": "observed-example"}
		sourcePath := write(filepath.Join(observedDir, "source.elf"), source)
		registryPath := write(filepath.Join(observedDir, "registry.json"), registryData)
		profilePath := jsonFile(filepath.Join(observedDir, "profile.json"), profile)
		args := []string{"--source", sourcePath, "--registry", registryPath, "--recipes", profilePath}
		original, before := make(map[string][]byte), make(map[string]os.FileInfo)
		for _, path := range []string{sourcePath, registryPath, profilePath} {
			original[path], err = os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			before[path], err = os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
		}
		var out bytes.Buffer
		if err := run(args, &out); err != nil {
			t.Fatal("observed reference CLI", err)
		}
		var report ReferenceReport
		if err := json.Unmarshal(out.Bytes(), &report); err != nil || report.Operation != "reference_observed" || report.Applied || report.SourceSHA256 != oracle.SourceSHA || report.RegistrySHA256 != profile["scope_sha256"] || report.GlyphmapSHA256 != "" || report.ProfileSHA256 != fmt.Sprintf("%x", sha256.Sum256(original[profilePath])) {
			t.Fatal("observed report identity", err, out.String())
		}
		rows := make(map[string]ReferenceRow)
		for _, row := range report.Queries["observed-example"] {
			rows[row.ID] = row
		}
		if len(rows) != 7 {
			t.Fatal("observed row count", out.String())
		}
		for _, want := range oracle.Expected.Entries {
			got := rows[want.ID]
			if got.Method != "declared-observed" || got.ContentOK != nil || len(got.Sites) != 0 || got.Target != "" || got.Divergent != want.Divergent || !slices.Equal(got.ObservedTargets, want.Targets) || len(got.ObservedSites) != len(want.Sites) {
				t.Fatal("observed row differs", want.ID, got)
			}
			for i, literal := range want.Sites {
				site := got.ObservedSites[i]
				if site.Error != "" || site.Ordinal != literal.Ordinal || site.Target == nil || *site.Target != literal.Target || !slices.Equal(site.Geometry.VMAs, literal.VMAs) || len(site.Words) != len(literal.Words) || len(site.WordMappings) != len(literal.Words) {
					t.Fatal("literal observed site", want.ID, i, site)
				}
				for j, word := range literal.Words {
					if site.Words[j] == nil || *site.Words[j] != word || len(site.WordMappings[j]) != 1 {
						t.Fatal("observed complete word", want.ID, i, j, site)
					}
					mapping := site.WordMappings[j][0]
					if mapping.Storage != "file_backed" || mapping.VMA != [2]uint64{literal.VMAs[j], literal.VMAs[j] + 4} || mapping.FileRange == nil || *mapping.FileRange != [2]uint64{literal.Offsets[j], literal.Offsets[j] + 4} || mapping.ProgramHeader == nil || *mapping.ProgramHeader != 0 {
						t.Fatal("complete observed word mapping", want.ID, mapping)
					}
				}
				if len(site.TargetMapping) != 1 || site.TargetMapping[0].Storage != literal.Mapping.Storage || site.TargetMapping[0].VMA != [2]uint64{uint64(literal.Target), uint64(literal.Target) + 1} {
					t.Fatal("literal target point mapping", want.ID, site.TargetMapping)
				}
				if literal.Mapping.Storage == "file_backed" && (site.TargetMapping[0].FileRange == nil || *site.TargetMapping[0].FileRange != [2]uint64{literal.Mapping.Offset, literal.Mapping.Offset + 1}) {
					t.Fatal("target point file offset", site)
				}
			}
		}
		summary := report.Summaries["observed-example"]
		if summary.Total != 7 || summary.Resolved != 7 || summary.Unresolved != 0 || summary.ObservedSites != 10 || summary.FailedSites != 0 || summary.DivergentRows != 1 || summary.MultiSite != 1 {
			t.Fatal("literal observed summary", summary)
		}
		for _, vector := range oracle.Invalid {
			badSource := bytes.Clone(source)
			var badRegistry Registry
			if err := json.Unmarshal(registryData, &badRegistry); err != nil {
				t.Fatal(err)
			}
			id := vector.ID
			if id == "" {
				switch vector.Name {
				case "reversed-pair", "unsupported-ref-type-or-no-sites":
					id = "0x468010"
				case "struct-coordinate-mismatch", "struct-addition-overflow":
					id = "0x468000"
				default:
					id = "0x467ff0"
				}
			}
			for i := range badRegistry.Entries {
				entry := &badRegistry.Entries[i]
				if entry.ID != id {
					continue
				}
				if vector.Site != nil {
					entry.RefSites = []ReferenceSite{*vector.Site}
				}
				if vector.RefType != "" {
					entry.RefType = vector.RefType
					entry.RefSites = nil
				}
			}
			if vector.Replacement != "" {
				word, err := hex.DecodeString(vector.Replacement)
				if err != nil {
					t.Fatal(err)
				}
				copy(badSource[vector.FileOffset:], word)
			}
			badProfile := maps.Clone(profile)
			badProfile["source_sha256"] = fmt.Sprintf("%x", sha256.Sum256(badSource))
			badRegistryData, err := json.Marshal(badRegistry)
			if err != nil {
				t.Fatal(err)
			}
			badProfile["scope_sha256"] = fmt.Sprintf("%x", sha256.Sum256(badRegistryData))
			out.Reset()
			if err := run([]string{"--source", write(filepath.Join(observedDir, "bad.elf"), badSource), "--registry", write(filepath.Join(observedDir, "bad-registry.json"), badRegistryData), "--recipes", jsonFile(filepath.Join(observedDir, "bad-profile.json"), badProfile)}, &out); err != nil {
				t.Fatal("invalid observed site must remain a report fact", vector.Name, err)
			}
			var got ReferenceReport
			if json.Unmarshal(out.Bytes(), &got) != nil {
				t.Fatal(out.String())
			}
			found := false
			for _, row := range got.Queries["observed-example"] {
				if row.ID != id {
					continue
				}
				found = true
				if len(row.ObservedTargets) != 0 {
					t.Fatal("invalid site inferred a fallback target", vector.Name, row)
				}
				if len(row.ObservedSites) == 0 {
					if row.Note == "" {
						t.Fatal("missing-sites fact lost", vector.Name)
					}
				} else {
					for _, site := range row.ObservedSites {
						if site.Error == "" || site.Target != nil || len(site.TargetMapping) != 0 {
							t.Fatal("invalid observed target not unknown", vector.Name, site)
						}
						if vector.Replacement != "" && (len(site.Words) != 2 || site.Words[0] == nil || site.Words[1] == nil) {
							t.Fatal("invalid opcode lost readable rawwords", vector.Name, site)
						}
					}
				}
			}
			if !found {
				t.Fatal("invalid selected row disappeared", vector.Name)
			}
		}
		for _, extra := range [][]string{{"--apply", "--output", filepath.Join(observedDir, "forbidden.elf")}, {"--glyphmap", "unused"}, {"--recipes", profilePath}, {"--fit-profile", "unused"}, {"--texture-profile", "unused"}, {"--snapshot", "list"}, {"--note", "unused"}, {"unexpected"}} {
			out.Reset()
			if err := run(append(slices.Clone(args), extra...), &out); err == nil || out.Len() != 0 {
				t.Fatal("observed report accepted foreign workflow", extra, err)
			}
			if extra[0] == "--glyphmap" {
				if err := run(append(slices.Clone(args), extra...), io.Discard); err == nil || !strings.Contains(err.Error(), "glyphmap and writes are forbidden") {
					t.Fatal("observed diagnostic directs users to a forbidden glyphmap", err)
				}
			}
		}
		for _, name := range []string{"empty family", "unknown family", "empty evidence", "wrong source hash", "wrong registry hash", "wrong size", "search fields", "patch field", "mapping field"} {
			bad := maps.Clone(profile)
			switch name {
			case "empty family":
				bad["registry_patch_ref"] = ""
			case "unknown family":
				bad["registry_patch_ref"] = "missing"
			case "empty evidence":
				bad["evidence"] = ""
			case "wrong source hash":
				bad["source_sha256"] = strings.Repeat("0", 64)
			case "wrong registry hash":
				bad["scope_sha256"] = strings.Repeat("0", 64)
			case "wrong size":
				bad["source_size"] = len(source) - 1
			case "search fields":
				bad["references"] = map[string]any{}
			case "patch field":
				bad["entries"] = map[string]any{}
			case "mapping field":
				bad["iso_elf_offset"] = ""
			}
			out.Reset()
			if err := run([]string{"--source", sourcePath, "--registry", registryPath, "--recipes", jsonFile(filepath.Join(observedDir, "invalid-profile.json"), bad)}, &out); err == nil || out.Len() != 0 {
				t.Fatal("observed profile accepted", name, err)
			}
		}
		for _, replacement := range []struct{ from, to string }{{`"operation":`, `"Operation":`}, {`"evidence":`, `"evidence":"duplicate","Evidence":`}, {`"source_size":`, `"ſource_size":`}} {
			bad := bytes.Replace(original[profilePath], []byte(replacement.from), []byte(replacement.to), 1)
			out.Reset()
			if err := run([]string{"--source", sourcePath, "--registry", registryPath, "--recipes", write(filepath.Join(observedDir, "alias-profile.json"), bad)}, &out); err == nil || out.Len() != 0 {
				t.Fatal("observed recipe alias accepted", replacement, err)
			}
		}
		for _, replacement := range []struct{ from, to string }{{`"entries":`, `"Entries":`}, {`"id":"0x467ff0"`, `"id":"0x467ff0","ID":"0x468010"`}, {`"patch_ref":"observed-example"`, `"patch_ref":"observed-example","Patch_Ref":"other"`}, {`"ref_sites":`, `"Ref_Sites":`}, {`"pointer_vma":`, `"Pointer_VMA":`}, {`"reg":`, `"REG":`}} {
			bad := bytes.Replace(registryData, []byte(replacement.from), []byte(replacement.to), 1)
			if bytes.Equal(bad, registryData) {
				t.Fatal("alias fixture missed", replacement)
			}
			badProfile := maps.Clone(profile)
			badProfile["scope_sha256"] = fmt.Sprintf("%x", sha256.Sum256(bad))
			out.Reset()
			if err := run([]string{"--source", sourcePath, "--registry", write(filepath.Join(observedDir, "alias-registry.json"), bad), "--recipes", jsonFile(filepath.Join(observedDir, "alias-registry-profile.json"), badProfile)}, &out); err == nil || out.Len() != 0 {
				t.Fatal("observed owned metadata alias accepted", replacement, err)
			}
		}
		for _, mode := range []string{"too many entries", "too many sites", "duplicate normalized ID", "opaque metadata", "partial code words", "split site word"} {
			var bad Registry
			if err := json.Unmarshal(registryData, &bad); err != nil {
				t.Fatal(err)
			}
			badSource := bytes.Clone(source)
			switch mode {
			case "too many entries":
				bad.Entries = nil
				for i := 0; i < 257; i++ {
					bad.Entries = append(bad.Entries, RegistryEntry{ID: fmt.Sprintf("0x%x", 0x900000+i*4), PatchRef: "observed-example", RefType: "unknown"})
				}
			case "too many sites":
				first := bad.Entries[0].RefSites[0]
				bad.Entries[0].RefSites = nil
				for i := 0; i < 257; i++ {
					bad.Entries[0].RefSites = append(bad.Entries[0].RefSites, first)
				}
			case "duplicate normalized ID":
				entry := bad.Entries[0]
				entry.ID = "00467FF0"
				bad.Entries = append(bad.Entries, entry)
			case "partial code words":
				bad.Entries[2].RefSites = []ReferenceSite{{LUIVMA: "0x11bc", ADDIUVMA: "0x11c0", Register: "$t0"}}
			case "split site word":
				bad.Entries[0].RefSites = []ReferenceSite{{PointerVMA: "0x11bc"}}
				binary.LittleEndian.PutUint32(badSource[68:], 510)
			}
			badData, err := json.Marshal(bad)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "opaque metadata" {
				badData = bytes.Replace(badData, []byte(`"entries":`), []byte(`"opaque":{"Entries":"kept","Pointer_VMA":7},"entries":`), 1)
				badData = bytes.Replace(badData, []byte(`"en":`), []byte(`"opaque":{"ID":123,"Ref_Sites":"kept"},"en":`), 1)
			}
			badProfile := maps.Clone(profile)
			badProfile["scope_sha256"] = fmt.Sprintf("%x", sha256.Sum256(badData))
			badProfile["source_sha256"] = fmt.Sprintf("%x", sha256.Sum256(badSource))
			out.Reset()
			err = run([]string{"--source", write(filepath.Join(observedDir, "bounds.elf"), badSource), "--registry", write(filepath.Join(observedDir, "bounds-registry.json"), badData), "--recipes", jsonFile(filepath.Join(observedDir, "bounds-profile.json"), badProfile)}, &out)
			if mode == "too many entries" || mode == "too many sites" || mode == "duplicate normalized ID" {
				if err == nil || out.Len() != 0 {
					t.Fatal("observed input bound accepted", mode, err)
				}
				continue
			}
			var got ReferenceReport
			if err != nil || json.Unmarshal(out.Bytes(), &got) != nil {
				t.Fatal("bounded observed facts", mode, err)
			}
			if mode == "opaque metadata" {
				if got.Summaries["observed-example"].Resolved != 7 {
					t.Fatal("opaque metadata changed observations", out.String())
				}
				continue
			}
			id := "0x468010"
			if mode == "split site word" {
				id = "0x467ff0"
			}
			for _, row := range got.Queries["observed-example"] {
				if row.ID != id {
					continue
				}
				site := row.ObservedSites[0]
				if site.Error == "" || site.Target != nil || len(row.ObservedTargets) != 0 {
					t.Fatal("partly backed words became a target", mode, site)
				}
				if mode == "partial code words" && (len(site.Words) != 2 || site.Words[0] == nil || site.Words[1] != nil) {
					t.Fatal("lost readable first word", site)
				}
				if mode == "split site word" && (len(site.Words) != 1 || site.Words[0] != nil || len(site.WordMappings[0]) != 2 || site.WordMappings[0][0].Storage != "file_backed" || site.WordMappings[0][1].Storage != "bss") {
					t.Fatal("split word was read or mapping lost", site)
				}
			}
		}
		for path, want := range original {
			got, err := os.ReadFile(path)
			after, statErr := os.Stat(path)
			if err != nil || statErr != nil || !bytes.Equal(got, want) || !os.SameFile(before[path], after) || before[path].ModTime() != after.ModTime() {
				t.Fatal("observed report changed input", path, err, statErr)
			}
		}
		if _, err := os.Stat(filepath.Join(observedDir, "forbidden.elf")); !os.IsNotExist(err) {
			t.Fatal("observed report wrote output", err)
		}
	}
	for _, example := range []struct {
		folder, oracle string
		rows           int
		inline         bool
	}{{"stream-audit", "stream-audit.json", 14, false}, {"reference-bound-audit", "reference-bound-audit.json", 7, false}, {"canonical-audit", "canonical-audit.json", 11, false}, {"fixed-audit", "fixed-inline-audit.json", 28, true}, {"pinned-raw-audit", "pinned-raw-audit.json", 3, false}, {"gp-audit", "gp-audit.json", 3, false}, {"reconciliation-audit", "reconciliation-audit.json", 8, false}} {
		auditDir := t.TempDir()
		var oracle struct {
			StreamAuditReport
			Bindings []struct {
				ID        string
				Target    uint32
				SiteCount int          `json:"site_count"`
				SiteWords [][2]uint64  `json:"site_words"`
				Mapping   []ELFMapping `json:"observed_mapping"`
			}
			Refusals []struct {
				Name         string
				SpanHex      string       `json:"span_hex"`
				ReadPin      *TextReadPin `json:"read_pin"`
				ProfileText  string       `json:"profile_text"`
				RegistryText string       `json:"registry_text"`
				SourceEdits  []struct {
					Offset int
					Hex    string
				} `json:"source_edits"`
			}
		}
		body, err := os.ReadFile(filepath.Join("testdata", example.oracle))
		if err != nil || json.Unmarshal(body, &oracle) != nil || len(oracle.Rows) != example.rows {
			t.Fatal("independent stream oracle", err)
		}
		profileData, err := os.ReadFile(filepath.Join("examples", example.folder, "profile.json"))
		var profile StreamAuditProfile
		if err != nil || json.Unmarshal(profileData, &profile) != nil {
			t.Fatal("stream example profile", err)
		}
		original, before := make(map[string][]byte), make(map[string]os.FileInfo)
		for role, input := range profile.Sources {
			data, err := os.ReadFile(filepath.Join("examples", example.folder, input.Path))
			if err != nil || int64(len(data)) != input.Size || fmt.Sprintf("%x", sha256.Sum256(data)) != input.SHA256 {
				t.Fatal("independent stream input pin", role, err)
			}
			path := write(filepath.Join(auditDir, input.Path), data)
			original[path] = data
			before[path], err = os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
		}
		profilePath := write(filepath.Join(auditDir, "profile.json"), profileData)
		original[profilePath] = profileData
		before[profilePath], err = os.Stat(profilePath)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := run([]string{"--stream-audit-profile", profilePath}, &out); err != nil {
			t.Fatal("paired stream audit", err)
		}
		var report StreamAuditReport
		if err := json.Unmarshal(out.Bytes(), &report); err != nil || report.Operation != "stream_audit" || report.Applied || report.ProfileSHA256 != fmt.Sprintf("%x", sha256.Sum256(profileData)) || report.Limits == "" || len(report.Rows) != len(oracle.Rows) {
			t.Fatal("stream report identity", err, out.String())
		}
		for role, input := range profile.Sources {
			input.Path = filepath.Join(auditDir, input.Path)
			if report.Sources[role] != input {
				t.Fatal("stream report lost declared input pin", role)
			}
		}
		for i := range report.Rows {
			sides := []*StreamAuditSide{&report.Rows[i].Reference, &report.Rows[i].Observed}
			if report.Rows[i].Canonical != nil {
				sides = append(sides, report.Rows[i].Canonical)
			}
			if (report.Rows[i].Canonical == nil) != (oracle.Rows[i].Canonical == nil) {
				t.Fatal("canonical side lost or invented", report.Rows[i].ID)
			}
			for j, side := range sides {
				want := oracle.Rows[i].Reference
				if j == 1 {
					want = oracle.Rows[i].Observed
				} else if j == 2 {
					want = *oracle.Rows[i].Canonical
				}
				if (side.Error == "") != (want.Error == "") {
					t.Fatal("stream decode support differs", report.Rows[i].ID, j, side.Error)
				}
				if side.Error != "" {
					side.Error = "unsupported"
				}
			}
		}
		got, err := json.Marshal(report.Rows)
		want, wantErr := json.Marshal(oracle.Rows)
		if err != nil || wantErr != nil || !bytes.Equal(got, want) {
			t.Fatalf("paired stream differs from precode literal tokens/factors\ngot %s\nwant %s", got, want)
		}
		if example.folder == "stream-audit" {
			var structures struct {
				Glyphmap map[string]string `json:"glyphmap"`
				Rows     []struct {
					Name              string
					ReferenceHex      string `json:"ref_hex"`
					ObservedHex       string `json:"observed_hex"`
					Decoder           string
					LineLimit         int                  `json:"line_limit"`
					Expected          StreamAuditStructure `json:"expected_structure"`
					OriginalReference struct {
						Tokens        []TextToken
						Error         *string `json:"source_error"`
						ConsumedBytes *int    `json:"consumed_bytes"`
						TrailingBytes *int    `json:"trailing_bytes"`
					} `json:"original_reference"`
					OriginalObserved struct {
						Tokens        []TextToken
						Error         *string `json:"source_error"`
						ConsumedBytes *int    `json:"consumed_bytes"`
						TrailingBytes *int    `json:"trailing_bytes"`
					} `json:"original_observed"`
				}
				Refusals []struct {
					Name, Decoder string
					LineLimit     int `json:"line_limit"`
				}
			}
			data, err := os.ReadFile("testdata/structural-audit.json")
			if err != nil || json.Unmarshal(data, &structures) != nil || len(structures.Rows) != 25 || len(structures.Refusals) != 5 {
				t.Fatal("independent structural source oracle", err)
			}
			for _, fixture := range structures.Rows {
				dir := t.TempDir()
				variant := StreamAuditProfile{Evidence: fixture.Name, Sources: map[string]RegistryInput{}, Entries: map[string]StreamAuditEntry{}}
				for role, text := range map[string]string{"reference": fixture.ReferenceHex, "observed": fixture.ObservedHex} {
					body, err := hex.DecodeString(text)
					if err != nil {
						t.Fatal("structural raw source", err)
					}
					path := write(filepath.Join(dir, role+".bin"), body)
					variant.Sources[role] = RegistryInput{Path: path, Size: int64(len(body)), SHA256: fmt.Sprintf("%x", sha256.Sum256(body))}
				}
				glyphData, err := json.Marshal(structures.Glyphmap)
				if err != nil {
					t.Fatal(err)
				}
				variant.Sources["glyphmap"] = RegistryInput{Path: write(filepath.Join(dir, "glyphmap.json"), glyphData), Size: int64(len(glyphData)), SHA256: fmt.Sprintf("%x", sha256.Sum256(glyphData))}
				limit := fixture.LineLimit
				variant.Entries["0x1000"] = StreamAuditEntry{Decoder: fixture.Decoder, LineLimit: &limit, Reference: AddressRange{Start: "0x0", End: fmt.Sprintf("0x%x", variant.Sources["reference"].Size)}, Observed: AddressRange{Start: "0x0", End: fmt.Sprintf("0x%x", variant.Sources["observed"].Size)}}
				out.Reset()
				var got StreamAuditReport
				if err := run([]string{"--stream-audit-profile", jsonFile(filepath.Join(dir, "structure.json"), variant)}, &out); err != nil || json.Unmarshal(out.Bytes(), &got) != nil || len(got.Rows) != 1 || !reflect.DeepEqual(got.Rows[0].Structure, &fixture.Expected) {
					t.Fatalf("structural source mismatch %s: %v\n%s", fixture.Name, err, out.String())
				}
				for i, side := range []StreamAuditSide{got.Rows[0].Reference, got.Rows[0].Observed} {
					expected := fixture.OriginalReference
					if i == 1 {
						expected = fixture.OriginalObserved
					}
					if (side.Error != "") != (expected.Error != nil) || side.Error == "" && (!reflect.DeepEqual(side.Tokens, expected.Tokens) || !reflect.DeepEqual(side.ConsumedBytes, expected.ConsumedBytes) || !reflect.DeepEqual(side.TrailingBytes, expected.TrailingBytes)) {
						t.Fatal("structural projection changed independently frozen decoder facts", fixture.Name, i, side)
					}
				}
				entry := variant.Entries["0x1000"]
				entry.LineLimit = nil
				variant.Entries["0x1000"] = entry
				out.Reset()
				var plain StreamAuditReport
				if err := run([]string{"--stream-audit-profile", jsonFile(filepath.Join(dir, "plain.json"), variant)}, &out); err != nil || json.Unmarshal(out.Bytes(), &plain) != nil {
					t.Fatal("unrequested structure", fixture.Name, err)
				}
				got.Rows[0].Structure = nil
				got.ProfileSHA256, got.Limits = plain.ProfileSHA256, plain.Limits
				if !reflect.DeepEqual(got, plain) {
					t.Fatal("structure affected other read facts", fixture.Name)
				}
				if fixture.Name != structures.Rows[0].Name {
					continue
				}
				for _, cut := range structures.Refusals {
					entry.Decoder, entry.LineLimit = cut.Decoder, &cut.LineLimit
					variant.Entries["0x1000"] = entry
					out.Reset()
					if err := run([]string{"--stream-audit-profile", jsonFile(filepath.Join(dir, "structural-domain-cut.json"), variant)}, &out); err == nil || out.Len() != 0 {
						t.Fatal("structural domain accepted", cut.Name, err)
					}
				}
				entry.Decoder, entry.LineLimit = fixture.Decoder, &limit
				variant.Entries["0x1000"] = entry
				wire, err := json.Marshal(variant)
				if err != nil || bytes.Count(wire, []byte(`"line_limit":4`)) != 1 {
					t.Fatal("structural wire fixture", err)
				}
				for _, replacement := range []string{`"line_limit":null`, `"LINE_LIMIT":4`, `"line_limit":4,"line_limit":5`, `"line_limit":1.5`, `"line_limit":"4"`, `"line_limit":true`, `"line_limit":4,"structure_proven":true`} {
					cut := bytes.Replace(wire, []byte(`"line_limit":4`), []byte(replacement), 1)
					out.Reset()
					if err := run([]string{"--stream-audit-profile", write(filepath.Join(dir, "structural-wire-cut.json"), cut)}, &out); err == nil || out.Len() != 0 {
						t.Fatal("ambiguous structural request accepted", replacement, err)
					}
				}
			}
		}
		if example.folder == "reconciliation-audit" || example.inline {
			var variant StreamAuditProfile
			if json.Unmarshal(profileData, &variant) != nil {
				t.Fatal("review policy fixture")
			}
			for id, entry := range variant.Entries {
				entry.Review = nil
				variant.Entries[id] = entry
			}
			out.Reset()
			var reviewed StreamAuditReport
			if err := run([]string{"--stream-audit-profile", jsonFile(filepath.Join(auditDir, "review-scope.json"), variant)}, &out); err != nil || json.Unmarshal(out.Bytes(), &reviewed) != nil {
				t.Fatal("review scope report", err)
			}
			for _, row := range reviewed.Rows {
				if row.Reconciliation != nil {
					t.Fatal("unreviewed profile gained bookkeeping decisions", row.ID)
				}
			}
		}
		if example.folder == "reconciliation-audit" {
			for _, cut := range []struct{ old, replacement string }{
				{`"review": {`, `"REVIEW": {`},
				{`"action": "allow"`, `"ACTION": "allow"`},
				{`"action": "allow"`, `"action": null`},
				{`"action": "allow"`, `"action": "allow", "action": "hold"`},
				{`"reason": "Reviewed literal matched cohort"`, `"reason": null`},
				{`"reason": "Reviewed literal matched cohort"`, `"REASON": "Reviewed literal matched cohort"`},
				{`"action": "allow"`, `"action": "allow", "canonical_match": true`},
			} {
				wire := bytes.Replace(profileData, []byte(cut.old), []byte(cut.replacement), 1)
				if bytes.Equal(wire, profileData) {
					t.Fatal("review wire cut did not mutate fixture", cut.old)
				}
				out.Reset()
				if err := run([]string{"--stream-audit-profile", write(filepath.Join(auditDir, "review-wire-cut.json"), wire)}, &out); err == nil || out.Len() != 0 {
					t.Fatal("review accepted ambiguous or supplied proof fields", cut.replacement, err)
				}
			}
			for _, cut := range []struct {
				replacement, reason string
				refuse              bool
			}{
				{`"missing_status": "drafted"`, "status_unknown", false},
				{`"status": 1`, "status_unknown", false},
				{`"status": "verified"`, "status_not_eligible", false},
				{`"STATUS": "drafted"`, "", true},
				{`"status": "drafted", "status": "patched"`, "", true},
				{`"opaque": {"status": null, "STATUS": "opaque", "status": 1}, "status": "drafted"`, "", false},
			} {
				var variant StreamAuditProfile
				if json.Unmarshal(profileData, &variant) != nil {
					t.Fatal("review status fixture")
				}
				input := variant.Sources["registry"]
				baseline := original[filepath.Join(auditDir, input.Path)]
				wire := bytes.Replace(baseline, []byte(`"status": "drafted"`), []byte(cut.replacement), 1)
				if bytes.Equal(wire, baseline) {
					t.Fatal("status wire cut did not mutate fixture", cut.replacement)
				}
				input.Path = write(filepath.Join(auditDir, "review-status.json"), wire)
				input.Size, input.SHA256 = int64(len(wire)), fmt.Sprintf("%x", sha256.Sum256(wire))
				variant.Sources["registry"] = input
				out.Reset()
				err := run([]string{"--stream-audit-profile", jsonFile(filepath.Join(auditDir, "review-status-profile.json"), variant)}, &out)
				if cut.refuse {
					if err == nil || out.Len() != 0 {
						t.Fatal("review accepted ambiguous selected status", cut.replacement, err)
					}
					continue
				}
				var reviewed StreamAuditReport
				if err != nil || json.Unmarshal(out.Bytes(), &reviewed) != nil || len(reviewed.Rows) != len(oracle.Rows) {
					t.Fatal("review status report", cut.replacement, err)
				}
				decision := reviewed.Rows[0].Reconciliation
				if decision == nil {
					t.Fatal("review lost status decision", cut.replacement)
				}
				if cut.reason == "" {
					if decision.Status != "proposed" {
						t.Fatal("review changed nested opaque metadata policy", decision)
					}
					continue
				}
				if decision.Status != "held" || len(decision.ProposedMachineFields) != 0 || !slices.Contains(decision.Reasons, cut.reason) {
					t.Fatal("review lost unknown/progressed status", cut.replacement, decision)
				}
			}
			var variant StreamAuditProfile
			if json.Unmarshal(profileData, &variant) != nil {
				t.Fatal("review unknown canonical fixture")
			}
			entry := variant.Entries[oracle.Rows[0].ID]
			entry.Canonical = nil
			variant.Entries[oracle.Rows[0].ID] = entry
			out.Reset()
			var reviewed StreamAuditReport
			if err := run([]string{"--stream-audit-profile", jsonFile(filepath.Join(auditDir, "review-unknown-canonical.json"), variant)}, &out); err != nil || json.Unmarshal(out.Bytes(), &reviewed) != nil {
				t.Fatal("review unknown canonical report", err)
			}
			decision := reviewed.Rows[0].Reconciliation
			if decision == nil || decision.Status != "held" || len(decision.ProposedMachineFields) != 0 || !slices.Contains(decision.Reasons, "canonical_unknown") {
				t.Fatal("missing canonical proof became a proposal", decision)
			}
		}
		if example.folder == "gp-audit" {
			if !strings.Contains(report.ObservedReferences.Limits, "not a live GP observation") || !strings.Contains(report.ObservedReferences.Limits, "Shared targets do not establish separate display ownership") {
				t.Fatal("GP report lost runtime and ownership limits")
			}
			info := report.ObservedReferences.RegisterInfo
			if info == nil || info.GlobalPointer == nil || *info.GlobalPointer != 0x100500 || info.SectionIndex == nil || *info.SectionIndex != 1 || info.FileRange == nil || *info.FileRange != [2]uint64{0xb00, 0xb18} || info.Error != "" {
				t.Fatal("GP fact lost independent metadata provenance", info)
			}
			var expected struct {
				Vectors []struct {
					Name     string
					GP, Word uint32
					Register uint32 `json:"expected_rt"`
					Valid    bool   `json:"valid_opcode_registers"`
					Target   *uint32
				} `json:"instruction_vectors"`
			}
			if err := json.Unmarshal(body, &expected); err != nil || len(expected.Vectors) != 8 {
				t.Fatal("independent GP vectors", err)
			}
			for _, vector := range expected.Vectors {
				geometry := ReferenceGeometry{VMAs: []uint64{0x100100}, Register: vector.Register, GlobalPointer: &vector.GP}
				target, err := referenceTarget(geometry, []uint32{vector.Word})
				if (err == nil) != vector.Valid || err == nil && (vector.Target == nil || target != *vector.Target) {
					t.Fatal("GP instruction equation differs", vector.Name, target, err)
				}
				geometry.GlobalPointer = nil
				if _, err := referenceTarget(geometry, []uint32{vector.Word}); err == nil {
					t.Fatal("GP target accepted without independently observed base", vector.Name)
				}
			}
			for _, site := range []ReferenceSite{
				{ADDIUVMA: "0x100100", Register: "$zero"},
				{ADDIUVMA: "0x100100", Register: "$unknown"},
				{ADDIUVMA: "0x100102", Register: "$a1"},
				{ADDIUVMA: "0x100100", Register: "$a1", LUIVMA: "0x1000fc"},
				{ADDIUVMA: "0x100100", Register: "$a1", PointerVMA: "0x100100"},
				{ADDIUVMA: "0x100100", Register: "$a1", StructVMA: "0x100100", FieldOffset: "0x0"},
			} {
				if _, err := normalizeReference("gp_relative", site, 0); err == nil {
					t.Fatal("GP geometry accepted foreign or invalid coordinates", site)
				}
			}
			data := slices.Clone(original[filepath.Join(auditDir, profile.Sources["observed"].Path)])
			binary.LittleEndian.PutUint32(data[0xb14:], 0)
			facts, err := inspect(bytes.NewReader(data), nil, &Recipes{Operation: "elf_layout", SourceSize: int64(len(data)), Evidence: "zero GP is a known value"})
			if err != nil || facts.RegisterInfo == nil || facts.RegisterInfo.GlobalPointer == nil || *facts.RegisterInfo.GlobalPointer != 0 || facts.RegisterInfo.Error != "" {
				t.Fatal("zero GP was treated as unknown", err)
			}
			facts, err = inspect(bytes.NewReader(data[:0xb10]), nil, &Recipes{Operation: "elf_layout", SourceSize: int64(len(data)), Evidence: "truncated physical metadata"})
			if err != nil || facts.RegisterInfo == nil || facts.RegisterInfo.GlobalPointer != nil || facts.RegisterInfo.Error == "" {
				t.Fatal("short metadata reader invented a GP", err)
			}
		}
		if len(report.Rows) > 0 && report.Rows[0].Decoder == "pinned_raw" {
			var projected struct {
				Rows []struct {
					Reference, Observed struct {
						RawControls []uint16 `json:"raw_control_words"`
					}
				}
				Policies []struct {
					Name   string
					Policy TextReadPin
				} `json:"policy_vectors"`
				Profiles []struct {
					Name     string
					Mutation map[string]json.RawMessage
				} `json:"profile_vectors"`
				Compatibility []struct {
					Name    string
					SpanHex string      `json:"span_hex"`
					ReadPin TextReadPin `json:"read_pin"`
					Tokens  []TextToken
				} `json:"compatibility_cases"`
			}
			if err := json.Unmarshal(body, &projected); err != nil {
				t.Fatal(err)
			}
			glyphData := original[filepath.Join(auditDir, profile.Sources["glyphmap"].Path)]
			encoding, forward, err := glyphMaps(glyphData, true)
			if err != nil {
				t.Fatal(err)
			}
			if len(projected.Compatibility) != 33 {
				t.Fatal("missing original raw-role compatibility corpus")
			}
			for _, specimen := range projected.Compatibility {
				span, err := hex.DecodeString(specimen.SpanHex)
				if err != nil {
					t.Fatal(specimen.Name, err)
				}
				before := slices.Clone(span)
				pinBefore, _ := json.Marshal(specimen.ReadPin)
				shape, err := controls(span, TextScanOptions{Decode: true, Glyphs: forward, ReadPin: &specimen.ReadPin})
				if err != nil || shape.Readiness != "blocked_pinned_reader" {
					t.Fatal("original raw-role corpus refused or authorized authoring", specimen.Name, err, shape.Readiness)
				}
				got, _ := json.Marshal(shape.Tokens)
				want, _ := json.Marshal(specimen.Tokens)
				pinAfter, _ := json.Marshal(specimen.ReadPin)
				if !bytes.Equal(got, want) || !bytes.Equal(span, before) || !bytes.Equal(pinBefore, pinAfter) {
					t.Fatal("original normalized tokens or input preservation differ", specimen.Name)
				}
			}
			for i, row := range report.Rows {
				for j, side := range []StreamAuditSide{row.Reference, row.Observed} {
					var controls []uint16
					for _, token := range side.Tokens {
						if token.Kind == "rawcontrol" {
							controls = append(controls, token.Word)
						}
					}
					want := projected.Rows[i].Reference.RawControls
					if j == 1 {
						want = projected.Rows[i].Observed.RawControls
					}
					if !slices.Equal(controls, want) {
						t.Fatal("raw controls lost independent order", row.ID, j)
					}
				}
			}
			entry := profile.Entries["0x100300"]
			pin := entry.ReadPins["reference"]
			data := original[filepath.Join(auditDir, profile.Sources["reference"].Path)][0x400:0x410]
			before := bytes.Clone(data)
			policyBefore, _ := json.Marshal(pin)
			shape, err := controls(data, TextScanOptions{Decode: true, Glyphs: forward, ReadPin: &pin})
			policyAfter, _ := json.Marshal(pin)
			if err != nil || shape.Readiness != "blocked_pinned_reader" || !bytes.Equal(data, before) || !bytes.Equal(policyBefore, policyAfter) {
				t.Fatal("pinned read changed inputs/context eligibility", err)
			}
			if _, err := encode("0", nil, encoding, TextEncodeOptions{Terminated: true, Source: &shape}); err == nil {
				t.Fatal("pinned interpretation authorized encoding")
			}
			for _, words := range []int{1, 4096} {
				span := make([]byte, words*2)
				end := len(span) - 2
				binary.LittleEndian.PutUint16(span[end:], 0xf800)
				pin := TextReadPin{Words: words, EndOffset: &end, SHA256: fmt.Sprintf("%x", sha256.Sum256(span)), Roles: []TextToken{}}
				shape, err := controls(span, TextScanOptions{Decode: true, Glyphs: forward, ReadPin: &pin})
				if err != nil || len(shape.Tokens) != words || shape.Readiness != "blocked_pinned_reader" {
					t.Fatal("bounded pinned word limit", words, err)
				}
			}
			for _, vector := range projected.Policies {
				if _, err := controls(data, TextScanOptions{Decode: true, Glyphs: forward, ReadPin: &vector.Policy}); err == nil {
					t.Fatal("pinned policy accepted", vector.Name)
				}
			}
			for _, name := range []string{"validation", "no glyphmap", "fixed", "positional", "header", "English", "terminated", "native", "opaque", "padded", "numeric", "nil endpoint", "nil roles", "empty nonnil payload"} {
				bad := TextScanOptions{Decode: true, Glyphs: forward, ReadPin: &pin}
				copyPin := pin
				bad.ReadPin = &copyPin
				switch name {
				case "validation":
					bad.Decode = false
				case "no glyphmap":
					bad.Glyphs = nil
				case "fixed":
					bad.FixedWords = 8
				case "positional":
					bad.PositionalLabels = true
				case "header":
					bad.RequireHDR = true
				case "English":
					english := "0"
					bad.English = &english
				case "terminated":
					bad.Terminated = true
				case "native":
					bad.Advances = map[uint16]int{1: 1}
				case "opaque":
					bad.ExactControls = true
				case "padded":
					bad.Padded = true
				case "numeric":
					bad.NumericBounds = []*NumericRange{{Min: 0, Max: 1}}
				case "nil endpoint":
					copyPin.EndOffset = nil
				case "nil roles":
					copyPin.Roles = nil
				case "empty nonnil payload":
					copyPin.Roles = slices.Clone(pin.Roles)
					copyPin.Roles[0].Payload = []byte{}
				}
				if _, err := controls(data, bad); err == nil {
					t.Fatal("pinned raw accepted incompatible policy", name)
				}
			}
			for _, vector := range projected.Profiles {
				var changed map[string]json.RawMessage
				entryData, _ := json.Marshal(entry)
				if err := json.Unmarshal(entryData, &changed); err != nil {
					t.Fatal(err)
				}
				for key, value := range vector.Mutation {
					changed[key] = value
				}
				encoded, _ := json.Marshal(changed)
				var badEntry StreamAuditEntry
				if err := json.Unmarshal(encoded, &badEntry); err != nil {
					t.Fatal(err)
				}
				bad := profile
				bad.Entries = maps.Clone(profile.Entries)
				bad.Entries["0x100300"] = badEntry
				var out bytes.Buffer
				if err := run([]string{"--stream-audit-profile", jsonFile(filepath.Join(auditDir, "bad-pin-profile.json"), bad)}, &out); err == nil || out.Len() != 0 {
					t.Fatal("pinned profile accepted", vector.Name)
				}
			}
			compact, _ := json.Marshal(profile)
			readPinBytes, _ := json.Marshal(entry.ReadPins)
			for _, cut := range []struct{ Name, Before, After string }{
				{"null pins", `"read_pins":` + string(readPinBytes), `"read_pins":null`},
				{"alias pins", `"read_pins":`, `"READ_PINS":`},
				{"alias words", `"words":8`, `"Words":8`},
				{"missing words", `"words":8,`, ``},
				{"missing endpoint", `"end_offset":14,`, ``},
				{"null endpoint", `"end_offset":14`, `"end_offset":null`},
				{"missing roles", `"roles":`, `"unowned_roles":`},
				{"alias kind", `"Kind":"rawarg"`, `"kind":"rawarg"`},
				{"missing word", `"Word":20480,`, ``},
				{"missing offset", `"Offset":4,`, ``},
				{"null word", `"Word":20480`, `"Word":null`},
				{"duplicate word", `"Word":20480`, `"Word":20480,"Word":20480`},
				{"ordinary decoder with pins", `"decoder":"pinned_raw"`, `"decoder":"narrative"`},
			} {
				changed := bytes.Replace(compact, []byte(cut.Before), []byte(cut.After), 1)
				if bytes.Equal(changed, compact) {
					t.Fatal("unused pinned wirecut", cut.Name)
				}
				var out bytes.Buffer
				if err := run([]string{"--stream-audit-profile", write(filepath.Join(auditDir, "bad-pin-wire.json"), changed)}, &out); err == nil || out.Len() != 0 {
					t.Fatal("pinned wire accepted", cut.Name)
				}
			}
			for _, vector := range []struct {
				Raw   string
				Valid bool
			}{
				{`{"outer":{"Word":0,"Offset":0}}`, true},
				{`{"outer":{"Offset":0}}`, false},
				{`{"outer":{"Word":0}}`, false},
			} {
				err := checkJSON(checkedJSON{raw: []byte(vector.Raw), requiredByDepth: map[int][]string{2: {"Word", "Offset"}}})
				if (err == nil) != vector.Valid {
					t.Fatal("required zero-valued JSON ownership", vector.Raw, err)
				}
			}
		}
		if profile.ObservedFamily != "" {
			facts := report.ObservedReferences
			operation := "reference_observed"
			if example.inline {
				operation = "reference_inline16"
			}
			if facts == nil || facts.Operation != operation || facts.SourceSHA256 != profile.Sources["observed"].SHA256 || facts.RegistrySHA256 != profile.Sources["registry"].SHA256 || len(facts.Queries[profile.ObservedFamily]) != len(oracle.Bindings) || len(report.ObservedMappings) != len(oracle.Bindings) {
				t.Fatal("bound audit lost reference provenance", out.String())
			}
			for i, expected := range oracle.Bindings {
				row := facts.Queries[profile.ObservedFamily][i]
				targetsMatch := slices.Equal(row.ObservedTargets, []uint32{expected.Target})
				if example.inline {
					targetsMatch = len(row.ObservedTargets) == 0
				}
				if row.ID != expected.ID || row.Divergent || len(row.ObservedSites) != expected.SiteCount || !targetsMatch || !reflect.DeepEqual(report.ObservedMappings[row.ID], expected.Mapping) || example.inline && !reflect.DeepEqual(report.ReferenceMappings[row.ID], expected.Mapping) {
					t.Fatal("bound audit differs from literal sites/target/full-window map", row.ID)
				}
				var words [][2]uint64
				for ordinal, site := range row.ObservedSites {
					targetMatches := site.Target != nil && *site.Target == expected.Target
					if example.inline {
						targetMatches = site.Target == nil && len(site.TargetMapping) == 0 && len(site.Geometry.VMAs) == 4 && site.Geometry.VMAs[0] == uint64(expected.Target)
					}
					if site.Ordinal != ordinal || site.Error != "" || !targetMatches || len(site.Words) != len(site.Geometry.VMAs) {
						t.Fatal("bound audit discarded a site", row.ID, ordinal)
					}
					for j, word := range site.Words {
						if word == nil {
							t.Fatal("bound site word unavailable", row.ID, ordinal)
						}
						words = append(words, [2]uint64{site.Geometry.VMAs[j], uint64(*word)})
					}
				}
				if !slices.Equal(words, expected.SiteWords) {
					t.Fatal("bound audit word facts differ", row.ID, words)
				}
			}
			for _, refusal := range oracle.Refusals {
				if refusal.SpanHex != "" {
					if refusal.ReadPin == nil {
						if refusal.Name != "unapproved-side" {
							t.Fatal("missing pinned refusal policy", refusal.Name)
						}
						continue // Source side-label refusal is verified by the profile side-key vector below.
					}
					raw, err := hex.DecodeString(refusal.SpanHex)
					if err != nil {
						t.Fatal(err)
					}
					_, forward, err := glyphMaps(original[filepath.Join(auditDir, profile.Sources["glyphmap"].Path)], true)
					if err != nil {
						t.Fatal(err)
					}
					before := bytes.Clone(raw)
					if _, err := controls(raw, TextScanOptions{Decode: true, Glyphs: forward, ReadPin: refusal.ReadPin}); err == nil || !bytes.Equal(raw, before) {
						t.Fatal("pinned source refusal differed or mutated bytes", refusal.Name)
					}
					continue
				}
				var bad StreamAuditProfile
				if json.Unmarshal([]byte(refusal.ProfileText), &bad) != nil {
					t.Fatal("independent bound refusal profile", refusal.Name)
				}
				if bad.ObservedFamily == "" && len(refusal.SourceEdits) == 0 && refusal.RegistryText == "" {
					// An unbound negative profile deliberately has only three inputs.
					for role, pin := range bad.Sources {
						if pin != profile.Sources[role] {
							t.Fatal("unbound refusal lost actual input pins", refusal.Name, role)
						}
					}
					out.Reset()
					if err := run([]string{"--stream-audit-profile", write(filepath.Join(auditDir, "unbound-refusal.json"), []byte(refusal.ProfileText))}, &out); err == nil || out.Len() != 0 {
						t.Fatal("audit accepted an unbound review", refusal.Name, err)
					}
					continue
				}
				data := bytes.Clone(original[filepath.Join(auditDir, profile.Sources["observed"].Path)])
				for _, edit := range refusal.SourceEdits {
					patch, err := hex.DecodeString(edit.Hex)
					if err != nil || edit.Offset < 0 || edit.Offset+len(patch) > len(data) {
						t.Fatal("invalid independent source edit", refusal.Name, err)
					}
					copy(data[edit.Offset:], patch)
				}
				registry := original[filepath.Join(auditDir, profile.Sources["registry"].Path)]
				if refusal.RegistryText != "" {
					registry = []byte(refusal.RegistryText)
				}
				if fmt.Sprintf("%x", sha256.Sum256(data)) != bad.Sources["observed"].SHA256 || fmt.Sprintf("%x", sha256.Sum256(registry)) != bad.Sources["registry"].SHA256 {
					t.Fatal("bound refusal must carry actual variant pins", refusal.Name)
				}
				if example.folder == "gp-audit" && slices.Contains([]string{"missing-reginfo", "duplicate-reginfo", "reginfo-size20"}, refusal.Name) {
					facts, err := references(data, registry, nil, Recipes{Operation: "reference_observed", SourceSize: int64(len(data)), SourceSHA256: bad.Sources["observed"].SHA256, ScopeSHA256: bad.Sources["registry"].SHA256, RegistryPatchRef: bad.ObservedFamily, Evidence: bad.Evidence})
					if err != nil || len(facts.Queries[bad.ObservedFamily]) != 3 || facts.Summaries[bad.ObservedFamily].FailedSites != 4 {
						t.Fatal("invalid GP metadata discarded reference observations", refusal.Name, err)
					}
					for _, row := range facts.Queries[bad.ObservedFamily] {
						for _, site := range row.ObservedSites {
							if site.Target != nil || site.Error == "" || len(site.Words) != 1 || site.Words[0] == nil {
								t.Fatal("unknown GP metadata invented target or lost readable word", refusal.Name, row.ID)
							}
						}
					}
				}
				write(filepath.Join(auditDir, bad.Sources["observed"].Path), data)
				write(filepath.Join(auditDir, bad.Sources["registry"].Path), registry)
				out.Reset()
				if err := run([]string{"--stream-audit-profile", write(filepath.Join(auditDir, "bound-refusal.json"), []byte(refusal.ProfileText))}, &out); err == nil || out.Len() != 0 {
					t.Fatal("bound audit accepted an invalid binding", refusal.Name, err)
				}

				for _, role := range []string{"observed", "registry"} {
					path := filepath.Join(auditDir, profile.Sources[role].Path)
					write(path, original[path])
					if err := os.Chtimes(path, before[path].ModTime(), before[path].ModTime()); err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, name := range []string{"missing registry", "registry without family", "unknown family", "wrong registry hash", "oversize observed", "oversize registry", "zero registry", "short registry", "directory registry"} {
				var bad StreamAuditProfile
				if json.Unmarshal(profileData, &bad) != nil {
					t.Fatal("bound profile fixture")
				}
				registry := bad.Sources["registry"]
				switch name {
				case "missing registry":
					delete(bad.Sources, "registry")
				case "registry without family":
					bad.ObservedFamily = ""
				case "unknown family":
					bad.ObservedFamily = "unselected-family"
				case "wrong registry hash":
					registry.SHA256 = strings.Repeat("0", 64)
					bad.Sources["registry"] = registry
				case "oversize observed":
					input := bad.Sources["observed"]
					input.Size = 65 << 20
					bad.Sources["observed"] = input
				case "oversize registry":
					registry.Size = 65 << 20
					bad.Sources["registry"] = registry
				case "zero registry":
					registry.Size = 0
					bad.Sources["registry"] = registry
				case "short registry":
					registry.Size--
					bad.Sources["registry"] = registry
				case "directory registry":
					registry.Path = auditDir
					bad.Sources["registry"] = registry
				}
				out.Reset()
				err := run([]string{"--stream-audit-profile", jsonFile(filepath.Join(auditDir, "bound-input-refusal.json"), bad)}, &out)
				if err == nil || out.Len() != 0 || strings.HasPrefix(name, "oversize") && !strings.Contains(err.Error(), "64 MiB") {
					t.Fatal("bound audit accepted invalid input policy", name, err)
				}
			}
			var alias StreamAuditProfile
			if json.Unmarshal(profileData, &alias) != nil {
				t.Fatal("bound alias fixture")
			}
			firstID := oracle.Bindings[0].ID
			numericID, err := number(firstID)
			if err != nil {
				t.Fatal(err)
			}
			alternateID := fmt.Sprintf("0X%08X", numericID)
			alias.Entries[alternateID] = alias.Entries[firstID]
			delete(alias.Entries, firstID)
			out.Reset()
			if err := run([]string{"--stream-audit-profile", jsonFile(filepath.Join(auditDir, "bound-ID-spelling.json"), alias)}, &out); err != nil {
				t.Fatal("bound IDs must compare numerically", err)
			}
			var aliasReport StreamAuditReport
			if json.Unmarshal(out.Bytes(), &aliasReport) != nil || aliasReport.Rows[0].ID != alternateID || !reflect.DeepEqual(aliasReport.ObservedMappings[alternateID], oracle.Bindings[0].Mapping) {
				t.Fatal("bound report lost profile ID spelling or mapping", out.String())
			}

			if example.inline {
				var windows StreamAuditProfile
				if json.Unmarshal(profileData, &windows) != nil {
					t.Fatal("fixed window fixture")
				}
				windows.ObservedFamily = ""
				delete(windows.Sources, "registry")
				for id, entry := range windows.Entries {
					entry.Canonical = nil
					entry.Review = nil
					windows.Entries[id] = entry
				}
				out.Reset()
				var windowReport StreamAuditReport
				if err := run([]string{"--stream-audit-profile", jsonFile(filepath.Join(auditDir, "inline-windows.json"), windows)}, &out); err != nil || json.Unmarshal(out.Bytes(), &windowReport) != nil || windowReport.ObservedReferences != nil || len(windowReport.ObservedMappings) != 0 || len(windowReport.ReferenceMappings) != 0 || strings.Contains(windowReport.Limits, "mappings are verified") {
					t.Fatal("fixed bare windows gained ownership claims", err, out.String())
				}
				for _, row := range windowReport.Rows {
					if row.Canonical != nil || row.Reconciliation != nil {
						t.Fatal("unrequested fixed wording inferred", row.ID)
					}
				}
				var absent StreamAuditProfile
				var noEN map[string]any
				if json.Unmarshal(profileData, &absent) != nil || json.Unmarshal(original[filepath.Join(auditDir, profile.Sources["registry"].Path)], &noEN) != nil {
					t.Fatal("missingfixed wording fixture")
				}
				delete(noEN["entries"].([]any)[0].(map[string]any), "en")
				noENData, err := json.Marshal(noEN)
				if err != nil {
					t.Fatal(err)
				}
				input := absent.Sources["registry"]
				input.Path = write(filepath.Join(auditDir, "inline-missing-EN.json"), noENData)
				input.Size = int64(len(noENData))
				input.SHA256 = fmt.Sprintf("%x", sha256.Sum256(noENData))
				absent.Sources["registry"] = input
				out.Reset()
				var unknown StreamAuditReport
				if err := run([]string{"--stream-audit-profile", jsonFile(filepath.Join(auditDir, "inline-missing-wording.json"), absent)}, &out); err != nil || json.Unmarshal(out.Bytes(), &unknown) != nil || unknown.Rows[0].Canonical == nil || unknown.Rows[0].Canonical.Error == "" || unknown.Rows[0].CanonicalComparison != nil {
					t.Fatal("missingfixed wording became intentionalempty", err, out.String())
				}
				for _, name := range []string{"pointer present", "empty pointer key", "null pointer key", "offset nonzero", "wrong stride", "missing stride", "null stride", "stride alias", "object not ID", "bad object", "wrong type", "missing sites", "multiple sites", "short original", "short observed", "shifted original", "shifted observed", "unbacked observed", "narrative cohort", "fixed wrapping", "fixed source authoring"} {
					var bad StreamAuditProfile
					var registry map[string]any
					if json.Unmarshal(profileData, &bad) != nil || json.Unmarshal(original[filepath.Join(auditDir, profile.Sources["registry"].Path)], &registry) != nil {
						t.Fatal("inline guard fixture")
					}
					entry := registry["entries"].([]any)[0].(map[string]any)
					site := entry["ref_sites"].([]any)[0].(map[string]any)
					selection := bad.Entries[firstID]
					switch name {
					case "pointer present":
						site["pointer_vma"] = entry["id"]
					case "empty pointer key":
						site["pointer_vma"] = ""
					case "null pointer key":
						site["pointer_vma"] = nil
					case "offset nonzero":
						site["field_offset"] = "0x2"
					case "wrong stride":
						site["stride"] = "0xe"
					case "missing stride":
						delete(site, "stride")
					case "null stride":
						site["stride"] = nil
					case "stride alias":
						delete(site, "stride")
						site["STRIDE"] = "0x10"
					case "object not ID":
						site["struct_vma"] = "0x100310"
					case "bad object":
						site["struct_vma"] = "oops"
					case "wrong type":
						entry["ref_type"] = "pointer_array"
					case "missing sites":
						entry["ref_sites"] = []any{}
					case "multiple sites":
						entry["ref_sites"] = []any{site, site}
					case "short original":
						selection.Reference.End = "0x40e"
					case "short observed":
						selection.Observed.End = "0x40e"
					case "shifted original":
						selection.Reference = AddressRange{Start: "0x402", End: "0x412"}
					case "shifted observed":
						selection.Observed = AddressRange{Start: "0x402", End: "0x412"}
					case "narrative cohort":
						selection.Decoder = "narrative"
					case "fixed wrapping":
						selection.Canonical.Wrap, selection.Canonical.Columns, selection.Canonical.Rows = "characters", 1, 1
					case "fixed source authoring":
						selection.Canonical.Authoring = "plain"
					case "unbacked observed":
						input := bad.Sources["observed"]
						data := bytes.Clone(original[filepath.Join(auditDir, input.Path)])
						binary.LittleEndian.PutUint32(data[52+16:], 0x300)
						input.Path = write(filepath.Join(auditDir, "inline-unbacked.elf"), data)
						input.SHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
						bad.Sources["observed"] = input
					}
					bad.Entries[firstID] = selection
					data, err := json.Marshal(registry)
					if err != nil {
						t.Fatal(err)
					}
					input := bad.Sources["registry"]
					input.Path = write(filepath.Join(auditDir, "inline-registry-variant.json"), data)
					input.Size = int64(len(data))
					input.SHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
					bad.Sources["registry"] = input
					out.Reset()
					err = run([]string{"--stream-audit-profile", jsonFile(filepath.Join(auditDir, "inline-boundary.json"), bad)}, &out)
					if name == "empty pointer key" || name == "null pointer key" {
						var held StreamAuditReport
						if err != nil || json.Unmarshal(out.Bytes(), &held) != nil || len(held.Rows) != len(report.Rows) {
							t.Fatal("inline pointer-key presence lost readable facts", name, err)
						}
						decision := held.Rows[0].Reconciliation
						if decision == nil || decision.Status != "held" || len(decision.ProposedMachineFields) != 0 || !slices.Contains(decision.Reasons, "inline_pointer_key_present") || held.Rows[0].CanonicalComparison == nil || !held.Rows[0].CanonicalComparison.StreamBytesEqual {
							t.Fatal("inline empty/null pointer key became a proposal", name, decision)
						}
						for id, entry := range bad.Entries {
							entry.Review = nil
							bad.Entries[id] = entry
						}
						out.Reset()
						var plain StreamAuditReport
						if err := run([]string{"--stream-audit-profile", jsonFile(filepath.Join(auditDir, "inline-presence-unreviewed.json"), bad)}, &out); err != nil || json.Unmarshal(out.Bytes(), &plain) != nil || len(plain.Rows) != len(report.Rows) || plain.Rows[0].Reconciliation != nil || plain.Rows[0].CanonicalComparison == nil || !plain.Rows[0].CanonicalComparison.StreamBytesEqual {
							t.Fatal("inline proposal policy changed unreviewed read behavior", name, err)
						}
						continue
					}
					if err == nil || out.Len() != 0 {
						t.Fatal("inline audit accepted invalid geometry/policy", name, err)
					}
				}
			}
			if example.folder == "canonical-audit" {
				var ordered struct {
					Groups []struct {
						Glyphmap map[string]string
						Cases    []struct {
							Name, EN, Status string
							SourceAuthoring  string `json:"source_authoring"`
							SourceOffset     int    `json:"source_offset"`
							Columns, Rows    int
							SourceHex        string `json:"source_hex"`
							ExpectedHex      string `json:"expected_hex"`
						}
					}
				}
				orderedData, err := os.ReadFile("testdata/source-ordered.json")
				if err != nil || json.Unmarshal(orderedData, &ordered) != nil || len(ordered.Groups) != 3 {
					t.Fatal("independent ordered audit literals", err)
				}
				accepted, refused := 0, 0
				for group, fixtures := range ordered.Groups {
					glyphData, err := json.Marshal(fixtures.Glyphmap)
					if err != nil {
						t.Fatal(err)
					}
					glyphPath := write(filepath.Join(auditDir, fmt.Sprintf("ordered-%d-glyphmap.json", group)), glyphData)
					for _, c := range fixtures.Cases {
						var variant StreamAuditProfile
						var registry map[string]any
						if json.Unmarshal(profileData, &variant) != nil || json.Unmarshal(original[filepath.Join(auditDir, profile.Sources["registry"].Path)], &registry) != nil || c.SourceAuthoring != "ordered" && c.SourceAuthoring != "plain" {
							t.Fatal("ordered audit fixture", c.Name)
						}
						// A one-entry registry cohort keeps unrelated streams and glyph maps out of this projection.
						registryEntries := registry["entries"].([]any)
						registryEntry := registryEntries[0].(map[string]any)
						if registryEntry["id"] != firstID {
							t.Fatal("ordered audit registry selection", c.Name)
						}
						registryEntry["en"] = c.EN
						registry["entries"] = registryEntries[:1]
						registryData, err := json.Marshal(registry)
						if err != nil {
							t.Fatal(err)
						}
						literal, err := hex.DecodeString(c.SourceHex)
						reference := bytes.Clone(original[filepath.Join(auditDir, profile.Sources["reference"].Path)])
						start := 0x400 + c.SourceOffset
						if err != nil || c.SourceOffset < 0 || start+len(literal) > len(reference) {
							t.Fatal("ordered audit source window", c.Name, err)
						}
						copy(reference[start:start+len(literal)], literal)
						entry := variant.Entries[firstID]
						entry.Reference = AddressRange{Start: fmt.Sprintf("0x%x", start), End: fmt.Sprintf("0x%x", start+len(literal))}
						entry.Canonical = &StreamAuditPolicy{Authoring: c.SourceAuthoring, Wrap: "none"}
						if c.Columns != 0 || c.Rows != 0 {
							entry.Canonical.Wrap, entry.Canonical.Columns, entry.Canonical.Rows = "characters", c.Columns, c.Rows
						}
						variant.Entries = map[string]StreamAuditEntry{firstID: entry}
						variant.Sources["glyphmap"] = RegistryInput{Path: glyphPath, Size: int64(len(glyphData)), SHA256: fmt.Sprintf("%x", sha256.Sum256(glyphData))}
						for role, data := range map[string][]byte{"registry": registryData, "reference": reference} {
							input := variant.Sources[role]
							input.Path = write(filepath.Join(auditDir, "ordered-"+role+"-variant.bin"), data)
							input.Size, input.SHA256 = int64(len(data)), fmt.Sprintf("%x", sha256.Sum256(data))
							variant.Sources[role] = input
						}
						input := variant.Sources["observed"]
						input.Path = filepath.Join(auditDir, input.Path)
						variant.Sources["observed"] = input
						out.Reset()
						var got StreamAuditReport
						if err := run([]string{"--stream-audit-profile", jsonFile(filepath.Join(auditDir, "ordered-authoring.json"), variant)}, &out); err != nil || json.Unmarshal(out.Bytes(), &got) != nil || len(got.Rows) != 1 || got.Applied || got.Operation != "stream_audit" {
							t.Fatal("ordered audit caller", c.Name, err, out.String())
						}
						row := got.Rows[0]
						observed := report.Rows[0].Observed
						if row.ID != firstID || row.Canonical == nil || row.Reference.Error != "" || row.Reference.Span != entry.Reference || row.Reference.StreamSHA256 != fmt.Sprintf("%x", sha256.Sum256(literal)) || row.Reference.ConsumedBytes == nil || *row.Reference.ConsumedBytes != len(literal) || row.Reference.TrailingBytes == nil || *row.Reference.TrailingBytes != 0 || row.Observed.StreamSHA256 != observed.StreamSHA256 || row.Observed.Span != observed.Span || !reflect.DeepEqual(row.Observed.Tokens, observed.Tokens) {
							t.Fatal("ordered audit lost source window or unchanged observation", c.Name, row)
						}
						if c.Status == "accept" {
							accepted++
							want, err := hex.DecodeString(c.ExpectedHex)
							if err != nil || row.Canonical.Error != "" || row.CanonicalComparison == nil || row.Canonical.StreamSHA256 != fmt.Sprintf("%x", sha256.Sum256(want)) || row.Canonical.SpanSHA256 != fmt.Sprintf("%x", sha256.Sum256(want)) || row.Canonical.ConsumedBytes == nil || *row.Canonical.ConsumedBytes != len(want) || row.Canonical.TrailingBytes == nil || *row.Canonical.TrailingBytes != 0 {
								t.Fatal("ordered canonical audit differs from independent whole literal", c.Name, err, row.Canonical)
							}
						} else if c.Status == "refuse" {
							refused++
							if row.Canonical.Error == "" || row.CanonicalComparison != nil || row.Canonical.ConsumedBytes != nil || row.Canonical.StreamSHA256 != "" {
								t.Fatal("ordered canonical audit fabricated refused output", c.Name, row.Canonical)
							}
						} else {
							t.Fatal("unknown ordered audit expectation", c.Name, c.Status)
						}
						for role, want := range map[string][]byte{"registry": registryData, "reference": reference, "glyphmap": glyphData, "observed": original[filepath.Join(auditDir, profile.Sources["observed"].Path)]} {
							input := variant.Sources[role]
							data, err := os.ReadFile(input.Path)
							if err != nil || !bytes.Equal(data, want) || got.Sources[role] != input {
								t.Fatal("ordered audit changed pinned input", c.Name, role, err)
							}
						}
					}
				}
				if accepted != 83 || refused != 28 {
					t.Fatal("ordered audit literal cohort changed", accepted, refused)
				}
				// Literal bytes come from the frozen original plain route, not encode.
				for _, c := range []struct {
					authoring, en string
					known, wrap   bool
				}{
					{"", "A", false, false}, {"markers", "A", false, false},
					{"plain", "A", true, false}, {"plain", "A", true, true},
					{"plain", "A{{", false, false}, {"plain", "{{HL:0xb007}}A", false, false},
				} {
					var variant StreamAuditProfile
					if json.Unmarshal(profileData, &variant) != nil {
						t.Fatal("colour policy fixture")
					}
					entry := variant.Entries[firstID]
					entry.Canonical.Authoring = c.authoring
					if c.wrap {
						entry.Canonical.Wrap, entry.Canonical.Columns, entry.Canonical.Rows = "characters", 1, 1
					}
					variant.Entries[firstID] = entry
					source := bytes.Clone(original[filepath.Join(auditDir, profile.Sources["reference"].Path)])
					literal, err := hex.DecodeString("002807b00400001000f8")
					start, startErr := number(entry.Reference.Start)
					end, endErr := number(entry.Reference.End)
					if err != nil || startErr != nil || endErr != nil || end-start != uint64(len(literal)) {
						t.Fatal("colour literal window")
					}
					copy(source[start:end], literal)
					wording, err := json.Marshal(c.en)
					if err != nil {
						t.Fatal(err)
					}
					registry := bytes.Replace(original[filepath.Join(auditDir, profile.Sources["registry"].Path)], []byte(`"en": "A|B"`), append([]byte(`"en": `), wording...), 1)
					for role, data := range map[string][]byte{"registry": registry, "reference": source} {
						input := variant.Sources[role]
						input.Path = write(filepath.Join(auditDir, "colour-"+role+"-variant.bin"), data)
						input.Size, input.SHA256 = int64(len(data)), fmt.Sprintf("%x", sha256.Sum256(data))
						variant.Sources[role] = input
					}
					out.Reset()
					var got StreamAuditReport
					err = run([]string{"--stream-audit-profile", jsonFile(filepath.Join(auditDir, "colour-authoring.json"), variant)}, &out)
					if err != nil || json.Unmarshal(out.Bytes(), &got) != nil || len(got.Rows) != len(report.Rows) {
						t.Fatal("colour authoring audit", c, err, out.String())
					}
					for i := 1; i < len(got.Rows); i++ {
						sides := []*StreamAuditSide{&got.Rows[i].Reference, &got.Rows[i].Observed, got.Rows[i].Canonical}
						for _, side := range sides {
							if side != nil && side.Error != "" {
								side.Error = "unsupported"
							}
						}
					}
					row := got.Rows[0]
					if row.Canonical == nil || !reflect.DeepEqual(row.Observed, report.Rows[0].Observed) || !reflect.DeepEqual(got.Rows[1:], report.Rows[1:]) {
						t.Fatal("colour audit changed unrelated observation", c)
					}
					if c.known {
						want, err := hex.DecodeString("002807b00100001000f8")
						if err != nil || row.Canonical.Error != "" || row.CanonicalComparison == nil || row.Canonical.StreamSHA256 != fmt.Sprintf("%x", sha256.Sum256(want)) || row.Canonical.ConsumedBytes == nil || *row.Canonical.ConsumedBytes != len(want) {
							t.Fatal("plain source colour differs from original literal", c, row.Canonical)
						}
					} else if row.Canonical.Error == "" || row.CanonicalComparison != nil {
						t.Fatal("colour authoring silently fell back", c, row.Canonical)
					}
					for role, want := range map[string][]byte{"registry": registry, "reference": source} {
						data, err := os.ReadFile(variant.Sources[role].Path)
						if err != nil || !bytes.Equal(data, want) {
							t.Fatal("colour audit mutated input", role, err)
						}
					}
				}
				for _, name := range []string{"unbound", "positional", "missing policy", "unknown wrap", "none columns", "none rows", "missing columns", "missing rows", "negative columns", "oversize rows", "unknown authoring"} {
					var bad StreamAuditProfile
					if json.Unmarshal(profileData, &bad) != nil {
						t.Fatal("canonical policy fixture")
					}
					entry := bad.Entries[firstID]
					switch name {
					case "unknown authoring":
						entry.Canonical.Authoring = "automatic"
					case "unbound":
						bad.ObservedFamily = ""
					case "positional":
						entry.Decoder = "positional"
					case "missing policy":
						entry.Canonical.Wrap = ""
					case "unknown wrap":
						entry.Canonical.Wrap = "automatic"
					case "none columns":
						entry.Canonical.Columns = 1
					case "none rows":
						entry.Canonical.Rows = 1
					case "missing columns":
						entry.Canonical = &StreamAuditPolicy{Wrap: "characters", Rows: 2}
					case "missing rows":
						entry.Canonical = &StreamAuditPolicy{Wrap: "characters", Columns: 2}
					case "negative columns":
						entry.Canonical = &StreamAuditPolicy{Wrap: "characters", Columns: -1, Rows: 2}
					case "oversize rows":
						entry.Canonical = &StreamAuditPolicy{Wrap: "characters", Columns: 2, Rows: 4097}
					}
					bad.Entries[firstID] = entry
					out.Reset()
					if err := run([]string{"--stream-audit-profile", jsonFile(filepath.Join(auditDir, "canonical-policy-cut.json"), bad)}, &out); err == nil || out.Len() != 0 {
						t.Fatal("canonical audit accepted invalid policy", name, err)
					}
				}

				for _, name := range []string{"empty EN", "missing EN", "null EN", "long EN", "nonstring EN", "EN alias", "invalid source context"} {
					var bad StreamAuditProfile
					if json.Unmarshal(profileData, &bad) != nil {
						t.Fatal("canonical wording fixture")
					}
					registryPath := filepath.Join(auditDir, profile.Sources["registry"].Path)
					referencePath := filepath.Join(auditDir, profile.Sources["reference"].Path)
					registryData := bytes.Clone(original[registryPath])
					referenceData := bytes.Clone(original[referencePath])
					old := []byte(`"en": "A|B"`)
					replacement := []byte(`"en": ""`)
					switch name {
					case "missing EN":
						replacement = []byte(`"unselected_note": "absent wording"`)
					case "null EN":
						replacement = []byte(`"en": null`)
					case "long EN":
						replacement = []byte(`"en": "` + strings.Repeat("A", 65537) + `"`)
					case "nonstring EN":
						replacement = []byte(`"en": 1`)
					case "EN alias":
						replacement = []byte(`"EN": "A|B"`)
					case "invalid source context":
						span := bad.Entries[firstID].Reference
						end, err := number(span.End)
						if err != nil {
							t.Fatal(err)
						}
						binary.LittleEndian.PutUint16(referenceData[end-2:], 1)
						replacement = old
					}
					registryData = bytes.Replace(registryData, old, replacement, 1)
					for role, data := range map[string][]byte{"registry": registryData, "reference": referenceData} {
						input := bad.Sources[role]
						input.Path = write(filepath.Join(auditDir, "canonical-"+role+"-variant.bin"), data)
						input.Size = int64(len(data))
						input.SHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
						bad.Sources[role] = input
					}
					out.Reset()
					err := run([]string{"--stream-audit-profile", jsonFile(filepath.Join(auditDir, "canonical-wording-variant.json"), bad)}, &out)
					if name == "nonstring EN" || name == "EN alias" {
						if err == nil || out.Len() != 0 {
							t.Fatal("canonical invalid wording wire was accepted", name, err)
						}
						continue
					}
					var got StreamAuditReport
					if err != nil || json.Unmarshal(out.Bytes(), &got) != nil || len(got.Rows) != len(oracle.Rows) {
						t.Fatal("canonical unknown wording report", name, err, out.String())
					}
					row := got.Rows[0]
					if row.Canonical == nil || row.Canonical.Error == "" || row.Canonical.ConsumedBytes != nil || row.CanonicalComparison != nil || row.Observed.Error != "" || !reflect.DeepEqual(row.Observed, report.Rows[0].Observed) {
						t.Fatal("canonical unknown lost observation or fabricated comparison", name, row)
					}
					if name == "invalid source context" && (row.Reference.Error == "" || row.Comparison != nil) {
						t.Fatal("canonical source decode failure became compared", row)
					}
				}
				for _, cut := range []struct{ old, replacement string }{
					{`"canonical": {`, `"CANONICAL": {`},
					{`"canonical": {
        "wrap": "none"
      }`, `"canonical": null`},
					{`"wrap": "none"`, `"wrap": null`},
					{`"wrap": "none"`, `"wrap": "none", "authoring": null`},
					{`"wrap": "none"`, `"wrap": "none", "AUTHORING": "plain"`},
					{`"wrap": "none"`, `"wrap": "none", "authoring": "plain", "authoring": "markers"`},
					{`"wrap": "none"`, `"wrap": "none", "authoring": false`},
					{`"columns": 2`, `"columns": null`},
					{`"rows": 2`, `"rows": null`},
					{`"wrap": "none"`, `"WRAP": "none"`},
					{`"wrap": "none"`, `"wrap": "none", "wrap": "none"`},
					{`"columns": 2`, `"columnſ": 2`},
					{`"columns": 2`, `"columns": 2.5`},
					{`"canonical": {`, `"canonical": {"unknown": 1,`},
				} {
					wire := bytes.Replace(profileData, []byte(cut.old), []byte(cut.replacement), 1)
					if bytes.Equal(wire, profileData) {
						t.Fatal("canonical wire cut did not mutate fixture", cut.old)
					}
					out.Reset()
					if err := run([]string{"--stream-audit-profile", write(filepath.Join(auditDir, "canonical-wire-cut.json"), wire)}, &out); err == nil || out.Len() != 0 {
						t.Fatal("canonical audit accepted invalid wire policy", cut.replacement, err)
					}
				}
			}
		} else if report.ObservedReferences != nil || report.ObservedMappings != nil {
			t.Fatal("plain stream audit gained reference claims")
		}
		for _, extra := range [][]string{{"--source", "unused"}, {"--registry", "unused"}, {"--glyphmap", "unused"}, {"--recipes", "unused"}, {"--fit-profile", "unused"}, {"--texture-profile", "unused"}, {"--snapshot", "list"}, {"--snapshot-dir", "unused"}, {"--tag", "unused"}, {"--commit", "unused"}, {"--note", "unused"}, {"--apply"}, {"--output", filepath.Join(auditDir, "forbidden.bin")}, {"unexpected"}} {
			out.Reset()
			if err := run(append([]string{"--stream-audit-profile", profilePath}, extra...), &out); err == nil || out.Len() != 0 {
				t.Fatal("stream audit accepted foreign workflow flag", extra, err)
			}
		}
		if profile.ObservedFamily == "" {
			for _, name := range []string{"no evidence", "no entries", "too many entries", "bad ID", "duplicate numeric ID", "unknown decoder", "empty decoder", "odd start", "odd end", "empty span", "reversed span", "negative start", "overflow end", "out of source", "large window", "missing source", "extra source", "wrong role", "empty path", "zero size", "negative size", "wrong size", "short hash", "nonhex hash", "wrong source hash", "wrong glyph hash", "oversize glyph", "directory source", "failed reference"} {
				var bad StreamAuditProfile
				if err := json.Unmarshal(profileData, &bad); err != nil {
					t.Fatal(err)
				}
				entry, input := bad.Entries["0x1000"], bad.Sources["reference"]
				switch name {
				case "no evidence":
					bad.Evidence = ""
				case "no entries":
					bad.Entries = nil
				case "too many entries":
					for i := 0; i < 4097; i++ {
						bad.Entries[fmt.Sprintf("0x%x", 0x2000+i)] = entry
					}
				case "bad ID":
					bad.Entries["oops"] = entry
				case "duplicate numeric ID":
					bad.Entries["1000"] = entry
				case "unknown decoder":
					entry.Decoder = "auto"
				case "empty decoder":
					entry.Decoder = ""
				case "odd start":
					entry.Reference.Start = "0x21"
				case "odd end":
					entry.Observed.End = "0x43"
				case "empty span":
					entry.Reference.End = entry.Reference.Start
				case "reversed span":
					entry.Reference.Start = "0x46"
				case "negative start":
					entry.Reference.Start = "-1"
				case "overflow end":
					entry.Reference.End = "0x100000000"
				case "out of source":
					entry.Reference.End = "0x200"
				case "large window":
					entry.Reference.End = "0x10022"
				case "missing source":
					delete(bad.Sources, "observed")
				case "extra source":
					bad.Sources["extra"] = input
				case "wrong role":
					delete(bad.Sources, "observed")
					bad.Sources["other"] = input
				case "empty path":
					input.Path = ""
				case "zero size":
					input.Size = 0
				case "negative size":
					input.Size = -1
				case "wrong size":
					input.Size++
				case "short hash":
					input.SHA256 = "00"
				case "nonhex hash":
					input.SHA256 = strings.Repeat("z", 64)
				case "wrong source hash":
					input.SHA256 = strings.Repeat("0", 64)
				case "wrong glyph hash", "oversize glyph":
					glyph := bad.Sources["glyphmap"]
					if name == "wrong glyph hash" {
						glyph.SHA256 = strings.Repeat("0", 64)
					} else {
						glyph.Size = 4<<20 + 1
					}
					bad.Sources["glyphmap"] = glyph
				case "directory source":
					input.Path = auditDir
				case "failed reference":
					input = bad.Sources["observed"]
					entry.Reference = bad.Entries["0x100a"].Observed
				}
				bad.Sources["reference"] = input
				if bad.Entries != nil {
					bad.Entries["0x1000"] = entry
				}
				path := jsonFile(filepath.Join(auditDir, "bad.json"), bad)
				out.Reset()
				err := run([]string{"--stream-audit-profile", path}, &out)
				if name == "failed reference" {
					var got StreamAuditReport
					if err != nil || json.Unmarshal(out.Bytes(), &got) != nil || got.Rows[0].Reference.Error == "" || got.Rows[0].Status != "decode_failed" || got.Rows[0].Comparison != nil || got.Rows[0].Reference.ConsumedBytes != nil {
						t.Fatal("failed reference must remain unknown", err, out.String())
					}
				} else if err == nil || out.Len() != 0 {
					t.Fatal("stream audit accepted invalid profile", name, err)
				}
			}
			for _, replacement := range []struct{ from, to string }{
				{`"evidence":`, `"unexpected":`},
				{`"evidence":`, `"Evidence":`},
				{`"sources": {`, `"ſources": {`},
				{`"sources": {`, `"Sources": {}, "sources": {`},
				{`"path": "reference.bin"`, `"path":"missing.bin", "Path":"reference.bin"`},
				{`"decoder": "narrative"`, `"decoder":"narrative", "Decoder":"positional"`},
				{`"start": "0x20"`, `"start":"0x20", "Start":"0x22"`},
				{`"evidence":`, `"evidence":"duplicate", "evidence":`},
				{`"evidence":`, `"evidence":"duplicate", "\u0065vidence":`},
				{`"sources": {`, `"sources": {"unknown":{},`},
				{`"reference": {`, `"reference": {"path":"duplicate",`},
				{`"0x1000": {`, `"0x1000": {"decoder":"duplicate",`},
				{`"start": "0x20"`, `"start":"0x20", "start":"0x20"`},
				{`"start": "0x20"`, `"start":"0x20", "unknown":"0x20"`},
				{`literal precode source/token facts, no readiness claim`, `\ud800`},
				{`literal precode source/token facts, no readiness claim`, `\udc00`},
			} {
				bad := bytes.Replace(profileData, []byte(replacement.from), []byte(replacement.to), 1)
				if bytes.Equal(bad, profileData) {
					t.Fatal("stream refusal fixture replacement missed", replacement.from)
				}
				path := write(filepath.Join(auditDir, "raw-bad.json"), bad)
				out.Reset()
				if err := run([]string{"--stream-audit-profile", path}, &out); err == nil || out.Len() != 0 {
					t.Fatal("stream audit accepted ambiguous JSON", replacement, err)
				}
			}
			for _, invalid := range [][]byte{nil, []byte(`null`), []byte(`[]`), []byte(`{`), append(bytes.Clone(profileData), []byte(` {}`)...), bytes.Replace(profileData, []byte("literal precode"), []byte{0xff}, 1)} {
				out.Reset()
				if err := run([]string{"--stream-audit-profile", write(filepath.Join(auditDir, "invalid-profile.json"), invalid)}, &out); err == nil || out.Len() != 0 {
					t.Fatal("stream audit accepted malformed profile", err)
				}
			}
			for _, badGlyphs := range [][]byte{[]byte(`[]`), []byte(`null`), []byte(`{"0x1":"A","0x1":"B"}`), []byte(`{"0x1":"\ud800"}`), []byte(`{"0x1":"\udc00"}`), []byte(`{"0x1":1}`), []byte(`{"oops":"A"}`), []byte("{\"0x1\":\"\xff\"}")} {
				var bad StreamAuditProfile
				if err := json.Unmarshal(profileData, &bad); err != nil {
					t.Fatal(err)
				}
				bad.Sources["glyphmap"] = RegistryInput{Path: write(filepath.Join(auditDir, "bad-glyphs.json"), badGlyphs), Size: int64(len(badGlyphs)), SHA256: fmt.Sprintf("%x", sha256.Sum256(badGlyphs))}
				out.Reset()
				if err := run([]string{"--stream-audit-profile", jsonFile(filepath.Join(auditDir, "glyph-profile.json"), bad)}, &out); err == nil || out.Len() != 0 {
					t.Fatal("stream audit accepted invalid glyphmap", string(badGlyphs), err)
				}
			}
			var expanded StreamAuditProfile
			if err := json.Unmarshal(profileData, &expanded); err != nil {
				t.Fatal(err)
			}
			expandedGlyphs, err := json.Marshal(map[string]string{"0x1": strings.Repeat("A", 65537), "0x2": "B", "0x3": "C", "0x4": "D", "0x5": "B"})
			if err != nil {
				t.Fatal(err)
			}
			expanded.Sources["glyphmap"] = RegistryInput{Path: write(filepath.Join(auditDir, "expanded-glyphs.json"), expandedGlyphs), Size: int64(len(expandedGlyphs)), SHA256: fmt.Sprintf("%x", sha256.Sum256(expandedGlyphs))}
			out.Reset()
			if err := run([]string{"--stream-audit-profile", jsonFile(filepath.Join(auditDir, "expanded-profile.json"), expanded)}, &out); err == nil || !strings.Contains(err.Error(), "expanded glyph text") || out.Len() != 0 {
				t.Fatal("stream audit did not bound expanded glyph aliases", err)
			}
			changed := bytes.Clone(original[filepath.Join(auditDir, "observed.bin")])
			changed[len(changed)-1] ^= 1
			write(filepath.Join(auditDir, "observed.bin"), changed)
			out.Reset()
			if err := run([]string{"--stream-audit-profile", profilePath}, &out); err == nil || !strings.Contains(err.Error(), "hash mismatch") || out.Len() != 0 {
				t.Fatal("stream audit ignored unselected source drift", err)
			}
			write(filepath.Join(auditDir, "observed.bin"), original[filepath.Join(auditDir, "observed.bin")])
			if err := os.Chtimes(filepath.Join(auditDir, "observed.bin"), before[filepath.Join(auditDir, "observed.bin")].ModTime(), before[filepath.Join(auditDir, "observed.bin")].ModTime()); err != nil {
				t.Fatal(err)
			}
			largePath := filepath.Join(auditDir, "large.bin")
			large, err := os.Create(largePath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := large.Write(original[filepath.Join(auditDir, "reference.bin")]); err != nil {
				t.Fatal(err)
			}
			if err := large.Truncate(65 << 20); err != nil {
				t.Fatal(err)
			}
			if _, err := large.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			hash := sha256.New()
			n, err := io.Copy(hash, large)
			if closeErr := large.Close(); err != nil || closeErr != nil {
				t.Fatal(err, closeErr)
			}
			largeProfile := StreamAuditProfile{Evidence: "sparse source beyond bounded metadata reader", Sources: map[string]RegistryInput{"reference": {Path: largePath, Size: n, SHA256: fmt.Sprintf("%x", hash.Sum(nil))}, "observed": {Path: largePath, Size: n, SHA256: fmt.Sprintf("%x", hash.Sum(nil))}, "glyphmap": profile.Sources["glyphmap"]}, Entries: map[string]StreamAuditEntry{"0x1000": profile.Entries["0x1000"]}}
			out.Reset()
			if err := run([]string{"--stream-audit-profile", jsonFile(filepath.Join(auditDir, "large-profile.json"), largeProfile)}, &out); err != nil {
				t.Fatal("bounded windows on same pinned large source", err)
			}
			var largeReport StreamAuditReport
			if json.Unmarshal(out.Bytes(), &largeReport) != nil || len(largeReport.Rows) != 1 || largeReport.Rows[0].Comparison == nil || !largeReport.Rows[0].Comparison.StreamBytesEqual {
				t.Fatal("large same-source comparison", out.String())
			}
			entry := largeProfile.Entries["0x1000"]
			entry.Reference.End = "0x10022"
			largeProfile.Entries["0x1000"] = entry
			out.Reset()
			if err := run([]string{"--stream-audit-profile", jsonFile(filepath.Join(auditDir, "wide-profile.json"), largeProfile)}, &out); err == nil || !strings.Contains(err.Error(), "bounded even") || out.Len() != 0 {
				t.Fatal("stream audit accepted in-file window beyond 64 KiB", err)
			}
		}
		for path, want := range original {
			got, err := os.ReadFile(path)
			after, statErr := os.Stat(path)
			if err != nil || statErr != nil || !bytes.Equal(got, want) || !os.SameFile(before[path], after) || before[path].ModTime() != after.ModTime() {
				t.Fatal("paired stream audit changed input", path, err, statErr)
			}
		}
		if _, err := os.Stat(filepath.Join(auditDir, "forbidden.bin")); !os.IsNotExist(err) {
			t.Fatal("stream audit wrote forbidden output", err)
		}
	}
	{
		auditDir := t.TempDir()
		var oracle struct {
			Registry Registry
			Mapping  struct {
				Base  string `json:"iso_elf_offset"`
				Delta string `json:"elf_vma_delta"`
				Size  int64  `json:"source_size"`
			}
			Cases []struct {
				Name         string
				SourceHex    string `json:"source_hex"`
				SourceSHA256 string `json:"source_sha256"`
				ScopeSHA256  string `json:"scope_sha256"`
				PointerState string `json:"pointer_state"`
				Expected     []map[string]any
			}
			Mutations []struct {
				Name, Mode     string
				Offset         int
				ReplacementHex string `json:"replacement_hex"`
			} `json:"byte_mutations"`
		}
		body, err := os.ReadFile("testdata/reference-check.json")
		if err != nil || json.Unmarshal(body, &oracle) != nil {
			t.Fatal("canonical reference word oracle", err)
		}
		for _, vector := range oracle.Cases {
			source, err := hex.DecodeString(vector.SourceHex)
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(source)) != vector.SourceSHA256 {
				t.Fatal("reference source oracle", vector.Name, err)
			}
			sourcePath := write(filepath.Join(auditDir, vector.Name+"-source.bin"), source)
			registryPath := jsonFile(filepath.Join(auditDir, vector.Name+"-registry.json"), oracle.Registry)
			glyphPath := write(filepath.Join(auditDir, "glyphs.json"), glyphs)
			profile := Recipes{Operation: "pointer_check", SourceSize: oracle.Mapping.Size, SourceSHA256: vector.SourceSHA256,
				ISOELFOffset: oracle.Mapping.Base, ELFVMADelta: oracle.Mapping.Delta, GlyphmapSHA256: fmt.Sprintf("%x", sha256.Sum256(glyphs)),
				ScopeSHA256: vector.ScopeSHA256, PointerState: vector.PointerState, RegistryPatchRef: "audit-example", Evidence: "independent literal5ID/8physicalword oracle"}
			profilePath := jsonFile(filepath.Join(auditDir, vector.Name+"-profile.json"), profile)
			args := []string{"--source", sourcePath, "--registry", registryPath, "--glyphmap", glyphPath, "--recipes", profilePath}
			original := make(map[string][]byte)
			before := make(map[string]os.FileInfo)
			for _, path := range []string{sourcePath, registryPath, glyphPath, profilePath} {
				original[path], err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				before[path], err = os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			if err := run(args, &out); err != nil {
				t.Fatal("mixed canonical reference audit", vector.Name, err)
			}
			var report struct {
				Applied      bool
				SourceSHA256 string `json:"source_sha256"`
				Edits        []map[string]any
			}
			if json.Unmarshal(out.Bytes(), &report) != nil || report.Applied || report.SourceSHA256 != vector.SourceSHA256 || !reflect.DeepEqual(report.Edits, vector.Expected) {
				t.Fatal("reference audit differs from literal physical word oracle", vector.Name, out.String())
			}
			output := filepath.Join(auditDir, "forbidden.bin")
			out.Reset()
			if err := run(append(slices.Clone(args), "--apply", "--output", output), &out); err == nil || !strings.Contains(err.Error(), "verification-only") || out.Len() != 0 {
				t.Fatal("mixed reference audit accepted apply", vector.Name, err)
			}
			if _, err := patchCopy(nil, output, []Recipes{{Operation: "guarded_words"}, profile}, nil, Registry{}, nil); err == nil || !strings.Contains(err.Error(), "verification-only") {
				t.Fatal("code guards escaped the table's read-only gate", err)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("mixed reference audit created output", err)
			}
			for path, want := range original {
				got, err := os.ReadFile(path)
				after, statErr := os.Stat(path)
				if err != nil || statErr != nil || !bytes.Equal(got, want) || !os.SameFile(before[path], after) || before[path].ModTime() != after.ModTime() {
					t.Fatal("reference audit changed input", path, err, statErr)
				}
			}
			for _, name := range []string{"unsupported type", "missing sites", "data code fields", "data struct fields", "missing object", "missing field", "wrong field", "unaligned object", "unaligned field", "overflowing field", "code data fields", "code struct fields", "missing register", "zero register", "unknown register", "missing upper", "missing lower", "reversed pair", "same site", "unaligned site", "below mapping", "outside source", "overflowing address", "duplicate pair", "shared upper", "wrong scope", "wrong glyph pin", "invalid landing"} {
				var bad Registry
				if err := json.Unmarshal(original[registryPath], &bad); err != nil {
					t.Fatal(err)
				}
				badProfile := profile
				data, object, code := &bad.Entries[0], &bad.Entries[1], &bad.Entries[2]
				switch name {
				case "unsupported type":
					code.RefType = "gp_relative"
				case "missing sites":
					code.RefSites = nil
				case "data code fields":
					data.RefSites[0].LUIVMA = "0x1030"
				case "data struct fields":
					data.RefSites[0].StructVMA = "0x1010"
				case "missing object":
					object.RefSites[0].StructVMA = ""
				case "missing field":
					object.RefSites[0].FieldOffset = ""
				case "wrong field":
					object.RefSites[0].FieldOffset = "0x8"
				case "unaligned object":
					object.RefSites[0].StructVMA = "0x1022"
				case "unaligned field":
					object.RefSites[0].FieldOffset = "0x2"
				case "overflowing field":
					object.RefSites[0].StructVMA, object.RefSites[0].FieldOffset = "0xfffffffc", "0x8"
				case "code data fields":
					code.RefSites[0].PointerVMA = "0x1010"
				case "code struct fields":
					code.RefSites[0].StructVMA = "0x1020"
				case "missing register":
					code.RefSites[0].Register = ""
				case "zero register":
					code.RefSites[0].Register = "$zero"
				case "unknown register":
					code.RefSites[0].Register = "$invalid"
				case "missing upper":
					code.RefSites[0].LUIVMA = ""
				case "missing lower":
					code.RefSites[0].ADDIUVMA = ""
				case "reversed pair":
					code.RefSites[0].LUIVMA, code.RefSites[0].ADDIUVMA = "0x103c", "0x1030"
				case "same site":
					code.RefSites[0].ADDIUVMA = code.RefSites[0].LUIVMA
				case "unaligned site":
					code.RefSites[0].LUIVMA = "0x1032"
				case "below mapping":
					code.RefSites[0].LUIVMA = "0xffc"
				case "outside source":
					code.RefSites[0].ADDIUVMA = "0x2000"
				case "overflowing address":
					code.RefSites[0].ADDIUVMA = "0x100000000"
				case "duplicate pair":
					code.RefSites = append(code.RefSites, code.RefSites[0])
				case "shared upper":
					other := code.RefSites[0]
					other.ADDIUVMA = "0x1050"
					code.RefSites = append(code.RefSites, other)
				case "wrong scope":
					badProfile.ScopeSHA256 = strings.Repeat("0", 64)
				case "wrong glyph pin":
					badProfile.GlyphmapSHA256 = strings.Repeat("0", 64)
				case "invalid landing":
					badProfile.PointerState, code.LandingVMA = "registry_landing", "0x4008012"
				}
				badRegistry := jsonFile(filepath.Join(auditDir, "bad-registry.json"), bad)
				badRecipe := jsonFile(filepath.Join(auditDir, "bad-profile.json"), badProfile)
				out.Reset()
				if err := run([]string{"--source", sourcePath, "--registry", badRegistry, "--glyphmap", glyphPath, "--recipes", badRecipe}, &out); err == nil || out.Len() != 0 {
					t.Fatal("reference audit accepted invalid scope", vector.Name, name)
				}
			}
			for _, mutation := range oracle.Mutations {
				if mutation.Mode != vector.Name {
					continue
				}
				changed := bytes.Clone(source)
				replacement, err := hex.DecodeString(mutation.ReplacementHex)
				if err != nil {
					t.Fatal(err)
				}
				copy(changed[mutation.Offset:], replacement)
				path := write(filepath.Join(auditDir, "changed.bin"), changed)
				badProfile := profile
				if mutation.Name != "unselected-neighbor-change" {
					badProfile.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(changed))
				}
				badRecipe := jsonFile(filepath.Join(auditDir, "changed-profile.json"), badProfile)
				out.Reset()
				if err := run([]string{"--source", path, "--registry", registryPath, "--glyphmap", glyphPath, "--recipes", badRecipe}, &out); err == nil || out.Len() != 0 {
					t.Fatal("reference audit accepted changed source", mutation.Name)
				}
			}
		}
	}
	{
		statusDir := t.TempDir()
		type count struct {
			Value *string
			Count int
		}
		type facts struct {
			Entries         int                `json:"registry_entries"`
			Groups          map[string][]count `json:"groups"`
			EmptyEN         []string           `json:"empty_en_ids"`
			MissingTags     []string           `json:"missing_tag_ids"`
			Unknown         []count            `json:"unknown_statuses"`
			FlowSteps       int                `json:"flow_steps"`
			FlowVMAs        int                `json:"flow_unique_vmas"`
			Schema          json.RawMessage    `json:"glossary_schema"`
			SchemaPresent   bool               `json:"glossary_schema_present"`
			GlossaryEntries int                `json:"glossary_entries"`
			Provenance      []count            `json:"glossary_provenance"`
			Todos           int                `json:"glossary_open_todos"`
		}
		type vector struct {
			Name, Registry, Glossary, Flow string
			Expected                       *facts
			MarkdownSnippets               []string `json:"markdown_snippets"`
		}
		var oracle struct {
			Template        string
			TemplateSHA256  string `json:"template_sha256"`
			Cases, Refusals []vector
		}
		body, err := os.ReadFile("testdata/registry-status.json")
		if err != nil || json.Unmarshal(body, &oracle) != nil {
			t.Fatal("status semantic oracle", err)
		}
		templateBytes, err := os.ReadFile(oracle.Template)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(templateBytes)) != oracle.TemplateSHA256 {
			t.Fatal("status template pin", err)
		}
		var baseProfile map[string]any
		var baseArgs []string
		for _, vector := range append(slices.Clone(oracle.Cases), oracle.Refusals...) {
			source := []byte(vector.Registry)
			sourcePath := write(filepath.Join(statusDir, vector.Name+"-registry.json"), source)
			inputs := make(map[string]RegistryInput)
			original := map[string][]byte{sourcePath: source}
			for name, data := range map[string][]byte{"glossary": []byte(vector.Glossary), "flow": []byte(vector.Flow), "template": templateBytes} {
				path := write(filepath.Join(statusDir, vector.Name+"-"+name), data)
				inputs[name] = RegistryInput{Path: filepath.Base(path), Size: int64(len(data)), SHA256: fmt.Sprintf("%x", sha256.Sum256(data))}
				original[path] = data
			}
			before := make(map[string]os.FileInfo)
			for path := range original {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				before[path] = info
			}
			profile := map[string]any{"operation": "registry_status", "source_size": len(source), "source_sha256": fmt.Sprintf("%x", sha256.Sum256(source)), "updated": "2026-10-20", "evidence": "independent complete3-input semantic oracle", "registry_columns": []string{"status", "source_pool", "chapter", "tier"}, "registry_inputs": inputs}
			profilePath := jsonFile(filepath.Join(statusDir, vector.Name+"-profile.json"), profile)
			args := []string{"--source", sourcePath, "--recipes", profilePath}
			output := filepath.Join(statusDir, vector.Name+".md")
			if vector.Name == "main" {
				baseProfile, baseArgs = maps.Clone(profile), slices.Clone(args)
			}
			for _, apply := range []bool{false, true} {
				if vector.Expected == nil && !apply {
					continue
				}
				command := slices.Clone(args)
				if apply {
					command = append(command, "--apply", "--output", output)
				}
				var out bytes.Buffer
				err := run(command, &out)
				if vector.Expected == nil {
					if err == nil || out.Len() != 0 {
						t.Fatal("status accepted malformed input", vector.Name)
					}
					if _, err := os.Stat(output); !os.IsNotExist(err) {
						t.Fatal("status published partial output", vector.Name, err)
					}
					continue
				}
				if err != nil {
					t.Fatal("status lifecycle", vector.Name, err)
				}
				var report struct {
					Operation    string
					Applied      bool
					OutputSHA256 string `json:"output_sha256"`
					Summary      facts
					Limits       string
				}
				if err := json.Unmarshal(out.Bytes(), &report); err != nil {
					t.Fatal("status receipt", vector.Name, err)
				}
				// Compare scalar facts independently of JSON string escaping.
				for _, target := range []*json.RawMessage{&report.Summary.Schema, &vector.Expected.Schema} {
					var scalar any
					decoder := json.NewDecoder(bytes.NewReader(*target))
					decoder.UseNumber()
					if err := decoder.Decode(&scalar); err != nil {
						t.Fatal("status schema scalar", vector.Name, err)
					}
					*target, err = json.Marshal(scalar)
					if err != nil {
						t.Fatal(err)
					}
				}
				if report.Operation != "registry_status" || report.Applied != apply || !reflect.DeepEqual(report.Summary, *vector.Expected) || !strings.Contains(report.Limits, "not historical Markdown byte parity") {
					t.Fatal("status differs from independent allmetric oracle", vector.Name, out.String())
				}
				if apply {
					markdown, err := os.ReadFile(output)
					if err != nil || fmt.Sprintf("%x", sha256.Sum256(markdown)) != report.OutputSHA256 {
						t.Fatal("status output pin", vector.Name, err)
					}
					for _, snippet := range vector.MarkdownSnippets {
						if !bytes.Contains(markdown, []byte(snippet)) {
							t.Fatal("status Markdown lost fact/order/escaping", vector.Name, snippet)
						}
					}
					out.Reset()
					if err := run(command, &out); err == nil || out.Len() != 0 {
						t.Fatal("status overwrote existing output", vector.Name)
					}
				} else if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatal("status preview wrote output", vector.Name, err)
				}
			}
			for path, want := range original {
				got, err := os.ReadFile(path)
				after, statErr := os.Stat(path)
				if err != nil || statErr != nil || !bytes.Equal(got, want) || !os.SameFile(before[path], after) || before[path].ModTime() != after.ModTime() {
					t.Fatal("status changed input", vector.Name, path, err, statErr)
				}
			}
		}
		for _, name := range []string{"missing glossary", "extra input", "wrong input hash", "wrong input size", "wrong template hash", "missing group", "duplicate group", "no date", "wrong source hash", "patch fields", "bad template", "missing template fact"} {
			bad := maps.Clone(baseProfile)
			inputs := maps.Clone(baseProfile["registry_inputs"].(map[string]RegistryInput))
			bad["registry_inputs"] = inputs
			switch name {
			case "missing glossary":
				delete(inputs, "glossary")
			case "extra input":
				inputs["extra"] = inputs["glossary"]
			case "wrong input hash", "wrong input size":
				input := inputs["flow"]
				if name == "wrong input hash" {
					input.SHA256 = strings.Repeat("0", 64)
				} else {
					input.Size++
				}
				inputs["flow"] = input
			case "wrong template hash":
				input := inputs["template"]
				input.SHA256 = strings.Repeat("0", 64)
				inputs["template"] = input
			case "missing group":
				bad["registry_columns"] = []string{"status", "chapter", "tier"}
			case "duplicate group":
				bad["registry_columns"] = []string{"status", "source_pool", "chapter", "tier", "status"}
			case "no date":
				delete(bad, "updated")
			case "wrong source hash":
				bad["source_sha256"] = strings.Repeat("0", 64)
			case "patch fields":
				bad["registry_updates"] = map[string]any{}
			case "bad template", "missing template fact":
				text := "{{"
				if name == "missing template fact" {
					text = "{{.not_a_fact}}"
				}
				path := write(filepath.Join(statusDir, "bad-template"), []byte(text))
				inputs["template"] = RegistryInput{Path: filepath.Base(path), Size: int64(len(text)), SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(text)))}
			}
			profilePath := jsonFile(filepath.Join(statusDir, "bad-profile.json"), bad)
			var out bytes.Buffer
			if err := run([]string{"--source", baseArgs[1], "--recipes", profilePath, "--apply", "--output", filepath.Join(statusDir, "forbidden.md")}, &out); err == nil || out.Len() != 0 {
				t.Fatal("status accepted malformed profile/template", name)
			}
			if _, err := os.Stat(filepath.Join(statusDir, "forbidden.md")); !os.IsNotExist(err) {
				t.Fatal("status published failed profile/template", name)
			}
		}
		for _, extra := range [][]string{{"--registry", baseArgs[1]}, {"--glyphmap", baseArgs[1]}, {"--recipes", baseArgs[3]}, {"--apply", "--output", baseArgs[1]}} {
			var out bytes.Buffer
			if err := run(append(slices.Clone(baseArgs), extra...), &out); err == nil || out.Len() != 0 {
				t.Fatal("status accepted incompatible inputs or source overwrite", extra)
			}
		}
		merge := map[string]any{"operation": "registry_merge", "source_size": baseProfile["source_size"], "source_sha256": baseProfile["source_sha256"], "evidence": "registry owner allowlist", "updated": "2026-10-20", "registry_updates": map[string]any{"0x20": map[string]any{"status": "decode_verified"}}}
		path := jsonFile(filepath.Join(statusDir, "merge.json"), merge)
		if err := run([]string{"--source", baseArgs[1], "--recipes", path}, io.Discard); err != nil {
			t.Fatal("valid merge control", err)
		}
		for _, field := range []string{"bundle_path", "bundle_sha256", "target_reference_sha256", "registry_inputs"} {
			bad := maps.Clone(merge)
			if field == "registry_inputs" {
				bad[field] = baseProfile[field]
			} else {
				bad[field] = "unrelated"
			}
			path := jsonFile(filepath.Join(statusDir, "foreign.json"), bad)
			var out bytes.Buffer
			if err := run([]string{"--source", baseArgs[1], "--recipes", path}, &out); err == nil || out.Len() != 0 {
				t.Fatal("registry allowlist ignored unrelated field", field)
			}
		}
	}
	{
		exportDir := t.TempDir()
		oracleBytes, err := os.ReadFile("testdata/registry-export.json")
		if err != nil {
			t.Fatal(err)
		}
		var oracle struct {
			Cases []struct {
				Name, Source   string
				SourceSHA256   string `json:"source_sha256"`
				ExpectedHex    string `json:"expected_hex"`
				ExpectedSHA256 string `json:"expected_sha256"`
				Columns        []string
				Rows           int
			}
			Refusals []struct{ Name, Source string }
		}
		if err := json.Unmarshal(oracleBytes, &oracle); err != nil {
			t.Fatal(err)
		}
		for _, vector := range oracle.Cases {
			expected, err := hex.DecodeString(vector.ExpectedHex)
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(expected)) != vector.ExpectedSHA256 || fmt.Sprintf("%x", sha256.Sum256([]byte(vector.Source))) != vector.SourceSHA256 {
				t.Fatal("registry CSV oracle pins", vector.Name, err)
			}
			sourcePath := write(filepath.Join(exportDir, vector.Name+".json"), []byte(vector.Source))
			before, err := os.Stat(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			profile := map[string]any{"operation": "registry_export", "source_size": len(vector.Source), "source_sha256": vector.SourceSHA256, "evidence": "independent precode CSV byte oracle", "registry_columns": vector.Columns}
			profilePath := jsonFile(filepath.Join(exportDir, vector.Name+"-profile.json"), profile)
			profileBytes, err := os.ReadFile(profilePath)
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"--source", sourcePath, "--recipes", profilePath}
			output := filepath.Join(exportDir, vector.Name+".csv")
			for _, apply := range []bool{false, true} {
				command := slices.Clone(args)
				if apply {
					command = append(command, "--apply", "--output", output)
				}
				var out bytes.Buffer
				if err := run(command, &out); err != nil {
					t.Fatal("registry CSV lifecycle", vector.Name, err)
				}
				var report struct {
					Operation    string
					Applied      bool
					SourceSHA256 string `json:"source_sha256"`
					OutputSHA256 string `json:"output_sha256"`
					Columns      []string
					Rows         int
					Limits       string
				}
				if err := json.Unmarshal(out.Bytes(), &report); err != nil || report.Operation != "registry_export" || report.Applied != apply || report.SourceSHA256 != vector.SourceSHA256 || report.OutputSHA256 != vector.ExpectedSHA256 ||
					report.Rows != vector.Rows || !reflect.DeepEqual(report.Columns, vector.Columns) || !strings.Contains(report.Limits, "not installed") {
					t.Fatal("registry CSV receipt differs", vector.Name, err, out.String())
				}
				if apply {
					got, err := os.ReadFile(output)
					if err != nil || !bytes.Equal(got, expected) {
						t.Fatal("registry CSV complete bytes", vector.Name, err)
					}
					out.Reset()
					if err := run(command, &out); err == nil || out.Len() != 0 {
						t.Fatal("registry CSV overwrote existing output", vector.Name)
					}
				} else if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatal("registry CSV preview wrote a file", vector.Name, err)
				}
			}
			var out bytes.Buffer
			if err := run(append(slices.Clone(args), "--apply", "--output", sourcePath), &out); err == nil || out.Len() != 0 {
				t.Fatal("registry CSV replaced its source", vector.Name)
			}
			preserved, readErr := os.ReadFile(sourcePath)
			after, statErr := os.Stat(sourcePath)
			currentProfile, profileErr := os.ReadFile(profilePath)
			if readErr != nil || statErr != nil || profileErr != nil || !bytes.Equal(preserved, []byte(vector.Source)) || !bytes.Equal(profileBytes, currentProfile) || !os.SameFile(before, after) || before.ModTime() != after.ModTime() {
				t.Fatal("registry CSV changed an input", vector.Name, readErr, statErr, profileErr)
			}
		}
		for _, vector := range oracle.Refusals {
			sourcePath := write(filepath.Join(exportDir, "refused.json"), []byte(vector.Source))
			profile := map[string]any{"operation": "registry_export", "source_size": len(vector.Source), "source_sha256": fmt.Sprintf("%x", sha256.Sum256([]byte(vector.Source))), "evidence": "typed source boundary", "registry_columns": []string{"id", "en"}}
			profilePath := jsonFile(filepath.Join(exportDir, "refused-profile.json"), profile)
			output := filepath.Join(exportDir, "refused.csv")
			var out bytes.Buffer
			if err := run([]string{"--source", sourcePath, "--recipes", profilePath, "--apply", "--output", output}, &out); err == nil || out.Len() != 0 {
				t.Fatal("registry CSV accepted refused domain", vector.Name)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("registry CSV published partial refusal", vector.Name, err)
			}
			if got, err := os.ReadFile(sourcePath); err != nil || !bytes.Equal(got, []byte(vector.Source)) {
				t.Fatal("registry CSV refusal changed source", vector.Name, err)
			}
		}
		vector := oracle.Cases[0]
		sourcePath := filepath.Join(exportDir, vector.Name+".json")
		profile := map[string]any{"operation": "registry_export", "source_size": len(vector.Source), "source_sha256": vector.SourceSHA256, "evidence": "profile boundary", "registry_columns": vector.Columns}
		for _, name := range []string{"empty columns", "duplicate column", "empty name", "too many columns", "long name", "wrong hash", "wrong size", "update fields", "updated date", "image field", "unknown field"} {
			bad := maps.Clone(profile)
			switch name {
			case "empty columns":
				bad["registry_columns"] = []string{}
			case "duplicate column":
				bad["registry_columns"] = []string{"id", "id"}
			case "empty name":
				bad["registry_columns"] = []string{""}
			case "too many columns":
				bad["registry_columns"] = make([]string, 65)
			case "long name":
				bad["registry_columns"] = []string{strings.Repeat("a", 257)}
			case "wrong hash":
				bad["source_sha256"] = strings.Repeat("0", 64)
			case "wrong size":
				bad["source_size"] = len(vector.Source) + 1
			case "update fields":
				bad["registry_updates"] = map[string]any{}
			case "updated date":
				bad["updated"] = "2026-10-20"
			case "image field":
				bad["iso_elf_offset"] = "0x0"
			case "unknown field":
				bad["unexpected"] = true
			}
			profilePath := jsonFile(filepath.Join(exportDir, "bad-profile.json"), bad)
			var out bytes.Buffer
			if err := run([]string{"--source", sourcePath, "--recipes", profilePath}, &out); err == nil || out.Len() != 0 {
				t.Fatal("registry CSV accepted invalid profile", name)
			}
		}
		profilePath := jsonFile(filepath.Join(exportDir, "valid-profile.json"), profile)
		args := []string{"--source", sourcePath, "--recipes", profilePath}
		for _, extra := range [][]string{{"--registry", sourcePath}, {"--glyphmap", sourcePath}, {"--recipes", profilePath}, {"--apply"}, {"--output", filepath.Join(exportDir, "unrequested.csv")}} {
			var out bytes.Buffer
			if err := run(append(slices.Clone(args), extra...), &out); err == nil || out.Len() != 0 {
				t.Fatal("registry CSV accepted incompatible inputs", extra)
			}
		}
		foreign, reg, glyphData, source := fixture(t, "same_length_stream")
		foreign.RegistryColumns = []string{"id"}
		if _, err := plan([]Recipes{foreign}, reg, glyphData, bytes.NewReader(source)); err == nil {
			t.Fatal("registry CSV fields leaked into valid image transaction")
		}
	}
	{
		layoutDir := t.TempDir()
		oracleBytes, err := os.ReadFile("testdata/elf-layout.json")
		if err != nil {
			t.Fatal(err)
		}
		var oracle struct {
			Bundle, Fixture string
			BundleSHA256    string `json:"bundle_sha256"`
			Files           map[string]string
			InputRanges     map[string]AddressRange `json:"input_ranges"`
			ExpectedRanges  map[string][]ELFMapping `json:"expected_ranges"`
			ProgramHeaders  []map[string]uint64     `json:"program_headers"`
			EntryPoint      uint64                  `json:"entry_point"`
			InvalidFiles    []string                `json:"invalid_files"`
			InvalidRanges   []AddressRange          `json:"invalid_ranges"`
		}
		if err := json.Unmarshal(oracleBytes, &oracle); err != nil {
			t.Fatal(err)
		}
		bundleBytes, err := os.ReadFile(oracle.Bundle)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(bundleBytes)) != oracle.BundleSHA256 {
			t.Fatal("ELF mapping oracle bundle pin", err)
		}
		bundle, err := zip.NewReader(bytes.NewReader(bundleBytes), int64(len(bundleBytes)))
		if err != nil {
			t.Fatal(err)
		}
		files := make(map[string][]byte)
		for _, entry := range bundle.File {
			reader, err := entry.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(reader)
			reader.Close()
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != oracle.Files[entry.Name] || files[entry.Name] != nil {
				t.Fatal("ELF mapping oracle member pin", entry.Name, err)
			}
			files[entry.Name] = data
		}
		if len(files) != len(oracle.Files) {
			t.Fatal("ELF mapping oracle members missing")
		}
		data := files[oracle.Fixture]
		sourcePath := write(filepath.Join(layoutDir, oracle.Fixture), data)
		before, err := os.Stat(sourcePath)
		if err != nil {
			t.Fatal(err)
		}
		profile := Recipes{Operation: "elf_layout", SourceSize: int64(len(data)), SourceSHA256: oracle.Files[oracle.Fixture], Evidence: "independent precode ELF mapping fixture", AddressRanges: oracle.InputRanges}
		profilePath := jsonFile(filepath.Join(layoutDir, "profile.json"), profile)
		args := []string{"--source", sourcePath, "--recipes", profilePath}
		var previous []byte
		for pass := 0; pass < 2; pass++ {
			var out bytes.Buffer
			if err := run(args, &out); err != nil {
				t.Fatal("ELF mapping CLI", err)
			}
			var report struct {
				Operation      string
				Applied        bool
				SourceSHA256   string                  `json:"source_sha256"`
				EntryPoint     uint64                  `json:"entry_point"`
				ProgramHeaders []map[string]uint64     `json:"program_headers"`
				AddressRanges  map[string][]ELFMapping `json:"address_ranges"`
				Limits         string
			}
			if err := json.Unmarshal(out.Bytes(), &report); err != nil || report.Operation != "elf_layout" || report.Applied || report.SourceSHA256 != profile.SourceSHA256 || report.EntryPoint != oracle.EntryPoint ||
				!reflect.DeepEqual(report.ProgramHeaders, oracle.ProgramHeaders) || !reflect.DeepEqual(report.AddressRanges, oracle.ExpectedRanges) || !strings.Contains(report.Limits, "do not prove") {
				t.Fatal("ELF mapping differs from independent intervals/headers", err, out.String())
			}
			if pass > 0 && !bytes.Equal(previous, out.Bytes()) {
				t.Fatal("ELF mapping output is nondeterministic")
			}
			previous = bytes.Clone(out.Bytes())
		}
		inventory := profile
		inventory.AddressRanges = nil
		state, err := inspect(bytes.NewReader(data), nil, &inventory)
		if err != nil || len(state.ELFSegments) != len(oracle.ProgramHeaders) || len(state.ELFMappings) != 0 {
			t.Fatal("ELF header inventory without queries", err)
		}
		for _, name := range oracle.InvalidFiles {
			bad := profile
			bad.SourceSize, bad.SourceSHA256 = int64(len(files[name])), oracle.Files[name]
			badSource := write(filepath.Join(layoutDir, name), files[name])
			badProfile := jsonFile(filepath.Join(layoutDir, "bad.json"), bad)
			var out bytes.Buffer
			if err := run([]string{"--source", badSource, "--recipes", badProfile}, &out); err == nil || out.Len() != 0 {
				t.Fatal("ELF mapping accepted malformed fixture", name, err)
			}
		}
		for _, query := range oracle.InvalidRanges {
			bad := profile
			bad.AddressRanges = map[string]AddressRange{"invalid": query}
			if _, err := inspect(bytes.NewReader(data), nil, &bad); err == nil {
				t.Fatal("ELF mapping accepted invalid query", query)
			}
		}
		for _, name := range []string{"bad hash", "patch fields", "empty name", "too many queries", "wrong machine", "wrong type", "duplicate LOAD", "no LOAD", "short payload", "edit readiness"} {
			bad, badData := profile, bytes.Clone(data)
			var edits []Edit
			switch name {
			case "bad hash":
				bad.SourceSHA256 = strings.Repeat("0", 64)
			case "patch fields":
				bad.Entries = map[string]Recipe{"0x1000": {}}
			case "empty name":
				bad.AddressRanges = map[string]AddressRange{"": {"0x1000", "0x1001"}}
			case "too many queries":
				bad.AddressRanges = make(map[string]AddressRange)
				for i := 0; i < 1025; i++ {
					bad.AddressRanges[fmt.Sprint(i)] = AddressRange{"0x1000", "0x1001"}
				}
			case "wrong machine":
				binary.LittleEndian.PutUint16(badData[18:], 3)
			case "wrong type":
				binary.LittleEndian.PutUint16(badData[16:], 3)
			case "duplicate LOAD":
				binary.LittleEndian.PutUint32(badData[52+32+8:], 0x1000)
			case "no LOAD":
				for at := 52; at < 52+5*32; at += 32 {
					binary.LittleEndian.PutUint32(badData[at:], 0)
				}
			case "short payload":
				badData = badData[:0x210]
			case "edit readiness":
				edits = []Edit{{Offset: 0x100, Old: []byte{0}, New: []byte{1}}}
			}
			if name == "bad hash" {
				badPath := jsonFile(filepath.Join(layoutDir, "bad.json"), bad)
				var out bytes.Buffer
				if err := run([]string{"--source", sourcePath, "--recipes", badPath}, &out); err == nil || out.Len() != 0 {
					t.Fatal("ELF mapping ignored source hash")
				}
			} else if _, err := inspect(bytes.NewReader(badData), edits, &bad); err == nil {
				t.Fatal("ELF mapping accepted", name)
			}
		}
		forbidden := filepath.Join(layoutDir, "must-not-exist.elf")
		for _, extra := range [][]string{{"--apply", "--output", forbidden}, {"--output", forbidden}, {"--registry", sourcePath}, {"--glyphmap", sourcePath}, {"--recipes", profilePath}} {
			var out bytes.Buffer
			if err := run(append(slices.Clone(args), extra...), &out); err == nil || out.Len() != 0 {
				t.Fatal("ELF mapping accepted incompatible CLI inputs", extra)
			}
		}
		if _, err := os.Stat(forbidden); !os.IsNotExist(err) {
			t.Fatal("ELF mapping created a patch output")
		}
		for _, operation := range []string{"same_length_stream", "cmb_member_replace", "iso_file_replace"} {
			foreign := Recipes{Operation: operation, AddressRanges: profile.AddressRanges}
			if _, err := plan([]Recipes{foreign}, Registry{}, nil, bytes.NewReader(data)); err == nil {
				t.Fatal("address report fields leaked into patch planning", operation)
			}
		}
		preserved, err := os.ReadFile(sourcePath)
		after, statErr := os.Stat(sourcePath)
		if err != nil || statErr != nil || !bytes.Equal(preserved, data) || !os.SameFile(before, after) || before.ModTime() != after.ModTime() {
			t.Fatal("ELF mapping changed its input", err, statErr)
		}
	}
	{
		// Frozen source-equation fixtures exercise the shared mapper and audit join.
		sentinelDir := t.TempDir()
		oracleData, err := os.ReadFile("testdata/sentinel-reader.json")
		if err != nil {
			t.Fatal(err)
		}
		var oracle struct {
			Bundle       string
			BundleSHA256 string `json:"bundle_sha256"`
			Files        map[string]struct {
				Bytes  int
				SHA256 string
			}
			Protocol struct {
				DispatchRange [2]uint64 `json:"dispatch_range"`
				LoadedRange   [2]uint64 `json:"loaded_range"`
				BlobRange     [2]uint64 `json:"blob_file_range"`
				ObservedWords []struct {
					Role    string
					Word    uint32
					Mapping ELFMapping `json:"ordinary_mapping"`
				} `json:"observed_words"`
				Canonical struct {
					Hex    string `json:"expected_hex"`
					SHA256 string
					Tokens []TextToken
					Target uint64 `json:"observed_target"`
				}
			}
			Mappings struct {
				Queries []struct {
					Name    string
					VMA     [2]uint64 `json:"vma_range"`
					Mapping []ELFMapping
				}
			}
			Guards struct {
				Guards []struct {
					Name, Source string
					Sentinel     *SentinelLayout
				}
			}
		}
		if err := json.Unmarshal(oracleData, &oracle); err != nil {
			t.Fatal(err)
		}
		bundleData, err := os.ReadFile(oracle.Bundle)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(bundleData)) != oracle.BundleSHA256 {
			t.Fatal("sentinel bundle pin", err)
		}
		files := bundledFixtures[oracle.Bundle]
		if len(files) != len(oracle.Files) {
			t.Fatal("sentinel fixture members")
		}
		for name, pin := range oracle.Files {
			body := files[name]
			if len(body) != pin.Bytes || fmt.Sprintf("%x", sha256.Sum256(body)) != pin.SHA256 {
				t.Fatal("sentinel fixture pin", name)
			}
			if err := os.MkdirAll(filepath.Dir(filepath.Join(sentinelDir, name)), 0700); err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(sentinelDir, name), body)
		}
		data := files["observed.elf"]
		var layout Recipes
		if err := json.Unmarshal(files["layout-profile.json"], &layout); err != nil {
			t.Fatal(err)
		}
		for _, query := range oracle.Mappings.Queries {
			layout.AddressRanges[query.Name] = AddressRange{Start: fmt.Sprintf("0x%x", query.VMA[0]), End: fmt.Sprintf("0x%x", query.VMA[1])}
		}
		state, err := inspect(bytes.NewReader(data), nil, &layout)
		if err != nil || state.Sentinel == nil {
			t.Fatal("sentinel installed protocol", err)
		}
		facts := state.Sentinel
		if facts.DispatchRange != oracle.Protocol.DispatchRange || facts.Loaded.VMA != oracle.Protocol.LoadedRange || facts.Loaded.Storage != "sentinel_blob" || facts.Loaded.ProgramHeader != nil || facts.Loaded.FileRange == nil || *facts.Loaded.FileRange != oracle.Protocol.BlobRange || len(facts.Words) != 12 || len(facts.WordMappings) != 12 {
			t.Fatal("sentinel allocation conflated dispatch/physical facts", facts)
		}
		for _, word := range oracle.Protocol.ObservedWords {
			if facts.Words[word.Role] != word.Word || !reflect.DeepEqual(facts.WordMappings[word.Role], []ELFMapping{word.Mapping}) {
				t.Fatal("sentinel observed instruction fact", word.Role)
			}
		}
		for _, query := range oracle.Mappings.Queries {
			if query.Mapping != nil && !reflect.DeepEqual(state.ELFMappings[query.Name], query.Mapping) {
				t.Fatal("sentinel independent interval", query.Name, state.ELFMappings[query.Name])
			}
		}
		cross := state.ELFMappings["cross-loaded-end"]
		if len(cross) != 2 || cross[0].Storage != "sentinel_blob" || cross[0].VMA[1] != oracle.Protocol.LoadedRange[1] || cross[1].Storage != "unmapped" || cross[1].FileRange != nil || cross[1].ProgramHeader != nil {
			t.Fatal("sentinel query escaped loaded endpoint", cross)
		}
		for _, name := range []string{"dispatch-only", "cross-dispatch-end"} {
			pieces := state.ELFMappings[name]
			if len(pieces) != 1 || pieces[0].Storage != "unmapped" || pieces[0].FileRange != nil {
				t.Fatal("dispatch recognition became physical mapping", name, pieces)
			}
		}
		for _, guard := range oracle.Guards.Guards {
			bad := layout
			bad.Sentinel = guard.Sentinel
			bad.SourceSize = int64(len(files[guard.Source]))
			if _, err := inspect(bytes.NewReader(files[guard.Source]), nil, &bad); err == nil {
				t.Fatal("sentinel protocol accepted", guard.Name)
			}
		}
		for _, name := range []string{"BSS overlap", "physical bytes claimed as LOAD", "nonadjacent loader pair", "truncated reader"} {
			bad := layout
			changed := bytes.Clone(data)
			switch name {
			case "BSS overlap":
				binary.LittleEndian.PutUint32(changed[52+20:], 0x04000002-0x00100000)
			case "physical bytes claimed as LOAD":
				binary.LittleEndian.PutUint32(changed[52+16:], 0x1700)
				binary.LittleEndian.PutUint32(changed[52+20:], 0x1700)
			case "nonadjacent loader pair":
				config := *layout.Sentinel
				config.LoaderVMAs = slices.Clone(config.LoaderVMAs)
				config.LoaderVMAs[1] = "0x100160"
				copy(changed[0x260:0x264], changed[0x244:0x248])
				bad.Sentinel = &config
			case "truncated reader":
				changed = changed[:len(changed)-1]
			}
			if _, err := inspect(bytes.NewReader(changed), nil, &bad); err == nil {
				t.Fatal("sentinel proof accepted", name)
			}
		}
		layoutPath := jsonFile(filepath.Join(sentinelDir, "all-ranges.json"), layout)
		var previous []byte
		for pass := 0; pass < 2; pass++ {
			var out bytes.Buffer
			if err := run([]string{"--source", filepath.Join(sentinelDir, "observed.elf"), "--recipes", layoutPath}, &out); err != nil {
				t.Fatal("sentinel layout CLI", err)
			}
			var report struct {
				Allocation *SentinelAllocation     `json:"sentinel_allocation"`
				Ranges     map[string][]ELFMapping `json:"address_ranges"`
			}
			if err := json.Unmarshal(out.Bytes(), &report); err != nil || !reflect.DeepEqual(report.Allocation, facts) || !reflect.DeepEqual(report.Ranges, state.ELFMappings) {
				t.Fatal("sentinel layout facts lost", err)
			}
			if pass > 0 && !bytes.Equal(previous, out.Bytes()) {
				t.Fatal("sentinel layout nondeterministic")
			}
			previous = bytes.Clone(out.Bytes())
		}
		profilePath := filepath.Join(sentinelDir, "stream-audit-profile.json")
		var audit StreamAuditProfile
		if err := json.Unmarshal(files["stream-audit-profile.json"], &audit); err != nil {
			t.Fatal(err)
		}
		previous = nil
		for pass := 0; pass < 2; pass++ {
			var out bytes.Buffer
			if err := run([]string{"--stream-audit-profile", profilePath}, &out); err != nil {
				t.Fatal("sentinel bound audit", err)
			}
			var report StreamAuditReport
			if err := json.Unmarshal(out.Bytes(), &report); err != nil || len(report.Rows) != 1 || !reflect.DeepEqual(report.SentinelAllocation, facts) {
				t.Fatal("sentinel bound allocation", err)
			}
			row := report.Rows[0]
			if row.Comparison == nil || row.Comparison.StreamBytesEqual || row.Canonical == nil || row.Canonical.Error != "" || row.CanonicalComparison == nil || !row.CanonicalComparison.StreamBytesEqual || row.Canonical.StreamSHA256 != oracle.Protocol.Canonical.SHA256 || !reflect.DeepEqual(row.Canonical.Tokens, oracle.Protocol.Canonical.Tokens) {
				t.Fatal("sentinel independent canonical row", row)
			}
			canonical, err := hex.DecodeString(oracle.Protocol.Canonical.Hex)
			if err != nil || !bytes.Equal(canonical, files["canonical-stream.bin"]) {
				t.Fatal("sentinel literal expectedbytes", err)
			}
			bound := report.ObservedReferences.Queries[audit.ObservedFamily][0]
			if len(bound.ObservedTargets) != 1 || uint64(bound.ObservedTargets[0]) != oracle.Protocol.Canonical.Target || bound.ObservedSites[0].TargetMapping[0].Storage != "unmapped" || report.ObservedMappings[row.ID][0].Storage != "sentinel_blob" {
				t.Fatal("sentinel target conflated ordinary ELF and external transport")
			}
			if pass > 0 && !bytes.Equal(previous, out.Bytes()) {
				t.Fatal("sentinel audit nondeterministic")
			}
			previous = bytes.Clone(out.Bytes())
		}
		for _, target := range []uint32{0x04000ffe, 0x04001000, 0x040ffffe, 0x04000011} {
			changed := bytes.Clone(data)
			binary.LittleEndian.PutUint32(changed[0x400:], target)
			bad := audit
			bad.Sources = maps.Clone(audit.Sources)
			pin := bad.Sources["observed"]
			pin.Path = write(filepath.Join(sentinelDir, "wrong-target.elf"), changed)
			pin.SHA256 = fmt.Sprintf("%x", sha256.Sum256(changed))
			bad.Sources["observed"] = pin
			var out bytes.Buffer
			if err := run([]string{"--stream-audit-profile", jsonFile(filepath.Join(sentinelDir, "wrong-target.json"), bad)}, &out); err == nil || out.Len() != 0 {
				t.Fatal("sentinel incomplete target window accepted", target)
			}
		}
		for _, route := range []string{"layout", "audit"} {
			var value map[string]any
			body := files["layout-profile.json"]
			if route == "audit" {
				body = files["stream-audit-profile.json"]
			}
			if err := json.Unmarshal(body, &value); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"null", "alias", "unknown", "scalar", "extra-loader", "extra-copy", "null-sites", "site-alias", "duplicate"} {
				bad := maps.Clone(value)
				config := maps.Clone(value["sentinel"].(map[string]any))
				switch name {
				case "null":
					bad["sentinel"] = nil
				case "alias":
					delete(bad, "sentinel")
					bad["Sentinel"] = config
				case "unknown":
					config["bogus"] = 1
				case "scalar":
					bad["sentinel"] = true
				case "extra-loader":
					config["loader_vmas"] = append(slices.Clone(config["loader_vmas"].([]any)), "0x100160")
				case "extra-copy":
					config["window_bases"] = append(slices.Clone(config["window_bases"].([]any)), "0x100180")
				case "null-sites":
					config["window_sizes"] = nil
				case "site-alias":
					config["Window_Bases"] = config["window_bases"]
					delete(config, "window_bases")
				}
				if name != "null" && name != "alias" && name != "scalar" {
					bad["sentinel"] = config
				}
				raw, err := json.Marshal(bad)
				if err != nil {
					t.Fatal(err)
				}
				if name == "duplicate" {
					raw = bytes.Replace(raw, []byte(`"retail_elf_size":1920`), []byte(`"retail_elf_size":1920,"retail_elf_size":1920`), 1)
				}
				path := write(filepath.Join(sentinelDir, "bad-wire.json"), raw)
				args := []string{"--source", filepath.Join(sentinelDir, "observed.elf"), "--recipes", path}
				if route == "audit" {
					args = []string{"--stream-audit-profile", path}
				}
				var out bytes.Buffer
				if err := run(args, &out); err == nil || out.Len() != 0 {
					t.Fatal("sentinel wire accepted", route, name)
				}
			}
		}
		for _, key := range []string{"sentinel", "Sentinel"} {
			for _, literal := range []string{"null", "{}"} {
				raw := []byte(fmt.Sprintf(`{"operation":"same_length_stream",%q:%s}`, key, literal))
				var out bytes.Buffer
				err := run([]string{"--source", filepath.Join(sentinelDir, "observed.elf"), "--recipes", write(filepath.Join(sentinelDir, "foreign-key.json"), raw)}, &out)
				if err == nil || out.Len() != 0 || !strings.Contains(err.Error(), "sentinel requires") {
					t.Fatal("sentinel foreign rawkey ignored", key, literal, err)
				}
			}
		}
		for _, name := range []string{"unbound", "inline"} {
			bad := audit
			bad.Entries = maps.Clone(audit.Entries)
			if name == "unbound" {
				bad.ObservedFamily = ""
			} else {
				entry := bad.Entries["0x100500"]
				entry.Decoder = "fixed16"
				bad.Entries["0x100500"] = entry
			}
			var out bytes.Buffer
			if err := run([]string{"--stream-audit-profile", jsonFile(filepath.Join(sentinelDir, "bad-mode.json"), bad)}, &out); err == nil || out.Len() != 0 {
				t.Fatal("sentinel config accepted foreign audit mode", name)
			}
		}
		foreign, reg, glyphs, image := fixture(t, "same_length_stream")
		foreign.Sentinel = layout.Sentinel
		if _, err := plan([]Recipes{foreign}, reg, glyphs, bytes.NewReader(image)); err == nil {
			t.Fatal("sentinel report config reached valid text patch planner")
		}
		for name, pin := range audit.Sources {
			got, err := os.ReadFile(filepath.Join(sentinelDir, pin.Path))
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(got)) != pin.SHA256 {
				t.Fatal("sentinel source changed", name, err)
			}
		}
	}
	{
		snapshotDir := t.TempDir()
		data, err := hex.DecodeString("496e646570656e64656e7420736e617073686f74206669787475726500ff0a")
		if err != nil {
			t.Fatal(err)
		}
		const digest = "c793a9b06f4e8e2f059f5a2c3a6890de770b3b90fe3f0e410c97e35a8e8f9954"
		source := write(filepath.Join(snapshotDir, "snapshot-source.bin"), data)
		before, _ := os.Stat(source)
		store := filepath.Join(snapshotDir, "snapshot-store")
		output := filepath.Join(snapshotDir, "snapshot-restored.bin")
		create := []string{"--snapshot", "create", "--snapshot-dir", store, "--tag", "before-edit", "--source", source, "--commit", strings.Repeat("a", 40), "--note", "independent binary fixture"}
		restore := []string{"--snapshot", "restore", "--snapshot-dir", store, "--tag", "before-edit"}
		for _, args := range [][]string{create, append(slices.Clone(create), "--apply"), {"--snapshot", "list", "--snapshot-dir", store}, restore, append(slices.Clone(restore), "--apply", "--output", output)} {
			var out bytes.Buffer
			if err := run(args, &out); err != nil {
				t.Fatal("snapshot lifecycle", args, err)
			}
			var report struct {
				Operation      string
				Receipt        SnapshotReceipt
				DigestVerified bool `json:"digest_verified"`
				Snapshots      []struct {
					Tag, Status    string
					DigestVerified bool `json:"digest_verified"`
				}
			}
			if err := json.Unmarshal(out.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report.Operation == "snapshot_list" {
				if len(report.Snapshots) != 1 || report.Snapshots[0].Tag != "before-edit" || report.Snapshots[0].Status != "present-unverified" || report.Snapshots[0].DigestVerified {
					t.Fatal("snapshot inventory claimed a measured digest", out.String())
				}
			} else if report.Receipt.SHA256 != digest || report.Receipt.Size != 31 || !report.DigestVerified || report.Receipt.CommitProvenance != "caller supplied; not verified" {
				t.Fatal("snapshot receipt", out.String())
			}
			if len(args) == len(create) {
				if _, err := os.Stat(store); !os.IsNotExist(err) {
					t.Fatal("snapshot preview wrote store", err)
				}
			}
		}
		got, err := os.ReadFile(output)
		after, _ := os.Stat(source)
		if err != nil || !bytes.Equal(got, data) || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
			t.Fatal("snapshot restore/source preservation", err)
		}
		for _, args := range [][]string{append(slices.Clone(create), "--apply"), append(slices.Clone(restore), "--apply", "--output", output), {"--snapshot", "create", "--snapshot-dir", store, "--tag", "../escape", "--source", source, "--commit", strings.Repeat("a", 40)}, {"--snapshot", "list", "--snapshot-dir", store, "--apply"}, {"--snapshot", "list", "--snapshot-dir", store, "--recipes", "not-read.json"}, {"--tag", "unused", "--source", source}} {
			var out bytes.Buffer
			if err := run(args, &out); err == nil {
				t.Fatal("snapshot invalid/overwrite accepted", args)
			}
		}
		payload := filepath.Join(store, "before-edit", "artifact.bin")
		receiptPath := filepath.Join(store, "before-edit", "receipt.json")
		receipt, _ := os.ReadFile(receiptPath)
		for _, mutation := range []string{"corrupt payload", "missing payload", "symlink payload", "wrong receipt tag", "unknown receipt field", "missing receipt"} {
			switch mutation {
			case "corrupt payload":
				bad := bytes.Clone(data)
				bad[0] ^= 1
				write(payload, bad)
			case "missing payload":
				if err := os.Remove(payload); err != nil {
					t.Fatal(err)
				}
			case "symlink payload":
				if err := os.Remove(payload); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(source, payload); err != nil {
					t.Fatal(err)
				}
			case "wrong receipt tag", "unknown receipt field":
				var fields map[string]any
				if err := json.Unmarshal(receipt, &fields); err != nil {
					t.Fatal(err)
				}
				if mutation == "wrong receipt tag" {
					fields["tag"] = "other"
				} else {
					fields["payload_path"] = "../../escape"
				}
				jsonFile(receiptPath, fields)
			case "missing receipt":
				if err := os.Remove(receiptPath); err != nil {
					t.Fatal(err)
				}
			}
			badOutput := filepath.Join(snapshotDir, "snapshot-invalid-output.bin")
			var out bytes.Buffer
			if err := run(append(slices.Clone(restore), "--apply", "--output", badOutput), &out); err == nil {
				t.Fatal("snapshot invalid source restored", mutation)
			}
			if _, err := os.Stat(badOutput); !os.IsNotExist(err) {
				t.Fatal("snapshot refusal published output", mutation, err)
			}
			out.Reset()
			if err := run([]string{"--snapshot", "list", "--snapshot-dir", store}, &out); err != nil || !strings.Contains(out.String(), `"digest_verified": false`) {
				t.Fatal("snapshot problem inventory", mutation, err)
			}
			if mutation == "symlink payload" {
				if err := os.Remove(payload); err != nil {
					t.Fatal(err)
				}
			}
			write(payload, data)
			write(receiptPath, receipt)
		}
		for _, vector := range []struct {
			Name   string
			Size   int64
			Digest string
		}{{"short", 32, digest}, {"long", 30, digest}, {"digest", 31, strings.Repeat("0", 64)}, {"invalid digest", 31, "abc"}, {"negative size", -1, digest}} {
			path := filepath.Join(snapshotDir, "stream-"+vector.Name)
			if err := writeNewFile(path, bytes.NewReader(data), vector.Size, vector.Digest, 0o600); err == nil {
				t.Fatal("stream publication accepted invalid preimage", vector.Name)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("stream publication did not clean owned output", vector.Name, err)
			}
		}
	}

	t.Run("standalone texture authoring", func(t *testing.T) {
		var fixture struct {
			Cases []struct {
				Name, Texture string
				Key           string `json:"bundle_key"`
				RGBA          string `json:"rgba_sha256"`
				Policy        string `json:"raster_policy"`
				Bundle        string `json:"bundle_path"`
			}
		}
		data, err := os.ReadFile("testdata/textures.json")
		if err != nil || json.Unmarshal(data, &fixture) != nil {
			t.Fatal("missing standalone texture fixture", err)
		}
		selected := map[string]bool{"std8": true, "std4-low-nibble": true, "raw32-font2": true, "std8-fullpage-nuno2": true, "std8-fullpage-maku02": true}
		checked := 0
		for _, c := range fixture.Cases {
			if !selected[c.Name] && c.Policy != "rgba" && !strings.HasPrefix(c.Name, "std8-small-") {
				continue
			}
			checked++
			bundle := c.Bundle
			if bundle == "" {
				bundle = "assets/cmb-members.zip"
			}
			assetDir := t.TempDir()
			archive, err := zip.OpenReader(bundle)
			if err != nil {
				t.Fatal(err)
			}
			defer archive.Close()
			var source []byte
			for _, member := range archive.File {
				if member.Name != c.Key {
					continue
				}
				r, err := member.Open()
				if err != nil {
					t.Fatal(err)
				}
				source, err = io.ReadAll(r)
				closeErr := r.Close()
				if err != nil || closeErr != nil {
					t.Fatal(err, closeErr)
				}
			}
			if len(source) == 0 {
				t.Fatal("missing texture CLI fixture")
			}
			sourcePath, profilePath := filepath.Join(assetDir, "source.txd"), filepath.Join(assetDir, "profile.json")
			pngPath, copyPath := filepath.Join(assetDir, "export.png"), filepath.Join(assetDir, "copy.txd")
			profile := TextureProfile{SourceSHA256: fmt.Sprintf("%x", sha256.Sum256(source)), SourceSize: int64(len(source)), Texture: c.Texture, PixelPolicy: c.Policy, Evidence: "Pinned independent texture fixture"}
			profileData, err := json.Marshal(profile)
			if err != nil {
				t.Fatal(err)
			}
			for path, data := range map[string][]byte{sourcePath: source, profilePath: profileData} {
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"--source", sourcePath, "--texture-profile", profilePath}
			var preview bytes.Buffer
			if err := run(args, &preview); err != nil {
				t.Fatal(err)
			}
			entries, _ := os.ReadDir(assetDir)
			if len(entries) != 2 {
				t.Fatal("texture preview wrote files")
			}
			var report map[string]any
			if err := json.Unmarshal(preview.Bytes(), &report); err != nil || report["mode"] != "export_png" || report["applied"] != false || report["rgba_sha256"] != c.RGBA {
				t.Fatalf("bad texture preview: %v %s", err, preview.String())
			}
			if report["palette_policy"] != "preserve" || c.Policy != "" && report["pixel_policy"] != c.Policy {
				t.Fatal("raster policy report mislabeled")
			}
			if c.Name == "std8" {
				// Independent known fixture offsets build a second native, not a second parser.
				if len(source) != 263576 || binary.LittleEndian.Uint32(source[28:]) != 0x15 || binary.LittleEndian.Uint32(source[120:]) != 1 {
					t.Fatal("inventory fixture structure changed")
				}
				inventoryDir := t.TempDir()
				inventorySource, inventoryProfile := filepath.Join(inventoryDir, "source.txd"), filepath.Join(inventoryDir, "profile.json")
				inventoryArgs := []string{"--source", inventorySource, "--texture-profile", inventoryProfile}
				for _, variant := range []string{"valid", "malformed info", "malformed extent", "uncalibrated", "duplicate"} {
					other := bytes.Clone(source[28:263564])
					otherName, issue := "other", ""
					if variant != "duplicate" {
						clear(other[44:64])
						copy(other[44:64], otherName)
					} else {
						otherName = c.Texture
					}
					header := &TextureHeader{Width: 1024, Height: 256, Depth: 8, RasterFormat: 0x2504, Version: 2}
					switch variant {
					case "malformed info":
						binary.LittleEndian.PutUint32(other[92:], 99)
						header, issue = nil, "unsupported texture info/pixel structs"
					case "malformed extent":
						binary.LittleEndian.PutUint32(other[96:], 0xffffffff)
						header, issue = nil, "RW chunk exceeds its parent"
					case "uncalibrated":
						binary.LittleEndian.PutUint32(other[112:], 16)
						header.Depth = 16
					}
					multi := append(bytes.Clone(source[:263564]), other...)
					multi = append(multi, source[263564:]...)
					binary.LittleEndian.PutUint32(multi[4:], uint32(len(multi)-12))
					binary.LittleEndian.PutUint16(multi[24:], 2)
					inventory := TextureProfile{Operation: "inventory", SourceSHA256: fmt.Sprintf("%x", sha256.Sum256(multi)), SourceSize: int64(len(multi)), Evidence: "Synthetic two-native discovery; codec support not inferred"}
					inventoryData, err := json.Marshal(inventory)
					if err != nil {
						t.Fatal(err)
					}
					for path, data := range map[string][]byte{inventorySource: multi, inventoryProfile: inventoryData} {
						if err := os.WriteFile(path, data, 0o600); err != nil {
							t.Fatal(err)
						}
					}
					var out bytes.Buffer
					if err := run(inventoryArgs, &out); err != nil {
						t.Fatal(variant, err)
					}
					var listed struct {
						Mode         string          `json:"mode"`
						CodecSupport string          `json:"codec_support"`
						SourceSHA256 string          `json:"source_sha256"`
						Textures     []NativeTexture `json:"textures"`
						Applied      bool            `json:"applied"`
					}
					if json.Unmarshal(out.Bytes(), &listed) != nil || listed.CodecSupport != "not_evaluated" || listed.SourceSHA256 != inventory.SourceSHA256 || listed.Mode != "inventory" || listed.Applied || len(listed.Textures) != 2 {
						t.Fatalf("inventory report: %s %s", variant, out.String())
					}
					first, second := listed.Textures[0], listed.Textures[1]
					if first.Name != c.Texture || first.Header == nil || *first.Header != (TextureHeader{Width: 1024, Height: 256, Depth: 8, RasterFormat: 0x2504, Version: 2}) || first.MetadataError != "" || second.Name != otherName || second.MetadataError != issue || (second.Header == nil) != (header == nil) || header != nil && *second.Header != *header {
						t.Fatalf("inventory metadata: %s %#v %#v", variant, first, second)
					}
					_, raster, err := texture(multi, c.Texture, nil, nil, "", nil)
					if variant == "duplicate" {
						if err == nil || raster != nil || !strings.Contains(err.Error(), "matches 2") {
							t.Fatal("duplicate selector admitted", err)
						}
					} else if err != nil || fmt.Sprintf("%x", sha256.Sum256(raster.Pix)) != c.RGBA {
						t.Fatal("unselected metadata changed valid codec selection", variant, err)
					}
					if issue != "" || variant == "uncalibrated" {
						if artifact, raster, err := texture(multi, otherName, nil, nil, "", nil); err == nil || artifact != nil || raster != nil || issue != "" && err.Error() != issue {
							t.Fatal("invalid selected raster admitted", variant, err)
						}
					}
					for _, mutation := range []string{"apply", "output", "selector", "png", "pin", "rectangles", "render", "palette", "pixels", "operation", "source pin", "source size", "evidence"} {
						bad := inventory
						badArgs := slices.Clone(inventoryArgs)
						switch mutation {
						case "apply":
							badArgs = append(badArgs, "--apply", "--output", filepath.Join(inventoryDir, "forbidden"))
						case "output":
							badArgs = append(badArgs, "--output", filepath.Join(inventoryDir, "forbidden"))
						case "selector":
							bad.Texture = c.Texture
						case "png":
							bad.PNG = "candidate.png"
						case "pin":
							bad.PNGSHA256 = inventory.SourceSHA256
						case "rectangles":
							bad.Rectangles = [][]int{{0, 0, 1, 1}}
						case "render":
							bad.Render = &RasterRender{}
						case "palette":
							bad.PalettePolicy = "preserve"
						case "pixels":
							bad.PixelPolicy = "rgba"
						case "operation":
							bad.Operation = "other"
						case "source pin":
							bad.SourceSHA256 = strings.Repeat("0", 64)
						case "source size":
							bad.SourceSize--
						case "evidence":
							bad.Evidence = ""
						}
						badData, err := json.Marshal(bad)
						if err != nil || os.WriteFile(inventoryProfile, badData, 0o600) != nil {
							t.Fatal(err)
						}
						out.Reset()
						if err := run(badArgs, &out); err == nil || out.Len() != 0 {
							t.Fatal("invalid inventory admitted", mutation, variant, err)
						}
					}
					if files, err := os.ReadDir(inventoryDir); err != nil || len(files) != 2 {
						t.Fatal("inventory wrote files", err)
					}
					if after, err := os.ReadFile(inventorySource); err != nil || !bytes.Equal(after, multi) {
						t.Fatal("inventory changed source", err)
					}
				}
			}
			var applied bytes.Buffer
			if err := run(append(slices.Clone(args), "--apply", "--output", pngPath), &applied); err != nil {
				t.Fatal(err)
			}
			pngData, err := os.ReadFile(pngPath)
			if err != nil || report["output_sha256"] != fmt.Sprintf("%x", sha256.Sum256(pngData)) {
				t.Fatal("export PNG differs", err)
			}
			profile.PNG, profile.PNGSHA256 = "export.png", fmt.Sprintf("%x", sha256.Sum256(pngData))
			profileData, err = json.Marshal(profile)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(profilePath, profileData, 0o600); err != nil {
				t.Fatal(err)
			}
			var imported bytes.Buffer
			if err := run(append(slices.Clone(args), "--apply", "--output", copyPath), &imported); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(imported.Bytes(), &report); err != nil || report["mode"] != "import_png" || report["rgba_sha256"] != c.RGBA || report["output_sha256"] != profile.SourceSHA256 {
				t.Fatalf("incorrect texture import report: %v %s", err, imported.String())
			}
			copied, err := os.ReadFile(copyPath)
			if err != nil || !bytes.Equal(copied, source) {
				t.Fatal("TXD no-op differs", err)
			}
			for _, path := range []string{pngPath, copyPath} {
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm()&^0o644 != 0 || info.Mode().Perm()&0o600 != 0o600 {
					t.Fatal("unsafe standalone output permissions", path, err)
				}
			}
			linked := filepath.Join(assetDir, "linked.txd")
			if err := os.Symlink(sourcePath, linked); err != nil {
				t.Fatal(err)
			}
			for _, refused := range []string{linked, assetDir, filepath.Join(sourcePath, "child"), filepath.Join(assetDir, "missing", "child")} {
				var out bytes.Buffer
				if err := run(append(slices.Clone(args), "--apply", "--output", refused), &out); err == nil || out.Len() != 0 {
					t.Fatalf("unsafe standalone publication admitted: %s", refused)
				}
			}
			for _, extra := range [][]string{{"--output", filepath.Join(assetDir, "forbidden")}, {"--apply"}, {"--apply", "--output", copyPath}, {"--apply", "--output", sourcePath}, {"--registry", sourcePath}, {"--glyphmap", sourcePath}, {"--recipes", profilePath}, {"--fit-profile", profilePath}, {"unexpected"}} {
				var out bytes.Buffer
				if err := run(append(slices.Clone(args), extra...), &out); err == nil || out.Len() != 0 {
					t.Fatalf("unsafe texture CLI combination admitted: %v", extra)
				}
			}
			for _, mutation := range []string{"source pin", "source size", "candidate pin", "missing candidate", "orphan candidate pin", "rectangle length", "rectangle outside", "unknown selector", "no evidence", "unknown pixel policy", "wrong palette field", "wrong pixel field", "conflicting policies", "missing color policy"} {
				if mutation == "missing color policy" && c.Policy == "" {
					continue
				}
				bad := profile
				switch mutation {
				case "source pin":
					bad.SourceSHA256 = strings.Repeat("0", 64)
				case "source size":
					bad.SourceSize++
				case "candidate pin":
					bad.PNGSHA256 = strings.Repeat("0", 64)
				case "missing candidate":
					bad.PNG = "absent.png"
				case "orphan candidate pin":
					bad.PNG = ""
				case "rectangle length":
					bad.Rectangles = [][]int{{0, 0, 1, 1, 9}}
				case "rectangle outside":
					bad.Rectangles = [][]int{{1024, 0, 1, 1}}
				case "unknown selector":
					bad.Texture = "absent"
				case "no evidence":
					bad.Evidence = ""
				case "unknown pixel policy":
					bad.PixelPolicy = "other"
				case "wrong palette field":
					bad.PalettePolicy, bad.PixelPolicy = "rgba", ""
				case "wrong pixel field":
					bad.PixelPolicy = "exact"
				case "conflicting policies":
					bad.PalettePolicy, bad.PixelPolicy = "exact", "rgba"
					bad.Rectangles = nil
				case "missing color policy":
					bad.PixelPolicy = ""
				}
				data, err := json.Marshal(bad)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(profilePath, data, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := run(append(slices.Clone(args), "--apply", "--output", filepath.Join(assetDir, "forbidden")), io.Discard); err == nil {
					t.Fatalf("bad texture policy admitted: %s", mutation)
				}
				if _, err := os.Stat(filepath.Join(assetDir, "forbidden")); !os.IsNotExist(err) {
					t.Fatal("refused texture created output")
				}
			}
			for _, bad := range [][]byte{[]byte(`null`), []byte(`{"unknown":true}`), append(bytes.Clone(profileData), []byte(` {}`)...)} {
				if err := os.WriteFile(profilePath, bad, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := run(args, io.Discard); err == nil {
					t.Fatal("malformed texture profile admitted")
				}
			}
			for path, expected := range map[string][]byte{sourcePath: source, pngPath: pngData, copyPath: source} {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, expected) {
					t.Fatal("texture changed input/existing output", path, err)
				}
			}
		}
		if checked != 31 {
			t.Fatal("missing standalone mode coverage", checked)
		}
		bitmapDir := t.TempDir()
		// The renderer starts from the original asset, never the already-English bundle.
		var bitmap struct {
			SourceBundle         string `json:"source_bundle"`
			SourceKey            string `json:"source_key"`
			SourceSHA            string `json:"source_sha256"`
			ExpectedBundle       string `json:"expected_bundle"`
			ExpectedKey          string `json:"expected_key"`
			TXD                  string `json:"txd_sha256"`
			RGBA                 string `json:"rgba_sha256"`
			SourceRGBA           string `json:"source_rgba_sha256"`
			PixelOffset          int    `json:"pixel_offset"`
			CLUTOffset           int    `json:"CLUT_offset"`
			Changed              int    `json:"changed_bytes"`
			Allowed              int    `json:"allowed_pixels"`
			Ledger               string `json:"changed_ledger_sha256"`
			Profile, Font, Atlas string
			Cells                []struct {
				ID   string
				RGBA string `json:"rgba_sha256"`
				BBox []int  `json:"alpha_bbox"`
				Ink  int    `json:"ink_pixels"`
			}
		}
		data, err = os.ReadFile("testdata/bitmap-render.json")
		if err != nil || json.Unmarshal(data, &bitmap) != nil || len(bitmap.Cells) != 5 {
			t.Fatal("missing bitmap oracle", err)
		}
		members := make(map[string][]byte)
		for _, input := range []struct{ name, path, key string }{{"source", bitmap.SourceBundle, bitmap.SourceKey}, {"expected", bitmap.ExpectedBundle, bitmap.ExpectedKey}} {
			archive, err := zip.OpenReader(input.path)
			if err != nil {
				t.Fatal(err)
			}
			for _, member := range archive.File {
				if member.Name != input.key {
					continue
				}
				reader, err := member.Open()
				if err != nil {
					t.Fatal(err)
				}
				body, readErr := io.ReadAll(io.LimitReader(reader, 1<<20))
				closeErr := reader.Close()
				if readErr != nil || closeErr != nil {
					t.Fatal(readErr, closeErr)
				}
				members[input.name] = body
			}
			if err := archive.Close(); err != nil {
				t.Fatal(err)
			}
		}
		source, expected := members["source"], members["expected"]
		if fmt.Sprintf("%x", sha256.Sum256(source)) != bitmap.SourceSHA || fmt.Sprintf("%x", sha256.Sum256(expected)) != bitmap.TXD {
			t.Fatal("bitmap fixture identity")
		}
		profileData, err := os.ReadFile(bitmap.Profile)
		if err != nil {
			t.Fatal(err)
		}
		var profile TextureProfile
		if json.Unmarshal(profileData, &profile) != nil || profile.Render == nil {
			t.Fatal("bitmap profile")
		}
		fontData, err := os.ReadFile(bitmap.Font)
		if err != nil {
			t.Fatal(err)
		}
		var font RasterFont
		if json.Unmarshal(fontData, &font) != nil || fmt.Sprintf("%x", sha256.Sum256(fontData)) != profile.Render.FontSHA256 {
			t.Fatal("bitmap font")
		}
		atlasData, err := os.ReadFile(bitmap.Atlas)
		if err != nil {
			t.Fatal(err)
		}
		imageFont, err := png.Decode(bytes.NewReader(atlasData))
		if err != nil {
			t.Fatal(err)
		}
		atlas, ok := imageFont.(*image.Gray)
		if !ok || fmt.Sprintf("%x", sha256.Sum256(atlasData)) != font.PNGSHA256 {
			t.Fatal("bitmap coverage type/pin")
		}
		_, base, err := texture(source, profile.Texture, nil, nil, "", nil)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(base.Pix)) != bitmap.SourceRGBA {
			t.Fatal("bitmap source decode", err)
		}
		baseBefore, atlasBefore := bytes.Clone(base.Pix), bytes.Clone(atlas.Pix)
		candidate, rectangles, err := composeCells(base, atlas, font, RasterComposition{Cells: profile.Render.Cells, Icons: nil})
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(candidate.Pix)) != bitmap.RGBA {
			t.Fatal("bitmap RGBA differs", err)
		}
		artifact, decoded, err := texture(source, profile.Texture, candidate, rectangles, "", nil)
		if err != nil || !bytes.Equal(artifact, expected) || !bytes.Equal(candidate.Pix, decoded.Pix) {
			t.Fatal("bitmap whole approved TXD differs", err)
		}
		mask := make([]bool, base.Rect.Dx()*base.Rect.Dy())
		allowed, changedPixels := 0, 0
		for _, rect := range rectangles {
			for y := rect.Min.Y; y < rect.Max.Y; y++ {
				for x := rect.Min.X; x < rect.Max.X; x++ {
					mask[y*base.Rect.Dx()+x] = true
					allowed++
				}
			}
		}
		for y := 0; y < base.Rect.Dy(); y++ {
			for x := 0; x < base.Rect.Dx(); x++ {
				if base.NRGBAAt(x, y) != candidate.NRGBAAt(x, y) {
					changedPixels++
					if !mask[y*base.Rect.Dx()+x] {
						t.Fatal("bitmap changed outside cells")
					}
				}
			}
		}
		var ledger []byte
		for at, old := range source {
			if artifact[at] != old {
				if at < bitmap.PixelOffset || at >= bitmap.PixelOffset+base.Rect.Dx()*base.Rect.Dy() {
					t.Fatal("bitmap changed metadata/CLUT/header")
				}
				ledger = binary.LittleEndian.AppendUint32(ledger, uint32(at))
				ledger = append(ledger, old, artifact[at])
			}
		}
		if allowed != bitmap.Allowed || changedPixels != bitmap.Changed || len(ledger) != bitmap.Changed*6 || fmt.Sprintf("%x", sha256.Sum256(ledger)) != bitmap.Ledger || !bytes.Equal(source[bitmap.CLUTOffset:bitmap.CLUTOffset+1024], artifact[bitmap.CLUTOffset:bitmap.CLUTOffset+1024]) {
			t.Fatal("bitmap containment/ledger")
		}
		for i, cell := range profile.Render.Cells {
			rect := rectangles[i]
			var pixels []byte
			bbox := image.Rectangle{}
			ink := 0
			for y := 0; y < rect.Dy(); y++ {
				for x := 0; x < rect.Dx(); x++ {
					p := candidate.NRGBAAt(rect.Min.X+x, rect.Min.Y+y)
					pixels = append(pixels, p.R, p.G, p.B, p.A)
					if p.A == 0 {
						if p != (color.NRGBA{255, 255, 255, 0}) {
							t.Fatal("hidden RGB lost")
						}
					} else {
						bbox = bbox.Union(image.Rect(x, y, x+1, y+1))
					}
					if p == (color.NRGBA{uint8(cell.Fill[0]), uint8(cell.Fill[1]), uint8(cell.Fill[2]), 255}) || p == (color.NRGBA{uint8(cell.Shade[0]), uint8(cell.Shade[1]), uint8(cell.Shade[2]), 255}) {
						ink++
					} else if p.A != 0 && p != (color.NRGBA{0, 0, 0, 255}) {
						t.Fatal("unexpected outline color")
					}
				}
			}
			want := bitmap.Cells[i]
			if want.ID != cell.ID || fmt.Sprintf("%x", sha256.Sum256(pixels)) != want.RGBA || ink != want.Ink || !reflect.DeepEqual([]int{bbox.Min.X, bbox.Min.Y, bbox.Max.X, bbox.Max.Y}, want.BBox) {
				t.Fatal("bitmap cell semantic oracle", cell.ID)
			}
		}
		again, _, err := composeCells(candidate, atlas, font, RasterComposition{Cells: profile.Render.Cells, Icons: nil})
		if err != nil || !bytes.Equal(again.Pix, candidate.Pix) || !bytes.Equal(baseBefore, base.Pix) || !bytes.Equal(atlasBefore, atlas.Pix) {
			t.Fatal("bitmap idempotence/inputs", err)
		}
		for _, mutation := range []string{"empty cells", "duplicate ID", "empty ID", "empty text", "missing glyph", "invalid UTF8", "long word", "overflow", "short cell", "negative cell", "outside cell", "long rect", "overlap", "short fill", "long fill", "transparent fill", "short shade", "transparent shade", "negative fill", "large fill", "negative shade", "large shade", "empty font", "bad key", "short glyph", "outside glyph", "advance", "empty glyph", "nonbinary"} {
			var badProfile TextureProfile
			var badFont RasterFont
			if json.Unmarshal(profileData, &badProfile) != nil || json.Unmarshal(fontData, &badFont) != nil {
				t.Fatal("clone bitmap inputs")
			}
			badAtlas := image.NewGray(atlas.Rect)
			copy(badAtlas.Pix, atlas.Pix)
			cells := badProfile.Render.Cells
			switch mutation {
			case "empty cells":
				cells = nil
			case "duplicate ID":
				cells[1].ID = cells[0].ID
			case "empty ID":
				cells[0].ID = ""
			case "empty text":
				cells[0].Text = ""
			case "missing glyph":
				cells[0].Text = "?"
			case "invalid UTF8":
				cells[0].Text = string([]byte{255})
			case "long word":
				cells[0].Text = strings.Repeat("A", 129)
			case "overflow":
				cells[0].Text = strings.Repeat("A", 10)
			case "short cell":
				cells[0].Rect[3] = 12
			case "negative cell":
				cells[0].Rect[0] = -1
			case "outside cell":
				cells[0].Rect[0] = 512
			case "long rect":
				cells[0].Rect = append(cells[0].Rect, 0)
			case "overlap":
				cells[1].Rect = slices.Clone(cells[0].Rect)
			case "short fill":
				cells[0].Fill = cells[0].Fill[:3]
			case "long fill":
				cells[0].Fill = append(cells[0].Fill, 0)
			case "transparent fill":
				cells[0].Fill[3] = 0
			case "short shade":
				cells[0].Shade = cells[0].Shade[:3]
			case "transparent shade":
				cells[0].Shade[3] = 0
			case "negative fill":
				cells[0].Fill[0] = -1
			case "large fill":
				cells[0].Fill[1] = 256
			case "negative shade":
				cells[0].Shade[0] = -1
			case "large shade":
				cells[0].Shade[2] = 256
			case "empty font":
				badFont.Glyphs = nil
			case "bad key":
				badFont.Glyphs["AA"] = badFont.Glyphs["A"]
			case "short glyph":
				g := badFont.Glyphs["A"]
				g.Rect = g.Rect[:3]
				badFont.Glyphs["A"] = g
			case "outside glyph":
				g := badFont.Glyphs["A"]
				g.Rect[0] = atlas.Rect.Dx()
				badFont.Glyphs["A"] = g
			case "advance":
				g := badFont.Glyphs["A"]
				g.Advance = 1
				badFont.Glyphs["A"] = g
			case "empty glyph":
				g := badFont.Glyphs["A"]
				for y := g.Rect[1]; y < g.Rect[1]+g.Rect[3]; y++ {
					for x := g.Rect[0]; x < g.Rect[0]+g.Rect[2]; x++ {
						badAtlas.SetGray(x, y, color.Gray{})
					}
				}
			case "nonbinary":
				badAtlas.SetGray(0, 0, color.Gray{127})
			}
			if out, rects, err := composeCells(base, badAtlas, badFont, RasterComposition{Cells: cells, Icons: nil}); err == nil || out != nil || rects != nil || !bytes.Equal(base.Pix, baseBefore) {
				t.Fatal("bitmap mutation admitted", mutation, err)
			}
		}
		sourcePath := write(filepath.Join(bitmapDir, "bitmap-source.txd"), source)
		outputPath := filepath.Join(bitmapDir, "bitmap-authored.txd")
		args := []string{"--source", sourcePath, "--texture-profile", bitmap.Profile}
		for _, apply := range []bool{false, true} {
			command := slices.Clone(args)
			if apply {
				command = append(command, "--apply", "--output", outputPath)
			}
			var out bytes.Buffer
			if err := run(command, &out); err != nil {
				t.Fatal(err)
			}
			var report map[string]any
			if json.Unmarshal(out.Bytes(), &report) != nil || report["output_sha256"] != bitmap.TXD || report["rgba_sha256"] != bitmap.RGBA || report["mode"] != "render_bitmap" || report["rendered_cells"] != float64(5) || report["applied"] != apply {
				t.Fatal("bitmap CLI report", out.String())
			}
			if apply {
				got, err := os.ReadFile(outputPath)
				if err != nil || !bytes.Equal(got, expected) {
					t.Fatal("bitmap CLI bytes", err)
				}
				out.Reset()
				if err := run(command, &out); err == nil || out.Len() != 0 {
					t.Fatal("bitmap overwrote output")
				}
			} else if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
				t.Fatal("bitmap preview wrote")
			}
		}
		serialized, err := json.Marshal(profile)
		if err != nil || !bytes.Contains(serialized, []byte(`"fill":[255,255,255,255]`)) {
			t.Fatal("bitmap colors must serialize as readable numeric arrays", err)
		}
		fontPath, err := filepath.Abs(bitmap.Font)
		if err != nil {
			t.Fatal(err)
		}
		atlasPath, err := filepath.Abs(bitmap.Atlas)
		if err != nil {
			t.Fatal(err)
		}
		for _, mutation := range []string{"source pin", "source size", "selector", "font pin", "font missing", "PNG conflict", "rectangle conflict", "exact conflict", "quantize conflict", "no font", "no cells", "empty word", "missing glyph", "font UTF8", "font extra JSON", "font unknown", "font PNG pin", "font PNG type", "font PNG bytes"} {
			var bad TextureProfile
			var badFont RasterFont
			if json.Unmarshal(profileData, &bad) != nil || json.Unmarshal(fontData, &badFont) != nil {
				t.Fatal("clone bitmap CLI")
			}
			bad.Render.Font = fontPath
			badFont.PNG = atlasPath
			switch mutation {
			case "source pin":
				bad.SourceSHA256 = strings.Repeat("0", 64)
			case "source size":
				bad.SourceSize++
			case "selector":
				bad.Texture = "missing"
			case "font pin":
				bad.Render.FontSHA256 = strings.Repeat("0", 64)
			case "font missing":
				bad.Render.Font = filepath.Join(bitmapDir, "absent-font.json")
			case "PNG conflict":
				bad.PNG, bad.PNGSHA256 = atlasPath, font.PNGSHA256
			case "rectangle conflict":
				bad.Rectangles = [][]int{{0, 0, 1, 1}}
			case "exact conflict":
				bad.PalettePolicy = "exact"
			case "quantize conflict":
				bad.PalettePolicy = "quantize"
			case "no font":
				bad.Render.Font = ""
			case "no cells":
				bad.Render.Cells = nil
			case "empty word":
				bad.Render.Cells[0].Text = ""
			case "missing glyph":
				bad.Render.Cells[0].Text = "?"
			case "font PNG pin":
				badFont.PNGSHA256 = strings.Repeat("0", 64)
			case "font PNG type":
				var encoded bytes.Buffer
				if png.Encode(&encoded, image.NewNRGBA(image.Rect(0, 0, 2, 2))) != nil {
					t.Fatal("encode font test")
				}
				badFont.PNG = write(filepath.Join(bitmapDir, "bitmap-colored-font.png"), encoded.Bytes())
				badFont.PNGSHA256 = fmt.Sprintf("%x", sha256.Sum256(encoded.Bytes()))
			case "font PNG bytes":
				badFont.PNG = write(filepath.Join(bitmapDir, "bitmap-invalid-font.png"), []byte("bad PNG"))
				badFont.PNGSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte("bad PNG")))
			}
			if strings.HasPrefix(mutation, "font ") && mutation != "font pin" && mutation != "font missing" {
				body, err := json.Marshal(badFont)
				if err != nil {
					t.Fatal(err)
				}
				switch mutation {
				case "font UTF8":
					body = []byte{255}
				case "font extra JSON":
					body = append(body, []byte(" {}")...)
				case "font unknown":
					body = append([]byte(`{"unknown":1,`), body[1:]...)
				}
				bad.Render.Font = write(filepath.Join(bitmapDir, "bitmap-invalid-font.json"), body)
				bad.Render.FontSHA256 = fmt.Sprintf("%x", sha256.Sum256(body))
			}
			badPath := jsonFile(filepath.Join(bitmapDir, "bitmap-invalid-profile.json"), bad)
			refused := filepath.Join(bitmapDir, "bitmap-refused.txd")
			var out bytes.Buffer
			if err := run([]string{"--source", sourcePath, "--texture-profile", badPath, "--apply", "--output", refused}, &out); err == nil || out.Len() != 0 {
				t.Fatal("bitmap CLI mutation admitted", mutation, err)
			}
			if _, err := os.Stat(refused); !os.IsNotExist(err) {
				t.Fatal("bitmap refusal created output", mutation)
			}
		}
		for path, want := range map[string][]byte{sourcePath: source, outputPath: expected, bitmap.Profile: profileData, bitmap.Font: fontData, bitmap.Atlas: atlasData} {
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("bitmap input/output changed", path, err)
			}
		}
		{
			nativeDir := t.TempDir()
			var oracle struct {
				Bundle, Profile, Font, Atlas string
				BundleSHA                    string `json:"bundle_sha256"`
				TXD                          string `json:"txd_sha256"`
				RGBA                         string `json:"rgba_sha256"`
			}
			body, err := os.ReadFile("testdata/native-raster.json")
			if err != nil || json.Unmarshal(body, &oracle) != nil {
				t.Fatal("native CLI oracle", err)
			}
			bundleData, err := os.ReadFile(oracle.Bundle)
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(bundleData)) != oracle.BundleSHA {
				t.Fatal("native CLI bundle", err)
			}
			bundle, err := zip.NewReader(bytes.NewReader(bundleData), int64(len(bundleData)))
			if err != nil {
				t.Fatal(err)
			}
			files := make(map[string][]byte)
			for _, key := range []string{"source.txd", "expected.txd"} {
				reader, err := bundle.Open(key)
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(reader)
				reader.Close()
				if err != nil {
					t.Fatal(err)
				}
				files[key] = data
			}
			sourcePath := write(filepath.Join(nativeDir, "native-source.txd"), files["source.txd"])
			output := filepath.Join(nativeDir, "native-authored.txd")
			for _, apply := range []bool{false, true} {
				args := []string{"--source", sourcePath, "--texture-profile", oracle.Profile}
				if apply {
					args = append(args, "--apply", "--output", output)
				}
				var out bytes.Buffer
				if err := run(args, &out); err != nil {
					t.Fatal(err)
				}
				var report map[string]any
				if json.Unmarshal(out.Bytes(), &report) != nil || report["mode"] != "render_bitmap" || report["output_sha256"] != oracle.TXD || report["rgba_sha256"] != oracle.RGBA || report["rendered_cells"] != float64(1) || report["applied"] != apply {
					t.Fatal("native CLI report", out.String())
				}
				if apply {
					got, err := os.ReadFile(output)
					if err != nil || !bytes.Equal(got, files["expected.txd"]) {
						t.Fatal("native CLI whole TXD", err)
					}
					if err := run(args, &out); err == nil {
						t.Fatal("native CLI overwrote output")
					}
				} else if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatal("native preview wrote output", err)
				}
			}
			profileData, err := os.ReadFile(oracle.Profile)
			if err != nil {
				t.Fatal(err)
			}
			fontData, err := os.ReadFile(oracle.Font)
			if err != nil {
				t.Fatal(err)
			}
			atlasData, err := os.ReadFile(oracle.Atlas)
			if err != nil {
				t.Fatal(err)
			}
			fontPath, err := filepath.Abs(oracle.Font)
			if err != nil {
				t.Fatal(err)
			}
			atlasPath, err := filepath.Abs(oracle.Atlas)
			if err != nil {
				t.Fatal(err)
			}
			iconZIPData, err := os.ReadFile("testdata/inline-icons.zip")
			if err != nil {
				t.Fatal(err)
			}
			iconBundle, err := zip.NewReader(bytes.NewReader(iconZIPData), int64(len(iconZIPData)))
			if err != nil {
				t.Fatal(err)
			}
			iconFiles := make(map[string][]byte)
			for _, name := range []string{"native/profile.json", "native/source.txd", "native/expected.txd"} {
				reader, err := iconBundle.Open(name)
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(reader)
				reader.Close()
				if err != nil {
					t.Fatal(err)
				}
				iconFiles[name] = data
			}
			var iconProfile TextureProfile
			if json.Unmarshal(iconFiles["native/profile.json"], &iconProfile) != nil {
				t.Fatal("CLI icon profile")
			}
			iconProfile.Render.Font = fontPath
			iconBody, err := json.Marshal(iconProfile)
			if err != nil {
				t.Fatal(err)
			}
			iconPath := write(filepath.Join(nativeDir, "inline-icons.json"), iconBody)
			iconSourcePath := write(filepath.Join(nativeDir, "inline-source.txd"), iconFiles["native/source.txd"])
			iconOutput := filepath.Join(nativeDir, "inline-output.txd")
			for _, apply := range []bool{false, true} {
				args := []string{"--source", iconSourcePath, "--texture-profile", iconPath}
				if apply {
					args = append(args, "--apply", "--output", iconOutput)
				}
				var out bytes.Buffer
				if err := run(args, &out); err != nil {
					t.Fatal("inline CLI", err)
				}
				var report map[string]any
				if json.Unmarshal(out.Bytes(), &report) != nil || report["output_sha256"] != "848674056354a177f4467c74865524b816ce53720f4c7f99e212203b69f4ce7c" || report["applied"] != apply {
					t.Fatal("inline CLI report", out.String())
				}
				if apply {
					actual, err := os.ReadFile(iconOutput)
					if err != nil || !bytes.Equal(actual, iconFiles["native/expected.txd"]) {
						t.Fatal("inline CLI complete native artifact", err)
					}
					var repeated bytes.Buffer
					if err := run(args, &repeated); err == nil || repeated.Len() != 0 {
						t.Fatal("inline CLI overwrite admitted", err)
					}
				} else if _, err := os.Stat(iconOutput); !os.IsNotExist(err) {
					t.Fatal("inline dry run published", err)
				}
			}
			for _, mutation := range []string{"unknown icon", "outside source", "text conflict", "null coordinate"} {
				var bad TextureProfile
				if json.Unmarshal(iconBody, &bad) != nil {
					t.Fatal("inline CLI clone")
				}
				switch mutation {
				case "unknown icon":
					bad.Render.Cells[0].Runs[1].Icon = "missing"
				case "outside source":
					bad.Render.Icons["lr"][0] = math.MaxInt
				case "text conflict":
					bad.Render.Cells[0].Runs[1].Text = "A"
				}
				body, err := json.Marshal(bad)
				if err != nil {
					t.Fatal(err)
				}
				if mutation == "null coordinate" {
					body = bytes.Replace(body, []byte(`"lr":[303,290,26,13]`), []byte(`"lr":[null,290,26,13]`), 1)
				}
				badPath := write(filepath.Join(nativeDir, "bad-inline.json"), body)
				refused := filepath.Join(nativeDir, "refused-inline.txd")
				var out bytes.Buffer
				if err := run([]string{"--source", iconSourcePath, "--texture-profile", badPath, "--apply", "--output", refused}, &out); err == nil || out.Len() != 0 {
					t.Fatal("inline CLI refusal", mutation, err)
				}
				if _, err := os.Stat(refused); !os.IsNotExist(err) {
					t.Fatal("inline CLI refusal published", mutation, err)
				}
			}
			for path, want := range map[string][]byte{iconPath: iconBody, iconSourcePath: iconFiles["native/source.txd"], iconOutput: iconFiles["native/expected.txd"]} {
				actual, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(actual, want) {
					t.Fatal("inline CLI source/profile/output preservation", path, err)
				}
			}
			for _, mutation := range []string{"source pin", "font pin", "PNG conflict", "palette conflict", "layout absent", "size fractional", "width absent", "stroke uncalibrated", "anchor short", "runs absent", "missing glyph", "color large", "background alpha", "pixel conflict", "font metrics", "font tile", "font bearing", "space bearing", "spill top", "spill left", "unknown field", "null number", "null color", "extra JSON", "tracking bound", "minimum fractional", "composition unknown", "stroke conflict", "stroke order", "stroke source", "stroke null", "source export", "source pixel conflict"} {
				var bad TextureProfile
				var badFont RasterFont
				if json.Unmarshal(profileData, &bad) != nil || json.Unmarshal(fontData, &badFont) != nil {
					t.Fatal("native CLI clone")
				}
				bad.Render.Font = fontPath
				cell := &bad.Render.Cells[0]
				switch mutation {
				case "source pin":
					bad.SourceSHA256 = strings.Repeat("0", 64)
				case "font pin":
					bad.Render.FontSHA256 = strings.Repeat("0", 64)
				case "PNG conflict":
					bad.PNG, bad.PNGSHA256 = atlasPath, badFont.PNGSHA256
				case "palette conflict":
					bad.PalettePolicy = "exact"
				case "layout absent":
					cell.Layout = nil
				case "size fractional":
					cell.Layout.Size = 22.1
				case "width absent":
					cell.Layout.MaxWidth = 0
				case "stroke uncalibrated":
					cell.Layout.Stroke = 1
				case "anchor short":
					cell.Layout.At = []float64{1}
				case "runs absent":
					cell.Runs = nil
				case "missing glyph":
					cell.Runs[0].Text = "’"
				case "color large":
					cell.Runs[0].Fill[0] = 256
				case "background alpha":
					cell.Background[3] = 0
				case "pixel conflict":
					cell.Text = "A"
				case "font metrics":
					badFont.CapHeight = 25
				case "font tile":
					g := badFont.Glyphs["L"]
					g.Rect[2]--
					badFont.Glyphs["L"] = g
				case "font bearing":
					g := badFont.Glyphs["L"]
					g.Left = -1
					badFont.Glyphs["L"] = g
				case "space bearing":
					g := badFont.Glyphs[" "]
					g.Left = 1
					badFont.Glyphs[" "] = g
				case "source export":
					bad.PalettePolicy = "source"
					bad.Render = nil
				case "source pixel conflict":
					bad.PalettePolicy = "source"
					bad.PixelPolicy = "rgba"
				case "tracking bound":
					cell.Layout.Tracking = 2
				case "minimum fractional":
					cell.Layout.MinSize = 16.1
				case "composition unknown":
					cell.Layout.Composite = "fast"
				case "stroke conflict":
					cell.Layout.Strokes = &[]BitmapStroke{{Radius: .5, Source: "glyph"}}
				case "stroke order", "stroke source", "stroke null":
					cell.Layout.Stroke = 0
					cell.Layout.Strokes = &[]BitmapStroke{{Radius: .65, Source: "color", Fill: []int{255, 207, 116, 255}}, {Radius: .5, Source: "glyph"}}
					if mutation == "stroke order" {
						(*cell.Layout.Strokes)[0].Radius = .25
					}
					if mutation == "stroke source" {
						(*cell.Layout.Strokes)[0].Source = "unknown"
					}
				case "spill top":
					cell.Layout.At[1]--
				case "spill left":
					cell.Layout.At[0] -= 4
				}
				if strings.HasPrefix(mutation, "font ") && mutation != "font pin" || mutation == "space bearing" {
					badFont.PNG = atlasPath
					data, err := json.Marshal(badFont)
					if err != nil {
						t.Fatal(err)
					}
					bad.Render.Font = write(filepath.Join(nativeDir, "invalid-font.json"), data)
					bad.Render.FontSHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
				}
				data, err := json.Marshal(bad)
				if err != nil {
					t.Fatal(err)
				}
				switch mutation {
				case "unknown field":
					data = bytes.Replace(data, []byte(`"layout":{`), []byte(`"layout":{"unknown":1,`), 1)
				case "stroke null":
					data = bytes.Replace(data, []byte(`"radius":0.65`), []byte(`"radius":null`), 1)
				case "null number":
					data = bytes.Replace(data, []byte(`"stroke":0.55`), []byte(`"stroke":null`), 1)
				case "null color":
					data = bytes.Replace(data, []byte(`"fill":[0,0,0,255]`), []byte(`"fill":[null,0,0,255]`), 1)
				case "extra JSON":
					data = append(data, []byte(" {}")...)
				}
				path := write(filepath.Join(nativeDir, "invalid-profile.json"), data)
				refused := filepath.Join(nativeDir, "refused.txd")
				var out bytes.Buffer
				err = run([]string{"--source", sourcePath, "--texture-profile", path, "--apply", "--output", refused}, &out)
				if err == nil || out.Len() != 0 {
					t.Fatal("native CLI admitted mutation", mutation, err)
				}
				if strings.HasPrefix(mutation, "spill ") && !strings.Contains(err.Error(), "spills outside") {
					t.Fatal("native CLI spill did not reach containment", mutation, err)
				}
				if _, err := os.Stat(refused); !os.IsNotExist(err) {
					t.Fatal("native refusal wrote output", mutation, err)
				}
			}
			var tutorial struct {
				Bundle, Profile string
				Actual          struct{ Source, Expected string }
			}
			styleMeta, err := os.ReadFile("testdata/native-styles.json")
			if err != nil || json.Unmarshal(styleMeta, &tutorial) != nil {
				t.Fatal("tutorial CLI manifest", err)
			}
			styleZIP, err := os.ReadFile(tutorial.Bundle)
			if err != nil {
				t.Fatal(err)
			}
			styleBundle, err := zip.NewReader(bytes.NewReader(styleZIP), int64(len(styleZIP)))
			if err != nil {
				t.Fatal(err)
			}
			var tutorialSource, tutorialExpected []byte
			for _, entry := range styleBundle.File {
				if entry.Name != tutorial.Actual.Source && entry.Name != tutorial.Actual.Expected {
					continue
				}
				reader, err := entry.Open()
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(reader)
				reader.Close()
				if err != nil {
					t.Fatal(err)
				}
				if entry.Name == tutorial.Actual.Source {
					tutorialSource = data
				} else {
					tutorialExpected = data
				}
			}
			tutorialInput := write(filepath.Join(nativeDir, "original-tutorial.txd"), tutorialSource)
			tutorialOutput := filepath.Join(nativeDir, "tutorial-output.txd")
			var tutorialReport bytes.Buffer
			args := []string{"--source", tutorialInput, "--texture-profile", tutorial.Profile}
			if err := run(args, &tutorialReport); err != nil || tutorialReport.Len() == 0 {
				t.Fatal("tutorial CLI preview", err)
			}
			tutorialReport.Reset()
			if err := run(append(args, "--apply", "--output", tutorialOutput), &tutorialReport); err != nil {
				t.Fatal("tutorial CLI apply", err)
			}
			written, err := os.ReadFile(tutorialOutput)
			if err != nil || !bytes.Equal(written, tutorialExpected) {
				t.Fatal("tutorial CLI whole artifact", err)
			}
			preserved, err := os.ReadFile(tutorialInput)
			if err != nil || !bytes.Equal(preserved, tutorialSource) {
				t.Fatal("tutorial CLI source changed", err)
			}
			for path, want := range map[string][]byte{sourcePath: files["source.txd"], output: files["expected.txd"], oracle.Profile: profileData, oracle.Font: fontData, oracle.Atlas: atlasData} {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("native CLI changed input/output", path, err)
				}
			}
		}
	})

	t.Run("read-only authoring fit", func(t *testing.T) {
		nativeProfile, _, fitGlyphs, nativeImage := fixture(t, "stream_reflow")
		elf := bytes.Clone(nativeImage[0x800 : 0x800+nativeProfile.Stream.RetailELFSize])
		clear(elf[0x10:0x44]) // Font inspection cannot depend on loader/window readiness.
		profile := FitProfile{
			SourceSize: int64(len(elf)), SourceSHA256: fmt.Sprintf("%x", sha256.Sum256(elf)),
			GlyphmapSHA256: fmt.Sprintf("%x", sha256.Sum256(fitGlyphs)), ELFVMADelta: "0", Font: *nativeProfile.Layout,
			Boxes: map[string]FitBox{
				"description": {MaxWidth: 50, MaxLines: 1, Evidence: "synthetic no-page lane"},
				"dialogue":    {MaxWidth: 40, MaxLines: 2, AllowPages: true, Evidence: "synthetic paged lane"},
			},
			Entries: map[string]FitEntry{"0x100": {Box: "description"}, "0x110": {Box: "dialogue"}},
		}
		canonical := []byte(`{"entries":[{"id":"0x100","en":"A B","status":"patched","ref_type":"struct_table_field"},{"id":"0x110","en":"A|B//C","status":"drafted","ref_type":"pointer_array","ref_sites":[{},{}]}]}`)
		sourcePath := write("fit-font.elf", elf)
		registryPath := write("fit-registry.json", canonical)
		glyphPath := write("fit-glyphs.json", fitGlyphs)
		profilePath := jsonFile("fit-profile.json", profile)
		args := []string{"--fit-profile", profilePath, "--source", sourcePath, "--registry", registryPath, "--glyphmap", glyphPath}
		before, _ := os.ReadDir(dir)
		var output bytes.Buffer
		if err := run(args, &output); err != nil {
			t.Fatal(err)
		}
		after, _ := os.ReadDir(dir)
		var report FitReport
		if err := json.Unmarshal(output.Bytes(), &report); err != nil || len(report.Entries) != 2 || len(before) != len(after) {
			t.Fatalf("authoring preview failed or wrote files: %v %s", err, output.String())
		}
		if report.Measurement != "native_pen_advances" || report.RegistrySHA256 != fmt.Sprintf("%x", sha256.Sum256(canonical)) || report.Entries[0].Status != "overflow" || report.Entries[0].Width != 55 || !reflect.DeepEqual(report.Entries[0].LineWidths, [][]int{{55}}) || report.Entries[1].Status != "within_profile" || !reflect.DeepEqual(report.Entries[1].LineWidths, [][]int{{13, 28}, {22}}) {
			t.Fatalf("wrong native measurements: %+v", report)
		}
		if report.Entries[0].EncodedSHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte{1, 0, 0, 0, 2, 0, 0, 0xf8})) {
			t.Fatal("authoring hash must be generated from new wording")
		}
		var repeat bytes.Buffer
		if err := run(args, &repeat); err != nil || !bytes.Equal(output.Bytes(), repeat.Bytes()) {
			t.Fatalf("fit report is not deterministic: %v", err)
		}
		{
			// Literal oracles were frozen independently of the encoder and LINE-count implementation.
			data, err := os.ReadFile("testdata/fit-line-count.json")
			if err != nil {
				t.Fatal(err)
			}
			var vectors struct {
				Cases []struct {
					Name string `json:"name"`
					Box  FitBox `json:"box"`
					FitRow
					DiagnosticKinds  []string `json:"diagnostic_kinds_in_order"`
					RepeatLineBreaks int      `json:"repeat_line_breaks"`
				} `json:"cases"`
				Refusals []map[string]any `json:"profile_refusals"`
			}
			if err := json.Unmarshal(data, &vectors); err != nil || len(vectors.Cases) != 17 || len(vectors.Refusals) != 5 {
				t.Fatal("invalid independent LINE-count vectors", err)
			}
			for _, c := range vectors.Cases {
				if c.RepeatLineBreaks != 0 {
					c.English = strings.Repeat("|", c.RepeatLineBreaks)
					c.EncodedHex = strings.Repeat("0008", c.RepeatLineBreaks) + "00f8"
					c.LineWidths = [][]int{make([]int, c.RepeatLineBreaks+1)}
				}
				policy := profile
				policy.Boxes = map[string]FitBox{"menu": c.Box}
				policy.Entries = map[string]FitEntry{"0x100": {Box: "menu"}}
				jsonFile("fit-profile.json", policy)
				jsonFile("fit-registry.json", Registry{Entries: []RegistryEntry{{ID: "0x100", EN: c.English}}})
				var out bytes.Buffer
				if err := run(args, &out); err != nil {
					t.Fatal(c.Name, err)
				}
				var got FitReport
				if err := json.Unmarshal(out.Bytes(), &got); err != nil || len(got.Entries) != 1 {
					t.Fatal(c.Name, "invalid fit report", err)
				}
				row := got.Entries[0]
				if row.Status != c.Status || row.EncodedHex != c.EncodedHex || row.Bytes != c.Bytes || row.Width != c.Width || row.Lines != c.Lines || !reflect.DeepEqual(row.LineWidths, c.LineWidths) || !reflect.DeepEqual(row.LineBreaks, c.LineBreaks) || !reflect.DeepEqual(got.Boxes["menu"], c.Box) {
					t.Fatalf("%s: independent LINE-count oracle mismatch: %+v", c.Name, row)
				}
				if row.EncodedHex != "" {
					literal, err := hex.DecodeString(c.EncodedHex)
					if err != nil || row.EncodedSHA256 != fmt.Sprintf("%x", sha256.Sum256(literal)) {
						t.Fatal(c.Name, "encoded hash differs from literal oracle", err)
					}
				}
				if len(row.Diagnostics) != len(c.DiagnosticKinds) {
					t.Fatal(c.Name, "diagnostics lost or added", row.Diagnostics)
				}
				for i, kind := range c.DiagnosticKinds {
					prefix := map[string]string{"width": "line width ", "height": "page lines ", "page": "PAGE ", "bytes": "encoded bytes ", "line_count": "LINE count ", "encoding": "encoding unavailable", "unsupported": "unsupported"}[kind]
					if prefix == "" || !strings.HasPrefix(row.Diagnostics[i], prefix) {
						t.Fatal(c.Name, "diagnostic precedence changed", row.Diagnostics)
					}
				}
			}
			for _, refusal := range vectors.Refusals {
				policy, _ := json.Marshal(profile)
				var raw map[string]any
				json.Unmarshal(policy, &raw)
				box := raw["boxes"].(map[string]any)["description"].(map[string]any)
				box["required_line_breaks"] = refusal["required_line_breaks"]
				if wrap, exists := refusal["wrap"]; exists {
					box["wrap"] = wrap
				}
				jsonFile("fit-profile.json", raw)
				var out bytes.Buffer
				if err := run(args, &out); err == nil || out.Len() != 0 {
					t.Fatal("invalid LINE-count profile admitted", refusal["name"])
				}
			}
			write("fit-registry.json", canonical)
			jsonFile("fit-profile.json", profile)
		}
		{
			// Exercise the authoring handoff; expected bytes stay independent of the fit encoder.
			flowDir := t.TempDir()
			flowELF := bytes.Clone(elf)
			clear(flowELF[0x100:0x110])
			copy(flowELF[0x100:0x110], []byte{4, 0, 0, 0xf8})
			flowSource := write(filepath.Join(flowDir, "flow-source.elf"), flowELF)
			original := []byte(`{"entries":[{"id":"0x100","en":"A","status":"drafted","opaque":{"keep":true}}],"root_extra":7}`)
			authorSource := write(filepath.Join(flowDir, "flow-registry.json"), original)
			policy := profile
			policy.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(flowELF))
			policy.Entries = map[string]FitEntry{"0x100": {Box: "description"}}
			fitProfile := jsonFile(filepath.Join(flowDir, "flow-fit.json"), policy)
			for i, c := range []struct {
				english, expectedHex string
				width                int
			}{{"B", "020000f8", 28}, {"A A", "01000000010000f8", 40}} {
				request := map[string]any{
					"operation": "registry_author", "source_size": len(original),
					"source_sha256": fmt.Sprintf("%x", sha256.Sum256(original)),
					"evidence":      "synthetic authoring handoff", "updated": "2026-10-20",
					"registry_updates": map[string]any{"0x100": map[string]string{"en": c.english}},
				}
				requestPath := jsonFile(filepath.Join(flowDir, "flow-request.json"), request)
				registryOutput := filepath.Join(flowDir, fmt.Sprintf("flow-registry-%d.json", i))
				if err := run([]string{"--source", authorSource, "--recipes", requestPath, "--apply", "--output", registryOutput}, io.Discard); err != nil {
					t.Fatal("authoring handoff registry", err)
				}
				authored, err := os.ReadFile(registryOutput)
				if err != nil {
					t.Fatal(err)
				}
				var compact bytes.Buffer
				if err := json.Compact(&compact, authored); err != nil || !bytes.Contains(compact.Bytes(), []byte(`"opaque":{"keep":true}`)) || !bytes.Contains(compact.Bytes(), []byte(`"root_extra":7`)) {
					t.Fatal("authoring handoff lost unrelated metadata", err)
				}
				var fitOutput bytes.Buffer
				if err := run([]string{"--source", flowSource, "--registry", registryOutput, "--glyphmap", glyphPath, "--fit-profile", fitProfile}, &fitOutput); err != nil {
					t.Fatal("authoring handoff fit", err)
				}
				var fitReport FitReport
				expected, err := hex.DecodeString(c.expectedHex)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(fitOutput.Bytes(), &fitReport); err != nil || len(fitReport.Entries) != 1 || fitReport.RegistrySHA256 != fmt.Sprintf("%x", sha256.Sum256(authored)) {
					t.Fatal("authoring handoff report provenance", err)
				}
				row := fitReport.Entries[0]
				if row.Status != "within_profile" || row.Width != c.width || row.EncodedHex != c.expectedHex || row.EncodedSHA256 != fmt.Sprintf("%x", sha256.Sum256(expected)) {
					t.Fatalf("authoring handoff independent encoding/fit mismatch: %+v", row)
				}
				table := Recipes{
					Operation: "stream_slot", SourceSHA256: policy.SourceSHA256, SourceSize: policy.SourceSize,
					GlyphmapSHA256: policy.GlyphmapSHA256, ISOELFOffset: "0", ELFVMADelta: "0",
					Entries: map[string]Recipe{"0x100": {ExpectedHex: hex.EncodeToString(flowELF[0x100:0x110]), EncodedSHA256: row.EncodedSHA256, Evidence: "synthetic owned16-byte slot, no native capacity claim"}},
				}
				tablePath := jsonFile(filepath.Join(flowDir, "flow-slot.json"), table)
				patchArgs := []string{"--source", flowSource, "--registry", registryOutput, "--glyphmap", glyphPath, "--recipes", tablePath}
				if err := run(patchArgs, io.Discard); err != nil {
					t.Fatal("authoring handoff dry run", err)
				}
				patchOutput := filepath.Join(flowDir, fmt.Sprintf("flow-patched-%d.elf", i))
				if err := run(append(slices.Clone(patchArgs), "--apply", "--output", patchOutput), io.Discard); err != nil {
					t.Fatal("authoring handoff apply", err)
				}
				want := bytes.Clone(flowELF)
				clear(want[0x100:0x110])
				copy(want[0x100:0x110], expected)
				got, err := os.ReadFile(patchOutput)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("authoring handoff full copy/slot containment", err)
				}
				if err := run(append(slices.Clone(patchArgs), "--apply", "--output", patchOutput), io.Discard); err == nil {
					t.Fatal("authoring handoff overwrote output")
				}
				for _, failure := range []string{"stale encoded hash", "wrong source pin"} {
					bad := table
					if failure == "stale encoded hash" {
						entry := table.Entries["0x100"]
						entry.EncodedSHA256 = strings.Repeat("0", 64)
						bad.Entries = map[string]Recipe{"0x100": entry}
					} else {
						bad.SourceSHA256 = strings.Repeat("0", 64)
					}
					jsonFile(filepath.Join(flowDir, "flow-slot.json"), bad)
					refused := filepath.Join(flowDir, "flow-refused.elf")
					if err := run(append(slices.Clone(patchArgs), "--apply", "--output", refused), io.Discard); err == nil {
						t.Fatal("authoring handoff accepted", failure)
					}
					if _, err := os.Stat(refused); !os.IsNotExist(err) {
						t.Fatal("authoring handoff published invalid copy", failure)
					}
				}
			}
			for path, want := range map[string][]byte{authorSource: original, flowSource: flowELF, sourcePath: elf, glyphPath: fitGlyphs} {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("authoring handoff changed input", path, err)
				}
			}
		}
		for _, c := range []struct {
			name, english, status string
			width                 int
			bounds                []*NumericRange
		}{
			{"new wording without target pin", "A A", "within_profile", 40, nil},
			{"no-page consumer", "A//B", "overflow", 28, nil},
			{"line ceiling", "A|B", "overflow", 28, nil},
			{"blank lines consume rows", "||||", "overflow", 0, nil},
			{"empty stream has one row", "", "within_profile", 0, nil},
			{"scale remains unknown", "<e864>A", "unsupported", 0, nil},
			{"nested string remains unknown", "{{PARAM:0xa000}}", "unsupported", 0, nil},
			{"missing glyph", "Z", "unsupported", 0, nil},
			{"bounded numeric argument", "A {{PARAM:0x7000}}", "overflow", 83, []*NumericRange{{Min: 1, Max: 10}}},
			{"unbounded numeric argument", "{{PARAM:0x7000}}", "unsupported", 0, nil},
			{"unused numeric bound", "A", "unsupported", 0, []*NumericRange{{Min: 1, Max: 10}}},
			{"invalid numeric bound", "{{PARAM:0x7000}}", "unsupported", 0, []*NumericRange{{Min: 10, Max: 1}}},
		} {
			t.Run(c.name, func(t *testing.T) {
				reg := Registry{Entries: []RegistryEntry{{ID: "0x100", EN: c.english}, {ID: "0x110", EN: "C"}}}
				jsonFile("fit-registry.json", reg)
				policy := profile
				policy.Entries = map[string]FitEntry{"0x100": {Box: "description", NumericBounds: c.bounds}}
				jsonFile("fit-profile.json", policy)
				var out bytes.Buffer
				if err := run(args, &out); err != nil {
					t.Fatal(err)
				}
				var got FitReport
				if err := json.Unmarshal(out.Bytes(), &got); err != nil || len(got.Entries) != 1 || got.Entries[0].Status != c.status || got.Entries[0].Width != c.width {
					t.Fatalf("wrong authoring result: %v %s", err, out.String())
				}
				if c.status == "unsupported" && got.Entries[0].LineWidths != nil {
					t.Fatal("unsupported semantics must not claim measured line bounds")
				}
			})
		}
		for _, c := range []struct {
			name, english, box, status string
			lines                      [][]int
			bounds                     []*NumericRange
		}{
			{"native width differs from glyph count", "A B", "description", "overflow", [][]int{{13, 28}}, nil},
			{"space counts at exact width", "A A", "dialogue", "within_profile", [][]int{{40}}, nil},
			{"wrap stays within two rows", "A A A", "dialogue", "within_profile", [][]int{{40, 13}}, nil},
			{"automatic pages", "A B C", "dialogue", "within_profile", [][]int{{13, 28}, {22}}, nil},
			{"manual line remains", "A|A", "description", "overflow", [][]int{{13, 13}}, nil},
			{"manual page remains", "A//A", "description", "overflow", [][]int{{13}, {13}}, nil},
			{"blank lines consume wrapped rows", "||||", "description", "overflow", [][]int{{0, 0, 0, 0, 0}}, nil},
			{"long word stays intact", "BBBB", "dialogue", "overflow", [][]int{{112}}, nil},
			{"paired highlight remains", "{{HL:0xb001}}A{{HL:0xb001}} A", "dialogue", "within_profile", [][]int{{40}}, nil},
			{"highlight cannot cross inserted page", "{{HL:0xb001}}A B C{{HL:0xb001}}", "dialogue", "unsupported", nil, nil},
			{"unpaired highlight remains unknown", "{{HL:0xb001}}A", "dialogue", "unsupported", nil, nil},
			{"wrapping cannot guess scale", "<e864>A", "dialogue", "unsupported", nil, nil},
			{"wrapping cannot guess substitution", "{{PARAM:0x7000}}", "dialogue", "unsupported", nil, nil},
			{"bounded count wraps", "A {{PARAM:0x7000}}", "dialogue", "within_profile", [][]int{{13, 28}}, []*NumericRange{{Min: 0, Max: 9}}},
			{"negative count stays indivisible", "A {{PARAM:0x7000}}", "description", "overflow", [][]int{{13, 50}}, []*NumericRange{{Min: -1, Max: -1}}},
			{"numeric bounds cross pages in order", "{{PARAM:0x7000}} A {{PARAM:0x7000}}", "dialogue", "within_profile", [][]int{{28, 13}, {28}}, []*NumericRange{{Min: 0, Max: 9}, {Min: 0, Max: 9}}},
			{"large count reports width overflow", "{{PARAM:0x7000}}", "dialogue", "overflow", [][]int{{252}}, []*NumericRange{{Min: 0, Max: 999999999}}},
			{"missing second numeric bound", "{{PARAM:0x7000}} {{PARAM:0x7000}}", "dialogue", "unsupported", nil, []*NumericRange{{Min: 0, Max: 9}}},
			{"unused wrapping numeric bound", "A", "dialogue", "unsupported", nil, []*NumericRange{{Min: 0, Max: 9}}},
			{"null wrapping numeric bound", "{{PARAM:0x7000}}", "dialogue", "unsupported", nil, []*NumericRange{nil}},
			{"invalid wrapping numeric domain", "{{PARAM:0x7000}}", "dialogue", "unsupported", nil, []*NumericRange{{Min: 0, Max: 1000000000}}},
		} {
			t.Run(c.name, func(t *testing.T) {
				policy := profile
				policy.Boxes = map[string]FitBox{}
				for name, box := range profile.Boxes {
					box.Wrap = true
					policy.Boxes[name] = box
				}
				policy.Entries = map[string]FitEntry{"0x100": {Box: c.box, NumericBounds: c.bounds}}
				jsonFile("fit-profile.json", policy)
				jsonFile("fit-registry.json", Registry{Entries: []RegistryEntry{{ID: "0x100", EN: c.english}}})
				var out bytes.Buffer
				if err := run(args, &out); err != nil {
					t.Fatal(err)
				}
				var got FitReport
				if err := json.Unmarshal(out.Bytes(), &got); err != nil || len(got.Entries) != 1 || got.Entries[0].Status != c.status || !reflect.DeepEqual(got.Entries[0].LineWidths, c.lines) || !got.Boxes[c.box].Wrap {
					t.Fatalf("wrong native wrap: %v %s", err, out.String())
				}
				if c.status != "unsupported" {
					encoded, err := hex.DecodeString(got.Entries[0].EncodedHex)
					if err != nil {
						t.Fatal(err)
					}
					// Formatting may replace spaces with boundaries, never change glyph/control order.
					literal, err := encode(c.english, nil, map[rune]uint16{' ': 0, 'A': 1, 'B': 2, 'C': 3}, TextEncodeOptions{Terminated: true})
					if err != nil {
						t.Fatal(err)
					}
					var sequences [2][]uint16
					for i, data := range [][]byte{literal, encoded} {
						for at := 0; at < len(data); at += 2 {
							word := binary.LittleEndian.Uint16(data[at:])
							if word != 0 && word != 0x0800 && word != 0x1000 {
								sequences[i] = append(sequences[i], word)
							}
						}
					}
					if !slices.Equal(sequences[0], sequences[1]) {
						t.Fatal("native wrapping changed glyph or control order")
					}
				}
			})
		}
		for _, wrap := range []bool{false, true} {
			for _, text := range []string{"A//||||", "||||//A", "||||A"} {
				policy := profile
				box := profile.Boxes["dialogue"]
				box.Wrap = wrap
				policy.Boxes = map[string]FitBox{"dialogue": box}
				policy.Entries = map[string]FitEntry{"0x100": {Box: "dialogue"}}
				jsonFile("fit-profile.json", policy)
				jsonFile("fit-registry.json", Registry{Entries: []RegistryEntry{{ID: "0x100", EN: text}}})
				var out bytes.Buffer
				if err := run(args, &out); err != nil {
					t.Fatal(err)
				}
				var got FitReport
				wantStatus, wantLines := "overflow", 5
				if wrap {
					// This consumer permits automatic pagination, including explicit line blocks.
					wantStatus, wantLines = "within_profile", 2
				}
				if err := json.Unmarshal(out.Bytes(), &got); err != nil || len(got.Entries) != 1 || got.Entries[0].Status != wantStatus || got.Entries[0].Lines != wantLines {
					t.Fatalf("blank-page height admitted (wrap=%v, text=%q): %v %s", wrap, text, err, out.String())
				}
				for _, page := range got.Entries[0].LineWidths {
					if len(page) > got.Entries[0].Lines {
						t.Fatal("height summary omits blank lines")
					}
				}
			}
		}
		write("fit-registry.json", canonical)
		jsonFile("fit-profile.json", profile)
		for _, c := range []struct {
			name, source, en, expected string
			wrap                       bool
		}{
			{"ordinary measurable", "0028040000f8", "A", "0028010000f8", false},
			{"paired measurable", "002801b0040008b000f8", "{{HL:0xb001}}A{{HL:0xb008}}", "002801b0010008b000f8", false},
			{"body setup unknown fit", "002804000140040000f8", "A{{STATE:0x4001}}B", "002801000140020000f8", false},
			{"opaque unknown fit", "0028040000b0111100f800102222040000f8", "A{{PARAM:0xb000}}B", "0028010000b0111100f800102222020000f8", false},
			{"scale unknown fit", "32e80028040000f8", "{{INIT:0xe832}}A", "32e80028010000f8", false},
			{"physical source tail", "0028040000f80000", "A", "", false},
			{"opaque native wrap", "0028040000b0111100f800102222040000f8", "A{{PARAM:0xb000}}B", "", true},
		} {
			for _, offset := range []int{0, 6} {
				data := bytes.Clone(elf)
				stream, err := hex.DecodeString(c.source)
				if err != nil {
					t.Fatal(err)
				}
				start := 0x100 + offset
				copy(data[start:], stream)
				policy := profile
				policy.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
				policy.Entries = map[string]FitEntry{"0x100": {Box: "description", Authoring: "ordered", Source: &AddressRange{Start: fmt.Sprintf("0x%x", start), End: fmt.Sprintf("0x%x", start+len(stream))}}}
				policy.Boxes = map[string]FitBox{"description": profile.Boxes["description"]}
				box := policy.Boxes["description"]
				box.Wrap = c.wrap
				policy.Boxes["description"] = box
				write("fit-font.elf", data)
				jsonFile("fit-profile.json", policy)
				jsonFile("fit-registry.json", Registry{Entries: []RegistryEntry{{ID: "0x100", EN: c.en}}})
				var out bytes.Buffer
				var got FitReport
				if err := run(args, &out); err != nil || json.Unmarshal(out.Bytes(), &got) != nil || len(got.Entries) != 1 {
					t.Fatal("ordered source fit caller", c.name, offset, err, out.String())
				}
				row := got.Entries[0]
				measurable := c.name == "ordinary measurable" || c.name == "paired measurable"
				if row.EncodedHex != c.expected || measurable && (row.Status != "within_profile" || row.Width != 13) || !measurable && (row.Status != "unsupported" || len(row.Diagnostics) == 0) {
					t.Fatal("ordered source serialization/measurement distinction", c.name, offset, row)
				}
				preserved, err := os.ReadFile(sourcePath)
				if err != nil || !bytes.Equal(data, preserved) {
					t.Fatal("ordered fit changed source", c.name, err)
				}
			}
		}
		write("fit-font.elf", elf)
		write("fit-registry.json", canonical)
		jsonFile("fit-profile.json", profile)
		for _, extra := range [][]string{{"--apply"}, {"--output", filepath.Join(dir, "fit-created.iso")}, {"--apply", "--output", sourcePath}, {"--recipes", profilePath}, {"unexpected"}} {
			var out bytes.Buffer
			if err := run(append(append([]string{}, args...), extra...), &out); err == nil || out.Len() != 0 {
				t.Fatalf("unsafe fit flag combination admitted: %v", extra)
			}
		}
		if _, err := os.Stat(filepath.Join(dir, "fit-created.iso")); !os.IsNotExist(err) {
			t.Fatal("fit mode created output")
		}
		for _, change := range []string{"source pin", "glyph pin", "missing ID", "normalized duplicate ID", "missing box", "invalid geometry", "character budgets", "font bounds", "space instruction", "named file absent", "missing source range", "missing source policy", "unknown source policy", "odd source range", "empty source range", "oversized source range", "outside source ELF"} {
			t.Run(change, func(t *testing.T) {
				data, _ := json.Marshal(profile)
				var bad FitProfile
				json.Unmarshal(data, &bad)
				switch change {
				case "source pin":
					bad.SourceSHA256 = strings.Repeat("0", 64)
				case "glyph pin":
					bad.GlyphmapSHA256 = strings.Repeat("0", 64)
				case "missing ID":
					bad.Entries["0x999"] = FitEntry{Box: "dialogue"}
				case "normalized duplicate ID":
					bad.Entries["0X0100"] = FitEntry{Box: "dialogue"}
				case "missing box":
					bad.Entries["0x100"] = FitEntry{Box: "absent"}
				case "invalid geometry":
					box := bad.Boxes["description"]
					box.MaxWidth = 0
					bad.Boxes["description"] = box
				case "character budgets":
					bad.Font.Columns = 22
				case "font bounds":
					bad.Font.FontTableVMA = "0xfffffffc"
				case "space instruction":
					bad.Font.SpaceWords["0x50"] = "0x3c0241c0"
				case "named file absent":
					bad.ISOFile = "missing.elf"
				case "missing source range", "missing source policy", "unknown source policy", "odd source range", "empty source range", "oversized source range", "outside source ELF":
					entry := bad.Entries["0x100"]
					entry.Authoring, entry.Source = "ordered", &AddressRange{Start: "0x100", End: "0x106"}
					switch change {
					case "missing source range":
						entry.Source = nil
					case "missing source policy":
						entry.Authoring = ""
					case "unknown source policy":
						entry.Authoring = "automatic"
					case "odd source range":
						entry.Source.Start = "0x101"
					case "empty source range":
						entry.Source.End = entry.Source.Start
					case "oversized source range":
						entry.Source.End = "0x2102"
					case "outside source ELF":
						entry.Source = &AddressRange{Start: fmt.Sprintf("0x%x", len(elf)), End: fmt.Sprintf("0x%x", len(elf)+2)}
					}
					bad.Entries["0x100"] = entry
				}
				jsonFile("fit-profile.json", bad)
				var out bytes.Buffer
				if err := run(args, &out); err == nil || out.Len() != 0 {
					t.Fatalf("invalid fit profile admitted: %s", change)
				}
			})
		}
		jsonFile("fit-profile.json", profile)
		validProfile, _ := os.ReadFile(profilePath)
		for _, ambiguous := range []string{
			`{"boxes":{"menu":{"required_line_breaks":0,"required_line_breaks":1}}}`,
			`{"boxes":{"menu":{"REQUIRED_LINE_BREAKS":1}}}`,
			`{"boxes":{"menu":{"required_line_breakſ":1}}}`,
			`{"source_size":12,"source_size":24}`,
		} {
			write("fit-profile.json", []byte(ambiguous))
			var out bytes.Buffer
			if err := run(args, &out); err == nil || out.Len() != 0 || !strings.Contains(err.Error(), "object key") {
				t.Fatal("ambiguous fit profile was not refused at JSON boundary", err)
			}
		}
		for _, bad := range [][]byte{[]byte(`{"output_sha256":"forbidden"}`), []byte(`null`), append(bytes.Clone(validProfile), []byte(` {}`)...)} {
			write("fit-profile.json", bad)
			if err := run(args, io.Discard); err == nil {
				t.Fatal("malformed or patch-shaped fit profile admitted")
			}
		}
		write("fit-profile.json", validProfile)
		for _, bad := range [][]byte{[]byte(`{"entries":[{"id":"100","en":"A"},{"id":"0X0100","en":"B"}]}`), []byte(`{"entries":null}`)} {
			write("fit-registry.json", bad)
			if err := run(args, io.Discard); err == nil {
				t.Fatal("ambiguous registry admitted")
			}
		}
		write("fit-registry.json", canonical)
		for path, expected := range map[string][]byte{sourcePath: elf, registryPath: canonical, glyphPath: fitGlyphs, profilePath: validProfile} {
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, expected) {
				t.Fatalf("fit changed input %s: %v", path, err)
			}
		}
		fontOnly := Recipes{Operation: "font_metrics", SourceSize: int64(len(elf)), ELFVMADelta: "0", Layout: &profile.Font}
		if _, err := inspect(bytes.NewReader(elf), []Edit{{ID: "0", Old: []byte{0, 0}, New: []byte{1, 0}}}, &fontOnly); err == nil {
			t.Fatal("font inspection admitted edit readiness")
		}
		if _, err := plan([]Recipes{fontOnly}, registry, fitGlyphs, bytes.NewReader(elf)); err == nil {
			t.Fatal("font inspection entered patch planning")
		}
		for _, path := range []string{sourcePath, registryPath, glyphPath, profilePath} {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
	})

	{
		original := []byte(`{"entries":[{"id":"0X0010","jp":"名前","en":"<Name>","status":"drafted","note":{"large":123456789012345678901234567890}},{"id":"20","unknown":[true,null]}],"last_updated":"2000-01-01","root_extra":{"decimal":1.2300e+45}}`)
		profile := Recipes{Operation: "registry_merge", SourceSize: int64(len(original)), SourceSHA256: fmt.Sprintf("%x", sha256.Sum256(original)), Evidence: "synthetic machine merge", Updated: "2026-10-17", RegistryUpdates: map[string]map[string]json.RawMessage{"10": {"status": json.RawMessage(`"patched"`), "patch_ref": json.RawMessage(`"reviewed"`)}}}
		sourcePath := write("registry-source.json", original)
		profilePath := jsonFile("registry-updates.json", profile)
		registryArgs := []string{"--source", sourcePath, "--recipes", profilePath}
		var preview bytes.Buffer
		before, _ := os.ReadDir(dir)
		if err := run(registryArgs, &preview); err != nil {
			t.Fatal(err)
		}
		after, _ := os.ReadDir(dir)
		if len(before) != len(after) || !strings.Contains(preview.String(), `"applied": false`) {
			t.Fatal("registry preview wrote files or omitted intent")
		}
		output := filepath.Join(dir, "registry-merged.json")
		applyArgs := append(append([]string{}, registryArgs...), "--apply", "--output", output)
		if err := run(applyArgs, io.Discard); err != nil {
			t.Fatal(err)
		}
		merged, err := os.ReadFile(output)
		if err != nil || bytes.Equal(merged, original) || merged[len(merged)-1] != '\n' {
			t.Fatalf("registry output missing or unchanged: %v", err)
		}
		if info, err := os.Stat(output); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatal("registry output permissions changed", err)
		}
		for _, refused := range []string{dir, filepath.Join(sourcePath, "child"), filepath.Join(dir, "missing", "child")} {
			var out bytes.Buffer
			if err := run(append(slices.Clone(registryArgs), "--apply", "--output", refused), &out); err == nil || out.Len() != 0 {
				t.Fatalf("unsafe registry publication admitted: %s", refused)
			}
		}
		var got struct {
			Entries []struct {
				ID, JP, EN, Status string
			} `json:"entries"`
			Updated string `json:"last_updated"`
		}
		if err := json.Unmarshal(merged, &got); err != nil || len(got.Entries) != 2 || got.Entries[0].ID != "0X0010" || got.Entries[0].JP != "名前" || got.Entries[0].EN != "<Name>" || got.Entries[0].Status != "patched" || got.Updated != profile.Updated {
			t.Fatalf("registry merge changed human/ID data: %v", err)
		}
		for _, literal := range []string{"123456789012345678901234567890", "1.2300e+45", `"patch_ref": "reviewed"`, `"unknown": [`, `"en": "<Name>"`} {
			if !bytes.Contains(merged, []byte(literal)) {
				t.Fatalf("registry merge lost opaque value %s", literal)
			}
		}
		var actual, expected map[string]any
		if err := json.Unmarshal(original, &expected); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(merged, &actual); err != nil {
			t.Fatal(err)
		}
		expected["last_updated"] = profile.Updated
		expectedEntry := expected["entries"].([]any)[0].(map[string]any)
		expectedEntry["status"], expectedEntry["patch_ref"] = "patched", "reviewed"
		actualJSON, _ := json.Marshal(actual)
		expectedJSON, _ := json.Marshal(expected)
		if !bytes.Equal(actualJSON, expectedJSON) {
			t.Fatal("registry merge changed fields beyond its declared updates/date")
		}
		for _, refused := range []string{output, sourcePath} {
			if err := run(append(append([]string{}, registryArgs...), "--apply", "--output", refused), io.Discard); err == nil {
				t.Fatal("registry merge overwrote an existing file")
			}
		}
		linked := filepath.Join(dir, "registry-symlink.json")
		if err := os.Symlink(sourcePath, linked); err != nil {
			t.Fatal(err)
		}
		if err := run(append(append([]string{}, registryArgs...), "--apply", "--output", linked), io.Discard); err == nil {
			t.Fatal("registry merge followed output symlink")
		}
		preserved, err := os.ReadFile(sourcePath)
		if err != nil || !bytes.Equal(preserved, original) {
			t.Fatal("registry merge changed source")
		}
		// Whitespace removal exercises shrinking; the normal input above grows.
		padded := append(bytes.Clone(original), bytes.Repeat([]byte(" "), 2048)...)
		profile.SourceSize, profile.SourceSHA256 = int64(len(padded)), fmt.Sprintf("%x", sha256.Sum256(padded))
		write("registry-source.json", padded)
		jsonFile("registry-updates.json", profile)
		shrunkenPath := filepath.Join(dir, "registry-shrunken.json")
		if err := run(append(append([]string{}, registryArgs...), "--apply", "--output", shrunkenPath), io.Discard); err != nil {
			t.Fatal(err)
		}
		shrunken, err := os.ReadFile(shrunkenPath)
		if err != nil || !bytes.Equal(shrunken, merged) {
			t.Fatal("registry encoding depends on input whitespace or retained old tail")
		}
		for _, field := range []string{"ref_type", "ref_sites", "preamble_words", "inline_codes", "jp_capacity_u16", "landing_vma", "landing_zone_id", "patch_ref", "discovered_by"} {
			profile.RegistryUpdates["10"][field] = json.RawMessage(`{"opaque":[true,null,123456789012345678901234567890]}`)
		}
		jsonFile("registry-updates.json", profile)
		opaqueOutput := filepath.Join(dir, "registry-opaque.json")
		if err := run(append(append([]string{}, registryArgs...), "--apply", "--output", opaqueOutput), io.Discard); err != nil {
			t.Fatal(err)
		}
		opaqueData, err := os.ReadFile(opaqueOutput)
		if err != nil || bytes.Count(opaqueData, []byte(`"opaque"`)) != 9 || bytes.Count(opaqueData, []byte("123456789012345678901234567890")) != 10 {
			t.Fatal("registry merge rejected or changed opaque machine values")
		}
		for _, old := range []string{`"drafted"`, `"zone_pending"`, `"patched"`, `"decode_verified"`, `"emulator_confirmed"`, `"unexpected"`, `null`} {
			for _, status := range []string{`"drafted"`, `"zone_pending"`, `"patched"`, `"decode_verified"`, `"emulator_confirmed"`, `"unexpected"`, `null`, `[]`, `1`} {
				data := []byte(`{"entries":[{"id":"10","status":` + old + `}]}`)
				profile.SourceSize, profile.SourceSHA256 = int64(len(data)), fmt.Sprintf("%x", sha256.Sum256(data))
				profile.RegistryUpdates = map[string]map[string]json.RawMessage{"0x0010": {"status": json.RawMessage(status)}}
				write("registry-source.json", data)
				jsonFile("registry-updates.json", profile)
				ranks := []string{`"drafted"`, `"zone_pending"`, `"patched"`, `"decode_verified"`, `"emulator_confirmed"`}
				accepted := slices.Index(ranks, status) >= 0 && slices.Index(ranks, status) >= slices.Index(ranks, old)
				if err := run(registryArgs, io.Discard); (err == nil) != accepted {
					t.Fatalf("registry status %s -> %s: %v", old, status, err)
				}
			}
		}
		for _, raw := range []string{
			`{"entries":[{"id":"10","\ud83d\ude00":"entry emoji"}],"\ud800\udc00":"minimum pair","\udbff\udfff":"maximum pair"}`,
			`{"entries":[{"id":"10","�":"entry replacement"}],"\ufffd":"escaped replacement","ordinary":"keep"}`,
			`{"entries":[{"id":"10","\\ud800":"literal escape"}],"slash\/key":"keep","quote\"key":"keep"}`,
			`{"entries":[{"id":"10","opaque":"\ud800"}],"nested":{"safe":"\ud801"},"text":"\"\\ud800\": not a key"}`,
			`{"entries":[{"id":"10","\uD83D\uDE00":"upper pair"}],"nested":{"\uDBFF\uDFFF":"keep"}}`,
			`{"entr\u0069es":[{"id":"10","nested_surrogate":{"\ud800":"entry-a","\ud801":"entry-b"}}],"nested":{"\ud800":"root-a","\ud801":"root-b"}}`,
			`{"unknown":[{"\ud800":"before"}],"entries":[{"id":"10"}],"after":[{"\ud801":"after"}]}`,
		} {
			profile.SourceSize, profile.SourceSHA256 = int64(len(raw)), fmt.Sprintf("%x", sha256.Sum256([]byte(raw)))
			profile.RegistryUpdates = map[string]map[string]json.RawMessage{"10": {"patch_ref": json.RawMessage(`"guarded"`)}}
			write("registry-source.json", []byte(raw))
			jsonFile("registry-updates.json", profile)
			validOutput := filepath.Join(dir, "registry-valid-key.json")
			if err := run(append(append([]string{}, registryArgs...), "--apply", "--output", validOutput), io.Discard); err != nil {
				t.Fatalf("refused valid registry keys/opaque values %q: %v", raw, err)
			}
			encoded, err := os.ReadFile(validOutput)
			if err != nil {
				t.Fatal(err)
			}
			var actual, expected map[string]any
			if err := json.Unmarshal([]byte(raw), &expected); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(encoded, &actual); err != nil {
				t.Fatal(err)
			}
			expected["last_updated"] = profile.Updated
			expected["entries"].([]any)[0].(map[string]any)["patch_ref"] = "guarded"
			actualJSON, _ := json.Marshal(actual)
			expectedJSON, _ := json.Marshal(expected)
			if !bytes.Equal(actualJSON, expectedJSON) {
				t.Fatalf("valid Unicode-key merge changed undeclared values: %s", encoded)
			}
			if bytes.Count(encoded, []byte(`"\ud800"`)) != strings.Count(raw, `"\ud800"`) || bytes.Count(encoded, []byte(`"\ud801"`)) != strings.Count(raw, `"\ud801"`) {
				t.Fatal("key validation changed opaque surrogate keys/values")
			}
			preserved, err := os.ReadFile(sourcePath)
			if err != nil || !bytes.Equal(preserved, []byte(raw)) {
				t.Fatal("key validation changed source")
			}
			if err := os.Remove(validOutput); err != nil {
				t.Fatal(err)
			}
		}
		for _, raw := range []string{`{"entries":[],"entries":[{"id":"10"}]}`, `{"entries":[{"id":"10","note":1,"note":2}]}`, `null`, `{}`, `[]`, `{`, `{"entries":null}`, `{"entries":[null]}`, `{"entries":[{"id":"oops"}]}`, `{"entries":[{"id":"100000000"}]}`, `{"entries":[{"id":"10"},{"id":"0X0010"}]}`, "{\"entries\":[]}\xff", `{"entries":[{"id":"10"}],"\ud800":"keep-a","\ud801":"keep-b"}`, `{"entries":[{"id":"10","\ud800":"keep-a","\ud801":"keep-b"}]}`, `{"entries":[{"id":"10"}],"\udc00":1}`, `{"entries":[{"id":"10"}],"\ud800\u0041":1}`, `{"entries":[{"id":"10"}],"\ud800\ud800":1}`, `{"entries":[{"id":"10"}],"\uDBFF":1}`, `{"entr\u0069es":[{"id":"10","\uDC00":"keep-a"}]}`} {
			profile.SourceSize, profile.SourceSHA256 = int64(len(raw)), fmt.Sprintf("%x", sha256.Sum256([]byte(raw)))
			profile.RegistryUpdates = map[string]map[string]json.RawMessage{"10": {"patch_ref": json.RawMessage(`null`)}}
			write("registry-source.json", []byte(raw))
			jsonFile("registry-updates.json", profile)
			refused := filepath.Join(dir, "registry-refused.json")
			if err := run(append(append([]string{}, registryArgs...), "--apply", "--output", refused), io.Discard); err == nil {
				t.Fatalf("accepted malformed registry %q", raw)
			}
			if _, err := os.Stat(refused); !os.IsNotExist(err) {
				t.Fatal("created output for malformed registry")
			}
		}
		for _, invalid := range []string{"human field", "unknown field", "metadata-only field", "missing ID", "duplicate updates", "null updates", "date", "hash", "evidence", "image fields", "source context", "image arguments", "mixed tables"} {
			profile = Recipes{Operation: "registry_merge", SourceSize: int64(len(original)), SourceSHA256: fmt.Sprintf("%x", sha256.Sum256(original)), Evidence: "synthetic machine merge", Updated: "2026-10-17", RegistryUpdates: map[string]map[string]json.RawMessage{"10": {"patch_ref": json.RawMessage(`null`)}}}
			args := append([]string{}, registryArgs...)
			switch invalid {
			case "human field":
				profile.RegistryUpdates["10"]["en"] = json.RawMessage(`"overwrite"`)
			case "unknown field":
				profile.RegistryUpdates["10"]["unknown"] = json.RawMessage(`true`)
			case "metadata-only field":
				profile.RegistryUpdates["10"]["midcontent_markup_shape"] = json.RawMessage(`true`)
			case "missing ID":
				profile.RegistryUpdates["99"] = profile.RegistryUpdates["10"]
			case "duplicate updates":
				profile.RegistryUpdates["0X0010"] = profile.RegistryUpdates["10"]
			case "null updates":
				profile.RegistryUpdates["10"] = nil
			case "date":
				profile.Updated = "2026-02-30"
			case "hash":
				profile.SourceSHA256 = strings.Repeat("0", 64)
			case "evidence":
				profile.Evidence = ""
			case "source context":
				profile.SourceContext = true
			case "image fields":
				profile.ISOELFOffset = "0x100"
			case "image arguments":
				args = append(args, "--registry", sourcePath)
			case "mixed tables":
				mixed := filepath.Join(dir, "registry-mixed")
				if err := os.Mkdir(mixed, 0700); err != nil {
					t.Fatal(err)
				}
				jsonFile("registry-mixed/a.json", profile)
				jsonFile("registry-mixed/b.json", r)
				args[3] = mixed
			}
			write("registry-source.json", original)
			jsonFile("registry-updates.json", profile)
			refused := filepath.Join(dir, "registry-refused.json")
			if err := run(append(args, "--apply", "--output", refused), io.Discard); err == nil {
				t.Fatalf("accepted invalid registry profile: %s", invalid)
			}
			if _, err := os.Stat(refused); !os.IsNotExist(err) {
				t.Fatal("created output for invalid registry profile")
			}
		}
		for _, limit := range []int64{0, 64<<20 + 1} {
			file, err := os.OpenFile(sourcePath, os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				t.Fatal(err)
			}
			truncateErr, closeErr := file.Truncate(limit), file.Close()
			if truncateErr != nil || closeErr != nil {
				t.Fatalf("prepare bounded registry source: %v %v", truncateErr, closeErr)
			}
			profile.SourceSize, profile.Evidence = limit, "bounded source"
			jsonFile("registry-updates.json", profile)
			if err := run(registryArgs, io.Discard); err == nil || !strings.Contains(err.Error(), "64 MiB") {
				t.Fatalf("accepted unbounded registry source %d: %v", limit, err)
			}
		}
		for _, useDate := range []bool{false, true} {
			imageProfile := r
			if useDate {
				imageProfile.Updated = "2026-10-17"
			} else {
				imageProfile.RegistryUpdates = map[string]map[string]json.RawMessage{}
			}
			if _, err := plan([]Recipes{imageProfile}, registry, glyphs, bytes.NewReader(sourceImage)); err == nil {
				t.Fatal("image planner accepted registry metadata")
			}
		}

		{
			importDir := t.TempDir()
			type jsonComparison struct {
				label            string
				actual, expected []byte
			}
			var completeComparisons []jsonComparison
			var fixtures struct {
				Glyphmap map[string]string
				Cases    []struct {
					Name, Policy, Source string
					DiscoveredBy         string            `json:"discovered_by"`
					MarkerOrders         string            `json:"marker_orders"`
					Glyphmap             map[string]string `json:"-"`
					Batches              []struct{ Name, Data string }
					ExpectedRows         json.RawMessage `json:"expected_rows"`
					Refuse               bool            `json:"expect_refuse"`
					Unchanged            bool            `json:"unchanged_source"`
					RawNumbers           []string        `json:"raw_number_literals"`
				}
			}
			data, err := os.ReadFile("testdata/registry-import.json")
			if err != nil || json.Unmarshal(data, &fixtures) != nil || len(fixtures.Cases) != 50 {
				t.Fatal("independent registry import fixtures", err)
			}
			glyphData, err := json.Marshal(fixtures.Glyphmap)
			if err != nil {
				t.Fatal(err)
			}
			glyphPath := write(filepath.Join(importDir, "import-glyphs.json"), glyphData)
			fullSweepFixtures := fixtures
			fullSweepFixtures.Glyphmap, fullSweepFixtures.Cases = nil, nil
			fullSweepData, err := os.ReadFile("testdata/registry-full-sweep.json")
			if err != nil || json.Unmarshal(fullSweepData, &fullSweepFixtures) != nil || len(fullSweepFixtures.Cases) != 55 {
				t.Fatal("independent full-sweep fixtures", err)
			}
			for _, c := range fullSweepFixtures.Cases {
				c.Glyphmap = fullSweepFixtures.Glyphmap
				fixtures.Cases = append(fixtures.Cases, c)
			}
			accepted, refused := 0, 0
			for _, c := range fixtures.Cases {
				caseGlyphData, caseGlyphPath := glyphData, glyphPath
				if c.Glyphmap != nil {
					caseGlyphData, err = json.Marshal(c.Glyphmap)
					if err != nil {
						t.Fatal(err)
					}
					caseGlyphPath = write(filepath.Join(importDir, "import-"+c.Name+"-glyphs.json"), caseGlyphData)
				}
				source := []byte(c.Source)
				sourcePath := write(filepath.Join(importDir, "import-"+c.Name+"-source.json"), source)
				inputs := map[string]RegistryInput{"glyphs": {Path: caseGlyphPath, Size: int64(len(caseGlyphData)), SHA256: fmt.Sprintf("%x", sha256.Sum256(caseGlyphData))}}
				originals := map[string][]byte{sourcePath: source, caseGlyphPath: caseGlyphData}
				declaration := map[string]any{"policy": c.Policy, "glyphmap": "glyphs"}
				batchNames := []string{}
				for i, batch := range c.Batches {
					name := fmt.Sprintf("batch%d", i)
					body := []byte(batch.Data)
					path := write(filepath.Join(importDir, "import-"+c.Name+"-"+name+".data"), body)
					inputs[name] = RegistryInput{Path: path, Size: int64(len(body)), SHA256: fmt.Sprintf("%x", sha256.Sum256(body))}
					originals[path] = body
					batchNames = append(batchNames, name)
				}
				declaration["batches"] = batchNames
				if c.Policy == "csv_drafts" {
					declaration["discovered_by"] = c.DiscoveredBy
				}
				if c.MarkerOrders != "" {
					body := []byte(c.MarkerOrders)
					path := write(filepath.Join(importDir, "import-"+c.Name+"-orders.json"), body)
					inputs["orders"] = RegistryInput{Path: path, Size: int64(len(body)), SHA256: fmt.Sprintf("%x", sha256.Sum256(body))}
					originals[path] = body
					declaration["marker_orders"] = "orders"
				}
				request := map[string]any{"operation": "registry_add", "source_size": len(source), "source_sha256": fmt.Sprintf("%x", sha256.Sum256(source)), "evidence": "Independent original import contracts and declared strict wire boundaries", "updated": "2026-11-05", "registry_import": declaration, "registry_inputs": inputs}
				profilePath := jsonFile(filepath.Join(importDir, "import-"+c.Name+"-profile.json"), request)
				profileData, err := os.ReadFile(profilePath)
				if err != nil {
					t.Fatal(err)
				}
				originals[profilePath] = profileData
				args := []string{"--source", sourcePath, "--recipes", profilePath}
				output := filepath.Join(importDir, "import-"+c.Name+"-out.json")
				var preview bytes.Buffer
				err = run(args, &preview)
				if c.Refuse {
					refused++
					if err == nil || preview.Len() != 0 {
						t.Fatal("import accepted refusal", c.Name, err, preview.String())
					}
					if err := run(append(slices.Clone(args), "--apply", "--output", output), io.Discard); err == nil {
						t.Fatal("import applied refused cohort", c.Name)
					}
					if _, err := os.Stat(output); !os.IsNotExist(err) {
						t.Fatal("import refusal published output", c.Name, err)
					}
				} else {
					accepted++
					if err != nil {
						t.Fatal("import refused admission", c.Name, err)
					}
					if _, err := os.Stat(output); !os.IsNotExist(err) {
						t.Fatal("import preview wrote output", c.Name, err)
					}
					var report struct {
						Operation string
						Import    struct {
							Policy  string
							Records int
							Limits  string
						}
						Limits string
					}
					if json.Unmarshal(preview.Bytes(), &report) != nil || report.Operation != "registry_add" || report.Import.Policy != c.Policy || !strings.Contains(report.Limits, "draft") || !strings.Contains(report.Import.Limits, "not byte-source") {
						t.Fatal("import misrepresented draft admission", c.Name, preview.String())
					}
					var applied bytes.Buffer
					if err := run(append(slices.Clone(args), "--apply", "--output", output), &applied); err != nil {
						t.Fatal("import apply", c.Name, err)
					}
					written, err := os.ReadFile(output)
					if err != nil {
						t.Fatal(err)
					}
					if c.Unchanged && !bytes.Equal(written, source) {
						t.Fatal("all-present import changed source bytes/date", c.Name)
					}
					for _, literal := range c.RawNumbers {
						if !bytes.Contains(written, []byte(literal)) {
							t.Fatal("import changed numeric lexeme", c.Name, literal)
						}
					}
					var document map[string]json.RawMessage
					if json.Unmarshal(written, &document) != nil {
						t.Fatal("import output JSON", c.Name)
					}
					completeComparisons = append(completeComparisons, jsonComparison{c.Name, document["entries"], c.ExpectedRows})
					if !c.Unchanged && string(document["last_updated"]) != `"2026-11-05"` {
						t.Fatal("import date not declared", c.Name, string(document["last_updated"]))
					}
					if err := run(append(slices.Clone(args), "--apply", "--output", output), io.Discard); err == nil {
						t.Fatal("import overwrote existing output", c.Name)
					}
					after, err := os.ReadFile(output)
					if err != nil || !bytes.Equal(after, written) {
						t.Fatal("exclusive import retry changed output", c.Name, err)
					}
				}
				for path, want := range originals {
					got, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(got, want) {
						t.Fatal("import changed input", c.Name, path, err)
					}
				}
			}
			if accepted != 32 || refused != 73 {
				t.Fatal("independent import cohort changed", accepted, refused)
			}
			var paired struct {
				Cases []struct {
					Name, Updated     string
					Registry          string `json:"registry_source"`
					Glossary          string `json:"glossary_source"`
					Corrections       string
					Proposals         string                                   `json:"glossary_proposals"`
					Refuse            bool                                     `json:"expect_refuse"`
					ExpectedRegistry  json.RawMessage                          `json:"expected_registry"`
					ExpectedGlossary  json.RawMessage                          `json:"expected_glossary"`
					RegistryUnchanged bool                                     `json:"registry_unchanged"`
					GlossaryUnchanged bool                                     `json:"glossary_unchanged"`
					RegistryBytes     string                                   `json:"expected_registry_bytes"`
					GlossaryBytes     string                                   `json:"expected_glossary_bytes"`
					RegistryLexemes   []string                                 `json:"registry_raw_lexemes"`
					GlossaryLexemes   []string                                 `json:"glossary_raw_lexemes"`
					Outcomes          struct{ Corrections, Glossary []string } `json:"expected_outcomes"`
					ApplyOutcomes     struct{ Corrections, Glossary []string } `json:"expected_apply_outcomes"`
				}
			}
			pairData, err := os.ReadFile("testdata/registry-paired.json")
			if err != nil || json.Unmarshal(pairData, &paired) != nil || len(paired.Cases) != 50 {
				t.Fatal("independent paired fixtures", err)
			}
			pairAccepted, pairRefused := 0, 0
			for _, c := range paired.Cases {
				source := []byte(c.Registry)
				sourcePath := write(filepath.Join(importDir, "paired-"+c.Name+"-source.json"), source)
				inputs := map[string]RegistryInput{}
				originals := map[string][]byte{sourcePath: source}
				for name, text := range map[string]string{"glossary": c.Glossary, "corrections": c.Corrections, "glossary_proposals": c.Proposals} {
					body := []byte(text)
					path := write(filepath.Join(importDir, "paired-"+c.Name+"-"+name+".json"), body)
					inputs[name] = RegistryInput{Path: path, Size: int64(len(body)), SHA256: fmt.Sprintf("%x", sha256.Sum256(body))}
					originals[path] = body
				}
				request := map[string]any{"operation": "registry_reconcile", "source_size": len(source), "source_sha256": fmt.Sprintf("%x", sha256.Sum256(source)), "evidence": "Independent frozen paired member contracts", "updated": c.Updated, "registry_inputs": inputs}
				profilePath := jsonFile(filepath.Join(importDir, "paired-"+c.Name+"-profile.json"), request)
				originals[profilePath], err = os.ReadFile(profilePath)
				if err != nil {
					t.Fatal(err)
				}
				args := []string{"--source", sourcePath, "--recipes", profilePath}
				output := filepath.Join(importDir, "paired-"+c.Name+"-out.zip")
				var previewHash string
				for _, apply := range []bool{false, true} {
					call := slices.Clone(args)
					if apply {
						call = append(call, "--apply", "--output", output)
					}
					var report bytes.Buffer
					err := run(call, &report)
					if c.Refuse {
						if err == nil || report.Len() != 0 {
							t.Fatal("paired refusal admitted", c.Name, apply, err, report.String())
						}
					} else {
						var summary struct {
							Hash                  string `json:"output_sha256"`
							Corrections, Glossary []struct{ Outcome string }
							Members               []struct{ Name string }
						}
						if err != nil || json.Unmarshal(report.Bytes(), &summary) != nil || len(summary.Members) != 2 || summary.Members[0].Name != "registry.json" || summary.Members[1].Name != "glossary.json" {
							t.Fatal("paired report", c.Name, apply, err, report.String())
						}
						want := c.Outcomes
						if apply {
							want = c.ApplyOutcomes
						}
						for kind, rows := range map[string][]struct{ Outcome string }{"corrections": summary.Corrections, "glossary": summary.Glossary} {
							expected := want.Corrections
							if kind == "glossary" {
								expected = want.Glossary
							}
							if len(rows) != len(expected) {
								t.Fatal("paired outcome count", c.Name, kind)
							}
							for i, row := range rows {
								if row.Outcome != expected[i] {
									t.Fatal("paired outcome order", c.Name, kind, i, row, expected)
								}
							}
						}
						if apply && summary.Hash != previewHash {
							t.Fatal("paired preview/apply hash differs", c.Name)
						}
						previewHash = summary.Hash
					}
					if !apply || c.Refuse {
						if _, err := os.Stat(output); !os.IsNotExist(err) {
							t.Fatal("paired preview/refusal published", c.Name, apply, err)
						}
					}
				}
				if c.Refuse {
					pairRefused++
				} else {
					pairAccepted++
					bundle, err := os.ReadFile(output)
					if err != nil || fmt.Sprintf("%x", sha256.Sum256(bundle)) != previewHash {
						t.Fatal("paired archive digest", c.Name, err)
					}
					archive, err := zip.NewReader(bytes.NewReader(bundle), int64(len(bundle)))
					if err != nil || len(archive.File) != 2 {
						t.Fatal("paired ZIP shape", c.Name, err)
					}
					members := map[string][]byte{}
					for i, file := range archive.File {
						name := []string{"registry.json", "glossary.json"}[i]
						if file.Name != name || file.Method != zip.Store {
							t.Fatal("paired member name/order/method", c.Name, file.Name, file.Method)
						}
						reader, err := file.Open()
						if err != nil {
							t.Fatal(err)
						}
						body, readErr := io.ReadAll(io.LimitReader(reader, 64<<20+1))
						closeErr := reader.Close()
						if readErr != nil || closeErr != nil || len(body) > 64<<20 {
							t.Fatal("paired member read/CRC/bound", c.Name, readErr, closeErr)
						}
						members[name] = body
						want, unchanged, raw, lexemes := c.ExpectedRegistry, c.RegistryUnchanged, c.RegistryBytes, c.RegistryLexemes
						if i == 1 {
							want, unchanged, raw, lexemes = c.ExpectedGlossary, c.GlossaryUnchanged, c.GlossaryBytes, c.GlossaryLexemes
						}
						completeComparisons = append(completeComparisons, jsonComparison{c.Name + "/" + name, body, want})
						if unchanged && !bytes.Equal(body, []byte(raw)) {
							t.Fatal("unchanged paired member/date reformatted", c.Name, name)
						}
						for _, needle := range lexemes {
							if !bytes.Contains(body, []byte(needle)) {
								t.Fatal("paired raw metadata lexeme lost", c.Name, name, needle)
							}
						}
					}
					second := output + "-second.zip"
					if err := run(append(slices.Clone(args), "--apply", "--output", second), io.Discard); err != nil {
						t.Fatal("paired deterministic repeat", c.Name, err)
					}
					if got, err := os.ReadFile(second); err != nil || !bytes.Equal(got, bundle) {
						t.Fatal("paired ZIP headers not deterministic", c.Name, err)
					}
					if err := run(append(slices.Clone(args), "--apply", "--output", output), io.Discard); err == nil {
						t.Fatal("paired overwrite accepted", c.Name)
					}
					if got, err := os.ReadFile(output); err != nil || !bytes.Equal(got, bundle) {
						t.Fatal("paired refusal changed existing output", c.Name, err)
					}
					// Reusing the emitted members must not append again or rewrite either date.
					replayInputs := maps.Clone(inputs)
					replaySource := write(filepath.Join(importDir, "paired-"+c.Name+"-replay-registry.json"), members["registry.json"])
					glossaryPath := write(filepath.Join(importDir, "paired-"+c.Name+"-replay-glossary.json"), members["glossary.json"])
					replayInputs["glossary"] = RegistryInput{Path: glossaryPath, Size: int64(len(members["glossary.json"])), SHA256: fmt.Sprintf("%x", sha256.Sum256(members["glossary.json"]))}
					replay := maps.Clone(request)
					replay["source_size"], replay["source_sha256"], replay["registry_inputs"] = len(members["registry.json"]), fmt.Sprintf("%x", sha256.Sum256(members["registry.json"])), replayInputs
					replayProfile := jsonFile(filepath.Join(importDir, "paired-"+c.Name+"-replay-profile.json"), replay)
					replayed := output + "-replayed.zip"
					if err := run([]string{"--source", replaySource, "--recipes", replayProfile, "--apply", "--output", replayed}, io.Discard); err != nil {
						t.Fatal("paired emitted-source replay", c.Name, err)
					}
					if got, err := os.ReadFile(replayed); err != nil || !bytes.Equal(got, bundle) {
						t.Fatal("paired replay changed annotation/member bytes/date", c.Name, err)
					}
				}
				for path, want := range originals {
					if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, want) {
						t.Fatal("paired operation changed input", c.Name, path, err)
					}
				}
			}
			if pairAccepted != 17 || pairRefused != 33 {
				t.Fatal("paired fixture cohort changed", pairAccepted, pairRefused)
			}
			var humanFixtures struct {
				Cases []struct {
					Name, Source, Decoded, Flow, Authored, Updated string
					ExpectedDocument                               json.RawMessage `json:"expected_document"`
					Refuse                                         bool            `json:"expect_refuse"`
					Unchanged                                      bool            `json:"unchanged_source"`
					RawNumbers                                     []string        `json:"raw_number_literals"`
				}
			}
			humanData, err := os.ReadFile("testdata/registry-human.json")
			if err != nil || json.Unmarshal(humanData, &humanFixtures) != nil || len(humanFixtures.Cases) != 55 {
				t.Fatal("independent human source fixtures", err)
			}
			humanAccepted, humanRefused := 0, 0
			for _, c := range humanFixtures.Cases {
				source := []byte(c.Source)
				sourcePath := write(filepath.Join(importDir, "human-"+c.Name+"-source.json"), source)
				inputs := make(map[string]RegistryInput)
				originals := map[string][]byte{sourcePath: source}
				for name, value := range map[string]string{"decoded": c.Decoded, "flow": c.Flow, "authored": c.Authored} {
					body := []byte(value)
					path := write(filepath.Join(importDir, "human-"+c.Name+"-"+name+".json"), body)
					inputs[name] = RegistryInput{Path: path, Size: int64(len(body)), SHA256: fmt.Sprintf("%x", sha256.Sum256(body))}
					originals[path] = body
				}
				request := map[string]any{"operation": "registry_human", "source_size": len(source), "source_sha256": fmt.Sprintf("%x", sha256.Sum256(source)), "evidence": "Independent manual55 full human states frozen before Go", "updated": c.Updated, "registry_inputs": inputs}
				profilePath := jsonFile(filepath.Join(importDir, "human-"+c.Name+"-profile.json"), request)
				profileData, err := os.ReadFile(profilePath)
				if err != nil {
					t.Fatal(err)
				}
				originals[profilePath] = profileData
				args := []string{"--source", sourcePath, "--recipes", profilePath}
				var firstOutput []byte
				for _, apply := range []bool{false, true} {
					output := filepath.Join(importDir, "human-"+c.Name+"-out.json")
					call := slices.Clone(args)
					if apply {
						call = append(call, "--apply", "--output", output)
					}
					var report bytes.Buffer
					err := run(call, &report)
					if c.Refuse {
						if err == nil || report.Len() != 0 {
							t.Fatal("human refusal", c.Name, apply, err, report.String())
						}
						if _, err := os.Stat(output); !os.IsNotExist(err) {
							t.Fatal("human refusal published", c.Name, err)
						}
						continue
					}
					if err != nil {
						t.Fatal("human admission", c.Name, apply, err)
					}
					var result struct {
						Operation        string
						Applied, Changed bool
						OutputSHA256     string `json:"output_sha256"`
					}
					if json.Unmarshal(report.Bytes(), &result) != nil || result.Operation != "registry_human" || result.Applied != apply || result.Changed == c.Unchanged {
						t.Fatal("human report", c.Name, report.String())
					}
					if !apply {
						if _, err := os.Stat(output); !os.IsNotExist(err) {
							t.Fatal("human preview published", c.Name, err)
						}
						continue
					}
					firstOutput, err = os.ReadFile(output)
					if err != nil || fmt.Sprintf("%x", sha256.Sum256(firstOutput)) != result.OutputSHA256 || c.Unchanged && !bytes.Equal(source, firstOutput) {
						t.Fatal("human whole output identity/noop", c.Name, err)
					}
					for _, literal := range c.RawNumbers {
						if !bytes.Contains(firstOutput, []byte(literal)) {
							t.Fatal("human raw number changed", c.Name, literal)
						}
					}
					completeComparisons = append(completeComparisons, jsonComparison{c.Name + "/human", firstOutput, c.ExpectedDocument})
					if err := run(call, io.Discard); err == nil {
						t.Fatal("human output overwrite allowed", c.Name)
					}
					replay := maps.Clone(request)
					replay["source_size"], replay["source_sha256"], replay["updated"] = len(firstOutput), result.OutputSHA256, "2026-11-06"
					replayProfile := jsonFile(filepath.Join(importDir, "human-"+c.Name+"-replay-profile.json"), replay)
					replayOutput := filepath.Join(importDir, "human-"+c.Name+"-replay.json")
					if err := run([]string{"--source", output, "--recipes", replayProfile, "--apply", "--output", replayOutput}, io.Discard); err != nil {
						t.Fatal("human emitted-source replay", c.Name, err)
					}
					body, err := os.ReadFile(replayOutput)
					if err != nil || !bytes.Equal(firstOutput, body) {
						t.Fatal("human replay bytes/date changed", c.Name, err)
					}
				}
				for path, body := range originals {
					current, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(current, body) {
						t.Fatal("human input mutated", c.Name, path, err)
					}
				}
				if c.Refuse {
					humanRefused++
				} else {
					humanAccepted++
				}
			}
			if humanAccepted != 29 || humanRefused != 26 {
				t.Fatal("human fixture cohort changed", humanAccepted, humanRefused)
			}

			for _, comparison := range completeComparisons {
				// Compare complete values without rounding arbitrary JSON integers or exponents.
				var actual, expected any
				decoder := json.NewDecoder(bytes.NewReader(comparison.actual))
				decoder.UseNumber()
				if err := decoder.Decode(&actual); err != nil {
					t.Fatal(err)
				}
				decoder = json.NewDecoder(bytes.NewReader(comparison.expected))
				decoder.UseNumber()
				if err := decoder.Decode(&expected); err != nil {
					t.Fatal(err)
				}
				pending := [][2]any{{actual, expected}}
				for len(pending) > 0 {
					pair := pending[len(pending)-1]
					pending = pending[:len(pending)-1]
					switch value := pair[0].(type) {
					case map[string]any:
						want, ok := pair[1].(map[string]any)
						if !ok || len(value) != len(want) {
							t.Fatal("import object shape", comparison.label, pair)
						}
						for key, child := range value {
							other, present := want[key]
							if !present {
								t.Fatal("unexpected import field", comparison.label, key)
							}
							pending = append(pending, [2]any{child, other})
						}
					case []any:
						want, ok := pair[1].([]any)
						if !ok || len(value) != len(want) {
							t.Fatal("import array shape", comparison.label, pair)
						}
						for i, child := range value {
							pending = append(pending, [2]any{child, want[i]})
						}
					case json.Number:
						want, ok := pair[1].(json.Number)
						if !ok {
							t.Fatal("import number type", comparison.label, pair)
						}
						left, lok := new(big.Rat).SetString(string(value))
						right, rok := new(big.Rat).SetString(string(want))
						if !lok || !rok || left.Cmp(right) != 0 {
							t.Fatal("import numeric value", comparison.label, pair)
						}
					default:
						if !reflect.DeepEqual(pair[0], pair[1]) {
							t.Fatal("import complete field value", comparison.label, pair)
						}
					}
				}
			}
			var provenance struct {
				Cases []struct {
					ID, SHA256       string
					DiscoveredBy     string `json:"discovered_by"`
					Bytes            int    `json:"utf8_bytes"`
					Accept           bool   `json:"expected_accept"`
					Note             string `json:"expected_note"`
					Provenance       string `json:"expected_discovered_by"`
					NoReportOrOutput bool   `json:"expected_no_report_or_publication"`
				}
			}
			boundaryData, err := os.ReadFile("testdata/registry-import-provenance.json")
			if err != nil || json.Unmarshal(boundaryData, &provenance) != nil || len(provenance.Cases) != 5 {
				t.Fatal("independent provenance boundaries", err)
			}
			for _, c := range provenance.Cases {
				if len(c.DiscoveredBy) != c.Bytes || fmt.Sprintf("%x", sha256.Sum256([]byte(c.DiscoveredBy))) != c.SHA256 || c.Accept == c.NoReportOrOutput {
					t.Fatal("provenance boundary literal changed", c.ID)
				}
				source := []byte(`{"entries":[]}`)
				batch := []byte("id,jp,en,chapter,character,event,tier,mode,source_pool,note\n0x20,A,A,c,n,,1,,p,\n")
				sourcePath := write(filepath.Join(importDir, "provenance-source.json"), source)
				batchPath := write(filepath.Join(importDir, "provenance-batch.csv"), batch)
				request := map[string]any{"operation": "registry_add", "source_size": len(source), "source_sha256": fmt.Sprintf("%x", sha256.Sum256(source)), "evidence": "Independent RRI-1 provenance boundary literals, including original 282-byte identity", "updated": "2026-11-05", "registry_import": RegistryImportSpec{Policy: "csv_drafts", Batches: []string{"batch"}, Glyphmap: "glyphs", DiscoveredBy: c.DiscoveredBy}, "registry_inputs": map[string]RegistryInput{"batch": {Path: batchPath, Size: int64(len(batch)), SHA256: fmt.Sprintf("%x", sha256.Sum256(batch))}, "glyphs": {Path: glyphPath, Size: int64(len(glyphData)), SHA256: fmt.Sprintf("%x", sha256.Sum256(glyphData))}}}
				profilePath := jsonFile(filepath.Join(importDir, "provenance-profile.json"), request)
				args := []string{"--source", sourcePath, "--recipes", profilePath}
				output := filepath.Join(importDir, "provenance-"+c.ID+".json")
				for _, apply := range []bool{false, true} {
					call := slices.Clone(args)
					if apply {
						call = append(call, "--apply", "--output", output)
					}
					var report bytes.Buffer
					err := run(call, &report)
					if c.Accept {
						if err != nil || report.Len() == 0 {
							t.Fatal("bounded original/ASCII/Unicode provenance refused", c.ID, apply, err)
						}
					} else if err == nil || report.Len() != 0 || !strings.Contains(err.Error(), "1..512") {
						t.Fatal("oversized provenance admitted or wrong boundary", c.ID, apply, err)
					}
					if !apply || !c.Accept {
						if _, err := os.Stat(output); !os.IsNotExist(err) {
							t.Fatal("provenance preview/refusal published", c.ID, apply, err)
						}
					}
				}
				if c.Accept {
					var document struct {
						Entries []struct {
							Note         string
							DiscoveredBy string `json:"discovered_by"`
						}
					}
					written, err := os.ReadFile(output)
					if err != nil || json.Unmarshal(written, &document) != nil || len(document.Entries) != 1 || document.Entries[0].Note != c.Note || document.Entries[0].DiscoveredBy != c.Provenance {
						t.Fatal("bounded provenance changed value", c.ID, err, string(written))
					}
				}
				if got, err := os.ReadFile(sourcePath); err != nil || !bytes.Equal(got, source) {
					t.Fatal("provenance boundary changed source", c.ID, err)
				}
			}
			prettyFiles := bundledFixtures["testdata/registry-import-pretty.zip"]
			var syntax struct {
				Cases []struct {
					ID       string
					Raw      string `json:"raw_utf8"`
					Upper    int64  `json:"upper_bound_bytes"`
					Actual   int    `json:"actual_pretty_bytes"`
					Expected string `json:"actual_pretty_utf8"`
				}
			}
			if json.Unmarshal(prettyFiles["syntax-literals.json"], &syntax) != nil || len(syntax.Cases) != 10 {
				t.Fatal("independent two-space budget syntax literals")
			}
			for _, c := range syntax.Cases {
				var formatted bytes.Buffer
				if err := json.Indent(&formatted, []byte(c.Raw), "", "  "); err != nil || formatted.String() != c.Expected || formatted.Len() != c.Actual || int64(c.Actual) > c.Upper {
					t.Fatal("independent actual formatting literal", c.ID, err)
				}
				if err := checkJSON(checkedJSON{raw: []byte(c.Raw)}); err != nil {
					t.Fatal("zero budget changed old checker policy", c.ID, err)
				}
				if err := checkJSON(checkedJSON{raw: []byte(c.Raw), maxPrettyBytes: c.Upper}); err != nil {
					t.Fatal("two-space bound refused its literal endpoint", c.ID, err)
				}
				if c.Upper > 1 {
					if err := checkJSON(checkedJSON{raw: []byte(c.Raw), maxPrettyBytes: c.Upper - 1}); err == nil || !strings.Contains(err.Error(), "byte budget") {
						t.Fatal("two-space budget missed syntax or conservative empty-container bound", c.ID, err)
					}
				}
			}
			type prettyCase struct {
				id, disposition, sha string
				bytes                int
			}
			var prettyCases []prettyCase
			var deep struct {
				Vectors []struct {
					ID          string
					Disposition string `json:"expected_new_budget_disposition"`
					Bytes       int    `json:"actual_expected_pretty_output_bytes"`
					SHA         string `json:"expected_pretty_output_sha256"`
				}
			}
			if json.Unmarshal(prettyFiles["deep-vectors.json"], &deep) != nil || len(deep.Vectors) != 3 {
				t.Fatal("independent deep budget vectors")
			}
			for _, c := range deep.Vectors {
				prettyCases = append(prettyCases, prettyCase{c.ID, c.Disposition, c.SHA, c.Bytes})
			}
			var inherited struct {
				Cases []struct {
					ID          string
					Disposition string `json:"expected_new_budget_disposition"`
					Bytes       int    `json:"expected_output_bytes"`
					SHA         string `json:"expected_output_sha256"`
				}
			}
			if json.Unmarshal(prettyFiles["inherited-boundaries.json"], &inherited) != nil || len(inherited.Cases) != 2 {
				t.Fatal("independent inherited budget vectors")
			}
			for _, c := range inherited.Cases {
				prettyCases = append(prettyCases, prettyCase{c.ID, c.Disposition, c.SHA, c.Bytes})
			}
			for _, c := range prettyCases {
				source := prettyFiles[c.id+"/source.json"]
				sourcePath := write(filepath.Join(importDir, c.id+"-source.json"), source)
				var request map[string]json.RawMessage
				if json.Unmarshal(prettyFiles[c.id+"/profile.json"], &request) != nil {
					t.Fatal("pretty input profile", c.id)
				}
				var inputs map[string]RegistryInput
				if json.Unmarshal(request["registry_inputs"], &inputs) != nil {
					t.Fatal("pretty input resource pins", c.id)
				}
				originals := map[string][]byte{sourcePath: source}
				for name, input := range inputs {
					body := prettyFiles[c.id+"/"+input.Path]
					if int64(len(body)) != input.Size || fmt.Sprintf("%x", sha256.Sum256(body)) != input.SHA256 {
						t.Fatal("pretty source resource pin", c.id, name)
					}
					input.Path = write(filepath.Join(importDir, c.id+"-"+name+".data"), body)
					inputs[name], originals[input.Path] = input, body
				}
				request["registry_inputs"], _ = json.Marshal(inputs)
				profilePath := jsonFile(filepath.Join(importDir, c.id+"-profile.json"), request)
				originals[profilePath], err = os.ReadFile(profilePath)
				if err != nil {
					t.Fatal(err)
				}
				args := []string{"--source", sourcePath, "--recipes", profilePath}
				output := filepath.Join(importDir, c.id+"-output.json")
				refuse := strings.HasPrefix(c.disposition, "refuse")
				for _, apply := range []bool{false, true} {
					call := slices.Clone(args)
					if apply {
						call = append(call, "--apply", "--output", output)
					}
					var report bytes.Buffer
					err := run(call, &report)
					if refuse {
						if err == nil || report.Len() != 0 || !strings.Contains(err.Error(), "byte budget") {
							t.Fatal("deep merged metadata escaped pre-indent bound", c.id, apply, err)
						}
					} else {
						var summary struct {
							Hash string `json:"output_sha256"`
						}
						if err != nil || json.Unmarshal(report.Bytes(), &summary) != nil || summary.Hash != c.sha {
							t.Fatal("deep metadata changed independent whole-output hash", c.id, apply, err, report.String())
						}
					}
					if refuse || !apply {
						if _, err := os.Stat(output); !os.IsNotExist(err) {
							t.Fatal("pretty preview/refusal published output", c.id, apply, err)
						}
					}
				}
				if c.id == "inherited-34-deep-plus-new" {
					var sourceDoc map[string]json.RawMessage
					var sourceRows []map[string]json.RawMessage
					if json.Unmarshal(source, &sourceDoc) != nil || json.Unmarshal(sourceDoc["entries"], &sourceRows) != nil {
						t.Fatal("shared budget inherited source")
					}
					var existingID string
					_ = json.Unmarshal(sourceRows[0]["id"], &existingID)
					for _, operation := range []string{"registry_author", "registry_merge", "registry_add"} {
						shared := maps.Clone(request)
						delete(shared, "registry_import")
						delete(shared, "registry_inputs")
						shared["operation"], _ = json.Marshal(operation)
						updates := map[string]map[string]json.RawMessage{existingID: {"en": json.RawMessage(`"B"`)}}
						switch operation {
						case "registry_merge":
							updates[existingID] = map[string]json.RawMessage{"patch_ref": json.RawMessage(`"shared"`)}
						case "registry_add":
							updates = map[string]map[string]json.RawMessage{"0x99ff": {"jp": json.RawMessage(`"A"`), "en": json.RawMessage(`"B"`), "status": json.RawMessage(`"drafted"`), "source_pool": json.RawMessage(`"synthetic"`)}}
						}
						shared["registry_updates"], _ = json.Marshal(updates)
						path := jsonFile(filepath.Join(importDir, operation+"-oversized.json"), shared)
						for _, apply := range []bool{false, true} {
							call := []string{"--source", sourcePath, "--recipes", path}
							if apply {
								call = append(call, "--apply", "--output", output)
							}
							var report bytes.Buffer
							if err := run(call, &report); err == nil || report.Len() != 0 || !strings.Contains(err.Error(), "byte budget") {
								t.Fatal("older registry route bypassed shared output budget", operation, apply, err)
							}
							if _, err := os.Stat(output); !os.IsNotExist(err) {
								t.Fatal("oversized registry route published", operation, err)
							}
						}
					}
					// Opaque root metadata joins only at the final compact stage.
					rootSource := maps.Clone(sourceDoc)
					rootSource["opaque_root"], _ = json.Marshal(map[string]json.RawMessage{"held": sourceDoc["entries"]})
					rootSource["entries"] = json.RawMessage(`[{"id":"0x99ff","jp":"A","en":"A","status":"drafted","source_pool":"synthetic"}]`)
					rootData, _ := json.Marshal(rootSource)
					rootPath := write(filepath.Join(importDir, "deep-root-source.json"), rootData)
					rootRequest := maps.Clone(request)
					rootRequest["source_size"], _ = json.Marshal(len(rootData))
					rootRequest["source_sha256"], _ = json.Marshal(fmt.Sprintf("%x", sha256.Sum256(rootData)))
					rootProfile := jsonFile(filepath.Join(importDir, "deep-root-profile.json"), rootRequest)
					for _, apply := range []bool{false, true} {
						call := []string{"--source", rootPath, "--recipes", rootProfile}
						if apply {
							call = append(call, "--apply", "--output", output)
						}
						var report bytes.Buffer
						if err := run(call, &report); err == nil || report.Len() != 0 || !strings.Contains(err.Error(), "byte budget") {
							t.Fatal("opaque root escaped final budget", apply, err)
						}
						if _, err := os.Stat(output); !os.IsNotExist(err) {
							t.Fatal("oversized root published", apply, err)
						}
					}
				}
				if !refuse {
					written, err := os.ReadFile(output)
					if err != nil || len(written) != c.bytes || fmt.Sprintf("%x", sha256.Sum256(written)) != c.sha || strings.Contains(c.disposition, "noop") && !bytes.Equal(written, source) {
						t.Fatal("deep budget output size/hash/noop", c.id, err)
					}
					if strings.Contains(c.disposition, "noop") {
						var sourceDoc map[string]json.RawMessage
						var sourceRows []map[string]json.RawMessage
						if json.Unmarshal(source, &sourceDoc) != nil || json.Unmarshal(sourceDoc["entries"], &sourceRows) != nil {
							t.Fatal("inline deep no-op source")
						}
						var id string
						_ = json.Unmarshal(sourceRows[0]["id"], &id)
						inline := maps.Clone(request)
						delete(inline, "registry_import")
						delete(inline, "registry_inputs")
						inline["registry_updates"], _ = json.Marshal(map[string]map[string]json.RawMessage{id: {"jp": sourceRows[0]["jp"], "en": sourceRows[0]["en"], "status": json.RawMessage(`"drafted"`), "source_pool": json.RawMessage(`"ignored incoming metadata"`)}})
						path := jsonFile(filepath.Join(importDir, "inline-deep-noop-profile.json"), inline)
						inlineOutput := output + "-inline.json"
						for _, apply := range []bool{false, true} {
							call := []string{"--source", sourcePath, "--recipes", path}
							if apply {
								call = append(call, "--apply", "--output", inlineOutput)
							}
							if err := run(call, io.Discard); err != nil {
								t.Fatal("shared serializer refused inline byte-noop", apply, err)
							}
							if !apply {
								if _, err := os.Stat(inlineOutput); !os.IsNotExist(err) {
									t.Fatal("inline no-op preview wrote", err)
								}
							}
						}
						if got, err := os.ReadFile(inlineOutput); err != nil || !bytes.Equal(got, source) {
							t.Fatal("shared serializer reformatted inline deep no-op", err)
						}
					}
				}
				for path, want := range originals {
					if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, want) {
						t.Fatal("pretty check changed input", c.id, path, err)
					}
				}
			}
			var serialization struct {
				Cases []struct {
					Operation string
					Source    string `json:"source_hex"`
					Registry  string `json:"registry_hex"`
					Glyphmap  string `json:"glyphmap_hex"`
					Profile   map[string]json.RawMessage
					Expected  string `json:"expected_output_hex"`
					Bytes     int    `json:"expected_output_bytes"`
					SHA       string `json:"expected_output_sha256"`
				}
			}
			parityData, err := os.ReadFile("testdata/registry-serialization.json")
			if err != nil || json.Unmarshal(parityData, &serialization) != nil || len(serialization.Cases) != 4 {
				t.Fatal("accepted718 serialization compatibility", err)
			}
			for _, c := range serialization.Cases {
				source, err := hex.DecodeString(c.Source)
				if err != nil {
					t.Fatal(err)
				}
				sourcePath := write(filepath.Join(importDir, c.Operation+"-parity-source.data"), source)
				profilePath := jsonFile(filepath.Join(importDir, c.Operation+"-parity-profile.json"), c.Profile)
				args := []string{"--source", sourcePath, "--recipes", profilePath}
				originals := map[string][]byte{sourcePath: source}
				for _, input := range []struct{ flag, encoded string }{{"--registry", c.Registry}, {"--glyphmap", c.Glyphmap}} {
					if input.encoded == "" {
						continue
					}
					body, err := hex.DecodeString(input.encoded)
					if err != nil {
						t.Fatal(err)
					}
					path := write(filepath.Join(importDir, c.Operation+input.flag+"-parity.data"), body)
					args = append(args, input.flag, path)
					originals[path] = body
				}
				output := filepath.Join(importDir, c.Operation+"-parity-output.json")
				for _, apply := range []bool{false, true} {
					call := slices.Clone(args)
					if apply {
						call = append(call, "--apply", "--output", output)
					}
					var report bytes.Buffer
					if err := run(call, &report); err != nil {
						t.Fatal("shared serializer route refused", c.Operation, apply, err)
					}
					if !apply {
						if _, err := os.Stat(output); !os.IsNotExist(err) {
							t.Fatal("shared serializer preview wrote", c.Operation, err)
						}
					}
				}
				written, err := os.ReadFile(output)
				want, decodeErr := hex.DecodeString(c.Expected)
				if err != nil || decodeErr != nil || len(written) != c.Bytes || !bytes.Equal(written, want) || fmt.Sprintf("%x", sha256.Sum256(written)) != c.SHA {
					t.Fatal("shared serializer changed accepted whole bytes", c.Operation, err, decodeErr)
				}
				for path, want := range originals {
					if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, want) {
						t.Fatal("serializer compatibility changed input", c.Operation, path, err)
					}
				}
			}
			// Source-bound writers share declaration, identity and publication refusals.
			pairBase := paired.Cases[0]
			for _, operation := range []string{"registry_reconcile", "registry_human", "full_sweep"} {
				mutations := []string{"inline updates", "import null", "columns", "no date", "bad date", "extra input", "missing input", "null input", "input alias", "input extra field", "bad glossary hash", "bad correction size", "non-UTF8 proposal", "wrong glossary root", "profile bound", "authored row bound", "combined row bound", "existing glossary bound", "resulting glossary bound", "combined byte bound", "glossary metadata output bound", "raw profile duplicate", "unpaired evidence"}
				if operation == "registry_human" {
					mutations = []string{"inline updates", "import null", "columns", "no date", "bad date", "extra input", "missing input", "null input", "input alias", "input extra field", "bad glossary hash", "bad correction size", "non-UTF8 proposal", "wrong glossary root", "profile bound", "combined byte bound", "raw profile duplicate", "unpaired evidence", "human flow bound", "human decoded bound", "human translations bound", "human existing registry bound", "human result bound"}
				}
				if operation == "full_sweep" {
					mutations = []string{"inline updates", "import null", "columns", "no date", "bad date", "extra input", "missing input", "null input", "input alias", "input extra field", "bad glossary hash", "bad correction size", "non-UTF8 proposal", "wrong glossary root", "profile bound", "combined byte bound", "raw profile duplicate", "unpaired evidence", "orders resource bound", "permutation bound", "orders glyph overlap", "orders batch overlap"}
				}
				for _, mutation := range mutations {
					source := []byte(pairBase.Registry)
					bodies := map[string][]byte{"glossary": []byte(pairBase.Glossary), "corrections": []byte(pairBase.Corrections), "glossary_proposals": []byte(pairBase.Proposals)}
					roles := []string{"glossary", "corrections", "glossary_proposals"}
					if operation == "registry_human" {
						base := humanFixtures.Cases[0]
						source = []byte(base.Source)
						bodies = map[string][]byte{"decoded": []byte(base.Decoded), "flow": []byte(base.Flow), "authored": []byte(base.Authored)}
						roles = []string{"decoded", "flow", "authored"}
					}
					if operation == "full_sweep" {
						base := fullSweepFixtures.Cases[0]
						source = []byte(base.Source)
						glyphBody, err := json.Marshal(fullSweepFixtures.Glyphmap)
						if err != nil {
							t.Fatal(err)
						}
						bodies = map[string][]byte{"batch": []byte(base.Batches[0].Data), "glyphs": glyphBody, "orders": []byte(base.MarkerOrders)}
						roles = []string{"batch", "glyphs", "orders"}
					}
					wantError := ""
					switch mutation {
					case "non-UTF8 proposal":
						bodies[roles[2]] = []byte{'[', 0xff, ']'}
					case "wrong glossary root":
						bodies[roles[0]] = []byte(`[]`)
						if operation == "full_sweep" {
							bodies[roles[0]] = []byte(`{}`)
						}
					case "authored row bound":
						row := `{"id":"0x10","old_en":"A","new_en":"B","note_suffix":" fix"}`
						bodies["corrections"] = []byte("[" + strings.Repeat(row+",", 65536) + row + "]")
						wantError = "65536"
					case "combined row bound":
						row := `{"id":"0x10","old_en":"A","new_en":"B","note_suffix":" fix"}`
						bodies["corrections"] = []byte("[" + strings.Repeat(row+",", 65535) + row + "]")
						wantError = "65536"
					case "existing glossary bound", "resulting glossary bound":
						var body strings.Builder
						body.WriteString(`{"entries":[`)
						count := 65537
						if mutation == "resulting glossary bound" {
							count = 65536
						}
						for i := 0; i < count; i++ {
							if i != 0 {
								body.WriteByte(',')
							}
							fmt.Fprintf(&body, `{"jp":"term%d","en":"A"}`, i)
						}
						body.WriteString("]}")
						bodies["glossary"] = []byte(body.String())
						wantError = "65536"
						if mutation == "resulting glossary bound" {
							wantError = "resulting glossary"
						}
					case "combined byte bound":
						bodies[roles[1]] = append([]byte("[]"), bytes.Repeat([]byte(" "), (33<<20)-2)...)
						wantError = "in total"
					case "glossary metadata output bound":
						var old map[string]json.RawMessage
						if json.Unmarshal(prettyFiles["inherited-34-deep-plus-new/source.json"], &old) != nil {
							t.Fatal("deep glossary source")
						}
						bodies["glossary"], _ = json.Marshal(map[string]json.RawMessage{"entries": json.RawMessage(`[]`), "opaque_root": old["entries"]})
						wantError = "byte budget"
					}
					if operation == "full_sweep" {
						switch mutation {
						case "combined byte bound":
							glyphBody, _ := json.Marshal(fullSweepFixtures.Glyphmap)
							bodies["glyphs"] = glyphBody
							bodies["batch"] = append(bodies["batch"], bytes.Repeat([]byte(" "), (33<<20)-len(bodies["batch"]))...)
						case "orders resource bound":
							bodies["orders"] = append([]byte("{}"), bytes.Repeat([]byte(" "), (1<<20)-1)...)
							wantError = "invalid"
						case "permutation bound":
							order := RegistryMarkerOrder{JPSHA256: strings.Repeat("a", 64), ENSHA256: strings.Repeat("b", 64), ENSourcesJP: make([]int, 65537)}
							bodies["orders"], _ = json.Marshal(map[string]RegistryMarkerOrder{"0x1000": order})
							wantError = "65536"
						}
					}
					if strings.HasPrefix(mutation, "human ") {
						wantError = "65536"
						switch mutation {
						case "human flow bound", "human decoded bound":
							name := "flow"
							if mutation == "human decoded bound" {
								name = "decoded"
							}
							row := `{"vma":"0x10","decoded_jp":"JP"}`
							bodies[name] = []byte("[" + strings.Repeat(row+",", 65536) + row + "]")
						case "human translations bound":
							var declaration map[string]json.RawMessage
							_ = json.Unmarshal(bodies["authored"], &declaration)
							var rows strings.Builder
							rows.WriteByte('{')
							for i := 0; i < 65537; i++ {
								if i != 0 {
									rows.WriteByte(',')
								}
								fmt.Fprintf(&rows, `"0x%x":{"en":"A","chapter":"menu","character":"system","event":"label","tier":"B","note":"note"}`, i)
							}
							rows.WriteByte('}')
							declaration["translations"] = json.RawMessage(rows.String())
							bodies["authored"], _ = json.Marshal(declaration)
						case "human existing registry bound", "human result bound":
							count := 65537
							if mutation == "human result bound" {
								count = 65536
							}
							var rows strings.Builder
							rows.WriteString(`{"entries":[`)
							for i := 0; i < count; i++ {
								if i != 0 {
									rows.WriteByte(',')
								}
								fmt.Fprintf(&rows, `{"id":"0x%x"}`, i+0x1000)
							}
							rows.WriteString("]}")
							source = []byte(rows.String())
						}
					}
					sourcePath := write(filepath.Join(importDir, "pair-wire-source.json"), source)
					inputs := map[string]RegistryInput{}
					originals := map[string][]byte{sourcePath: source}
					for name, body := range bodies {
						path := write(filepath.Join(importDir, "pair-wire-"+name+".json"), body)
						inputs[name] = RegistryInput{Path: path, Size: int64(len(body)), SHA256: fmt.Sprintf("%x", sha256.Sum256(body))}
						originals[path] = body
					}
					request := map[string]any{"operation": operation, "source_size": len(source), "source_sha256": fmt.Sprintf("%x", sha256.Sum256(source)), "evidence": "shared pinned writer refusals", "updated": pairBase.Updated, "registry_inputs": inputs}
					if operation == "full_sweep" {
						request["operation"] = "registry_add"
						request["registry_import"] = map[string]any{"policy": "full_sweep", "batches": []string{"batch"}, "glyphmap": "glyphs", "marker_orders": "orders"}
					}

					switch mutation {
					case "inline updates":
						request["registry_updates"] = map[string]any{}
					case "import null":
						request["registry_import"] = nil
					case "columns":
						request["registry_columns"] = []string{}
					case "no date":
						delete(request, "updated")
					case "bad date":
						request["updated"] = "tomorrow"
					case "extra input":
						inputs["other"] = inputs[roles[0]]
					case "missing input":
						delete(inputs, roles[0])
					case "bad glossary hash":
						pin := inputs[roles[0]]
						pin.SHA256 = strings.Repeat("0", 64)
						inputs[roles[0]] = pin
					case "bad correction size":
						pin := inputs[roles[1]]
						pin.Size++
						inputs[roles[1]] = pin
					case "profile bound":
						request["evidence"] = strings.Repeat("x", 1<<20)
						wantError = "bounded profile"
					case "combined byte bound":
						pin := inputs[roles[2]]
						pin.Size = 34 << 20
						inputs[roles[2]] = pin
					}
					if operation == "full_sweep" {
						declaration, _ := request["registry_import"].(map[string]any)
						switch mutation {
						case "combined byte bound":
							declaration["batches"] = []string{"batch", "more"}
							inputs["more"] = RegistryInput{Path: inputs["batch"].Path, Size: 34 << 20, SHA256: inputs["batch"].SHA256}
							pin := inputs["orders"]
							pin.Size = int64(len(bodies["orders"]))
							inputs["orders"] = pin
						case "orders glyph overlap":
							declaration["marker_orders"] = "glyphs"
						case "orders batch overlap":
							declaration["marker_orders"] = "batch"
						}
					}
					raw, _ := json.Marshal(request)
					switch mutation {
					case "null input":
						path, _ := json.Marshal(inputs[roles[0]].Path)
						raw = bytes.Replace(raw, append([]byte(`"path":`), path...), []byte(`"path":null`), 1)
					case "input alias":
						raw = bytes.Replace(raw, []byte(`"size":`), []byte(`"Size":`), 1)
					case "input extra field":
						raw = bytes.Replace(raw, []byte(`"path":`), []byte(`"other":0,"path":`), 1)
					case "unpaired evidence":
						raw = bytes.Replace(raw, []byte(`"shared pinned writer refusals"`), []byte(`"\ud800"`), 1)
					case "raw profile duplicate":
						raw = bytes.Replace(raw, []byte(`"updated":`), []byte(`"updated":"2040-02-03","updated":`), 1)
					}
					profilePath := write(filepath.Join(importDir, "pair-wire-profile.json"), raw)
					originals[profilePath] = raw
					output := filepath.Join(importDir, "pair-wire-refused.zip")
					for _, apply := range []bool{false, true} {
						call := []string{"--source", sourcePath, "--recipes", profilePath}
						if apply {
							call = append(call, "--apply", "--output", output)
						}
						var report bytes.Buffer
						if err := run(call, &report); err == nil || report.Len() != 0 || wantError != "" && !strings.Contains(err.Error(), wantError) {
							t.Fatal("pinned writer wire/budget admitted or wrong boundary", mutation, apply, err, report.String())
						}
						if _, err := os.Stat(output); !os.IsNotExist(err) {
							t.Fatal("pinned writer wire published", mutation, apply, err)
						}
					}
					for path, want := range originals {
						if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, want) {
							t.Fatal("pinned writer wire changed input", mutation, path, err)
						}
					}
				}
			}
			// Both result-count endpoints remain usable as inputs to the same writer.
			for _, operation := range []string{"registry_reconcile", "registry_human"} {
				var glossary strings.Builder
				glossary.WriteString(`{"entries":[`)
				for i := 0; i < 65535; i++ {
					if i != 0 {
						glossary.WriteByte(',')
					}
					fmt.Fprintf(&glossary, `{"jp":"term%d","en":"A"}`, i)
				}
				glossary.WriteString("]}")
				source := []byte(pairBase.Registry)
				bodies := map[string][]byte{"glossary": []byte(glossary.String()), "corrections": []byte(pairBase.Corrections), "glossary_proposals": []byte(pairBase.Proposals)}
				if operation == "registry_human" {
					base := humanFixtures.Cases[0]
					bodies = map[string][]byte{"decoded": []byte(base.Decoded), "flow": []byte(base.Flow), "authored": []byte(base.Authored)}
					var rows strings.Builder
					rows.WriteString(`{"entries":[`)
					for i := 0; i < 65535; i++ {
						if i != 0 {
							rows.WriteByte(',')
						}
						fmt.Fprintf(&rows, `{"id":"0x%x"}`, i+0x1000)
					}
					rows.WriteString("]}")
					source = []byte(rows.String())
				}
				sourcePath := write(filepath.Join(importDir, "pair-full-source.json"), source)
				inputs := map[string]RegistryInput{}
				for name, body := range bodies {
					path := write(filepath.Join(importDir, "pair-full-"+name+".json"), body)
					inputs[name] = RegistryInput{Path: path, Size: int64(len(body)), SHA256: fmt.Sprintf("%x", sha256.Sum256(body))}
				}
				request := map[string]any{"operation": operation, "source_size": len(source), "source_sha256": fmt.Sprintf("%x", sha256.Sum256(source)), "evidence": "RPR-1 exact consuming endpoint", "updated": pairBase.Updated, "registry_inputs": inputs}
				var first []byte
				for iteration := 0; iteration < 2; iteration++ {
					profile := jsonFile(filepath.Join(importDir, fmt.Sprintf("%s-full-%d-profile.json", operation, iteration)), request)
					output := filepath.Join(importDir, fmt.Sprintf("%s-full-%d.out", operation, iteration))
					if err := run([]string{"--source", sourcePath, "--recipes", profile, "--apply", "--output", output}, io.Discard); err != nil {
						t.Fatal("last glossary slot or replay refused", iteration, err)
					}
					body, err := os.ReadFile(output)
					if err != nil {
						t.Fatal(err)
					}
					if iteration == 1 {
						if !bytes.Equal(body, first) {
							t.Fatal("full glossary replay changed pair")
						}
						break
					}
					first = body
					if operation == "registry_human" {
						var doc struct{ Entries []json.RawMessage }
						if json.Unmarshal(body, &doc) != nil || len(doc.Entries) != 65536 {
							t.Fatal("last human registry slot output count", len(doc.Entries))
						}
						sourcePath = write(filepath.Join(importDir, "human-full-replay-source.json"), body)
						request["source_size"], request["source_sha256"] = len(body), fmt.Sprintf("%x", sha256.Sum256(body))
						continue
					}
					archive, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
					if err != nil || len(archive.File) != 2 {
						t.Fatal("full glossary archive", err)
					}
					for _, file := range archive.File {
						reader, err := file.Open()
						if err != nil {
							t.Fatal(err)
						}
						member, readErr := io.ReadAll(reader)
						closeErr := reader.Close()
						if readErr != nil || closeErr != nil {
							t.Fatal(readErr, closeErr)
						}
						path := write(filepath.Join(importDir, "pair-full-replay-"+file.Name), member)
						if file.Name == "registry.json" {
							sourcePath = path
							request["source_size"], request["source_sha256"] = len(member), fmt.Sprintf("%x", sha256.Sum256(member))
						} else {
							var doc struct{ Entries []json.RawMessage }
							if json.Unmarshal(member, &doc) != nil || len(doc.Entries) != 65536 {
								t.Fatal("last glossary slot output count", len(doc.Entries))
							}
							inputs["glossary"] = RegistryInput{Path: path, Size: int64(len(member)), SHA256: fmt.Sprintf("%x", sha256.Sum256(member))}
						}
					}
				}
			}
			// The caller's frozen profile must still be the exact file before publication.
			for _, operation := range []string{"registry_reconcile", "registry_human", "full_sweep"} {
				source := []byte(pairBase.Registry)
				texts := map[string]string{"glossary": pairBase.Glossary, "corrections": pairBase.Corrections, "glossary_proposals": pairBase.Proposals}
				if operation == "registry_human" {
					base := humanFixtures.Cases[0]
					source = []byte(base.Source)
					texts = map[string]string{"decoded": base.Decoded, "flow": base.Flow, "authored": base.Authored}
				}
				if operation == "full_sweep" {
					base := fullSweepFixtures.Cases[0]
					source = []byte(base.Source)
					glyphBody, _ := json.Marshal(fullSweepFixtures.Glyphmap)
					texts = map[string]string{"batch": base.Batches[0].Data, "glyphs": string(glyphBody), "orders": base.MarkerOrders}
				}
				sourcePath := write(filepath.Join(importDir, "pair-profile-drift-source.json"), source)
				inputs := map[string]RegistryInput{}
				for name, text := range texts {
					body := []byte(text)
					path := write(filepath.Join(importDir, "pair-profile-drift-"+name+".json"), body)
					inputs[name] = RegistryInput{Path: path, Size: int64(len(body)), SHA256: fmt.Sprintf("%x", sha256.Sum256(body))}
				}
				profile := Recipes{Operation: operation, SourceSize: int64(len(source)), SourceSHA256: fmt.Sprintf("%x", sha256.Sum256(source)), Evidence: "frozen profile lifecycle", Updated: pairBase.Updated, RegistryInputs: inputs}
				request := map[string]any{"operation": profile.Operation, "source_size": profile.SourceSize, "source_sha256": profile.SourceSHA256, "evidence": profile.Evidence, "updated": profile.Updated, "registry_inputs": profile.RegistryInputs}
				if operation == "full_sweep" {
					profile.Operation = "registry_add"
					profile.RegistryImport = &RegistryImportSpec{Policy: "full_sweep", Batches: []string{"batch"}, Glyphmap: "glyphs", MarkerOrders: "orders"}
					request["operation"], request["registry_import"] = profile.Operation, profile.RegistryImport
				}
				raw, _ := json.Marshal(request)
				profilePath := write(filepath.Join(importDir, "pair-profile-drift.json"), append(bytes.Clone(raw), '\n'))
				output := filepath.Join(importDir, "pair-profile-drift-refused.zip")
				for _, apply := range []bool{false, true} {
					file, err := os.Open(sourcePath)
					if err != nil {
						t.Fatal(err)
					}
					var report bytes.Buffer
					err = authorRegistry(file, []Recipes{profile}, raw, RegistryOptions{ProfilePath: profilePath, Output: output, Apply: apply}, &report)
					closeErr := file.Close()
					if err == nil || !strings.Contains(err.Error(), "profile changed") || report.Len() != 0 || closeErr != nil {
						t.Fatal("paired profile drift ignored", apply, err, closeErr)
					}
					if _, err := os.Stat(output); !os.IsNotExist(err) {
						t.Fatal("paired profile drift published", apply, err)
					}
				}
			}
			for _, example := range []struct{ source, profile, marker string }{
				{"examples/registry-import/source.json", "examples/registry-import/profile.json", `"0x20"`},
				{"examples/registry-reconcile/registry.json", "examples/registry-reconcile/profile.json", `"glossary.json"`},
				{"examples/registry-human/registry.json", "examples/registry-human/profile.json", `"wording": "new"`},
				{"examples/registry-full-sweep/registry.json", "examples/registry-full-sweep/profile.json", `"full_sweep"`},
				{"examples/registry-full-sweep/registry.json", "recipes/registry/historical-discoveries.json", `"0x4ef500"`},
				{"examples/registry-reward-notes/registry.json", "examples/registry-reward-notes/profile.json", `"registry_author"`},
			} {
				var report bytes.Buffer
				if err := run([]string{"--source", example.source, "--recipes", example.profile}, &report); err != nil || !bytes.Contains(report.Bytes(), []byte(example.marker)) {
					t.Fatal("documented registry example", example.profile, err, report.String())
				}
			}

			// Declarations and pinned inputs fail before any output is published.
			base := fixtures.Cases[0]
			wireSource := []byte(base.Source)
			wireSourcePath := write(filepath.Join(importDir, "wire-source.json"), wireSource)
			for _, mutation := range []string{
				"foreign empty marker_orders", "null import", "nonobject import", "missing policy", "null policy", "policy alias", "unknown policy", "unknown field", "empty batches", "null batches", "65 batches", "duplicate batches", "glyph overlap", "missing glyph name", "JSON provenance", "CSV no provenance", "wrong operation", "inline empty", "inline null", "root alias", "root duplicate", "declaration duplicate", "unused input", "missing input", "empty path", "zero size", "oversized input", "size mismatch", "hash mismatch", "pin alias", "pin null", "pin unknown", "directory input", "invalid UTF-8", "invalid JSON", "JSON object", "null record", "scalar record", "duplicate record key", "record alias", "unpaired text", "null glyphmap", "unpaired glyphmap", "row bound", "aggregate budget",
			} {
				batch := []byte(base.Batches[0].Data)
				glyphBody := glyphData
				switch mutation {
				case "invalid UTF-8":
					batch = []byte{'[', 0xff, ']'}
				case "invalid JSON":
					batch = []byte(`[{`)
				case "JSON object":
					batch = []byte(`{"entries":[]}`)
				case "null record":
					batch = []byte(`[null]`)
				case "scalar record":
					batch = []byte(`["row"]`)
				case "duplicate record key":
					batch = []byte(`[{"id":"0x20","id":"0x21"}]`)
				case "record alias":
					batch = []byte(`[{"id":"0x20","JP":"A"}]`)
				case "unpaired text":
					batch = bytes.Replace(batch, []byte(`"en":`), []byte(`"en":"\ud800","discarded":`), 1)
				case "null glyphmap":
					glyphBody = []byte(`null`)
					var rows []map[string]json.RawMessage
					if json.Unmarshal(batch, &rows) != nil {
						t.Fatal("glyph-root fixture")
					}
					rows[0]["jp"], rows[0]["en"] = json.RawMessage(`" "`), json.RawMessage(`" "`)
					batch, _ = json.Marshal(rows)
				case "unpaired glyphmap":
					glyphBody = []byte(`{"1":"\ud800"}`)
				case "row bound":
					batch = []byte("[" + strings.Repeat("{},", 65536) + "{}]")
				case "aggregate budget":
					batch = append(batch, bytes.Repeat([]byte(" "), (33<<20)-len(batch))...)
				}
				batchPath := write(filepath.Join(importDir, "wire-batch.json"), batch)
				glyphPath := write(filepath.Join(importDir, "wire-glyphs.json"), glyphBody)
				inputs := map[string]RegistryInput{
					"batch":  {Path: batchPath, Size: int64(len(batch)), SHA256: fmt.Sprintf("%x", sha256.Sum256(batch))},
					"glyphs": {Path: glyphPath, Size: int64(len(glyphBody)), SHA256: fmt.Sprintf("%x", sha256.Sum256(glyphBody))},
				}
				declaration := map[string]any{"policy": "json_kinds", "batches": []string{"batch"}, "glyphmap": "glyphs"}
				request := map[string]any{"operation": "registry_add", "source_size": len(wireSource), "source_sha256": fmt.Sprintf("%x", sha256.Sum256(wireSource)), "evidence": "Explicit import wire refusals", "updated": "2026-11-05", "registry_import": declaration, "registry_inputs": inputs}
				switch mutation {
				case "foreign empty marker_orders":
					declaration["marker_orders"] = ""
				case "null import":
					request["registry_import"] = nil
				case "nonobject import":
					request["registry_import"] = []string{}
				case "missing policy":
					delete(declaration, "policy")
				case "null policy":
					declaration["policy"] = nil
				case "policy alias":
					delete(declaration, "policy")
					declaration["Policy"] = "json_kinds"
				case "unknown policy":
					declaration["policy"] = "automatic"
				case "unknown field":
					declaration["other"] = true
				case "empty batches":
					declaration["batches"] = []string{}
				case "null batches":
					declaration["batches"] = nil
				case "65 batches":
					declaration["batches"] = make([]string, 65)
				case "duplicate batches":
					declaration["batches"] = []string{"batch", "batch"}
				case "glyph overlap":
					declaration["glyphmap"] = "batch"
				case "missing glyph name":
					declaration["glyphmap"] = ""
				case "JSON provenance":
					declaration["discovered_by"] = ""
				case "CSV no provenance":
					declaration["policy"] = "csv_drafts"
				case "wrong operation":
					request["operation"] = "registry_author"
				case "inline empty":
					request["registry_updates"] = map[string]any{}
				case "inline null":
					request["registry_updates"] = nil
				case "aggregate budget":
					declaration["batches"] = []string{"batch", "overflow"}
					inputs["overflow"] = RegistryInput{Path: batchPath, Size: 34 << 20, SHA256: inputs["batch"].SHA256}
				case "unused input":
					inputs["unused"] = inputs["batch"]
				case "missing input":
					delete(inputs, "batch")
				case "empty path", "zero size", "oversized input", "size mismatch", "hash mismatch", "directory input":
					input := inputs["batch"]
					switch mutation {
					case "empty path":
						input.Path = ""
					case "zero size":
						input.Size = 0
					case "oversized input":
						input.Size = 64<<20 + 1
					case "size mismatch":
						input.Size++
					case "hash mismatch":
						input.SHA256 = strings.Repeat("0", 64)
					case "directory input":
						input.Path = importDir
					}
					inputs["batch"] = input
				}
				raw, err := json.Marshal(request)
				if err != nil {
					t.Fatal(err)
				}
				switch mutation {
				case "root alias":
					raw = bytes.Replace(raw, []byte(`"registry_import":`), []byte(`"Registry_Import":`), 1)
				case "root duplicate":
					raw = bytes.Replace(raw, []byte(`"registry_import":`), []byte(`"registry_import":null,"registry_import":`), 1)
				case "declaration duplicate":
					raw = bytes.Replace(raw, []byte(`"policy":`), []byte(`"policy":null,"policy":`), 1)
				case "pin alias":
					raw = bytes.Replace(raw, []byte(`"size":`), []byte(`"Size":`), 1)
				case "pin null":
					quotedPath, _ := json.Marshal(batchPath)
					raw = bytes.Replace(raw, append([]byte(`"path":`), quotedPath...), []byte(`"path":null`), 1)
				case "pin unknown":
					raw = bytes.Replace(raw, []byte(`"path":`), []byte(`"other":0,"path":`), 1)
				}
				profilePath := write(filepath.Join(importDir, "wire-profile.json"), raw)
				args := []string{"--source", wireSourcePath, "--recipes", profilePath}
				output := filepath.Join(importDir, "wire-refused.json")
				for _, apply := range []bool{false, true} {
					call := slices.Clone(args)
					if apply {
						call = append(call, "--apply", "--output", output)
					}
					var report bytes.Buffer
					if err := run(call, &report); err == nil || report.Len() != 0 || mutation == "aggregate budget" && !strings.Contains(err.Error(), "in total") {
						t.Fatal("invalid import wire request admitted", mutation, apply, err, report.String())
					}
					if _, err := os.Stat(output); !os.IsNotExist(err) {
						t.Fatal("invalid import wire request published", mutation, err)
					}
				}
				for path, want := range map[string][]byte{wireSourcePath: wireSource, profilePath: raw, batchPath: batch, glyphPath: glyphBody} {
					got, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(got, want) {
						t.Fatal("wire refusal changed input", mutation, path, err)
					}
				}
			}
		}

		{
			var vectors struct {
				Source json.RawMessage `json:"source"`
				Cases  []struct {
					ID, Key, Expected string
					ErrorContains     string `json:"error_contains"`
					Body              map[string]json.RawMessage
					Updates           map[string]map[string]json.RawMessage
				} `json:"cases"`
			}
			data, err := os.ReadFile("testdata/registry-add.json")
			if err != nil || json.Unmarshal(data, &vectors) != nil || len(vectors.Cases) != 13 {
				t.Fatal("missing registry add source/review vectors", err)
			}
			var originalDoc map[string]json.RawMessage
			var originalEntries []map[string]json.RawMessage
			if json.Unmarshal(vectors.Source, &originalDoc) != nil || json.Unmarshal(originalDoc["entries"], &originalEntries) != nil {
				t.Fatal("invalid source oracle")
			}
			sourcePath := write("registry-add-source.json", vectors.Source)
			for _, vector := range vectors.Cases {
				updates := vector.Updates
				if updates == nil {
					updates = map[string]map[string]json.RawMessage{vector.Key: vector.Body}
				}
				request := map[string]any{"operation": "registry_add", "source_size": len(vectors.Source), "source_sha256": fmt.Sprintf("%x", sha256.Sum256(vectors.Source)), "evidence": "Independent precode draft insertion vectors", "updated": "2026-10-20", "registry_updates": updates}
				profilePath := jsonFile("registry-add-updates.json", request)
				profileData, err := os.ReadFile(profilePath)
				if err != nil {
					t.Fatal(err)
				}
				args := []string{"--source", sourcePath, "--recipes", profilePath}
				output := filepath.Join(dir, "registry-add-"+vector.ID+".json")
				var preview bytes.Buffer
				err = run(args, &preview)
				insert := strings.HasPrefix(vector.Expected, "insert")
				present := strings.HasPrefix(vector.Expected, "already_present")
				if !insert && !present {
					if err == nil || preview.Len() != 0 || vector.ErrorContains != "" && !strings.Contains(err.Error(), vector.ErrorContains) {
						t.Fatal("invalid add admitted", vector.ID, err)
					}
					if err := run(append(slices.Clone(args), "--apply", "--output", output), io.Discard); err == nil {
						t.Fatal("invalid add applied", vector.ID)
					}
					if _, err := os.Stat(output); !os.IsNotExist(err) {
						t.Fatal("invalid add created output", vector.ID, err)
					}
					continue
				}
				if err != nil {
					t.Fatal(vector.ID, err)
				}
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatal("add preview wrote output", vector.ID, err)
				}
				var report struct {
					Added   []string `json:"added_ids"`
					Present []string `json:"already_present_ids"`
					Hash    string   `json:"output_sha256"`
					Updated string   `json:"updated"`
					Limits  string   `json:"limits"`
				}
				if json.Unmarshal(preview.Bytes(), &report) != nil || report.Added == nil || report.Present == nil || report.Limits == "" || (len(report.Added) == 1) != insert || (len(report.Present) == 1) != present {
					t.Fatal("wrong add report", vector.ID, preview.String())
				}
				if err := run(append(slices.Clone(args), "--apply", "--output", output), io.Discard); err != nil {
					t.Fatal(vector.ID, err)
				}
				actual, err := os.ReadFile(output)
				if err != nil || report.Hash != fmt.Sprintf("%x", sha256.Sum256(actual)) {
					t.Fatal("add preview/apply hash mismatch", vector.ID, err)
				}
				if present {
					if !bytes.Equal(actual, vectors.Source) || report.Updated != "2026-10-01" || !slices.Equal(report.Present, []string{"0x10"}) {
						t.Fatal("already-present batch changed source bytes/date/metadata", vector.ID)
					}
				} else {
					wantDoc := maps.Clone(originalDoc)
					newEntry := maps.Clone(vector.Body)
					newEntry["id"] = json.RawMessage(`"0x20"`)
					wantDoc["entries"], err = json.Marshal([]map[string]json.RawMessage{originalEntries[0], newEntry})
					if err != nil {
						t.Fatal(err)
					}
					wantDoc["last_updated"] = json.RawMessage(`"2026-10-20"`)
					var gotDoc map[string]json.RawMessage
					if json.Unmarshal(actual, &gotDoc) != nil {
						t.Fatal("invalid added registry")
					}
					want, _ := json.Marshal(wantDoc)
					got, _ := json.Marshal(gotDoc)
					if !bytes.Equal(got, want) || report.Updated != "2026-10-20" || !slices.Equal(report.Added, []string{"0x20"}) || !bytes.Contains(actual, []byte("9007199254740993")) {
						t.Fatal("add changed undeclared data", vector.ID, string(actual))
					}
				}
				for _, existing := range []string{sourcePath, output} {
					if err := run(append(slices.Clone(args), "--apply", "--output", existing), io.Discard); err == nil {
						t.Fatal("add overwrote existing file", vector.ID, existing)
					}
				}
				if after, err := os.ReadFile(sourcePath); err != nil || !bytes.Equal(after, vectors.Source) {
					t.Fatal("add changed source", err)
				}
				if after, err := os.ReadFile(profilePath); err != nil || !bytes.Equal(after, profileData) {
					t.Fatal("add changed profile", err)
				}
				if err := os.Remove(output); err != nil {
					t.Fatal(err)
				}
			}
			// Mixed new/present entries sort numerically, including IDs whose lexical order differs.
			body := map[string]json.RawMessage{"jp": json.RawMessage(`"あ"`), "en": json.RawMessage(`""`), "status": json.RawMessage(`"drafted"`), "source_pool": json.RawMessage(`"unknown"`), "opaque": json.RawMessage(`{"n":1.2300e+45,"x":1,"x":2}`)}
			present := map[string]json.RawMessage{"jp": json.RawMessage(`"あ"`), "en": json.RawMessage(`"A"`), "status": json.RawMessage(`"drafted"`), "source_pool": json.RawMessage(`"incoming ignored"`)}
			request := map[string]any{"operation": "registry_add", "source_size": len(vectors.Source), "source_sha256": fmt.Sprintf("%x", sha256.Sum256(vectors.Source)), "evidence": "Mixed numeric order and raw preservation", "updated": "2026-10-20", "registry_updates": map[string]map[string]json.RawMessage{"0x100": body, "0x2": body, "0x10": present}}
			profilePath := jsonFile("registry-add-updates.json", request)
			args := []string{"--source", sourcePath, "--recipes", profilePath}
			output := filepath.Join(dir, "registry-add-mixed.json")
			if err := run(append(slices.Clone(args), "--apply", "--output", output), io.Discard); err != nil {
				t.Fatal(err)
			}
			actual, err := os.ReadFile(output)
			var doc struct {
				Entries []map[string]json.RawMessage `json:"entries"`
			}
			if err != nil || json.Unmarshal(actual, &doc) != nil || len(doc.Entries) != 3 || string(doc.Entries[0]["id"]) != `"0x2"` || string(doc.Entries[1]["id"]) != `"0X0010"` || string(doc.Entries[2]["id"]) != `"0x100"` || bytes.Count(actual, []byte("1.2300e+45")) != 2 || bytes.Count(actual, []byte(`"x":`)) != 4 {
				t.Fatal("mixed add lost numeric order/raw values", err, string(actual))
			}
			for _, mutation := range []string{"null jp", "null en", "numeric en", "null status", "empty pool", "null pool", "inner ID", "out of range ID", "duplicate key", "duplicate root", "surrogate new", "surrogate old", "extra field", "bad date", "image fields", "stale hash", "glyph input", "registry input", "empty updates"} {
				bad := maps.Clone(request)
				row := maps.Clone(body)
				bad["registry_updates"] = map[string]map[string]json.RawMessage{"20": row}
				badArgs := slices.Clone(args)
				switch mutation {
				case "null jp":
					row["jp"] = json.RawMessage(`null`)
				case "null en":
					row["en"] = json.RawMessage(`null`)
				case "numeric en":
					row["en"] = json.RawMessage(`1`)
				case "null status":
					row["status"] = json.RawMessage(`null`)
				case "empty pool":
					row["source_pool"] = json.RawMessage(`""`)
				case "null pool":
					row["source_pool"] = json.RawMessage(`null`)
				case "inner ID":
					row["id"] = json.RawMessage(`"20"`)
				case "out of range ID":
					bad["registry_updates"] = map[string]map[string]json.RawMessage{"100000000": row}
				case "surrogate new":
					row["en"] = json.RawMessage(`"\ud800"`)
				case "surrogate old":
					old := bytes.ReplaceAll(vectors.Source, []byte(`"A"`), []byte(`"\ud800"`))
					write("registry-add-source.json", old)
					bad["source_size"], bad["source_sha256"] = len(old), fmt.Sprintf("%x", sha256.Sum256(old))
					row["en"] = json.RawMessage(`"\ufffd"`)
					bad["registry_updates"] = map[string]map[string]json.RawMessage{"10": row}
				case "extra field":
					bad["other"] = true
				case "bad date":
					bad["updated"] = "yesterday"
				case "image fields":
					bad["iso_elf_offset"] = "0x0"
				case "stale hash":
					bad["source_sha256"] = strings.Repeat("0", 64)
				case "glyph input":
					badArgs = append(badArgs, "--glyphmap", sourcePath)
				case "registry input":
					badArgs = append(badArgs, "--registry", sourcePath)
				case "empty updates":
					bad["registry_updates"] = map[string]map[string]json.RawMessage{}
				}
				jsonFile("registry-add-updates.json", bad)
				if mutation == "duplicate key" || mutation == "duplicate root" {
					raw, err := os.ReadFile(profilePath)
					if err != nil {
						t.Fatal(err)
					}
					before := bytes.Clone(raw)
					if mutation == "duplicate key" {
						raw = bytes.Replace(raw, []byte(`"en":""`), []byte(`"en":"","en":"B"`), 1)
					} else {
						raw = bytes.Replace(raw, []byte(`"operation":"registry_add"`), []byte(`"operation":"registry_add","operation":"registry_add"`), 1)
					}
					if bytes.Equal(before, raw) {
						t.Fatal("duplicate fixture was not mutated", mutation)
					}
					write("registry-add-updates.json", raw)
				}
				refused := filepath.Join(dir, "registry-add-refused.json")
				var out bytes.Buffer
				if err := run(append(badArgs, "--apply", "--output", refused), &out); err == nil || out.Len() != 0 {
					t.Fatal("invalid addition admitted", mutation, err, out.String())
				}
				if _, err := os.Stat(refused); !os.IsNotExist(err) {
					t.Fatal("invalid addition created output", mutation, err)
				}
				write("registry-add-source.json", vectors.Source)
			}
			for _, path := range []string{sourcePath, profilePath, output} {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
		}

		{
			original := []byte(`{"entries":[{"id":"0X0010","en":"Old","jp":"元","status":"drafted","note":{"old":true},"ref_sites":[{"vma":"123"}],"opaque":{"x":1,"x":2}},{"id":"20","en":"Installed","status":"patched","patch_ref":"disc","note":"prior"}],"last_updated":"2000-01-01","root_extra":{"number":1.2300e+45}}`)
			english := "新しい <Name>&😀|Next"
			en, _ := json.Marshal(english)
			updates := map[string]map[string]json.RawMessage{"10": {"en": en, "note": json.RawMessage(`""`)}, "20": {"en": json.RawMessage(`"Installed"`), "note": json.RawMessage(`"Checked"`)}}
			request := map[string]any{"operation": "registry_author", "source_size": len(original), "source_sha256": fmt.Sprintf("%x", sha256.Sum256(original)), "evidence": "synthetic author ownership", "updated": "2026-10-19", "registry_updates": updates}
			write("registry-source.json", original)
			profilePath := jsonFile("registry-updates.json", request)
			validProfile, err := os.ReadFile(profilePath)
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"--source", sourcePath, "--recipes", profilePath}
			var preview, repeat bytes.Buffer
			before, _ := os.ReadDir(dir)
			if err := run(args, &preview); err != nil {
				t.Fatal(err)
			}
			if err := run(args, &repeat); err != nil || !bytes.Equal(preview.Bytes(), repeat.Bytes()) {
				t.Fatal("author preview nondeterministic", err)
			}
			after, _ := os.ReadDir(dir)
			if len(before) != len(after) {
				t.Fatal("author preview wrote files")
			}
			output := filepath.Join(dir, "registry-authored.json")
			if err := run(append(slices.Clone(args), "--apply", "--output", output), io.Discard); err != nil {
				t.Fatal(err)
			}
			actual, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			var expected, got map[string]any
			if json.Unmarshal(original, &expected) != nil || json.Unmarshal(actual, &got) != nil {
				t.Fatal("invalid author output")
			}
			expected["last_updated"] = request["updated"]
			expected["entries"].([]any)[0].(map[string]any)["en"] = english
			expected["entries"].([]any)[0].(map[string]any)["note"] = ""
			expected["entries"].([]any)[1].(map[string]any)["note"] = "Checked"
			if !reflect.DeepEqual(got, expected) || !bytes.Contains(actual, []byte("1.2300e+45")) || bytes.Count(actual, []byte(`"x":`)) != 2 {
				t.Fatal("author changed undeclared fields/opaque lexemes/order")
			}
			var report struct {
				Output string `json:"output_sha256"`
			}
			if json.Unmarshal(preview.Bytes(), &report) != nil || report.Output != fmt.Sprintf("%x", sha256.Sum256(actual)) {
				t.Fatal("author preview/apply mismatch")
			}
			for _, existing := range []string{sourcePath, output} {
				if err := run(append(slices.Clone(args), "--apply", "--output", existing), io.Discard); err == nil {
					t.Fatal("author overwrote existing file")
				}
			}
			if err := os.Remove(output); err != nil {
				t.Fatal(err)
			}
			for _, status := range []string{`"drafted"`, `"zone_pending"`, `"patched"`, `"decode_verified"`, `"emulator_confirmed"`, `"superseded"`, `null`, `[]`} {
				for _, en := range []string{`"Old"`, `"Changed"`} {
					body := []byte(fmt.Sprintf(`{"entries":[{"id":"10","en":"Old","status":%s}]}`, status))
					request["source_size"], request["source_sha256"] = len(body), fmt.Sprintf("%x", sha256.Sum256(body))
					request["registry_updates"] = map[string]map[string]json.RawMessage{"10": {"en": json.RawMessage(en), "note": json.RawMessage(`"safe"`)}}
					write("registry-source.json", body)
					jsonFile("registry-updates.json", request)
					accepted := en == `"Old"` || status == `"drafted"` || status == `"zone_pending"`
					for _, apply := range []bool{false, true} {
						call := slices.Clone(args)
						if apply {
							call = append(call, "--apply", "--output", output)
						}
						var report bytes.Buffer
						err := run(call, &report)
						if (err == nil) != accepted || err != nil && report.Len() != 0 {
							t.Fatalf("author lock %s/%s/apply%t: %v", status, en, apply, err)
						}
						if apply && accepted {
							if err := os.Remove(output); err != nil {
								t.Fatal(err)
							}
						} else if _, err := os.Stat(output); !os.IsNotExist(err) {
							t.Fatal("author refusal created output")
						}
					}
					if unchanged, err := os.ReadFile(sourcePath); err != nil || !bytes.Equal(unchanged, body) {
						t.Fatal("author changed source", err)
					}
				}
			}
			write("registry-source.json", original)
			for _, old := range []string{`"\ud800"`, `"\udc00"`, `"\ud800\u0041"`} {
				for _, status := range []string{"patched", "decode_verified", "emulator_confirmed", "superseded"} {
					body := []byte(fmt.Sprintf(`{"entries":[{"id":"10","en":%s,"status":"%s"}]}`, old, status))
					for _, field := range []string{"en", "note"} {
						request["source_size"], request["source_sha256"] = len(body), fmt.Sprintf("%x", sha256.Sum256(body))
						request["registry_updates"] = map[string]map[string]json.RawMessage{"10": {field: json.RawMessage(`"�"`)}}
						write("registry-source.json", body)
						jsonFile("registry-updates.json", request)
						for _, apply := range []bool{false, true} {
							call := slices.Clone(args)
							if apply {
								call = append(call, "--apply", "--output", output)
							}
							var report bytes.Buffer
							err := run(call, &report)
							if (err == nil) != (field == "note") || err != nil && (!strings.Contains(err.Error(), "paired Unicode surrogates") || report.Len() != 0) {
								t.Fatalf("selected old EN repaired before lock: %s/%s/%s: %v", old, status, field, err)
							}
							if apply && field == "note" {
								out, readErr := os.ReadFile(output)
								if readErr != nil || !bytes.Contains(out, []byte(old)) {
									t.Fatal("note-only changed unselected opaque EN", readErr)
								}
								if err := os.Remove(output); err != nil {
									t.Fatal(err)
								}
							} else if _, err := os.Stat(output); !os.IsNotExist(err) {
								t.Fatal("surrogate refusal created output")
							}
						}
					}
				}
			}
			write("registry-source.json", original)
			for _, c := range []struct{ field, value string }{
				{"en", `null`}, {"note", `null`}, {"en", `""`}, {"en", `1`}, {"note", `true`}, {"en", `{}`}, {"note", `[]`}, {"en", `"\ud800"`}, {"note", `"\udc00"`}, {"en", `"\ud800\u0041"`}, {"status", `"drafted"`}, {"jp", `"replace"`}, {"patch_ref", `"wrong"`}, {"unknown", `1`},
			} {
				var bad map[string]json.RawMessage
				json.Unmarshal(validProfile, &bad)
				value, _ := json.Marshal(map[string]map[string]json.RawMessage{"10": {c.field: json.RawMessage(c.value)}})
				bad["registry_updates"] = value
				jsonFile("registry-updates.json", bad)
				for _, apply := range []bool{false, true} {
					call := slices.Clone(args)
					if apply {
						call = append(call, "--apply", "--output", output)
					}
					var out bytes.Buffer
					if err := run(call, &out); err == nil || out.Len() != 0 {
						t.Fatalf("author admitted%s=%s", c.field, c.value)
					}
					if _, err := os.Stat(output); !os.IsNotExist(err) {
						t.Fatal("bad author value created output")
					}
				}
			}
			for _, raw := range []string{
				`{"entries":[{"id":"10","en":"Old","status":"drafted","note":"a","note":"b"}]}`,
				`{"entries":[{"id":"10","en":"Old","status":"drafted","note":"a","no\u0074e":"b"}]}`,
				`{"entries":[],"entries":[{"id":"10","en":"Old","status":"drafted"}]}`,
				`{"entries":[],"entr\u0069es":[{"id":"10","en":"Old","status":"drafted"}]}`,
			} {
				var bad map[string]json.RawMessage
				json.Unmarshal(validProfile, &bad)
				bad["source_size"], _ = json.Marshal(len(raw))
				bad["source_sha256"], _ = json.Marshal(fmt.Sprintf("%x", sha256.Sum256([]byte(raw))))
				bad["registry_updates"] = json.RawMessage(`{"10":{"en":"New"}}`)
				write("registry-source.json", []byte(raw))
				jsonFile("registry-updates.json", bad)
				for _, apply := range []bool{false, true} {
					call := slices.Clone(args)
					if apply {
						call = append(call, "--apply", "--output", output)
					}
					if err := run(call, io.Discard); err == nil || !strings.Contains(err.Error(), "duplicate registry object key") {
						t.Fatal("author collapsed duplicate source key or wrong guard", raw, err)
					}
					if _, err := os.Stat(output); !os.IsNotExist(err) {
						t.Fatal("ambiguous author source created output")
					}
				}
			}
			write("registry-source.json", original)
			for _, rawUpdates := range []string{
				`{"10":{"en":"One","en":"Two"}}`, `{"10":{"en":"One","\u0065n":"Two"}}`, `{"10":{"en":"One"},"10":{"en":"Two"}}`, `{"10":{"en":"One"},"\u0031\u0030":{"en":"Two"}}`, `{"10":{"en":"One"},"0X0010":{"en":"Two"}}`,
			} {
				raw := fmt.Sprintf(`{"operation":"registry_author","source_size":%d,"source_sha256":"%x","evidence":"test","updated":"2026-10-19","registry_updates":%s}`, len(original), sha256.Sum256(original), rawUpdates)
				write("registry-updates.json", []byte(raw))
				if err := run(append(slices.Clone(args), "--apply", "--output", output), io.Discard); err == nil {
					t.Fatal("author collapsed duplicate update key", rawUpdates)
				}
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatal("duplicate author update created output")
				}
			}
			for _, raw := range []string{
				strings.Replace(string(validProfile), `"operation":"registry_author"`, `"operation":"registry_author","operation":"registry_author"`, 1),
				strings.Replace(string(validProfile), `"operation":"registry_author"`, `"operation":"registry_author","oper\u0061tion":"registry_author"`, 1),
			} {
				write("registry-updates.json", []byte(raw))
				if err := run(append(slices.Clone(args), "--apply", "--output", output), io.Discard); err == nil || !strings.Contains(err.Error(), "duplicate registry object key") {
					t.Fatal("ambiguous author envelope admitted or wrong guard", err)
				}
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatal("ambiguous author table created output")
				}
			}
			for _, value := range []string{`"\ud83d\ude00"`, `"literal \\ud800"`} {
				var good map[string]json.RawMessage
				json.Unmarshal(validProfile, &good)
				updates, _ := json.Marshal(map[string]map[string]json.RawMessage{"10": {"en": json.RawMessage(value)}})
				good["registry_updates"] = updates
				jsonFile("registry-updates.json", good)
				if err := run(args, io.Discard); err != nil {
					t.Fatal("valid author Unicode/literalescape refused", err)
				}
			}
			for _, invalid := range []string{"date", "hash", "evidence", "unknown input", "extra image field", "missing field", "empty row", "null row", "missing ID", "extra operation", "extra recipe"} {
				var bad map[string]json.RawMessage
				json.Unmarshal(validProfile, &bad)
				call := slices.Clone(args)
				switch invalid {
				case "date":
					bad["updated"] = json.RawMessage(`"2026-02-30"`)
				case "hash":
					bad["source_sha256"] = json.RawMessage(`"wrong"`)
				case "evidence":
					bad["evidence"] = json.RawMessage(`""`)
				case "unknown input":
					call = append(call, "--registry", sourcePath)
				case "extra image field":
					bad["placement"] = json.RawMessage(`""`)
				case "missing field":
					delete(bad, "updated")
				case "empty row":
					bad["registry_updates"] = json.RawMessage(`{"10":{}}`)
				case "null row":
					bad["registry_updates"] = json.RawMessage(`{"10":null}`)
				case "missing ID":
					bad["registry_updates"] = json.RawMessage(`{"99":{"en":"New"}}`)
				case "extra operation":
					call = append(call, "--fit-profile", profilePath)
				case "extra recipe":
					call = append(call, "--recipes", profilePath)
				}
				jsonFile("registry-updates.json", bad)
				if err := run(append(call, "--apply", "--output", output), io.Discard); err == nil {
					t.Fatal("invalid author request admitted", invalid)
				}
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatal("invalid author request created output")
				}
			}
			write("registry-updates.json", validProfile)
			for _, extra := range [][]string{{"--apply", "--output", filepath.Join(dir, "registry-symlink.json")}, {"--output", output}, {"--apply"}} {
				if err := run(append(slices.Clone(args), extra...), io.Discard); err == nil {
					t.Fatal("unsafe author output admitted", extra)
				}
			}
			if preserved, err := os.ReadFile(sourcePath); err != nil || !bytes.Equal(preserved, original) {
				t.Fatal("author refusal changed source", err)
			}
		}
		// Keep the existing image CLI fixture's directory-count assertion independent.
		for _, path := range []string{"registry-source.json", "registry-updates.json", "registry-merged.json", "registry-shrunken.json", "registry-opaque.json", "registry-symlink.json", "registry-mixed/a.json", "registry-mixed/b.json", "registry-mixed"} {
			if err := os.Remove(filepath.Join(dir, path)); err != nil {
				t.Fatal(err)
			}
		}
	}
	args := []string{"--source", write("source.iso", sourceImage), "--registry", jsonFile("registry.json", registry), "--recipes", jsonFile("recipes.json", r), "--glyphmap", write("glyphs.json", glyphs)}
	var out bytes.Buffer
	if err := run(args, &out); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadDir(dir)
	if len(before) != 4 || !strings.Contains(out.String(), `"applied": false`) {
		t.Fatal("dry run wrote output or bad report")
	}
	output := filepath.Join(dir, "copy.iso")
	out.Reset()
	applyArgs := append(append([]string{}, args...), "--apply", "--output", output)
	if err := run(applyArgs, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"applied": true`) {
		t.Fatal("bad apply report")
	}
	if err := run(applyArgs, io.Discard); err == nil {
		t.Fatal("CLI overwrote output")
	}
	for _, extra := range [][]string{{"extra"}, {"--apply"}, {"--output", filepath.Join(dir, "unused.iso")}, {"--unknown"}} {
		if err := run(append(append([]string{}, args...), extra...), io.Discard); err == nil {
			t.Fatal("accepted invalid CLI")
		}
	}
	// Put the later fixed field first on disk to exercise combined ordering.
	copy(sourceImage[32:36], []byte{4, 0, 0, 0})
	r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(sourceImage))
	fixed := r
	fixed.Operation = "fixed_field"
	fixed.Entries = map[string]Recipe{"0x20": {ExpectedHex: "04000000", Evidence: "synthetic bounded fixed field"}}
	registry.Entries = append(registry.Entries, registry.Entries[0])
	registry.Entries[1].ID, registry.Entries[1].EN = "0x20", "B"
	write("source.iso", sourceImage)
	jsonFile("registry.json", registry)
	tableDir := filepath.Join(dir, "tables")
	if err := os.Mkdir(tableDir, 0700); err != nil {
		t.Fatal(err)
	}
	jsonFile("tables/z-stream.json", r)
	jsonFile("tables/a-fixed.json", fixed)
	args[5] = tableDir
	out.Reset()
	if err := run(args, &out); err != nil {
		t.Fatal(err)
	}
	var report struct {
		Edits []Edit `json:"edits"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Edits) != 2 || report.Edits[0].ID != "0x10" || report.Edits[1].ID != "0x20" {
		t.Fatal("combined report is incomplete or unordered")
	}
	mixedOutput := filepath.Join(dir, "mixed.iso")
	if err := run(append(append([]string{}, args...), "--apply", "--output", mixedOutput), io.Discard); err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(sourceImage)
	copy(want[16:20], []byte{1, 0, 0, 0xf8})
	copy(want[32:36], []byte{2, 0, 0, 0})
	patched, err := os.ReadFile(mixedOutput)
	if err != nil || !bytes.Equal(patched, want) {
		t.Fatal("mixed-profile copy differs from complete expected image")
	}
	registry.Entries = append(registry.Entries, RegistryEntry{ID: "0x12", EN: "B"})
	for _, name := range []string{"duplicate ID", "normalized duplicate ID", "overlap", "source hash", "source size", "glyphmap", "operation", "empty table", "malformed table"} {
		bad := fixed
		entry := fixed.Entries["0x20"]
		bad.Entries = map[string]Recipe{"0x20": entry}
		switch name {
		case "duplicate ID":
			bad.Entries = map[string]Recipe{"0x10": entry}
		case "normalized duplicate ID":
			bad.Entries = map[string]Recipe{"0X0010": entry}
		case "overlap":
			bad.Entries = map[string]Recipe{"0x12": entry}
		case "source hash":
			bad.SourceSHA256 = strings.Repeat("1", 64)
		case "source size":
			bad.SourceSize++
		case "glyphmap":
			bad.GlyphmapSHA256 = strings.Repeat("1", 64)
		case "operation":
			bad.Operation = "unknown"
		case "empty table":
			bad.Entries = nil
		}
		jsonFile("tables/a-fixed.json", bad)
		if name == "malformed table" {
			write("tables/a-fixed.json", []byte("{"))
		}
		refused := filepath.Join(dir, "refused.iso")
		if err := run(append(append([]string{}, args...), "--apply", "--output", refused), io.Discard); err == nil {
			t.Fatalf("accepted batch %s", name)
		}
		if _, err := os.Stat(refused); !os.IsNotExist(err) {
			t.Fatalf("created batch output for %s", name)
		}
	}
	emptyDir := filepath.Join(dir, "empty")
	if err := os.Mkdir(emptyDir, 0700); err != nil {
		t.Fatal(err)
	}
	args[5] = emptyDir
	if err := run(args, io.Discard); err == nil {
		t.Fatal("accepted empty recipe directory")
	}
	original, err := os.ReadFile(filepath.Join(dir, "source.iso"))
	if err != nil || !bytes.Equal(original, sourceImage) {
		t.Fatal("batch processing changed source")
	}
	copy(sourceImage[40:48], []byte{0x30, 0, 0, 0, 0x30, 0, 0, 0})
	write("source.iso", sourceImage)
	r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(sourceImage))
	fixed.SourceSHA256 = r.SourceSHA256
	refs := r
	refs.Operation = "pointer_check"
	refs.Entries = nil
	refs.RegistryPatchRef = "synthetic-family"
	refs.Evidence = "synthetic exact canonical sites"
	refs.ScopeSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte{0x30, 0, 0, 0, 0x28, 0, 0, 0, 0x30, 0, 0, 0, 0x2c, 0, 0, 0}))
	var pointerRegistry Registry
	if err := json.Unmarshal([]byte(`{"entries":[{"id":"0x30","patch_ref":"synthetic-family","ref_type":"pointer_array","ref_sites":[{"pointer_vma":"0x28"},{"pointer_vma":"0x2c"}]}]}`), &pointerRegistry); err != nil {
		t.Fatal(err)
	}
	pointerRegistry.Entries = append(pointerRegistry.Entries, registry.Entries...)
	jsonFile("registry.json", pointerRegistry)
	args[5] = jsonFile("pointers.json", refs)
	out.Reset()
	if err := run(args, &out); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Edits) != 2 || report.Edits[0].Operation != "pointer_check" || report.Edits[0].Offset != 40 || report.Edits[1].Offset != 44 {
		t.Fatal("bad multi-site pointer report")
	}
	pointerEdits, err := plan([]Recipes{refs}, pointerRegistry, glyphs, nil)
	if err != nil {
		t.Fatal(err)
	}
	gpRegistry := pointerRegistry
	gpRegistry.Entries = slices.Clone(pointerRegistry.Entries)
	gpRegistry.Entries[0].RefType = "gp_relative"
	gpRegistry.Entries[0].RefSites = []ReferenceSite{{ADDIUVMA: "0x28", Register: "$a0"}}
	if _, err := plan([]Recipes{refs}, gpRegistry, glyphs, nil); err == nil {
		t.Fatal("read-only GP observation became pointer-check authority")
	}
	pointerSource, err := os.Open(filepath.Join(dir, "source.iso"))
	if err != nil {
		t.Fatal(err)
	}
	defer pointerSource.Close()
	for _, name := range []string{"missing", "extra", "ID", "offset", "operation", "old", "new"} {
		bad := append([]Edit(nil), pointerEdits...)
		switch name {
		case "missing":
			bad = bad[:1]
		case "extra":
			bad = append(bad, bad[0])
		case "ID":
			bad[0].ID = "0x34"
		case "offset":
			bad[0].Offset = 36
		case "operation":
			bad[0].Operation = "fixed_field"
		case "old":
			bad[0].Old = []byte{0x31, 0, 0, 0}
		case "new":
			bad[0].New = []byte{0x31, 0, 0, 0}
		}
		if err := verifySource(pointerSource, []Recipes{refs}, bad, pointerRegistry, glyphs); err == nil {
			t.Fatalf("direct verifier accepted forged %s", name)
		}
	}
	if _, err := patchCopy(nil, filepath.Join(dir, "no-source.iso"), []Recipes{refs}, nil, Registry{}, nil); err == nil || !strings.Contains(err.Error(), "verification-only") {
		t.Fatalf("pointer apply touched invalid context before refusal: %v", err)
	}
	jsonFile("tables/a-fixed.json", fixed)
	jsonFile("tables/z-stream.json", r)
	jsonFile("tables/pointers.json", refs)
	for _, path := range []string{filepath.Join(dir, "pointers.json"), tableDir} {
		args[5] = path
		refused := filepath.Join(dir, "read-only.iso")
		err := run(append(append([]string{}, args...), "--apply", "--output", refused), io.Discard)
		if err == nil || !strings.Contains(err.Error(), "verification-only") {
			t.Fatalf("pointer apply not explicitly refused: %v", err)
		}
		if _, err := os.Stat(refused); !os.IsNotExist(err) {
			t.Fatal("pointer check created output")
		}
	}
	args[5] = filepath.Join(dir, "pointers.json")
	for _, name := range []string{"missing selector", "wrong selector", "missing hash", "invalid hash", "wrong hash", "explicit entries", "text selector"} {
		bad := refs
		switch name {
		case "missing selector":
			bad.RegistryPatchRef = ""
		case "wrong selector":
			bad.RegistryPatchRef = "absent-family"
		case "missing hash":
			bad.ScopeSHA256 = ""
		case "invalid hash":
			bad.ScopeSHA256 = "zz"
		case "wrong hash":
			bad.ScopeSHA256 = strings.Repeat("1", 64)
		case "explicit entries":
			bad.Entries = r.Entries
		case "text selector":
			bad.Operation, bad.Entries = r.Operation, r.Entries
		}
		jsonFile("pointers.json", bad)
		if err := run(args, io.Discard); err == nil {
			t.Fatalf("accepted invalid pointer scope: %s", name)
		}
	}
	jsonFile("pointers.json", refs)
	for _, name := range []string{"empty", "partial", "duplicate", "unaligned", "changed site", "wrong type", "changed ID", "added member", "removed member", "reordered"} {
		data, _ := json.Marshal(pointerRegistry)
		var bad Registry
		if err := json.Unmarshal(data, &bad); err != nil {
			t.Fatal(err)
		}
		entry := &bad.Entries[0]
		switch name {
		case "empty":
			entry.RefSites = nil
		case "partial":
			entry.RefSites = entry.RefSites[:1]
		case "duplicate":
			entry.RefSites[1] = entry.RefSites[0]
		case "unaligned":
			entry.RefSites[0].PointerVMA = "0x2a"
		case "changed site":
			entry.RefSites[0].PointerVMA = "0x24"
		case "wrong type":
			entry.RefType = "instruction_pair"
		case "changed ID":
			entry.ID = "0x34"
		case "added member":
			extra := *entry
			extra.ID = "0x34"
			extra.RefSites = extra.RefSites[:1:1]
			bad.Entries = append(bad.Entries, extra)
		case "removed member":
			entry.PatchRef = "other-family"
		case "reordered":
			entry.ID = "0X0030"
			entry.RefSites[0], entry.RefSites[1] = entry.RefSites[1], entry.RefSites[0]
			bad.Entries[0], bad.Entries[2] = bad.Entries[2], bad.Entries[0]
		}
		jsonFile("registry.json", bad)
		err := run(args, io.Discard)
		if (name == "reordered") != (err == nil) {
			t.Fatalf("wrong canonical scope result for %s: %v", name, err)
		}
	}
	jsonFile("registry.json", pointerRegistry)
	sourceImage[40] = 0x31
	write("source.iso", sourceImage)
	refs.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(sourceImage))
	jsonFile("pointers.json", refs)
	if err := run(args, io.Discard); err == nil || !strings.Contains(err.Error(), "unexpected image bytes") {
		t.Fatalf("bad pointer word accepted or wrong guard: %v", err)
	}
	copy(sourceImage[40:48], []byte{0x30, 0, 0, 4, 0x30, 0, 0, 4})
	write("source.iso", sourceImage)
	refs.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(sourceImage))
	refs.PointerState = "registry_landing"
	refs.ScopeSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte{0x30, 0, 0, 4, 0x28, 0, 0, 0, 0x30, 0, 0, 4, 0x2c, 0, 0, 0}))
	pointerRegistry.Entries[0].LandingVMA = "0x04000030"
	jsonFile("registry.json", pointerRegistry)
	jsonFile("pointers.json", refs)
	out.Reset()
	if err := run(args, &out); err != nil {
		t.Fatalf("current landing pointer check: %v", err)
	}
	var landingReport struct {
		Edits []struct {
			OldHex string `json:"old_hex"`
		} `json:"edits"`
	}
	if err := json.Unmarshal(out.Bytes(), &landingReport); err != nil || len(landingReport.Edits) != 2 || landingReport.Edits[0].OldHex != "30000004" || landingReport.Edits[1].OldHex != "30000004" {
		t.Fatalf("current landing report differs: %v", err)
	}
	pointerRegistry.Entries[0].LandingVMA = "0x04000040"
	jsonFile("registry.json", pointerRegistry)
	if err := run(args, io.Discard); err == nil {
		t.Fatal("accepted changed canonical landing in pointer check")
	}
	streamRecipe, streamRegistry, streamGlyphs, streamImage := fixture(t, "stream_append")
	write("source.iso", streamImage)
	write("glyphmap.json", streamGlyphs)
	jsonFile("registry.json", streamRegistry)
	args[5] = jsonFile("append.json", streamRecipe)
	out.Reset()
	if err := run(args, &out); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || len(report.Edits) != 5 {
		t.Fatalf("bad append CLI report: %v", err)
	}
	streamOutput := filepath.Join(dir, "appended.iso")
	if err := run(append(append([]string{}, args...), "--apply", "--output", streamOutput), io.Discard); err != nil {
		t.Fatal(err)
	}
	streamWant := bytes.Clone(streamImage)
	copy(streamWant[0x1010:], []byte{1, 0, 2, 0, 0, 0xf8})
	copy(streamWant[0x1020:], []byte{3, 0, 0, 0xf8})
	copy(streamWant[0xa00:], []byte{0x10, 0, 0, 4, 0x10, 0, 0, 4, 0x20, 0, 0, 4})
	streamGot, err := os.ReadFile(streamOutput)
	if err != nil || !bytes.Equal(streamGot, streamWant) {
		t.Fatal("CLI append differs from complete expected image")
	}
	streamEdits, err := plan([]Recipes{streamRecipe}, streamRegistry, streamGlyphs, bytes.NewReader(streamImage))
	if err != nil {
		t.Fatal(err)
	}
	streamSource, err := os.Open(filepath.Join(dir, "source.iso"))
	if err != nil {
		t.Fatal(err)
	}
	defer streamSource.Close()
	for _, name := range []string{"missing payload", "missing pointer", "destination", "payload", "old", "role", "ID"} {
		bad := append([]Edit(nil), streamEdits...)
		switch name {
		case "missing payload":
			bad = bad[:3]
		case "missing pointer":
			bad = bad[1:]
		case "destination":
			bad[0].New = []byte{0x30, 0, 0, 4}
		case "payload":
			bad[3].New = []byte{3, 0, 2, 0, 0, 0xf8}
		case "old":
			bad[3].Old = []byte{1, 0, 0, 0, 0, 0}
		case "role":
			bad[3].Operation = "same_length_stream"
		case "ID":
			bad[3].ID = "0x110"
		}
		refused := filepath.Join(dir, "forged-stream.iso")
		if _, err := patchCopy(streamSource, refused, []Recipes{streamRecipe}, bad, streamRegistry, streamGlyphs); err == nil {
			t.Fatalf("writer accepted forged stream %s", name)
		}
		if _, err := os.Stat(refused); !os.IsNotExist(err) {
			t.Fatal("created forged stream output")
		}
	}
	unchanged, err := os.ReadFile(filepath.Join(dir, "source.iso"))
	if err != nil || !bytes.Equal(unchanged, streamImage) {
		t.Fatal("append changed its source")
	}
	r, registry, glyphs, boundedImage := fixture(t, "stream_source")
	write("source.iso", boundedImage)
	write("glyphmap.json", glyphs)
	jsonFile("registry.json", registry)
	args[5] = jsonFile("bounded.json", r)
	out.Reset()
	if err := run(args, &out); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || len(report.Edits) != 6 {
		t.Fatalf("bounded CLI: %v", err)
	}
	boundedEdits, err := plan([]Recipes{r}, registry, glyphs, bytes.NewReader(boundedImage))
	if err != nil {
		t.Fatal(err)
	}
	boundedSource, err := os.Open(filepath.Join(dir, "source.iso"))
	if err != nil {
		t.Fatal(err)
	}
	defer boundedSource.Close()
	for _, forgery := range []string{"missing padding", "padding data", "padding target", "padding role", "padding extent", "source origin"} {
		bad := slices.Clone(boundedEdits)
		switch forgery {
		case "missing padding":
			bad = append(bad[:4:4], bad[5:]...)
		case "padding data":
			bad[4].New = []byte{1, 0}
		case "padding target":
			bad[4].Offset += 2
		case "padding role":
			bad[4].Operation = "fixed_field"
		case "padding extent":
			bad[4].Old, bad[4].New = make([]byte, 4), make([]byte, 4)
		case "source origin":
			bad[0].Old = []byte{0x10, 0, 0, 4}
		}
		output := filepath.Join(dir, "forged-bounded.iso")
		if _, err := patchCopy(boundedSource, output, []Recipes{r}, bad, registry, glyphs); err == nil {
			t.Fatalf("accepted forged %s", forgery)
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("created forged bounded output")
		}
	}
	unchanged, err = os.ReadFile(filepath.Join(dir, "source.iso"))
	if err != nil || !bytes.Equal(unchanged, boundedImage) {
		t.Fatal("bounded verifier modified source")
	}
	{
		fixtureData, err := os.ReadFile("testdata/markup-registry.json")
		if err != nil {
			t.Fatal(err)
		}
		var reference struct {
			SourceHex string `json:"source_hex"`
			ImageHex  string `json:"image_hex"`
			Glyphs    map[string]string
			Updates   map[string]json.RawMessage
			Tagged    int
		}
		if err := json.Unmarshal(fixtureData, &reference); err != nil {
			t.Fatal(err)
		}
		original, err := hex.DecodeString(reference.SourceHex)
		if err != nil {
			t.Fatal(err)
		}
		sourceImage, err := hex.DecodeString(reference.ImageHex)
		if err != nil {
			t.Fatal(err)
		}
		glyphData, _ := json.Marshal(reference.Glyphs)
		profile := Recipes{Operation: "registry_markup", SourceSize: int64(len(sourceImage)), SourceSHA256: fmt.Sprintf("%x", sha256.Sum256(sourceImage)), ScopeSHA256: fmt.Sprintf("%x", sha256.Sum256(original)), GlyphmapSHA256: fmt.Sprintf("%x", sha256.Sum256(glyphData)), ISOELFOffset: "0", ELFVMADelta: "0", Updated: "2026-10-17", Evidence: "actual Python metadata oracle on synthetic bytes"}
		sourcePath, registryPath, glyphPath := write("markup-source.bin", sourceImage), write("markup-registry.json", original), write("markup-glyphs.json", glyphData)
		profilePath := jsonFile("markup-profile.json", profile)
		args := []string{"--source", sourcePath, "--registry", registryPath, "--glyphmap", glyphPath, "--recipes", profilePath}
		var preview bytes.Buffer
		if err := run(args, &preview); err != nil {
			t.Fatal(err)
		}
		var report struct {
			Updates map[string]map[string]json.RawMessage
		}
		if err := json.Unmarshal(preview.Bytes(), &report); err != nil || len(report.Updates) != reference.Tagged {
			t.Fatalf("metadata preview: %s %v", preview.Bytes(), err)
		}
		for id, expected := range reference.Updates {
			var got, want any
			if err := json.Unmarshal(report.Updates[id]["midcontent_markup_shape"], &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(expected, &want); err != nil {
				t.Fatal(err)
			}
			a, _ := json.Marshal(got)
			b, _ := json.Marshal(want)
			if !bytes.Equal(a, b) {
				t.Fatalf("%s metadata: %s != %s", id, a, b)
			}
		}
		output := filepath.Join(dir, "markup-output.json")
		if err := run(append(append([]string{}, args...), "--apply", "--output", output), io.Discard); err != nil {
			t.Fatal(err)
		}
		if err := run(append(append([]string{}, args...), "--apply", "--output", output), io.Discard); err == nil {
			t.Fatal("metadata overwrote existing output")
		}
		got, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]json.RawMessage
		if err := json.Unmarshal(original, &document); err != nil {
			t.Fatal(err)
		}
		var entries []map[string]json.RawMessage
		if err := json.Unmarshal(document["entries"], &entries); err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			var id string
			_ = json.Unmarshal(entry["id"], &id)
			if expected, ok := reference.Updates[id]; ok {
				entry["midcontent_markup_shape"] = expected
			}
		}
		document["entries"], _ = json.Marshal(entries)
		document["last_updated"], _ = json.Marshal(profile.Updated)
		expected, _ := json.Marshal(document)
		var normalized [][]byte
		for _, raw := range [][]byte{got, expected} {
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.UseNumber()
			var value any
			if err := decoder.Decode(&value); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			normalized = append(normalized, data)
		}
		if !bytes.Equal(normalized[0], normalized[1]) {
			t.Fatal("metadata changed unrelated registry data or selection")
		}
		for path, expected := range map[string][]byte{sourcePath: sourceImage, registryPath: original, glyphPath: glyphData} {
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, expected) {
				t.Fatalf("metadata changed input %s", path)
			}
		}
		profileData, _ := json.Marshal(profile)
		for field, value := range map[string]any{"wording_field": "jp", "registry_updates": map[string]any{}, "source_sha256": strings.Repeat("0", 64), "source_size": len(sourceImage) - 1, "scope_sha256": strings.Repeat("0", 64), "glyphmap_sha256": strings.Repeat("0", 64), "iso_elf_offset": "no", "elf_vma_delta": "no", "updated": "bad", "evidence": "", "entries": map[string]any{"10": map[string]any{}}, "registry_patch_ref": "forged", "stream": map[string]any{}, "layout": map[string]any{}, "growth": map[string]any{}, "values": map[string]string{"forged": "1"}, "word_blocks": map[string]any{"forged": map[string]any{}}} {
			var bad map[string]any
			_ = json.Unmarshal(profileData, &bad)
			bad[field] = value
			for _, operation := range []string{"registry_markup", "text_shapes"} {
				bad["operation"] = operation
				jsonFile("markup-profile.json", bad)
				forbidden := filepath.Join(dir, "markup-forbidden.json")
				invalidArgs := append([]string{}, args...)
				if operation == "registry_markup" {
					invalidArgs = append(invalidArgs, "--apply", "--output", forbidden)
				}
				if err := run(invalidArgs, io.Discard); err == nil {
					t.Fatalf("metadata accepted invalid %s", field)
				}
				if _, err := os.Stat(forbidden); !os.IsNotExist(err) {
					t.Fatalf("metadata created output for invalid %s", field)
				}
			}
		}
		// The ordinary merge operation never gains permission to forge this derived field.
		merge := Recipes{Operation: "registry_merge", SourceSize: int64(len(original)), SourceSHA256: fmt.Sprintf("%x", sha256.Sum256(original)), Updated: profile.Updated, Evidence: profile.Evidence, RegistryUpdates: report.Updates}
		mergeArgs := []string{"--source", registryPath, "--recipes", jsonFile("markup-profile.json", merge), "--apply", "--output", filepath.Join(dir, "markup-forbidden.json")}
		if err := run(mergeArgs, io.Discard); err == nil {
			t.Fatal("ordinary merge accepted generated markup fields")
		}
		for _, c := range []struct {
			glyphs map[string]string
			tagged int
		}{
			{map[string]string{"01": "A"}, 0},
			{map[string]string{"0x1": "A"}, 0},
			{map[string]string{"1": "A", "0x1": "B"}, reference.Tagged},
			{map[string]string{"1": "A", "65536": "unused", "garbage": "unused", "-1": "unused"}, reference.Tagged},
		} {
			data, _ := json.Marshal(c.glyphs)
			write("markup-glyphs.json", data)
			profile.GlyphmapSHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
			jsonFile("markup-profile.json", profile)
			preview.Reset()
			if err := run(args, &preview); err != nil {
				t.Fatal(err)
			}
			report.Updates = nil
			if err := json.Unmarshal(preview.Bytes(), &report); err != nil || len(report.Updates) != c.tagged {
				t.Fatalf("noncanonical glyph key altered source grammar: %s %v", preview.Bytes(), err)
			}
		}
		write("markup-glyphs.json", glyphData)
		profile.GlyphmapSHA256 = fmt.Sprintf("%x", sha256.Sum256(glyphData))
		for _, c := range []struct {
			index   int
			field   string
			raw     json.RawMessage
			refused bool
		}{
			{0, "ref_sites", json.RawMessage(`[null]`), true},
			{0, "en", json.RawMessage(`123`), true},
			{11, "en", json.RawMessage(`123`), false},
			{12, "en", json.RawMessage(`123`), false},
		} {
			old := entries[c.index][c.field]
			entries[c.index][c.field] = c.raw
			document["entries"], _ = json.Marshal(entries)
			data, _ := json.Marshal(document)
			write("markup-registry.json", data)
			profile.ScopeSHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
			jsonFile("markup-profile.json", profile)
			err := run(args, io.Discard)
			entries[c.index][c.field] = old
			if (err != nil) != c.refused {
				t.Fatalf("metadata boundary index%d/%s error=%v", c.index, c.field, err)
			}
		}
		for _, entry := range entries {
			entry["status"] = json.RawMessage(`"patched"`)
		}
		document["entries"], _ = json.Marshal(entries)
		zeroSource, _ := json.Marshal(document)
		write("markup-registry.json", zeroSource)
		profile.ScopeSHA256 = fmt.Sprintf("%x", sha256.Sum256(zeroSource))
		jsonFile("markup-profile.json", profile)
		zeroOutput := filepath.Join(dir, "markup-zero.json")
		if err := run(append(append([]string{}, args...), "--apply", "--output", zeroOutput), io.Discard); err != nil {
			t.Fatal(err)
		}
		got, err = os.ReadFile(zeroOutput)
		if err != nil {
			t.Fatal(err)
		}
		var zero map[string]json.RawMessage
		if err := json.Unmarshal(got, &zero); err != nil {
			t.Fatal(err)
		}
		if string(zero["last_updated"]) != `"2026-10-17"` {
			t.Fatal("zero-tag save lost explicit date")
		}

		// The complete translated address determines the boundary, including below-delta IDs.
		for _, c := range []struct {
			base, id, delta uint64
			offset          int
		}{
			{16, 24, 32, 8},
			{16, 16, 32, 0},
			{16, 15, 32, -1},
			{16, 32, 32, 16},
			{16, 24, 0, 40},
			{16, 80, 0, 96},
			{0, 0, 0, 0},
			{16, 0xffffffff, 0, -1},
			{16, 0xffffffff, 0xffffffff, 16},
		} {
			sourceImage := make([]byte, 96)
			valid := c.offset >= 0 && c.offset+6 <= len(sourceImage)
			if valid {
				copy(sourceImage[c.offset:], []byte{1, 0, 0, 0x70, 0, 0xf8})
			}
			data, _ := json.Marshal(map[string]any{"entries": []map[string]any{{"id": fmt.Sprintf("0x%x", c.id), "status": "drafted", "ref_sites": []map[string]any{{"ptr_vma": "0x50"}}, "en": "{{PARAM:0x7000}}"}}})
			write("markup-source.bin", sourceImage)
			write("markup-registry.json", data)
			profile.SourceSize = int64(len(sourceImage))
			profile.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(sourceImage))
			profile.ScopeSHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
			profile.ISOELFOffset = fmt.Sprintf("0x%x", c.base)
			profile.ELFVMADelta = fmt.Sprintf("0x%x", c.delta)
			jsonFile("markup-profile.json", profile)
			preview.Reset()
			if err := run(args, &preview); err != nil {
				t.Fatal(err)
			}
			report.Updates = nil
			if err := json.Unmarshal(preview.Bytes(), &report); err != nil || (len(report.Updates) == 1) != valid {
				t.Fatalf("translated address base%#x+id%#x-delta%#x: %s %v", c.base, c.id, c.delta, preview.Bytes(), err)
			}
			if valid {
				var tag struct {
					Readiness string `json:"readiness"`
					Targets   int    `json:"n_target_tokens"`
				}
				if err := json.Unmarshal(report.Updates[fmt.Sprintf("0x%x", c.id)]["midcontent_markup_shape"], &tag); err != nil || tag.Readiness != "ready_as_is" || tag.Targets != 1 {
					t.Fatalf("translated source metadata: %s %v", preview.Bytes(), err)
				}
			}
		}
	}
	{
		data, err := os.ReadFile("testdata/text-shapes.json")
		if err != nil {
			t.Fatal(err)
		}
		var oracle struct {
			Cases []struct {
				Name             string
				ImageHex         string `json:"image_hex"`
				Registry         json.RawMessage
				Glyphs           map[string]string
				Base, Delta      string
				Shapes, Clusters json.RawMessage
			}
		}
		if err := json.Unmarshal(data, &oracle); err != nil {
			t.Fatal(err)
		}
		for _, c := range oracle.Cases {
			sourceImage, err := hex.DecodeString(c.ImageHex)
			if err != nil {
				t.Fatal(err)
			}
			glyphs, _ := json.Marshal(c.Glyphs)
			profile := Recipes{Operation: "text_shapes", SourceSize: int64(len(sourceImage)), SourceSHA256: fmt.Sprintf("%x", sha256.Sum256(sourceImage)), ScopeSHA256: fmt.Sprintf("%x", sha256.Sum256(c.Registry)), GlyphmapSHA256: fmt.Sprintf("%x", sha256.Sum256(glyphs)), ISOELFOffset: c.Base, ELFVMADelta: c.Delta, Updated: "2026-10-17", Evidence: "Actual Python fullreport mains on synthetic inputs"}
			sourcePath, registryPath, glyphPath := write("shapes-source.bin", sourceImage), write("shapes-registry.json", c.Registry), write("shapes-glyphs.json", glyphs)
			args := []string{"--source", sourcePath, "--registry", registryPath, "--glyphmap", glyphPath, "--recipes", jsonFile("shapes-profile.json", profile)}
			var output bytes.Buffer
			for repeat := 0; repeat < 3; repeat++ {
				output.Reset()
				if err := run(args, &output); err != nil {
					t.Fatalf("%s: %v", c.Name, err)
				}
				var report map[string]json.RawMessage
				if err := json.Unmarshal(output.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				for key, want := range map[string]json.RawMessage{"shapes": c.Shapes, "clusters": c.Clusters} {
					var normalized [][]byte
					for _, raw := range []json.RawMessage{report[key], want} {
						decoder := json.NewDecoder(bytes.NewReader(raw))
						decoder.UseNumber()
						var value any
						if err := decoder.Decode(&value); err != nil {
							t.Fatal(err)
						}
						encoded, err := json.Marshal(value)
						if err != nil {
							t.Fatal(err)
						}
						normalized = append(normalized, encoded)
					}
					if !bytes.Equal(normalized[0], normalized[1]) {
						t.Fatalf("%s %s differs from actual Python fullreport:\ngot %s\nwant %s", c.Name, key, normalized[0], normalized[1])
					}
				}
			}
			if c.Name == "ordered-240-source-streams-plus-selection" {
				for _, field := range []string{"en", "ref_type"} {
					var document map[string]json.RawMessage
					_ = json.Unmarshal(c.Registry, &document)
					var entries []map[string]json.RawMessage
					_ = json.Unmarshal(document["entries"], &entries)
					entries[0][field] = json.RawMessage(`123`)
					document["entries"], _ = json.Marshal(entries)
					bad, _ := json.Marshal(document)
					write("shapes-registry.json", bad)
					profile.ScopeSHA256 = fmt.Sprintf("%x", sha256.Sum256(bad))
					jsonFile("shapes-profile.json", profile)
					if err := run(args, io.Discard); err == nil {
						t.Fatalf("text report accepted nonstring %s", field)
					}
				}
				write("shapes-registry.json", c.Registry)
				profile.ScopeSHA256 = fmt.Sprintf("%x", sha256.Sum256(c.Registry))
				jsonFile("shapes-profile.json", profile)
			}
			forbidden := filepath.Join(dir, "shapes-forbidden.json")
			if err := run(append(append([]string{}, args...), "--apply", "--output", forbidden), io.Discard); err == nil {
				t.Fatal("read-only text report accepted apply")
			}
			if _, err := os.Stat(forbidden); !os.IsNotExist(err) {
				t.Fatal("read-only text report created output")
			}
			for path, want := range map[string][]byte{sourcePath: sourceImage, registryPath: c.Registry, glyphPath: glyphs} {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("text report modified %s", path)
				}
			}
		}
	}

	{
		labels, reg, glyphData, source := fixture(t, "stream_reflow_labels")
		input := write("labels-source.iso", source)
		args := []string{"--source", input, "--registry", jsonFile("labels-registry.json", reg), "--recipes", jsonFile("labels-recipes.json", labels), "--glyphmap", write("labels-glyphs.json", glyphData)}
		var report bytes.Buffer
		if err := run(args, &report); err != nil || !strings.Contains(report.String(), `"stream_label_payload"`) || !strings.Contains(report.String(), `"applied": false`) {
			t.Fatalf("positional CLI preview: %s, %v", report.String(), err)
		}
		output := filepath.Join(dir, "labels-copy.iso")
		apply := append(slices.Clone(args), "--apply", "--output", output)
		if err := run(apply, io.Discard); err != nil {
			t.Fatal(err)
		}
		want := bytes.Clone(source)
		for offset, pointer := range map[int]uint32{0xa00: 0x04000010, 0xa04: 0x04000010, 0xa08: 0x04000030} {
			binary.LittleEndian.PutUint32(want[offset:], pointer)
		}
		copy(want[0x2010:], []byte{0, 0xb8, 0, 0xb0, 1, 0, 2, 0, 0, 0xd8, 0, 0xa0, 0xf6, 0xb8, 3, 0, 0, 0xf8})
		copy(want[0x2030:], []byte{3, 0, 0, 0xf8})
		actual, err := os.ReadFile(output)
		if err != nil || !bytes.Equal(actual, want) {
			t.Fatalf("positional CLI whole-copy oracle: %v", err)
		}
		if err := run(apply, io.Discard); err == nil {
			t.Fatal("positional CLI overwrote output")
		}
		original, err := os.ReadFile(input)
		if err != nil || !bytes.Equal(original, source) {
			t.Fatal("positional CLI changed source")
		}
	}
	{
		// Signed ADDIU, unsigned ORI, padding, row layouts and conflicting ownership.
		data := make([]byte, 0x9000)
		for offset, word := range map[int]uint32{0: 0x3c081000, 4: 0x35098000, 8: 0x3c081001, 12: 0x2509800a, 16: 0x3c0b1000, 20: 0x356b8010,
			0x80: 0x10008000, 0x84: 0x1000800a, 0x88: 0x10008010, 0x8c: 0x10008030, 0x91: 0x10008040, 0xa0: 0x10008060} {
			binary.LittleEndian.PutUint32(data[offset:], word)
		}
		for offset, word := range map[int]uint16{0x8000: 1, 0x8002: 0xf800, 0x800a: 2, 0x800c: 0xf800, 0x8014: 3, 0x8016: 0xf800,
			0x8020: 1, 0x8022: 2, 0x8028: 3, 0x8030: 4, 0x8032: 0xf800, 0x8040: 1, 0x8042: 0xf800, 0x8050: 1, 0x8052: 0xf800, 0x8060: 1, 0x8062: 0xf800} {
			binary.LittleEndian.PutUint16(data[offset:], word)
		}
		canonical := []byte(`{"entries":[{"id":"0x10008000","jp":"A","source_pool":"sample","chapter":"prologue","landing_vma":null},{"id":"0x10008008","jp":"B","source_pool":"sample","chapter":"prologue","landing_vma":"0x4000010"},{"id":"0x10008014","jp":"C","source_pool":"sample","chapter":"other"},{"id":"0x10008020","jp":"AB","source_pool":"sample","chapter":"prologue"},{"id":"0x10008030","jp":"あ","source_pool":"sample"},{"id":"0x10008040","jp":"A","source_pool":"sample"},{"id":"0x10008050","jp":"A","source_pool":"sample"},{"id":"0x1000805e","jp":"A","source_pool":"sample"},{"id":"0x10008060","jp":"A","source_pool":"sample"},{"id":"0x10008070","source_pool":"other","ref_sites":[{"pointer_vma":"0x100000a0"}]}]}`)
		glyphData := []byte(`{"1":"A","2":"B","3":"C","4":"あ"}`)
		profile := Recipes{Operation: "reference_candidates", SourceSize: int64(len(data)), SourceSHA256: fmt.Sprintf("%x", sha256.Sum256(data)),
			ScopeSHA256: fmt.Sprintf("%x", sha256.Sum256(canonical)), GlyphmapSHA256: fmt.Sprintf("%x", sha256.Sum256(glyphData)),
			ISOELFOffset: "0x0", ELFVMADelta: "0x10000000", Evidence: "synthetic reference candidates, not patch guards",
			References: &ReferenceScan{FileRange: AddressRange{"0x0", "0x9000"}, PointerMinVMA: "0x10000080", SkipWords: 8, DecodeWords: 500,
				Queries: map[string]ReferenceQuery{"sample": {SourcePool: "sample", ContentRange: AddressRange{"0x10008000", "0x10008100"}, Backward: true, CheckCollisions: true,
					StructRows: []ReferenceTable{{Start: "0x10008020", End: "0x10008030", Stride: 16}}, Excluded: map[string]string{"0x10008030": "known exclusion"}}}}}
		profile.References.Queries["unlanded"] = ReferenceQuery{Chapter: "prologue", UnlandedOnly: true,
			ContentRange: AddressRange{"0x10008000", "0x10008100"}, OmitIDs: []string{"0x10008020"}}
		sourcePath := write("references.bin", data)
		registryPath := write("references-registry.json", canonical)
		glyphPath := write("references-glyphs.json", glyphData)
		profilePath := jsonFile("references-profile.json", profile)
		args := []string{"--source", sourcePath, "--registry", registryPath, "--glyphmap", glyphPath, "--recipes", profilePath}
		before, _ := os.ReadDir(dir)
		var output bytes.Buffer
		if err := run(args, &output); err != nil {
			t.Fatal(err)
		}
		var report ReferenceReport
		if err := json.Unmarshal(output.Bytes(), &report); err != nil || report.Applied || len(report.Queries["sample"]) != 9 {
			t.Fatalf("reference report population/read-only: %v, %s", err, output.String())
		}
		if selected := report.Queries["unlanded"]; len(selected) != 1 || selected[0].ID != "0x10008000" {
			t.Fatalf("unlanded chapter/omit selection: %#v", selected)
		}
		rows := report.Queries["sample"]
		wantSummary := ReferenceSummary{Total: 9, Resolved: 6, Unresolved: 3, Hybrids: 3, MultiSite: 3, CollisionRows: 2,
			ByType: map[string]int{"pointer_array": 5, "struct_table_field": 1, "unknown": 3}}
		if !reflect.DeepEqual(report.Summaries["sample"], wantSummary) {
			t.Fatalf("reference summary: %#v", report.Summaries["sample"])
		}
		mismatched := bytes.Replace(canonical, []byte(`"jp":"A"`), []byte(`"jp":"Z"`), 1)
		mismatchPolicy := profile
		mismatchPolicy.ScopeSHA256 = fmt.Sprintf("%x", sha256.Sum256(mismatched))
		advisory, err := references(data, mismatched, glyphData, mismatchPolicy)
		if err != nil || advisory.Summaries["sample"].ContentMismatches != 1 || advisory.Summaries["unlanded"].ContentMismatches != 1 || advisory.Summaries["sample"].Resolved != 6 {
			t.Fatalf("content mismatches must remain advisory: %#v, %v", advisory, err)
		}
		for i, method := range []string{"direct", "forward(1w)", "backward(4B)", "struct-row", "excluded", "unresolved", "unresolved", "forward(1w)", "direct"} {
			if rows[i].Method != method {
				t.Fatalf("reference %s: got %s, want %s", rows[i].ID, rows[i].Method, method)
			}
			if rows[i].RefType != "unknown" && (rows[i].ContentOK == nil || !*rows[i].ContentOK) {
				t.Fatalf("reference %s content: %#v", rows[i].ID, rows[i])
			}
		}
		for i, lower := range []string{"0x10000004", "0x1000000c", "0x10000014"} {
			if !rows[i].Hybrid || len(rows[i].Sites) != 2 || rows[i].Sites[1].ADDIUVMA != lower {
				t.Fatalf("reference immediate arithmetic/site ordering: %#v", rows[i])
			}
		}
		if len(rows[5].UnfilteredSites) != 1 || rows[5].UnfilteredSites[0].PointerVMA != "0x10000091" || len(rows[6].UnfilteredSites) != 0 ||
			!slices.Equal(rows[7].Collisions, []string{"0x10008060", "0x10008070"}) || !slices.Equal(rows[8].Collisions, []string{"0x1000805e", "0x10008070"}) {
			t.Fatalf("reference raw recheck/collision evidence: %#v", rows)
		}
		for _, name := range []string{"different field", "pointer alias", "same field", "alternate base", "field overflow", "invalid offset", "shared high", "same pair"} {
			var document struct {
				Entries []map[string]json.RawMessage `json:"entries"`
			}
			if err := json.Unmarshal(canonical, &document); err != nil {
				t.Fatal(err)
			}
			site := ReferenceSite{StructVMA: "0x10008020", FieldOffset: "0x0"}
			want, rowIndex := true, 3
			switch name {
			case "different field":
				site.FieldOffset, want = "0x4", false
			case "pointer alias":
				site = ReferenceSite{PointerVMA: "0x10008020"}
			case "alternate base":
				site.StructVMA, site.FieldOffset = "0x1000801c", "0x4"
			case "field overflow":
				site.StructVMA, site.FieldOffset = "0xfffffff0", "0x20"
			case "invalid offset":
				site.FieldOffset = "invalid"
			case "shared high", "same pair":
				site, rowIndex = ReferenceSite{LUIVMA: "0x10000000", ADDIUVMA: "0x10000004"}, 0
				if name == "shared high" {
					site.ADDIUVMA, want = "0x1000000c", false
				}
			}
			document.Entries[len(document.Entries)-1]["ref_sites"], _ = json.Marshal([]ReferenceSite{site})
			registryBytes, _ := json.Marshal(document)
			policy := profile
			policy.ScopeSHA256 = fmt.Sprintf("%x", sha256.Sum256(registryBytes))
			got, err := references(data, registryBytes, glyphData, policy)
			if name == "field overflow" || name == "invalid offset" {
				if err == nil {
					t.Fatalf("reference ownership accepted %s", name)
				}
				continue
			}
			if err != nil || slices.Contains(got.Queries["sample"][rowIndex].Collisions, "0x10008070") != want {
				t.Fatalf("reference ownership %s: %#v, %v", name, got, err)
			}
		}
		for _, name := range []string{"source hash", "registry hash", "glyph hash", "scan bounds", "odd scan", "content range", "ID range", "query missing selector", "row stride", "duplicate ID", "JP type", "patch fields", "draft import", "wording selector", "mode missing"} {
			encoded, _ := json.Marshal(profile)
			var bad Recipes
			_ = json.Unmarshal(encoded, &bad)
			registryBytes := canonical
			q := bad.References.Queries["sample"]
			switch name {
			case "source hash":
				bad.SourceSHA256 = strings.Repeat("0", 64)
			case "registry hash":
				bad.ScopeSHA256 = strings.Repeat("0", 64)
			case "glyph hash":
				bad.GlyphmapSHA256 = strings.Repeat("0", 64)
			case "scan bounds":
				bad.References.FileRange.End = "0x10000"
			case "odd scan":
				bad.References.FileRange.Start = "0x1"
			case "content range":
				q.ContentRange.Start, q.IDRange = "invalid", &AddressRange{"0x10008000", "0x10008100"}
			case "ID range":
				q.IDRange = &AddressRange{"invalid", "0x10008100"}
			case "query missing selector":
				q.SourcePool = ""
			case "row stride":
				q.StructRows[0].Stride = 3
			case "duplicate ID":
				registryBytes = bytes.Replace(canonical, []byte("0x10008008"), []byte("0X10008000"), 1)
				bad.ScopeSHA256 = fmt.Sprintf("%x", sha256.Sum256(registryBytes))
			case "JP type":
				registryBytes = bytes.Replace(canonical, []byte(`"jp":"A"`), []byte(`"jp":123`), 1)
				bad.ScopeSHA256 = fmt.Sprintf("%x", sha256.Sum256(registryBytes))
			case "patch fields":
				bad.Entries = map[string]Recipe{"0x10008000": {}}
			case "wording selector":
				bad.WordingField = "jp"
			case "draft import":
				bad.RegistryImport = &RegistryImportSpec{}
			case "mode missing":
				bad.References = nil
			}
			if bad.References != nil {
				bad.References.Queries["sample"] = q
			}
			if _, err := references(data, registryBytes, glyphData, bad); err == nil {
				t.Fatalf("reference report accepted %s", name)
			}
		}
		forbidden := filepath.Join(dir, "references-forbidden.bin")
		if err := run(append(slices.Clone(args), "--apply", "--output", forbidden), io.Discard); err == nil {
			t.Fatal("reference report accepted apply")
		}
		if _, err := os.Stat(forbidden); !os.IsNotExist(err) {
			t.Fatal("reference report created an output")
		}
		after, _ := os.ReadDir(dir)
		if len(before) != len(after) {
			t.Fatal("reference preview wrote files")
		}
		for path, want := range map[string][]byte{sourcePath: data, registryPath: canonical, glyphPath: glyphData} {
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("reference report changed %s", path)
			}
		}
		imageProfile, reg, glyphs, source := fixture(t, "same_length_stream")
		imageProfile.References = profile.References
		if _, err := plan([]Recipes{imageProfile}, reg, glyphs, bytes.NewReader(source)); err == nil {
			t.Fatal("reference discovery leaked into guarded image planning")
		}
	}
	{
		reverse, reg, glyphData, input := fixture(t, "guarded_words_reverse")
		_, _, _, original := fixture(t, "guarded_words")
		sourcePath := write("reverse-source.iso", input)
		profilePath := jsonFile("reverse.json", reverse)
		args := []string{"--source", sourcePath, "--registry", jsonFile("reverse-registry.json", reg), "--glyphmap", write("reverse-glyphs.json", glyphData), "--recipes", profilePath}
		for _, apply := range []bool{false, true} {
			var out bytes.Buffer
			output := filepath.Join(dir, "reverse-copy.iso")
			command := slices.Clone(args)
			if apply {
				command = append(command, "--apply", "--output", output)
			}
			if err := run(command, &out); err != nil {
				t.Fatal("reverse CLI", err)
			}
			var report map[string]any
			if err := json.Unmarshal(out.Bytes(), &report); err != nil || report["expected_output_sha256"] != reverse.OutputSHA256 || report["applied"] != apply {
				t.Fatal("reverse CLI lost its output pin", err, out.String())
			}
			if apply {
				got, err := os.ReadFile(output)
				if err != nil || !bytes.Equal(got, original) || report["output_sha256"] != reverse.OutputSHA256 {
					t.Fatal("reverse CLI did not restore predecessor", err)
				}
				out.Reset()
				if err := run(command, &out); err == nil || out.Len() != 0 {
					t.Fatal("reverse CLI overwrote existing output")
				}
			} else if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("reverse preview created output", err)
			}
		}
		reverse.SourceSHA256 = strings.Repeat("0", 64)
		profilePath = jsonFile("reverse.json", reverse)
		var out bytes.Buffer
		if err := run(append(slices.Clone(args), "--apply", "--output", filepath.Join(dir, "reverse-invalid.iso")), &out); err == nil || out.Len() != 0 {
			t.Fatal("reverse CLI ignored source pin")
		}
		preserved, err := os.ReadFile(sourcePath)
		if err != nil || !bytes.Equal(preserved, input) {
			t.Fatal("reverse CLI changed source", err)
		}
	}
	for _, reverse := range []bool{false, true} {
		slot, reg, glyphData, original := fixture(t, "stream_slot")
		target := bytes.Clone(original)
		copy(target[16:32], []byte{0, 0x28, 1, 0, 0, 8, 2, 0, 0, 0x10, 0, 0xf8, 0, 0, 0, 0})
		clear(target[40:44])
		words := slot
		words.Operation = "guarded_words"
		words.Entries = map[string]Recipe{"0x28": {ExpectedHex: "cccccccc", Evidence: "CLI typed mixed transaction", Words: []Word{{Hex: "0", Assembly: "nop"}}}}
		input, want := original, target
		if reverse {
			input, want = target, original
			slot.WordingField = "jp"
			row := slot.Entries["0x10"]
			row.ExpectedHex, row.EncodedSHA256 = hex.EncodeToString(target[16:32]), fmt.Sprintf("%x", sha256.Sum256(original[16:32]))
			slot.Entries["0x10"] = row
			words.Entries["0x28"] = Recipe{ExpectedHex: "00000000", Evidence: "CLI explicit predecessor words", Words: []Word{{Hex: "cccccccc", Assembly: ".word original fixture bytes"}}}
		}
		slot.SourceSHA256, slot.OutputSHA256 = fmt.Sprintf("%x", sha256.Sum256(input)), fmt.Sprintf("%x", sha256.Sum256(want))
		words.SourceSHA256, words.OutputSHA256 = slot.SourceSHA256, slot.OutputSHA256
		sourcePath := write("slot-source.bin", input)
		registryPath, glyphPath := jsonFile("slot-registry.json", reg), write("slot-glyphs.json", glyphData)
		slotPath, wordsPath := jsonFile("slot.json", slot), jsonFile("slot-words.json", words)
		for _, wordsFirst := range []bool{false, true} {
			paths := []string{slotPath, wordsPath}
			if wordsFirst {
				paths[0], paths[1] = paths[1], paths[0]
			}
			args := []string{"--source", sourcePath, "--registry", registryPath, "--glyphmap", glyphPath, "--recipes", paths[0], "--recipes", paths[1]}
			output := filepath.Join(dir, fmt.Sprintf("slot-%v-%v.bin", reverse, wordsFirst))
			for _, apply := range []bool{false, true} {
				command := slices.Clone(args)
				if apply {
					command = append(command, "--apply", "--output", output)
				}
				var out bytes.Buffer
				if err := run(command, &out); err != nil {
					t.Fatal("mixed slot CLI", err)
				}
				var report map[string]any
				if err := json.Unmarshal(out.Bytes(), &report); err != nil || report["expected_output_sha256"] != slot.OutputSHA256 || report["applied"] != apply {
					t.Fatal("mixed slot CLI lost transaction binding", err)
				}
				if apply {
					got, err := os.ReadFile(output)
					if err != nil || !bytes.Equal(got, want) || report["output_sha256"] != slot.OutputSHA256 {
						t.Fatal("mixed slot CLI differs from complete independent bytes", err)
					}
					out.Reset()
					if err := run(command, &out); err == nil || out.Len() != 0 {
						t.Fatal("mixed slot CLI overwrote existing output")
					}
				} else if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatal("mixed slot preview created output", err)
				}
			}
		}
		for _, selector := range []string{"en", "JP", "other"} {
			bad := slot
			bad.WordingField = selector
			badPath := jsonFile("slot-bad-selector.json", bad)
			var out bytes.Buffer
			if err := run([]string{"--source", sourcePath, "--registry", registryPath, "--glyphmap", glyphPath, "--recipes", badPath, "--apply", "--output", filepath.Join(dir, "slot-selector-refused.bin")}, &out); err == nil || out.Len() != 0 {
				t.Fatalf("CLI accepted invalid wording selector %q", selector)
			}
			if _, err := os.Stat(filepath.Join(dir, "slot-selector-refused.bin")); !os.IsNotExist(err) {
				t.Fatal("invalid wording selector created output", err)
			}
		}
		preserved, err := os.ReadFile(sourcePath)
		if err != nil || !bytes.Equal(preserved, input) {
			t.Fatal("mixed slot CLI changed source", err)
		}
	}
}

func TestRegistryWordingAndNewRecipeNeedsNoHandler(t *testing.T) {
	r, registry, glyphs, image := fixture(t, "same_length_stream")
	first, err := plan([]Recipes{r}, registry, glyphs, nil)
	if err != nil {
		t.Fatal(err)
	}
	registry.Entries[0].EN = "B"
	next, err := plan([]Recipes{r}, registry, glyphs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first[0].New, next[0].New) {
		t.Fatal("registry wording ignored")
	}
	entry := registry.Entries[0]
	entry.ID = "0x20"
	registry.Entries = append(registry.Entries, entry)
	copy(image[32:], []byte{4, 0, 0, 0xf8})
	r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
	r.Entries["0x20"] = Recipe{ExpectedHex: "040000f8", Evidence: "fourth recipe, same operation"}
	edits, err := plan([]Recipes{r}, registry, glyphs, nil)
	if err != nil || len(edits) != 2 {
		t.Fatalf("new recipe: %v %v", edits, err)
	}
	if edits[0].Offset >= edits[1].Offset {
		t.Fatal("unstable plan ordering")
	}

}

func TestPilotHistoricalGoldenBytes(t *testing.T) {
	for _, vector := range []struct {
		Name  string
		Mask  []bool
		Width int
		Spec  RasterMaskTransform
		Want  []bool
	}{
		{"cross", []bool{false, false, false, false, true, false, false, false, false}, 3, RasterMaskTransform{Kind: "dilate", Iterations: 1}, []bool{false, true, false, true, true, true, false, true, false}},
		{"saturate", []bool{true, false, false, false, false, false, false, false, false}, 3, RasterMaskTransform{Kind: "dilate", Iterations: math.MaxInt}, []bool{true, true, true, true, true, true, true, true, true}},
		{"diagonal does not drain", []bool{false, true, true, true, false, true, true, true, true}, 3, RasterMaskTransform{Kind: "fill_holes"}, []bool{false, true, true, true, true, true, true, true, true}},
		{"empty background", []bool{false, false, false, false}, 2, RasterMaskTransform{Kind: "fill_holes"}, []bool{false, false, false, false}},
		{"bad width", []bool{true}, 0, RasterMaskTransform{Kind: "fill_holes"}, nil},
		{"incomplete rows", []bool{true, false, true}, 2, RasterMaskTransform{Kind: "fill_holes"}, nil},
		{"empty grid", nil, 1, RasterMaskTransform{Kind: "fill_holes"}, nil},
		{"unknown transform", []bool{true}, 1, RasterMaskTransform{Kind: "unknown"}, nil},
		{"unowned count", []bool{true}, 1, RasterMaskTransform{Kind: "fill_holes", Iterations: 1}, nil},
		{"zero dilation until stable", []bool{true, false, false, false}, 2, RasterMaskTransform{Kind: "dilate"}, []bool{true, true, true, true}},
		{"erode first layer", []bool{true, true, true, true, true, true, true, true, true}, 3, RasterMaskTransform{Kind: "erode", Iterations: 1}, []bool{false, false, false, false, true, false, false, false, false}},
		{"erode until stable", []bool{true, true, true, true, true, true, true, true, true}, 3, RasterMaskTransform{Kind: "erode"}, []bool{false, false, false, false, false, false, false, false, false}},
		{"four connected minimum", []bool{true, false, false, false, true, true, false, false, false}, 3, RasterMaskTransform{Kind: "minimum", MinimumSize: 2}, []bool{false, false, false, false, true, true, false, false, false}},
		{"fractional minimum", []bool{true, true, false, false}, 2, RasterMaskTransform{Kind: "minimum", MinimumSize: 2.5}, []bool{false, false, false, false}},
		{"nonfinite minimum", []bool{true}, 1, RasterMaskTransform{Kind: "minimum", MinimumSize: math.NaN()}, nil},
		{"eight connected seed", []bool{true, false, false, false, true, false, false, false, true}, 3, RasterMaskTransform{Kind: "components", Connectivity: 8, Seeds: []int{0}}, []bool{true, false, false, false, true, false, false, false, true}},
		{"four connected seed", []bool{true, false, false, false, true, false, false, false, true}, 3, RasterMaskTransform{Kind: "components", Connectivity: 4, Seeds: []int{0}}, []bool{true, false, false, false, false, false, false, false, false}},
		{"all components without seeds", []bool{true, false, false, true}, 2, RasterMaskTransform{Kind: "components", Connectivity: 4}, []bool{true, false, false, true}},
		{"empty seeds select none", []bool{true, false, false, true}, 2, RasterMaskTransform{Kind: "components", Connectivity: 8, Seeds: []int{}}, []bool{false, false, false, false}},
		{"repeated seeds union", []bool{true, false, false, true}, 2, RasterMaskTransform{Kind: "components", Connectivity: 4, Seeds: []int{0, 0, 3}}, []bool{true, false, false, true}},
		{"tag vetoes diagonal component", []bool{true, false, false, true}, 2, RasterMaskTransform{Kind: "components", Connectivity: 8, Reject: []bool{false, false, false, true}}, []bool{false, false, false, false}},
		{"tag stays in four component", []bool{true, false, false, true}, 2, RasterMaskTransform{Kind: "components", Connectivity: 4, Reject: []bool{false, false, false, true}}, []bool{true, false, false, false}},
		{"background tags do not veto", []bool{true, false, false, true}, 2, RasterMaskTransform{Kind: "components", Connectivity: 8, Reject: []bool{false, true, true, false}}, []bool{true, false, false, true}},
		{"eight component minimum equality", []bool{true, false, false, true}, 2, RasterMaskTransform{Kind: "components", Connectivity: 8, MinimumSize: 2}, []bool{true, false, false, true}},
		{"eight component fractional minimum", []bool{true, false, false, true}, 2, RasterMaskTransform{Kind: "components", Connectivity: 8, MinimumSize: 2.5}, []bool{false, false, false, false}},
		{"missing connectivity", []bool{true}, 1, RasterMaskTransform{Kind: "components"}, nil},
		{"unknown connectivity", []bool{true}, 1, RasterMaskTransform{Kind: "components", Connectivity: 6}, nil},
		{"component count unused", []bool{true}, 1, RasterMaskTransform{Kind: "components", Connectivity: 8, Iterations: 1}, nil},
		{"background seed refusal", []bool{true, false}, 2, RasterMaskTransform{Kind: "components", Connectivity: 8, Seeds: []int{1}}, nil},
		{"later background seed refusal", []bool{true, false}, 2, RasterMaskTransform{Kind: "components", Connectivity: 8, Seeds: []int{0, 1}}, nil},
		{"negative seed refusal", []bool{true}, 1, RasterMaskTransform{Kind: "components", Connectivity: 8, Seeds: []int{-1}}, nil},
		{"one over seed refusal", []bool{true}, 1, RasterMaskTransform{Kind: "components", Connectivity: 8, Seeds: []int{1}}, nil},
		{"exact seed count", []bool{true}, 1, RasterMaskTransform{Kind: "components", Connectivity: 8, Seeds: make([]int, maxRasterSelections)}, []bool{true}},
		{"one over seed count", []bool{true}, 1, RasterMaskTransform{Kind: "components", Connectivity: 8, Seeds: make([]int, maxRasterSelections+1)}, nil},
		{"rejection dimensions", []bool{true}, 1, RasterMaskTransform{Kind: "components", Connectivity: 8, Reject: []bool{}}, nil},
		{"component criteria on morphology", []bool{true}, 1, RasterMaskTransform{Kind: "dilate", Connectivity: 8}, nil},
		{"component criteria on fill", []bool{true}, 1, RasterMaskTransform{Kind: "fill_holes", Seeds: []int{}}, nil},
		{"component criteria on minimum", []bool{true}, 1, RasterMaskTransform{Kind: "minimum", Reject: []bool{true}}, nil},
		{"label zero is immutable input background", []bool{true, false, true}, 3, RasterMaskTransform{Kind: "components", Connectivity: 4, Seeds: []int{1}, BackgroundSeed: "label-zero"}, []bool{false, true, false}},
		{"disconnected label zero", []bool{false, true, false, false, true, false}, 3, RasterMaskTransform{Kind: "components", Connectivity: 4, Seeds: []int{0}, BackgroundSeed: "label-zero"}, []bool{true, false, true, true, false, true}},
		{"mixed foreground background labels", []bool{false, true, false, false, true, false}, 3, RasterMaskTransform{Kind: "components", Connectivity: 4, Seeds: []int{0, 1}, BackgroundSeed: "label-zero"}, []bool{true, true, true, true, true, true}},
		{"empty label seed list", []bool{true, false}, 2, RasterMaskTransform{Kind: "components", Connectivity: 4, Seeds: []int{}, BackgroundSeed: "label-zero"}, []bool{false, false}},
		{"empty foreground label zero", []bool{false, false, false, false}, 2, RasterMaskTransform{Kind: "components", Connectivity: 4, Seeds: []int{0}, BackgroundSeed: "label-zero"}, []bool{true, true, true, true}},
		{"unknown background seed policy", []bool{true}, 1, RasterMaskTransform{Kind: "components", Connectivity: 4, Seeds: []int{0}, BackgroundSeed: "all"}, nil},
		{"label zero needs seed presence", []bool{true}, 1, RasterMaskTransform{Kind: "components", Connectivity: 4, BackgroundSeed: "label-zero"}, nil},
		{"label zero refuses size criteria", []bool{true}, 1, RasterMaskTransform{Kind: "components", Connectivity: 4, Seeds: []int{0}, BackgroundSeed: "label-zero", MinimumSize: 1}, nil},
		{"label zero refuses empty rejection mask", []bool{true}, 1, RasterMaskTransform{Kind: "components", Connectivity: 4, Seeds: []int{0}, BackgroundSeed: "label-zero", Reject: []bool{}}, nil},
		{"label zero refuses tag criteria", []bool{true}, 1, RasterMaskTransform{Kind: "components", Connectivity: 4, Seeds: []int{0}, BackgroundSeed: "label-zero", Reject: []bool{false}}, nil},
		{"background criteria on erosion", []bool{true}, 1, RasterMaskTransform{Kind: "erode", BackgroundSeed: "label-zero"}, nil},
	} {
		before := slices.Clone(vector.Mask)
		beforeReject, beforeSeeds := slices.Clone(vector.Spec.Reject), slices.Clone(vector.Spec.Seeds)
		got, err := transformRasterMask(vector.Mask, vector.Width, vector.Spec)
		if vector.Want == nil {
			if err == nil || got != nil {
				t.Fatal("shared mask refusal", vector.Name, err)
			}
		} else if err != nil || !slices.Equal(got, vector.Want) {
			t.Fatal("shared mask source topology", vector.Name, got, err)
		}
		if !slices.Equal(vector.Mask, before) {
			t.Fatal("shared topology mutated its input", vector.Name)
		}
		if !slices.Equal(vector.Spec.Reject, beforeReject) || !slices.Equal(vector.Spec.Seeds, beforeSeeds) {
			t.Fatal("shared topology mutated component criteria", vector.Name)
		}
		if len(got) > 0 {
			got[0] = !got[0]
			if !slices.Equal(vector.Mask, before) {
				t.Fatal("shared topology returned an input alias", vector.Name)
			}
			if !slices.Equal(vector.Spec.Reject, beforeReject) {
				t.Fatal("shared topology returned a rejection-mask alias", vector.Name)
			}
		}
	}
	selectionImage := image.NewNRGBA(image.Rect(7, 13, 10, 16))
	draw.Draw(selectionImage, selectionImage.Rect, image.NewUniform(color.NRGBA{255, 255, 255, 255}), image.Point{}, draw.Src)
	selectionImage.SetNRGBA(8, 14, color.NRGBA{90, 90, 90, 0})
	selectionBefore := slices.Clone(selectionImage.Pix)
	selectionThreshold := 100.0
	selected, _, err := selectRaster(selectionImage, RasterFootprint{Rect: []int{0, 0, 3, 3}, Any: [][]RasterSelection{{{LuminanceBelow: &selectionThreshold}}}}, 1<<28)
	if err != nil || !slices.Equal(selected, []bool{false, false, false, false, true, false, false, false, false}) || !bytes.Equal(selectionImage.Pix, selectionBefore) {
		t.Fatal("shared selection lost origin, hidden RGB or input preservation", selected, err)
	}
	emptyComponentSeeds, centerComponentSeed := [][]int{}, [][]int{{1, 1}}
	for _, seeds := range []*[][]int{nil, &emptyComponentSeeds, &centerComponentSeed} {
		spec := RasterFootprint{Rect: []int{0, 0, 3, 3}, SampleRect: []int{1, 1, 1, 1}, Any: [][]RasterSelection{{}}, Components: &RasterComponentFilter{Connectivity: 8, Seeds: seeds}}
		mask, charged, err := selectRaster(selectionImage, spec, 1<<28)
		wantCenter := seeds == nil || len(*seeds) > 0
		if err != nil || !slices.Equal(mask, []bool{false, false, false, false, wantCenter, false, false, false, false}) || !bytes.Equal(selectionImage.Pix, selectionBefore) {
			t.Fatal("sampling leaked outside its rectangle or component seeds lost presence", mask, err)
		}
		if _, _, err := selectRaster(selectionImage, spec, charged); err != nil {
			t.Fatal("exact component work charge refused", charged, err)
		}
		if mask, _, err := selectRaster(selectionImage, spec, charged-1); err == nil || mask != nil {
			t.Fatal("component work accepted one under charge", charged, err)
		}
		wire, err := json.Marshal(spec)
		var restored RasterFootprint
		if err != nil || json.Unmarshal(wire, &restored) != nil || restored.Components == nil || (restored.Components.Seeds == nil) != (seeds == nil) {
			t.Fatal("component seed presence lost in JSON roundtrip", string(wire), err)
		}
		if seeds != nil && len(*restored.Components.Seeds) != len(*seeds) {
			t.Fatal("explicit empty component seeds changed in JSON", string(wire))
		}
	}
	for _, spec := range []RasterFootprint{
		{Rect: []int{0, 0, 3, 3}, SampleRect: []int{1, 1, 1, 1}, Any: [][]RasterSelection{{}}, Grow: 1},
		{Rect: []int{0, 0, 3, 3}, SampleRect: []int{1, 1, 1, 1}, Any: [][]RasterSelection{{{Below: map[string]float64{"alpha": 1}}}}, Components: &RasterComponentFilter{Connectivity: 8}, Grow: 1},
	} {
		mask, _, err := selectRaster(selectionImage, spec, 1<<28)
		if err != nil || !slices.Equal(mask, []bool{false, true, false, true, true, true, false, true, false}) {
			t.Fatal("whole topology growth was clipped to sampling or became eight-connected", mask, err)
		}
	}
	samplingCore := [][]RasterSelection{{}}
	zeroCoreGrowth := 0
	coreSample, _, err := selectRaster(selectionImage, RasterFootprint{Rect: []int{0, 0, 3, 3}, SampleRect: []int{1, 1, 1, 1}, Any: [][]RasterSelection{}, Core: &samplingCore, CoreGrow: &zeroCoreGrowth, Fill: "core"}, 1<<28)
	if err != nil || !slices.Equal(coreSample, []bool{false, false, false, false, true, false, false, false, false}) {
		t.Fatal("core sampling evaluated outside SampleRect", coreSample, err)
	}
	for _, selection := range [][][]RasterSelection{
		{{{Above: map[string]float64{"luminance": 100}}}},
		{{{Above: map[string]float64{"alpha": 255}}}},
		{{{Below: map[string]float64{"luminance": 100}}}},
	} {
		spec := RasterFootprint{Rect: []int{0, 0, 3, 3}, Any: selection, Fill: "holes", Components: &RasterComponentFilter{Connectivity: 4, Seeds: &[][]int{{0, 0}, {1, 1}}, BackgroundSeed: "label-zero"}, Erode: 1}
		mask, charged, err := selectRaster(selectionImage, spec, 1<<28)
		if err != nil || !slices.Equal(mask, []bool{false, false, false, false, true, false, false, false, false}) {
			t.Fatal("flood did not fill holes/select label union/erode within Rect in order", mask, err)
		}
		if _, _, err := selectRaster(selectionImage, spec, charged); err != nil {
			t.Fatal("exact flood work charge refused", charged, err)
		}
		if mask, _, err := selectRaster(selectionImage, spec, charged-1); err == nil || mask != nil {
			t.Fatal("one-under flood charge accepted", charged, err)
		}
		spec.Erode = 0
		withoutErosion, oldCharge, err := selectRaster(selectionImage, spec, 1<<28)
		if err != nil || oldCharge >= charged || slices.Contains(withoutErosion, false) {
			t.Fatal("zero erosion did not skip or extra erosion work went uncharged", oldCharge, charged, err)
		}
		spec.Erode = -1
		untilStable, _, err := selectRaster(selectionImage, spec, 1<<28)
		if err != nil || slices.Contains(untilStable, true) {
			t.Fatal("negative erosion did not converge", untilStable, err)
		}
	}
	paddedBackground, _, err := selectRaster(selectionImage, RasterFootprint{Rect: []int{0, 0, 3, 3}, SampleRect: []int{1, 1, 1, 1}, Any: [][]RasterSelection{}, Components: &RasterComponentFilter{Connectivity: 4, Seeds: &centerComponentSeed, BackgroundSeed: "label-zero"}}, 1<<28)
	if err != nil || slices.Contains(paddedBackground, false) {
		t.Fatal("label zero did not cover the full topology Rect including padding", paddedBackground, err)
	}
	for _, reject := range []*[][]RasterSelection{&[][]RasterSelection{}, new([][]RasterSelection)} {
		spec := RasterFootprint{Rect: []int{0, 0, 3, 3}, Any: [][]RasterSelection{}, Components: &RasterComponentFilter{Connectivity: 4, Seeds: &centerComponentSeed, BackgroundSeed: "label-zero", Reject: reject}}
		if mask, _, err := selectRaster(selectionImage, spec, 1<<28); err == nil || mask != nil {
			t.Fatal("label zero lost explicit rejection criteria presence", err)
		}
	}
	rejectPresence := RasterComponentFilter{Connectivity: 4, Seeds: &centerComponentSeed, BackgroundSeed: "label-zero", Reject: &[][]RasterSelection{}}
	rejectWire, err := json.Marshal(rejectPresence)
	var rejectRestored RasterComponentFilter
	if err != nil || json.Unmarshal(rejectWire, &rejectRestored) != nil || rejectRestored.Reject == nil || len(*rejectRestored.Reject) != 0 {
		t.Fatal("empty rejection criteria disappeared in JSON roundtrip", string(rejectWire), err)
	}
	for _, spec := range []RasterFootprint{
		{Rect: []int{0, 0, 3, 3}, SampleRect: []int{}},
		{Rect: []int{0, 0, 3, 3}, SampleRect: []int{-1, 0, 1, 1}},
		{Rect: []int{0, 0, 3, 3}, SampleRect: []int{2, 2, 2, 1}},
		{Rect: []int{1, 1, 2, 2}, SampleRect: []int{0, 0, 1, 1}},
		{Rect: []int{0, 0, 3, 3}, Components: &RasterComponentFilter{}},
		{Rect: []int{0, 0, 3, 3}, Components: &RasterComponentFilter{Connectivity: 8, Seeds: &[][]int{{1}}}},
		{Rect: []int{0, 0, 3, 3}, SampleRect: []int{1, 1, 1, 1}, Components: &RasterComponentFilter{Connectivity: 8, Seeds: &[][]int{{0, 0}}}},
		{Rect: []int{0, 0, 3, 3}, Any: [][]RasterSelection{{{Below: map[string]float64{"alpha": -1}}, {Above: map[string]float64{"unknown": 1}}}}},
	} {
		if mask, _, err := selectRaster(selectionImage, spec, 1<<28); err == nil || mask != nil {
			t.Fatal("invalid sampling or component contract accepted", spec, err)
		}
	}
	legacyThreshold := 80.0
	for _, selection := range []RasterSelection{
		{LuminanceBelow: &legacyThreshold, Below: map[string]float64{"luminance": 100}},
		{Above: map[string]float64{"Alpha": 0}},
		{Above: map[string]float64{"alpha": math.NaN()}},
		{Below: map[string]float64{"red-blue": math.Inf(1)}},
	} {
		got, _, err := selectRaster(selectionImage, RasterFootprint{Rect: []int{0, 0, 3, 3}, Any: [][]RasterSelection{{selection}}}, 1<<28)
		if selection.LuminanceBelow != nil {
			if err != nil || slices.Contains(got, true) {
				t.Fatal("map threshold overwrote rather than conjoined the legacy threshold", got, err)
			}
		} else if err == nil || got != nil {
			t.Fatal("invalid scalar property or threshold accepted", selection, err)
		}
	}
	selected, _, err = selectRaster(selectionImage, RasterFootprint{Rect: []int{0, 0, 3, 3}, Any: [][]RasterSelection{{{Below: map[string]float64{"alpha": 0.5}}}}}, 1<<28)
	if err != nil || !slices.Equal(selected, []bool{false, false, false, false, true, false, false, false, false}) {
		t.Fatal("scalar comparison rounded its floating threshold", selected, err)
	}
	emptyCore := [][]RasterSelection{}
	for _, core := range []*[][]RasterSelection{nil, &emptyCore} {
		spec := RasterFootprint{Rect: []int{0, 0, 3, 3}, Any: [][]RasterSelection{{}}, Core: core}
		mask, charged, err := selectRaster(selectionImage, spec, 1<<28)
		if err != nil || charged < 1 || slices.Contains(mask, core != nil) {
			t.Fatal("absent and explicitly empty core were conflated", mask, charged, err)
		}
		if _, _, err := selectRaster(selectionImage, spec, charged); err != nil {
			t.Fatal("exact footprint work charge refused", err)
		}
		if mask, _, err := selectRaster(selectionImage, spec, charged-1); err == nil || mask != nil {
			t.Fatal("footprint work budget accepted one-over charge", charged, err)
		}
		wire, err := json.Marshal(spec)
		var restored RasterFootprint
		if err != nil || json.Unmarshal(wire, &restored) != nil || (restored.Core == nil) != (core == nil) {
			t.Fatal("core presence lost during JSON roundtrip", string(wire), err)
		}
	}
	for _, spec := range []RasterFootprint{
		{Rect: []int{0, 0, 3, 3}, Any: [][]RasterSelection{{}}, Fill: "core"},
		{Rect: []int{0, 0, 3, 3}, Any: [][]RasterSelection{{}}, Clip: []int{}},
		{Rect: []int{0, 0, 3, 3}, Any: [][]RasterSelection{{}}, Exclude: [][]int{{-1, 0, 1, 1}}},
		{Rect: []int{0, 0, 3, 3}, Any: [][]RasterSelection{{}}, Fill: "unknown"},
	} {
		if mask, _, err := selectRaster(selectionImage, spec, 1<<28); err == nil || mask != nil || !bytes.Equal(selectionImage.Pix, selectionBefore) {
			t.Fatal("invalid footprint accepted or changed input", spec, err)
		}
	}
	mixedPermissions := RasterReconstruction{
		Allow:    [][]int{{0, 0, 3, 3}},
		AllowAdd: [][]int{{0, 0, 1, 1}},
		Masks: &RasterPermissionMasks{
			Exclude:  []RasterFootprint{{Rect: []int{0, 0, 3, 3}, Any: [][]RasterSelection{{}}, Fill: "none"}},
			AllowAdd: []RasterFootprint{{Rect: []int{2, 2, 1, 1}, Any: [][]RasterSelection{{}}, Fill: "none"}},
		},
		Erases: []RasterErase{{ID: "mixed-permission-order", Rect: []int{0, 0, 3, 3}, Method: "clear"}},
	}
	mixedResult, _, err := composeCells(selectionImage, nil, RasterFont{}, RasterComposition{Reconstruction: &mixedPermissions})
	if err != nil || !bytes.Equal(selectionImage.Pix, selectionBefore) {
		t.Fatal("mixed rectangle/mask stage order or source preservation", err)
	}
	for y := 0; y < 3; y++ {
		for x := 0; x < 3; x++ {
			want := selectionImage.NRGBAAt(7+x, 13+y)
			if x == 0 && y == 0 || x == 2 && y == 2 {
				want = color.NRGBA{}
			}
			if mixedResult.NRGBAAt(7+x, 13+y) != want {
				t.Fatal("dynamic exclusion/addition must share rectangle stage ordering", x, y)
			}
		}
	}
	selectionBundle, err := os.ReadFile("testdata/mask-selection.zip")
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(selectionBundle)) != "f82ef016267f47cfe83616cd3267f344ad5b5ac7d5e03ad8627b54367c941524" {
		t.Fatal("original-only scalar source archive", err)
	}
	selectionArchive, err := zip.NewReader(bytes.NewReader(selectionBundle), int64(len(selectionBundle)))
	if err != nil {
		t.Fatal(err)
	}
	selectionFacts, err := fs.ReadFile(selectionArchive, "vectors.json")
	var scalarCases struct {
		Vectors []struct {
			ID, Original, Mask string
			Shape              [2]int
			Groups             [][]RasterSelection
			OriginalSHA        string `json:"original_sha256"`
			MaskSHA            string `json:"mask_sha256"`
		}
	}
	if err != nil || json.Unmarshal(selectionFacts, &scalarCases) != nil || len(scalarCases.Vectors) != 5 {
		t.Fatal("original-only scalar source cases", err)
	}
	for _, vector := range scalarCases.Vectors {
		raw, err := fs.ReadFile(selectionArchive, vector.Original)
		want, maskErr := fs.ReadFile(selectionArchive, vector.Mask)
		if err != nil || maskErr != nil || fmt.Sprintf("%x", sha256.Sum256(raw)) != vector.OriginalSHA || fmt.Sprintf("%x", sha256.Sum256(want)) != vector.MaskSHA || len(raw) != vector.Shape[0]*vector.Shape[1]*4 || len(want) != vector.Shape[0]*vector.Shape[1] {
			t.Fatal("scalar original byte pins", vector.ID, err, maskErr)
		}
		input := &image.NRGBA{Pix: slices.Clone(raw), Stride: vector.Shape[1] * 4, Rect: image.Rect(7, 13, 7+vector.Shape[1], 13+vector.Shape[0])}
		union := make([]bool, len(want))
		for _, group := range vector.Groups {
			mask, _, err := selectRaster(input, RasterFootprint{Rect: []int{0, 0, vector.Shape[1], vector.Shape[0]}, Any: [][]RasterSelection{group}}, 1<<28)
			if err != nil {
				t.Fatal("original scalar group", vector.ID, err)
			}
			for at, selected := range mask {
				union[at] = union[at] || selected
			}
		}
		for at, selected := range union {
			if selected != (want[at] == 255) {
				t.Fatal("whole original scalar OR mask differs", vector.ID, at)
			}
		}
		if !bytes.Equal(input.Pix, raw) {
			t.Fatal("scalar selector mutated original RGBA", vector.ID)
		}
	}
	sharedPanelData, err := os.ReadFile("profiles/permissions/batch-c-panels.json")
	var sharedPanel RasterReconstruction
	if err != nil || json.Unmarshal(sharedPanelData, &sharedPanel) != nil || len(sharedPanel.Allow) == 0 {
		t.Fatal("authoritative shared panel geometry", err)
	}
	for _, sourceBundle := range []struct {
		Path, SHA256 string
		Cases        int
		Canonical    bool
	}{
		{"testdata/footprint-source.zip", "85e32925d6d05a0a1de43faa093bdfba2c76f7facd615aeb01bbf842320287de", 179, true},
		{"testdata/component-source.zip", "00e6f0edff1e33b5161ad5e9db605b13bfc4710407a11e86068b0dd45344b384", 30, false},
		{"testdata/flood-source.zip", "5606007ccf4721edcb962bb1f77f6adef13d9b166c5a6e0a664dd2d4e16aaeca", 88, false},
	} {
		footprintBundle, err := os.ReadFile(sourceBundle.Path)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(footprintBundle)) != sourceBundle.SHA256 {
			t.Fatal("original-only footprint archive", err)
		}
		footprintArchive, err := zip.NewReader(bytes.NewReader(footprintBundle), int64(len(footprintBundle)))
		if err != nil {
			t.Fatal(err)
		}
		footprintFiles := make(map[string][]byte)
		for _, entry := range footprintArchive.File {
			body, err := fs.ReadFile(footprintArchive, entry.Name)
			if err != nil {
				t.Fatal(err)
			}
			footprintFiles[entry.Name] = body
		}
		var completeTables struct {
			Assets map[string]string `json:"asset_to_complete_flat_table"`
			Tables map[string]struct {
				SHA256      string `json:"sha256"`
				PanelPrefix int    `json:"canonical_panel_prefix_records"`
			} `json:"tables"`
		}
		if data, present := footprintFiles["table-ledger.json"]; present {
			if json.Unmarshal(data, &completeTables) != nil || len(completeTables.Assets) != 4 || len(completeTables.Tables) != 3 {
				t.Fatal("complete source table and stable asset joins")
			}
		}
		var footprints struct {
			Vectors []struct {
				ID      string
				Fixture struct {
					Raw, SHA256 string
					Size        int
					Shape       [3]int
				}
				Permissions RasterReconstruction
				Native      [][]int `json:"NATIVE_RECTANGLES"`
				Mask        string  `json:"expected_mask_blob"`
				MaskSHA     string  `json:"expected_mask_sha256"`
				RGBA        string  `json:"expected_rgba_blob"`
				RGBASHA     string  `json:"expected_rgba_sha256"`
				Kind        string  `json:"observation_kind"`
				Erases      []RasterErase
				Order       []string
			}
		}
		if json.Unmarshal(footprintFiles["projection.json"], &footprints) != nil || len(footprints.Vectors) != sourceBundle.Cases {
			t.Fatal("source footprint vector schema")
		}
		for _, vector := range footprints.Vectors {
			if strings.HasSuffix(vector.ID, "/final_allow") && (sourceBundle.Canonical || len(completeTables.Assets) > 0) {
				parts := strings.Split(vector.ID, "/")
				texture := parts[len(parts)-2]
				// The historical generic-only t2 expectation stays literal, not a runtime table.
				if !sourceBundle.Canonical || texture != "mini_t2" {
					name := texture + ".json"
					panelPrefix := false
					if complete, exists := completeTables.Assets[texture]; exists {
						name = filepath.Base(complete)
						panelPrefix = completeTables.Tables[complete].PanelPrefix > 0
					} else {
						switch texture {
						case "mini_g04", "mini_g09", "mini_g11":
							panelPrefix = true
						}
					}
					data, err := os.ReadFile(filepath.Join("profiles", "permissions", "footprints", name))
					vector.Permissions = RasterReconstruction{}
					if err != nil || json.Unmarshal(data, &vector.Permissions) != nil {
						t.Fatal("source permission table", texture, err)
					}
					if complete, exists := completeTables.Assets[texture]; exists && fmt.Sprintf("%x", sha256.Sum256(data)) != completeTables.Tables[complete].SHA256 {
						t.Fatal("complete source table identity", texture)
					}
					if panelPrefix && (len(vector.Permissions.Allow) < len(sharedPanel.Allow) || !reflect.DeepEqual(vector.Permissions.Allow[:len(sharedPanel.Allow)], sharedPanel.Allow)) {
						t.Fatal("flattened permission geometry drifted from shared panel authority", texture)
					}
				}
			}
			raw := footprintFiles[vector.Fixture.Raw]
			if len(raw) != vector.Fixture.Size || fmt.Sprintf("%x", sha256.Sum256(raw)) != vector.Fixture.SHA256 || vector.Fixture.Shape[2] != 4 {
				t.Fatal("footprint original input pin", vector.ID)
			}
			width, height := vector.Fixture.Shape[1], vector.Fixture.Shape[0]
			if len(raw) != width*height*4 {
				t.Fatal("footprint original dimensions", vector.ID)
			}
			want := footprintFiles[vector.Mask]
			if vector.Kind == "RGBA" {
				want = footprintFiles[vector.RGBA]
				if len(want) != len(raw) || fmt.Sprintf("%x", sha256.Sum256(want)) != vector.RGBASHA {
					t.Fatal("whole source RGBA order pin", vector.ID)
				}
			} else if len(want) != width*height || fmt.Sprintf("%x", sha256.Sum256(want)) != vector.MaskSHA {
				t.Fatal("whole source mask pin", vector.ID)
			}
			for _, shift := range []image.Point{{}, {7, 13}} {
				if shift != (image.Point{}) && sourceBundle.Canonical && !strings.HasSuffix(vector.ID, "/macro/01") && vector.Kind != "RGBA" {
					continue
				}
				var reconstruction RasterReconstruction
				body, err := json.Marshal(vector.Permissions)
				if err != nil || json.Unmarshal(body, &reconstruction) != nil {
					t.Fatal("footprint recipe clone", vector.ID, err)
				}
				paint := color.NRGBA{23, 71, 129, 173}
				if vector.Kind == "RGBA" {
					reconstruction.Erases = vector.Erases
				} else {
					for i, rect := range vector.Native {
						reconstruction.Erases = append(reconstruction.Erases, RasterErase{ID: fmt.Sprintf("source-window-%d", i), Rect: rect, Method: "flat", Fill: []int{int(paint.R), int(paint.G), int(paint.B), int(paint.A)}})
					}
				}
				input := &image.NRGBA{Pix: slices.Clone(raw), Stride: width * 4, Rect: image.Rect(0, 0, width, height).Add(shift)}
				got, _, err := composeCells(input, nil, RasterFont{}, RasterComposition{Reconstruction: &reconstruction, Order: vector.Order})
				if err != nil {
					t.Fatal("original footprint recipe", vector.ID, shift, err)
				}
				if vector.Kind == "RGBA" {
					if !bytes.Equal(got.Pix, want) {
						t.Fatal("whole original/current/order RGBA differs", vector.ID, shift, fmt.Sprintf("%x", sha256.Sum256(got.Pix)))
					}
				} else {
					for at, bit := range want {
						original := color.NRGBA{raw[at*4], raw[at*4+1], raw[at*4+2], raw[at*4+3]}
						if original == paint {
							t.Fatal("source witness paint must differ from all original pixels", vector.ID, at)
						}
						expected := original
						if bit == 255 {
							expected = paint
						}
						actual := got.NRGBAAt(shift.X+at%width, shift.Y+at/width)
						if actual != expected {
							t.Fatal("complete original mask differs", vector.ID, shift, at, original, expected, actual)
						}
					}
				}
				if !bytes.Equal(input.Pix, raw) {
					t.Fatal("footprint changed immutable source", vector.ID, shift)
				}
			}
		}
	}
	for _, fixture := range []struct {
		Path, SHA256 string
		Cases        int
	}{
		{"testdata/reconstruction-rows.zip", "1fc8751a5f42731d1f4e78b0582316bda331ac9559d62a1d66e7863638e7f58e", 45},
		{"testdata/reconstruction-masks.zip", "bfaadb71c12020fa85000ac8893ddb526f54c9b79abbf2439be0bf6d92de6c5d", 18},
	} {
		data, err := os.ReadFile(fixture.Path)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != fixture.SHA256 {
			t.Fatal("original-only reconstruction corpus", err)
		}
		bundle, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		body, err := fs.ReadFile(bundle, "vectors.json")
		var oracle struct {
			Vectors []struct {
				Name, Outcome       string
				Size                [2]int
				TrueType            bool
				Composition         json.RawMessage
				Base, Output, Allow struct{ Path, SHA256 string }
			}
		}
		if err != nil || json.Unmarshal(body, &oracle) != nil || len(oracle.Vectors) != fixture.Cases {
			t.Fatal("reconstruction vector table", err)
		}
		fontData, err := os.ReadFile("fonts/noto/NotoSans-CondensedExtraBold.ttf")
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(fontData)) != "e8411ed0b4635955dcaf8a237930c14f391fb1cd248544131a7dda138e71e197" {
			t.Fatal("shared runtime TrueType source", err)
		}
		for _, vector := range oracle.Vectors {
			pixels := make(map[string][]byte)
			for _, item := range []struct{ Path, SHA256 string }{vector.Base, vector.Output, vector.Allow} {
				if item.Path == "" {
					continue
				}
				raw, err := fs.ReadFile(bundle, item.Path)
				if err != nil || fmt.Sprintf("%x", sha256.Sum256(raw)) != item.SHA256 {
					t.Fatal("reconstruction original pixel pin", vector.Name, item.Path, err)
				}
				pixels[item.Path] = raw
			}
			var composition RasterComposition
			decoder := json.NewDecoder(bytes.NewReader(vector.Composition))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&composition)
			if vector.Outcome == "decode-refusal" {
				if err == nil || !strings.Contains(err.Error(), `unknown field "bogus"`) {
					t.Fatal("unknown original mask key must remain a strict refusal", vector.Name, err)
				}
				continue
			}
			if err != nil {
				t.Fatal(vector.Name, err)
			}
			if vector.Name == "explicit-all" {
				composition.Reconstruction.Erases[0].All = make([]RasterSelection, maxRasterSelections)
			}
			beforeComposition, err := json.Marshal(composition)
			if err != nil {
				t.Fatal(err)
			}
			baseData, expected, allowed := pixels[vector.Base.Path], pixels[vector.Output.Path], pixels[vector.Allow.Path]
			w, h := vector.Size[0], vector.Size[1]
			if len(baseData) != w*h*4 || len(allowed) != w*h || vector.Outcome == "success" && len(expected) != len(baseData) {
				t.Fatal("reconstruction dimensions", vector.Name)
			}
			font := RasterFont{}
			if vector.TrueType {
				font = RasterFont{TrueType: &RegistryInput{SHA256: "e8411ed0b4635955dcaf8a237930c14f391fb1cd248544131a7dda138e71e197"}, TrueTypeData: fontData, Layout: "RAQM"}
			}
			if vector.Name == "ordered-text-rows" {
				for _, mutation := range []string{"omitted order", "identity collision"} {
					var bad RasterComposition
					if json.Unmarshal(vector.Composition, &bad) != nil {
						t.Fatal("mixed recipe clone")
					}
					want := "explicit ordered"
					if mutation == "omitted order" {
						bad.Order = nil
					} else {
						bad.Reconstruction.Erases[0].ID = bad.Cells[0].ID
						want = "duplicate"
					}
					input := &image.NRGBA{Pix: slices.Clone(baseData), Stride: w * 4, Rect: image.Rect(0, 0, w, h)}
					before := sha256.Sum256(input.Pix)
					got, rectangles, err := composeCells(input, nil, font, bad)
					if err != nil && strings.Contains(err.Error(), "-tags nativefonts") {
						continue
					}
					if err == nil || !strings.Contains(err.Error(), want) || got != nil || rectangles != nil || sha256.Sum256(input.Pix) != before {
						t.Fatal("mixed reconstruction guard", mutation, err)
					}
				}
			}
			for _, shifted := range []bool{false, true} {
				base := &image.NRGBA{Pix: slices.Clone(baseData), Stride: w * 4, Rect: image.Rect(0, 0, w, h)}
				if shifted {
					parent := image.NewNRGBA(image.Rect(-9, 3, w+7, h+11))
					bounds := image.Rect(-4, 7, w-4, h+7)
					draw.Draw(parent, bounds, base, base.Rect.Min, draw.Src)
					base = parent.SubImage(bounds).(*image.NRGBA)
				}
				before := sha256.Sum256(base.Pix)
				got, rectangles, err := composeCells(base, nil, font, composition)
				afterComposition, marshalErr := json.Marshal(composition)
				if sha256.Sum256(base.Pix) != before || marshalErr != nil || !bytes.Equal(beforeComposition, afterComposition) {
					t.Fatal("reconstruction mutated source or recipe", vector.Name, shifted)
				}
				if vector.TrueType && err != nil && strings.Contains(err.Error(), "-tags nativefonts") {
					if got != nil || rectangles != nil {
						t.Fatal("disabled font partial result")
					}
					continue
				}
				if vector.Outcome == "compose-refusal" {
					want := map[string]string{"unknown-method-positive": "unknown reconstruction method", "flat-missing-color-positive": "requires RGB or RGBA", "immediate-text-leak": "outside allow"}[vector.Name]
					if err == nil || want == "" || !strings.Contains(err.Error(), want) || got != nil || rectangles != nil {
						t.Fatal("reconstruction refusal and no partial output", vector.Name, shifted, err)
					}
					continue
				}
				if err != nil || got == nil || got.Rect != base.Rect || len(rectangles) != len(composition.Cells)+len(composition.Reconstruction.Erases) {
					t.Fatal("reconstruction ordered composition", vector.Name, shifted, err)
				}
				for _, rect := range rectangles {
					if !rect.In(base.Rect) {
						t.Fatal("coarse native guard outside base", vector.Name, rect)
					}
				}
				for y := 0; y < h; y++ {
					for x := 0; x < w; x++ {
						at := (y*w + x) * 4
						pixel := got.NRGBAAt(base.Rect.Min.X+x, base.Rect.Min.Y+y)
						if pixel != (color.NRGBA{expected[at], expected[at+1], expected[at+2], expected[at+3]}) {
							t.Fatal("original whole RGBA reconstruction", vector.Name, shifted, x, y, pixel, expected[at:at+4])
						}
						if allowed[y*w+x] == 0 && pixel != base.NRGBAAt(base.Rect.Min.X+x, base.Rect.Min.Y+y) {
							t.Fatal("changed pixel outside exact reconstruction allow", vector.Name, x, y)
						}
					}
				}
			}
		}
	}
	{
		base := image.NewNRGBA(image.Rect(0, 0, 3, 3))
		base.SetNRGBA(1, 1, color.NRGBA{123, 45, 67, 0})
		valid := []byte(`{"reconstruction":{"allow":[[0,0,3,3]],"erases":[{"id":"erase","rect":[0,0,3,3],"near":[123,45,67],"method":"rows"}]},"order":["erase"]}`)
		var implicit RasterComposition
		if json.Unmarshal(valid, &implicit) != nil {
			t.Fatal("implicit order fixture")
		}
		backing := []string{"caller-owned-sentinel"}
		implicit.Order = backing[:0]
		got, _, err := composeCells(base, nil, RasterFont{}, implicit)
		if err != nil || got == nil || backing[0] != "caller-owned-sentinel" {
			t.Fatal("default order preserves caller backing storage", err, backing)
		}
		for _, mutation := range []string{"nil base", "oversize base", "empty base", "missing allow", "short allow", "outside exclude", "outside add", "region count", "no steps", "step count", "duplicate id", "empty id", "long id", "invalid id", "short rect", "zero rect", "negative rect", "overflow rect", "missing order step", "duplicate order step", "unknown order step", "near length", "near channel", "nan below", "infinite above", "missing fill", "bad fill", "unused icons", "work bound", "clause count", "clause near", "clause exclusion", "empty exclusion", "exclusion alpha", "nan saturation", "infinite clause", "selection work"} {
			var composition RasterComposition
			if err := json.Unmarshal(valid, &composition); err != nil {
				t.Fatal(err)
			}
			input := base
			r := composition.Reconstruction
			op := &r.Erases[0]
			switch mutation {
			case "nil base":
				input = nil
			case "oversize base":
				input = &image.NRGBA{Rect: image.Rect(0, 0, 4097, 1)}
			case "empty base":
				input = &image.NRGBA{}
			case "missing allow":
				r.Allow = nil
			case "short allow":
				r.Allow[0] = []int{0, 0, 3}
			case "outside exclude":
				r.Exclude = [][]int{{2, 2, 2, 1}}
			case "outside add":
				r.AllowAdd = [][]int{{0, -1, 1, 1}}
			case "region count":
				r.Allow = make([][]int, 65)
			case "no steps":
				r.Erases = nil
				composition.Order = nil
			case "step count":
				r.Erases = make([]RasterErase, 65)
			case "duplicate id":
				r.Erases = append(r.Erases, *op)
				composition.Order = append(composition.Order, "erase")
			case "empty id":
				op.ID = ""
			case "long id":
				op.ID = strings.Repeat("a", 129)
			case "invalid id":
				op.ID = string([]byte{0xff})
			case "short rect":
				op.Rect = []int{0, 0, 3}
			case "zero rect":
				op.Rect[2] = 0
			case "negative rect":
				op.Rect[0] = -1
			case "overflow rect":
				op.Rect[0] = int(^uint(0) >> 1)
				op.Rect[2] = int(^uint(0) >> 1)
			case "missing order step":
				composition.Order = []string{"erase", "missing"}
			case "duplicate order step":
				next := *op
				next.ID = "next"
				r.Erases = append(r.Erases, next)
				composition.Order = []string{"erase", "erase"}
			case "unknown order step":
				composition.Order = []string{"missing"}
			case "near length":
				op.Near = []int{1, 2}
			case "near channel":
				op.Near[0] = 256
			case "nan below":
				value := math.NaN()
				op.LuminanceBelow = &value
			case "infinite above":
				value := math.Inf(1)
				op.LuminanceAbove = &value
			case "missing fill":
				op.Method = "flat"
			case "bad fill":
				op.Method = "flat"
				op.Fill = []int{1, 2, 256}
			case "clause count":
				op.All = make([]RasterSelection, maxRasterSelections+1)
			case "clause near":
				op.All = []RasterSelection{{Near: []int{1, 2}}}
			case "clause exclusion":
				op.All = []RasterSelection{{NotNear: []int{1, 2}}}
			case "empty exclusion":
				op.NotNear = []int{}
			case "exclusion alpha":
				op.NotNear = []int{0, 0, 0, 256}
			case "nan saturation":
				v := math.NaN()
				op.SaturationBelow = &v
			case "infinite clause":
				v := math.Inf(1)
				op.All = []RasterSelection{{SaturationBelow: &v}}
			case "selection work":
				input = image.NewNRGBA(image.Rect(0, 0, 1024, 1024))
				r.Allow = [][]int{{0, 0, 1024, 1024}}
				op.Rect = []int{0, 0, 1024, 1024}
				op.All = make([]RasterSelection, maxRasterSelections)
			case "unused icons":
				composition.Icons = map[string][]int{"unused": {0, 0, 1, 1}}
			case "work bound":
				input = image.NewNRGBA(image.Rect(0, 0, 1024, 1024))
				r.Allow = [][]int{{0, 0, 1024, 1024}}
				r.Erases = nil
				composition.Order = nil
				for i := 0; i < 32; i++ {
					r.Erases = append(r.Erases, RasterErase{ID: strconv.Itoa(i), Rect: []int{0, 0, 1024, 1024}, Method: "rows"})
				}
			}
			before := sha256.Sum256(base.Pix)
			got, rectangles, err := composeCells(input, nil, RasterFont{}, composition)
			if err == nil || got != nil || rectangles != nil || sha256.Sum256(base.Pix) != before {
				t.Fatal("reconstruction guard/no partial output", mutation, err)
			}
		}
	}
	{
		data, err := os.ReadFile("testdata/asset-manifest.zip")
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != assetManifestFixtureSHA {
			t.Fatal("independent discovery oracle", err)
		}
		bundle, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		files := make(map[string][]byte)
		for _, member := range bundle.File {
			reader, err := member.Open()
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(io.LimitReader(reader, 1<<20))
			closeErr := reader.Close()
			if readErr != nil || closeErr != nil {
				t.Fatal(readErr, closeErr)
			}
			files[member.Name] = body
		}
		var oracle struct {
			Cases []struct {
				Name   string
				Size   [2]int
				RGBA   string      `json:"rgba_sha256"`
				Status string      `json:"new_contract_status"`
				Scores *[6]float64 `json:"new_contract_scores"`
			}
		}
		if json.Unmarshal(files["primary/score-oracles.json"], &oracle) != nil || len(oracle.Cases) != 33 {
			t.Fatal("independent score vectors")
		}
		for _, vector := range oracle.Cases {
			raw := files["primary/pixels/"+vector.Name+".rgba"]
			if len(raw) != vector.Size[0]*vector.Size[1]*4 || fmt.Sprintf("%x", sha256.Sum256(raw)) != vector.RGBA {
				t.Fatal("literal pixel pin", vector.Name)
			}
			raster := &image.NRGBA{Pix: raw, Stride: vector.Size[0] * 4, Rect: image.Rect(0, 0, vector.Size[0], vector.Size[1])}
			for _, shifted := range []bool{false, true} {
				input := raster
				if shifted {
					parent := image.NewNRGBA(image.Rect(0, 0, vector.Size[0]+5, vector.Size[1]+4))
					bounds := image.Rect(3, 2, 3+vector.Size[0], 2+vector.Size[1])
					draw.Draw(parent, bounds, raster, raster.Bounds().Min, draw.Src)
					input = parent.SubImage(bounds).(*image.NRGBA)
				}
				before := sha256.Sum256(input.Pix)
				got := inspectRaster(input, `battle\player\plain.txd`, "plain")
				if got.Status != vector.Status || got.Tier != "model" || sha256.Sum256(input.Pix) != before {
					t.Fatal("discovery status/preservation", vector.Name, shifted, got)
				}
				if vector.Scores == nil {
					if got.Score != nil || got.Diagnostic == "" {
						t.Fatal("unavailable measurement", vector.Name, got)
					}
					continue
				}
				if got.Score == nil {
					t.Fatal("missing measured score", vector.Name)
				}
				s := got.Score
				actual := [6]float64{float64(s.GlyphClusters), s.ClusterFraction, float64(s.GlyphTiles), s.DominantColorFraction, s.OpaqueFraction, float64(s.TextLineRows)}
				if actual != *vector.Scores {
					t.Fatal("independent six-counter score", vector.Name, shifted, actual, *vector.Scores)
				}
			}
		}
		var flags struct {
			NewPixels []struct {
				Name   string
				Size   [2]int
				Scores [6]float64 `json:"hand_expected_score"`
				RGBA   string     `json:"RGBA_sha256"`
			} `json:"new_pixel_cases"`
			Cases []struct {
				Entry, Texture string
				Pixel          string `json:"pixel_name"`
				Tier           string
				Reasons        []string
				Decoded        bool        `json:"decoded"`
				Scores         *[6]float64 `json:"score"`
			} `json:"flag_cases"`
		}
		if json.Unmarshal(files["realflags/real-pixel-flags.json"], &flags) != nil || len(flags.NewPixels) != 3 || len(flags.Cases) != 25 {
			t.Fatal("actual pixel flags")
		}
		for _, vector := range flags.NewPixels {
			raw := files["realflags/pixels/"+vector.Name+".rgba"]
			if fmt.Sprintf("%x", sha256.Sum256(raw)) != vector.RGBA {
				t.Fatal("new flag pixel pin", vector.Name)
			}
			got := inspectRaster(&image.NRGBA{Pix: raw, Stride: vector.Size[0] * 4, Rect: image.Rect(0, 0, vector.Size[0], vector.Size[1])}, "plain", "plain")
			if got.Score == nil {
				t.Fatal("missing threshold score", vector.Name)
			}
			s := got.Score
			if ([6]float64{float64(s.GlyphClusters), s.ClusterFraction, float64(s.GlyphTiles), s.DominantColorFraction, s.OpaqueFraction, float64(s.TextLineRows)}) != vector.Scores {
				t.Fatal("flag threshold counters", vector.Name, got.Score, vector.Scores)
			}
		}
		for _, vector := range flags.Cases {
			var raster *image.NRGBA
			if vector.Decoded {
				data := files["primary/pixels/"+vector.Pixel+".png"]
				if data == nil {
					data = files["realflags/pixels/"+vector.Pixel+".png"]
				}
				decoded, err := png.Decode(bytes.NewReader(data))
				if err != nil {
					t.Fatal("flag PNG", vector.Pixel, err)
				}
				raster = image.NewNRGBA(decoded.Bounds())
				draw.Draw(raster, raster.Bounds(), decoded, decoded.Bounds().Min, draw.Src)
			}
			got := inspectRaster(raster, vector.Entry, vector.Texture)
			if got.Tier != vector.Tier || !reflect.DeepEqual(got.FlagReasons, vector.Reasons) {
				t.Fatal("original ordered flag reasons", vector.Entry, vector.Texture, vector.Pixel, got, vector.Reasons)
			}
		}
	}
	for _, fixture := range []struct {
		Path, SHA256 string
		Vectors      int
	}{
		{"testdata/raster-resampling.zip", "1ff4ba495241d12e72f4c3d09f5e841a1aa86bfea739bea38e9db69ce4bf9a61", 134},
		{"testdata/raster-nearest.zip", "65a3505a9e8388527cccc6e78d25da9f77be5e07f4230e370581fca7a7a2e665", 10},
	} {
		bundleData, err := os.ReadFile(fixture.Path)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(bundleData)) != fixture.SHA256 {
			t.Fatal("resampling oracle bundle", err)
		}
		bundle, err := zip.NewReader(bytes.NewReader(bundleData), int64(len(bundleData)))
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := bundle.Open("vectors.json")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(manifest)
		manifest.Close()
		var oracle struct {
			Vectors []struct {
				ID, Mode, Filter string
				Crop             []int  `json:"crop"`
				SourceRect       [4]int `json:"source_rect"`
				TargetSize       [2]int `json:"target_size"`
				Input, Output    struct {
					Entry, SHA256 string
					RawSHA256     string `json:"raw_sha256"`
				}
			}
		}
		if err != nil || json.Unmarshal(body, &oracle) != nil || len(oracle.Vectors) != fixture.Vectors {
			t.Fatal("resampling oracle manifest", err)
		}
		for _, vector := range oracle.Vectors {
			var rasters [2]image.Image
			var rawPixels [2][]byte
			for i, entry := range []struct{ Key, SHA, RawSHA string }{{vector.Input.Entry, vector.Input.SHA256, vector.Input.RawSHA256}, {vector.Output.Entry, vector.Output.SHA256, vector.Output.RawSHA256}} {
				reader, err := bundle.Open(entry.Key)
				if err != nil {
					t.Fatal(vector.ID, err)
				}
				data, err := io.ReadAll(reader)
				reader.Close()
				if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != entry.SHA {
					t.Fatal("resampling PNG pin", vector.ID, err)
				}
				decoded, err := png.Decode(bytes.NewReader(data))
				if err != nil {
					t.Fatal(vector.ID, err)
				}
				if vector.Mode == "Gray" {
					gray, ok := decoded.(*image.Gray)
					if !ok {
						t.Fatal("resampling gray fixture", vector.ID)
					}
					rasters[i], rawPixels[i] = gray, gray.Pix
				} else {
					rgba := image.NewNRGBA(decoded.Bounds())
					for y := rgba.Rect.Min.Y; y < rgba.Rect.Max.Y; y++ {
						for x := rgba.Rect.Min.X; x < rgba.Rect.Max.X; x++ {
							rgba.SetNRGBA(x, y, color.NRGBAModel.Convert(decoded.At(x, y)).(color.NRGBA))
						}
					}
					rasters[i], rawPixels[i] = rgba, rgba.Pix
				}
				if fmt.Sprintf("%x", sha256.Sum256(rawPixels[i])) != entry.RawSHA {
					t.Fatal("resampling raw fixture", vector.ID, i)
				}
			}
			before := bytes.Clone(rawPixels[0])
			rect := image.Rect(vector.SourceRect[0], vector.SourceRect[1], vector.SourceRect[2], vector.SourceRect[3])
			var source image.Image
			switch parent := rasters[0].(type) {
			case *image.Gray:
				source = parent.SubImage(rect)
			case *image.NRGBA:
				source = parent.SubImage(rect)
			}
			filter := vector.Filter
			if filter == "" {
				filter = "lanczos"
			}
			var crop *image.Rectangle
			if vector.Crop != nil {
				if len(vector.Crop) != 4 {
					t.Fatal("nearest crop fixture", vector.ID)
				}
				crop = &image.Rectangle{Min: image.Pt(vector.Crop[0], vector.Crop[1]), Max: image.Pt(vector.Crop[2], vector.Crop[3])}
			}
			out, err := resizeRaster(source, vector.TargetSize[0], vector.TargetSize[1], filter, crop)
			if err != nil || out.Bounds() != rasters[1].Bounds() || out == source {
				t.Fatal("resampling dimensions/fresh output", vector.ID, err)
			}
			var got []byte
			switch raster := out.(type) {
			case *image.Gray:
				got = raster.Pix
				if vector.Mode != "Gray" {
					t.Fatal("resampling output mode", vector.ID)
				}
			case *image.NRGBA:
				got = raster.Pix
				if vector.Mode != "NRGBA" {
					t.Fatal("resampling output mode", vector.ID)
				}
			default:
				t.Fatal("resampling output type", vector.ID)
			}
			if !bytes.Equal(got, rawPixels[1]) || !bytes.Equal(before, rawPixels[0]) {
				t.Fatal("resampling golden/source differs", vector.ID)
			}
			if filter == "nearest" {
				parent := image.NewNRGBA(image.Rect(7, 13, rect.Dx()+16, rect.Dy()+22))
				copy(parent.Pix, bytes.Repeat([]byte{0xa5}, len(parent.Pix)))
				window := image.Rect(11, 17, 11+rect.Dx(), 17+rect.Dy())
				draw.Draw(parent, window, source, source.Bounds().Min, draw.Src)
				paddedBefore := bytes.Clone(parent.Pix)
				padded, err := resizeRaster(parent.SubImage(window), vector.TargetSize[0], vector.TargetSize[1], filter, crop)
				if err != nil || !bytes.Equal(padded.(*image.NRGBA).Pix, rawPixels[1]) || !bytes.Equal(parent.Pix, paddedBefore) {
					t.Fatal("nearest nonzero origin/stride/padding", vector.ID, err)
				}
				padded.(*image.NRGBA).Pix[0] ^= 255
				if !bytes.Equal(parent.Pix, paddedBefore) {
					t.Fatal("nearest padded source aliases output", vector.ID)
				}
				gray := image.NewGray(image.Rect(0, 0, rect.Dx(), rect.Dy()))
				for i := range gray.Pix {
					gray.Pix[i] = rawPixels[0][4*i]
				}
				grayBefore := bytes.Clone(gray.Pix)
				grayOut, err := resizeRaster(gray, vector.TargetSize[0], vector.TargetSize[1], filter, crop)
				if err != nil || grayOut.Bounds() != out.Bounds() || !bytes.Equal(gray.Pix, grayBefore) {
					t.Fatal("nearest Gray geometry/source", vector.ID, err)
				}
				for i, pixel := range grayOut.(*image.Gray).Pix {
					if pixel != rawPixels[1][4*i] {
						t.Fatal("nearest Gray original channel oracle", vector.ID, i)
					}
				}
			}
			got[0] ^= 255
			if !bytes.Equal(before, rawPixels[0]) {
				t.Fatal("resampling output aliases source", vector.ID)
			}
		}
		var nilGray *image.Gray
		var nilRGBA *image.NRGBA
		for _, bad := range []struct {
			Name          string
			Source        image.Image
			Width, Height int
		}{
			{"nil", nil, 1, 1}, {"typed nil gray", nilGray, 1, 1}, {"typed nil rgba", nilRGBA, 1, 1},
			{"unsupported", image.NewRGBA(image.Rect(0, 0, 2, 2)), 1, 1},
			{"empty", &image.Gray{}, 1, 1},
			{"zero width", image.NewGray(image.Rect(0, 0, 2, 2)), 0, 1},
			{"negative height", image.NewGray(image.Rect(0, 0, 2, 2)), 1, -1},
			{"large width", image.NewGray(image.Rect(0, 0, 2, 2)), 4097, 1},
			{"large area", image.NewGray(image.Rect(0, 0, 2, 2)), 1025, 1025},
			{"large source", &image.Gray{Rect: image.Rect(0, 0, 4097, 1)}, 1, 1},
			{"negative stride", &image.Gray{Pix: make([]byte, 4), Stride: -2, Rect: image.Rect(0, 0, 2, 2)}, 1, 1},
			{"short stride", &image.Gray{Pix: make([]byte, 4), Stride: 1, Rect: image.Rect(0, 0, 2, 2)}, 1, 1},
			{"short pixels", &image.Gray{Pix: make([]byte, 3), Stride: 2, Rect: image.Rect(0, 0, 2, 2)}, 1, 1},
			{"overflow stride", &image.Gray{Pix: make([]byte, 4), Stride: int(^uint(0) >> 1), Rect: image.Rect(0, 0, 2, 2)}, 1, 1},
			{"crossed intermediate", image.NewGray(image.Rect(0, 0, 256, 4096)), 4096, 256},
		} {
			if out, err := resizeRaster(bad.Source, bad.Width, bad.Height, "lanczos", nil); err == nil || out != nil {
				t.Fatal("resampling refusal", bad.Name, err)
			}
		}
	}
	{
		// This digest was frozen from original Pillow output before Go implementation.
		digest := sha256.New()
		pairs, pixels := 0, 0
		for sw := 1; sw <= 256; sw++ {
			source := image.NewNRGBA(image.Rect(0, 0, sw, 1))
			for x := 0; x < sw; x++ {
				source.SetNRGBA(x, 0, color.NRGBA{byte(x), byte(x >> 8), byte(x * 31), 255})
			}
			for dw := 1; dw <= 512; dw++ {
				out, err := resizeRaster(source, dw, 1, "nearest", nil)
				if err != nil {
					t.Fatal("nearest finite sweep", sw, dw, err)
				}
				var size [4]byte
				binary.LittleEndian.PutUint16(size[:2], uint16(sw))
				binary.LittleEndian.PutUint16(size[2:], uint16(dw))
				digest.Write(size[:])
				digest.Write(out.(*image.NRGBA).Pix)
				pairs++
				pixels += dw
			}
		}
		if pairs != 131072 || pixels != 33619968 || fmt.Sprintf("%x", digest.Sum(nil)) != "3669acffb5d7acdb7d16bb1ff866b470046d733a336e5bf0ebdac56d0f7c92fb" {
			t.Fatal("nearest original finite sweep digest", pairs, pixels)
		}
		for _, size := range []image.Point{{512, 512}, {1024, 512}} {
			source := image.NewNRGBA(image.Rect(0, 0, size.X, size.Y))
			for i := 0; i < len(source.Pix); i += 4 {
				copy(source.Pix[i:i+4], []byte{17, 23, 31, 0})
			}
			before := sha256.Sum256(source.Pix)
			out, err := resizeRaster(source, size.X*3, size.Y*3, "nearest", nil)
			if err != nil || out.Bounds() != image.Rect(0, 0, size.X*3, size.Y*3) || before != sha256.Sum256(source.Pix) {
				t.Fatal("nearest presentation capacity", size, err)
			}
			for i := 0; i < len(out.(*image.NRGBA).Pix); i += 4 {
				if !bytes.Equal(out.(*image.NRGBA).Pix[i:i+4], []byte{17, 23, 31, 0}) {
					t.Fatal("nearest presentation hidden pixels", size, i)
				}
			}
		}
		for _, bad := range []struct {
			Name, Filter  string
			Width, Height int
			Crop          *image.Rectangle
		}{
			{"unknown filter", "linear", 1, 1, nil},
			{"crop on lanczos", "lanczos", 1, 1, &image.Rectangle{Max: image.Pt(1, 1)}},
			{"zero output", "nearest", 0, 1, nil},
			{"negative output", "nearest", 1, -1, nil},
			{"large axis", "nearest", 16385, 1, nil},
			{"large area", "nearest", 4096, 4097, nil},
			{"zero crop", "nearest", 1, 1, &image.Rectangle{}},
			{"inverted crop", "nearest", 1, 1, &image.Rectangle{Min: image.Pt(2, 2), Max: image.Pt(1, 1)}},
			{"large crop axis", "nearest", 1, 1, &image.Rectangle{Max: image.Pt(4097, 1)}},
			{"large crop area", "nearest", 1, 1, &image.Rectangle{Max: image.Pt(1025, 1025)}},
			{"crop negative overflow", "nearest", 1, 1, &image.Rectangle{Min: image.Pt(-1<<31, 0), Max: image.Pt(1, 1)}},
			{"crop positive overflow", "nearest", 1, 1, &image.Rectangle{Min: image.Pt(1<<31, 0), Max: image.Pt(1<<31+1, 1)}},
		} {
			if out, err := resizeRaster(image.NewNRGBA(image.Rect(0, 0, 2, 2)), bad.Width, bad.Height, bad.Filter, bad.Crop); err == nil || out != nil {
				t.Fatal("nearest refusal", bad.Name, err)
			}
		}
	}

	{
		var oracle struct {
			Bundle, Profile, Font, Atlas string
			BundleSHA                    string            `json:"bundle_sha256"`
			TXD                          string            `json:"txd_sha256"`
			RGBA                         string            `json:"rgba_sha256"`
			Ledger                       string            `json:"changed_ledger_sha256"`
			Entries                      map[string]string `json:"entries"`
			Raw                          map[string]string `json:"raw_sha256"`
			Counter                      struct {
				Font, Cell, Atlas, Layer, Candidate string
				Origin                              [2]int
			} `json:"counter_case"`
		}
		body, err := os.ReadFile("testdata/native-raster.json")
		if err != nil || json.Unmarshal(body, &oracle) != nil {
			t.Fatal("native raster oracle", err)
		}
		bundleData, err := os.ReadFile(oracle.Bundle)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(bundleData)) != oracle.BundleSHA {
			t.Fatal("native raster bundle", err)
		}
		bundle, err := zip.NewReader(bytes.NewReader(bundleData), int64(len(bundleData)))
		if err != nil {
			t.Fatal(err)
		}
		files := make(map[string][]byte)
		rasters := make(map[string]*image.NRGBA)
		for _, entry := range bundle.File {
			reader, err := entry.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(reader)
			reader.Close()
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != oracle.Entries[entry.Name] {
				t.Fatal("native fixture pin", entry.Name, err)
			}
			files[entry.Name] = data
			if strings.HasSuffix(entry.Name, ".png") {
				decoded, err := png.Decode(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				raster := image.NewNRGBA(decoded.Bounds())
				draw.Draw(raster, raster.Rect, decoded, decoded.Bounds().Min, draw.Src)
				if fmt.Sprintf("%x", sha256.Sum256(raster.Pix)) != oracle.Raw[strings.TrimSuffix(entry.Name, ".png")] {
					t.Fatal("native PNG raw pin", entry.Name)
				}
				rasters[entry.Name] = raster
			}
		}
		for y := 0; y < 256; y++ {
			for x := 0; x < 256; x++ {
				if pixelOver(rasters["over-dst.png"].NRGBAAt(x, y), rasters["over-src.png"].NRGBAAt(x, y)) != rasters["over-out.png"].NRGBAAt(x, y) {
					t.Fatal("Pillow pixelOver alpha domain", x, y)
				}
			}
		}
		var counterFont RasterFont
		var counterCell BitmapCell
		if json.Unmarshal(files[oracle.Counter.Font], &counterFont) != nil || json.Unmarshal(files[oracle.Counter.Cell], &counterCell) != nil {
			t.Fatal("counter oracle data")
		}
		counterImage, err := png.Decode(bytes.NewReader(files[oracle.Counter.Atlas]))
		if err != nil {
			t.Fatal(err)
		}
		counterAtlas := counterImage.(*image.Gray)
		counterLayer, counterOrigin, err := renderRuns(counterAtlas, counterFont, counterCell, nil)
		if err != nil || counterOrigin != image.Pt(oracle.Counter.Origin[0], oracle.Counter.Origin[1]) || len(counterLayer.Pix) != len(rasters[oracle.Counter.Layer].Pix) {
			t.Fatal("four-connected counter layer", err)
		}
		for i, value := range counterLayer.Pix {
			if uint8(math.RoundToEven(float64(value))) != rasters[oracle.Counter.Layer].Pix[i] {
				t.Fatal("four-connected counter rounded layer", i)
			}
		}
		counterBase := image.NewNRGBA(image.Rect(0, 0, 256, 256))
		counterCandidate, _, err := composeCells(counterBase, counterAtlas, counterFont, RasterComposition{Cells: []BitmapCell{counterCell}, Icons: nil})
		if err != nil || !bytes.Equal(counterCandidate.Pix, rasters[oracle.Counter.Candidate].Pix) {
			t.Fatal("four-connected counter candidate", err)
		}
		var profile TextureProfile
		var font RasterFont
		profileData, err := os.ReadFile(oracle.Profile)
		if err != nil || json.Unmarshal(profileData, &profile) != nil {
			t.Fatal(err)
		}
		fontData, err := os.ReadFile(oracle.Font)
		if err != nil || json.Unmarshal(fontData, &font) != nil {
			t.Fatal(err)
		}
		atlasData, err := os.ReadFile(oracle.Atlas)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := png.Decode(bytes.NewReader(atlasData))
		if err != nil {
			t.Fatal(err)
		}
		atlas := decoded.(*image.Gray)
		layer, origin, err := renderRuns(atlas, font, profile.Render.Cells[0], nil)
		if err != nil || origin != image.Pt(98, 217) || layer.Rect != image.Rect(0, 0, 322, 35) || len(layer.Pix) != len(rasters["layer.png"].Pix) {
			t.Fatal("native unclipped word layer/fit/placement", origin, err)
		}
		for i, value := range layer.Pix {
			if uint8(math.RoundToEven(float64(value))) != rasters["layer.png"].Pix[i] {
				t.Fatal("native rounded word layer", i)
			}
		}
		iconData, err := os.ReadFile("testdata/inline-icons.zip")
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(iconData)) != "e569d9722466d9763af09aa9b3ada3548dff5615188efb7b4189339f9e66fba4" {
			t.Fatal("original inline icon fixture", err)
		}
		iconZIP, err := zip.NewReader(bytes.NewReader(iconData), int64(len(iconData)))
		if err != nil {
			t.Fatal(err)
		}
		iconFiles := make(map[string][]byte)
		for _, entry := range iconZIP.File {
			reader, err := entry.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				t.Fatal(err)
			}
			iconFiles[entry.Name] = data
		}
		var iconCases struct {
			Cases []struct {
				Name, Base   string
				Cell         BitmapCell
				Icons        map[string][]int
				Expected     string  `json:"expected_rgba"`
				SHA          string  `json:"expected_sha256"`
				Destinations [][]int `json:"icon_destinations"`
			}
		}
		if json.Unmarshal(iconFiles["vectors.json"], &iconCases) != nil || len(iconCases.Cases) != 11 {
			t.Fatal("inline icon vectors")
		}
		iconAtlasBefore := bytes.Clone(atlas.Pix)
		for _, vector := range iconCases.Cases {
			decoded, err := png.Decode(bytes.NewReader(iconFiles[vector.Base]))
			if err != nil {
				t.Fatal(err)
			}
			base := image.NewNRGBA(decoded.Bounds())
			draw.Draw(base, base.Rect, decoded, decoded.Bounds().Min, draw.Src)
			before := bytes.Clone(base.Pix)
			expected := iconFiles[vector.Expected]
			if fmt.Sprintf("%x", sha256.Sum256(expected)) != vector.SHA {
				t.Fatal("original inline expected pin", vector.Name)
			}
			for _, shift := range []image.Point{{}, {7, 13}} {
				shifted := *base
				shifted.Rect = shifted.Rect.Add(shift)
				out, mask, err := composeCells(&shifted, atlas, font, RasterComposition{Cells: []BitmapCell{vector.Cell}, Icons: vector.Icons})
				if err != nil || !bytes.Equal(out.Pix, expected) || len(mask) != 1 || mask[0] != base.Rect.Add(shift) {
					t.Fatal("whole original inline RGBA/shifted geometry", vector.Name, shift, err)
				}
			}
			if !bytes.Equal(base.Pix, before) || !bytes.Equal(atlas.Pix, iconAtlasBefore) {
				t.Fatal("inline source/atlas changed", vector.Name)
			}
			if vector.Name == "mixed" {
				defaultCell := vector.Cell
				defaultLayout := *vector.Cell.Layout
				defaultLayout.IconGap = nil
				defaultCell.Layout = &defaultLayout
				out, _, err := composeCells(base, atlas, font, RasterComposition{Cells: []BitmapCell{defaultCell}, Icons: vector.Icons})
				if err != nil || !bytes.Equal(out.Pix, expected) {
					t.Fatal("omitted icon gap differs from original default2", err)
				}
			}
			if vector.Cell.Group == nil {
				layer, _, err := renderRuns(atlas, font, vector.Cell, vector.Icons)
				if err != nil || len(layer.Icons) != len(vector.Destinations) {
					t.Fatal("inline placements", vector.Name, err)
				}
				for i, at := range vector.Destinations {
					if layer.Icons[i].At != image.Pt(at[0], at[1]) || layer.Icons[i].Source.Size() != image.Pt(2, 2) {
						t.Fatal("two-stage icon rounding/fixed dimensions", vector.Name, i, layer.Icons[i])
					}
				}
			}
		}
		var iconProfile TextureProfile
		if json.Unmarshal(iconFiles["native/profile.json"], &iconProfile) != nil {
			t.Fatal("native icon profile")
		}
		iconSource := iconFiles["native/source.txd"]
		_, iconBase, err := texture(iconSource, iconProfile.Texture, nil, nil, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		iconCandidate, iconMask, err := composeCells(iconBase, atlas, font, RasterComposition{Cells: iconProfile.Render.Cells, Icons: iconProfile.Render.Icons})
		if err != nil || !bytes.Equal(iconCandidate.Pix, iconFiles["native/expected.raw"]) {
			t.Fatal("native icon original complete RGBA", err)
		}
		iconArtifact, _, err := texture(iconSource, iconProfile.Texture, iconCandidate, iconMask, iconProfile.PalettePolicy, nil)
		if err != nil || !bytes.Equal(iconArtifact, iconFiles["native/expected.txd"]) {
			t.Fatal("native icon unchanged codec projection", err)
		}
		for _, mutation := range []string{"unknown", "text conflict", "color conflict", "short source", "negative source", "source overflow", "empty source", "too many sources", "invalid source name", "gap negative", "gap nan", "gap infinite", "gap large", "transparent target spill", "pixel font"} {
			body, _ := json.Marshal(iconCases.Cases[8].Cell)
			var cell BitmapCell
			if err := json.Unmarshal(body, &cell); err != nil {
				t.Fatal(err)
			}
			icons := map[string][]int{"mark": {1, 0, 2, 2}}
			badFont := font
			switch mutation {
			case "unknown":
				cell.Runs[0].Icon = "missing"
			case "text conflict":
				cell.Runs[0].Text = "A"
			case "color conflict":
				cell.Runs[0].Fill = []int{255, 255, 255, 255}
			case "short source":
				icons["mark"] = []int{1, 0, 2}
			case "negative source":
				icons["mark"][0] = -1
			case "source overflow":
				icons["mark"][0] = math.MaxInt
			case "empty source":
				icons["mark"][2] = 0
			case "too many sources":
				for i := 0; i < 65; i++ {
					icons[fmt.Sprint(i)] = []int{1, 0, 2, 2}
				}
			case "invalid source name":
				icons["\xff"] = []int{1, 0, 2, 2}
			case "gap negative", "gap nan", "gap infinite", "gap large":
				value := -1.0
				switch mutation {
				case "gap nan":
					value = math.NaN()
				case "gap infinite":
					value = math.Inf(1)
				case "gap large":
					value = 64.01
				}
				cell.Layout.IconGap = &value
			case "transparent target spill":
				cell.Layout.At[1] = 0
			case "pixel font":
				badFont.Em, badFont.Ascent, badFont.Descent, badFont.CapHeight = 0, 0, 0, 0
			}
			out, mask, err := composeCells(image.NewNRGBA(image.Rect(0, 0, 96, 64)), atlas, badFont, RasterComposition{Cells: []BitmapCell{cell}, Icons: icons})
			if err == nil || out != nil || mask != nil || !bytes.Equal(atlas.Pix, iconAtlasBefore) {
				t.Fatal("inline refusal/preservation", mutation, err)
			}
			if mutation == "transparent target spill" && !strings.Contains(err.Error(), "icon spills outside") {
				t.Fatal("full icon containment not exercised", err)
			}
		}
		styleAtlasBefore := bytes.Clone(atlas.Pix)
		var styles struct {
			Bundle  string
			SHA     string `json:"bundle_sha256"`
			Entries map[string]string
			OldWord string `json:"old_janky_word"`
			Profile string
			Paint   struct {
				Base, Float, Pillow string
				Rect                []int `json:"background_rect"`
			}
			Actual struct {
				Source, Expected, Texture string
				RGBA                      string `json:"rgba_sha256"`
				Changes                   int    `json:"native_changes"`
				Rectangle                 [4]int
			}

			Cases []struct {
				Cell                    BitmapCell
				Canvas, Shape, Origin   [2]int
				Word, Placed, Candidate string
				WordPNG                 string `json:"word_png"`
			}
		}
		styleData, err := os.ReadFile("testdata/native-styles.json")
		if err != nil || json.Unmarshal(styleData, &styles) != nil {
			t.Fatal("native style manifest", err)
		}
		var sourceColors struct {
			Bundle  string
			SHA     string `json:"bundle_sha256"`
			Entries map[string]string
			Cases   []struct {
				Name, Source, Expected, Candidate, Default, Texture string
				Rect                                                [4]int
				RGBA                                                string `json:"rgba_sha256"`
				PixelOffset                                         int    `json:"pixel_offset"`
				PixelBytes                                          int    `json:"pixel_bytes"`
			}
		}
		sourceMeta, err := os.ReadFile("testdata/source-colors.json")
		if err != nil || json.Unmarshal(sourceMeta, &sourceColors) != nil {
			t.Fatal("source color manifest", err)
		}
		var groups struct {
			Bundle  string
			SHA     string `json:"bundle_sha256"`
			Entries map[string]string
			Cases   []struct {
				Cell      BitmapCell
				Candidate string
			}
			Actual struct {
				Source, Expected, Profile, Texture string
				Raw                                string `json:"raw_sha256"`
				RGBA                               string `json:"rgba_sha256"`
				Changes                            int    `json:"native_changes"`
			}
		}
		groupMeta, err := os.ReadFile("testdata/native-line-groups.json")
		if err != nil || json.Unmarshal(groupMeta, &groups) != nil || len(groups.Cases) != 8 {
			t.Fatal("native line group manifest", err)
		}
		styleFiles, sourceFiles := make(map[string][]byte), make(map[string][]byte)
		groupFiles := make(map[string][]byte)
		for _, fixture := range []struct {
			Path, SHA string
			Pins      map[string]string
			Files     map[string][]byte
		}{
			{styles.Bundle, styles.SHA, styles.Entries, styleFiles},
			{sourceColors.Bundle, sourceColors.SHA, sourceColors.Entries, sourceFiles},
			{groups.Bundle, groups.SHA, groups.Entries, groupFiles},
		} {
			data, err := os.ReadFile(fixture.Path)
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != fixture.SHA {
				t.Fatal("raster fixture bundle", fixture.Path, err)
			}
			bundle, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			if len(bundle.File) != len(fixture.Pins) {
				t.Fatal("raster fixture entry count", fixture.Path)
			}
			for _, entry := range bundle.File {
				reader, err := entry.Open()
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(reader)
				reader.Close()
				if err != nil || fmt.Sprintf("%x", sha256.Sum256(body)) != fixture.Pins[entry.Name] {
					t.Fatal("raster fixture pin", entry.Name, err)
				}
				fixture.Files[entry.Name] = body
			}
		}
		for _, vector := range groups.Cases {
			panel := image.NewNRGBA(image.Rect(0, 0, 1024, 512))
			draw.Draw(panel, panel.Rect, image.NewUniform(color.NRGBA{244, 195, 110, 255}), image.Point{}, draw.Src)
			before := bytes.Clone(panel.Pix)
			started := time.Now()
			candidate, mask, err := composeCells(panel, atlas, font, RasterComposition{Cells: []BitmapCell{vector.Cell}, Icons: nil})
			if err != nil || !bytes.Equal(candidate.Pix, groupFiles[vector.Candidate]) || len(mask) != 1 || !bytes.Equal(before, panel.Pix) || !bytes.Equal(styleAtlasBefore, atlas.Pix) {
				t.Fatal("native group canonical composition", vector.Cell.ID, err)
			}
			t.Logf("native group %s %.3fs", vector.Cell.ID, time.Since(started).Seconds())
		}
		groupSource := groupFiles[groups.Actual.Source]
		_, groupBase, err := texture(groupSource, groups.Actual.Texture, nil, nil, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		var groupProfile TextureProfile
		groupProfileData, err := os.ReadFile(groups.Actual.Profile)
		if err != nil || json.Unmarshal(groupProfileData, &groupProfile) != nil {
			t.Fatal("native group profile", err)
		}
		groupRaw, groupMask, err := composeCells(groupBase, atlas, font, RasterComposition{Cells: groupProfile.Render.Cells, Icons: nil})
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(groupRaw.Pix)) != groups.Actual.Raw {
			t.Fatal("native group actual raw composition", err)
		}
		groupArtifact, groupDecoded, err := texture(groupSource, groups.Actual.Texture, groupRaw, groupMask, "source", nil)
		if err != nil || !bytes.Equal(groupArtifact, groupFiles[groups.Actual.Expected]) || fmt.Sprintf("%x", sha256.Sum256(groupDecoded.Pix)) != groups.Actual.RGBA {
			t.Fatal("native group actual whole artifact", err)
		}
		groupChanges := 0
		for i, value := range groupSource {
			if value != groupArtifact[i] {
				groupChanges++
			}
		}
		if groupChanges != groups.Actual.Changes {
			t.Fatal("native group actual change count", groupChanges)
		}
		for _, mutation := range []string{"mixed runs", "scalar anchor", "scalar width", "empty lines", "too many lines", "short box", "outside box", "nan box", "negative leading", "infinite leading", "horizontal align", "vertical align", "spill", "late missing glyph"} {
			body, _ := json.Marshal(groups.Cases[0].Cell)
			var cell BitmapCell
			if err := json.Unmarshal(body, &cell); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "mixed runs":
				cell.Runs = cell.Group.Lines[0]
			case "scalar anchor":
				cell.Layout.At = []float64{1, 1}
			case "scalar width":
				cell.Layout.MaxWidth = 1
			case "empty lines":
				cell.Group.Lines = nil
			case "too many lines":
				cell.Group.Lines = make([][]BitmapRun, 17)
			case "short box":
				cell.Group.Box = []float64{0, 0, 1}
			case "outside box":
				cell.Group.Box[0] = -1
			case "nan box":
				cell.Group.Box[2] = math.NaN()
			case "negative leading":
				cell.Group.Leading = -1
			case "infinite leading":
				cell.Group.Leading = math.Inf(1)
			case "horizontal align":
				cell.Layout.Align = "diagonal"
			case "vertical align":
				cell.Group.VerticalAlign = "bottom"
			case "spill":
				cell.Group.Box[1] = 0
				cell.Group.Box[3] = 1
			case "late missing glyph":
				cell.Group.Lines[1][0].Text = "\u2603"
			}
			panel := image.NewNRGBA(image.Rect(0, 0, 1024, 512))
			before := bytes.Clone(panel.Pix)
			out, mask, err := composeCells(panel, atlas, font, RasterComposition{Cells: []BitmapCell{cell}, Icons: nil})
			if err == nil || out != nil || mask != nil || !bytes.Equal(before, panel.Pix) || !bytes.Equal(styleAtlasBefore, atlas.Pix) {
				t.Fatal("native group refusal/input preservation", mutation, err)
			}
		}
		for _, vector := range sourceColors.Cases {
			source := sourceFiles[vector.Source]
			before := bytes.Clone(source)
			candidate, err := png.Decode(bytes.NewReader(sourceFiles[vector.Candidate]))
			if err != nil {
				t.Fatal(err)
			}
			r := vector.Rect
			artifact, raster, err := texture(source, vector.Texture, candidate, []image.Rectangle{image.Rect(r[0], r[1], r[0]+r[2], r[1]+r[3])}, "source", nil)
			if err != nil || !bytes.Equal(artifact, sourceFiles[vector.Expected]) || fmt.Sprintf("%x", sha256.Sum256(raster.Pix)) != vector.RGBA {
				t.Fatal("source color two-stage oracle", vector.Name, err)
			}
			if !bytes.Equal(source, before) || !bytes.Equal(source[:vector.PixelOffset], artifact[:vector.PixelOffset]) || !bytes.Equal(source[vector.PixelOffset+vector.PixelBytes:], artifact[vector.PixelOffset+vector.PixelBytes:]) {
				t.Fatal("source color input/header/CLUT/siblings", vector.Name)
			}
			defaultArtifact, _, err := texture(source, vector.Texture, candidate, nil, "", nil)
			if vector.Default == "" {
				if err == nil || defaultArtifact != nil || !strings.Contains(err.Error(), "too many distinct") {
					t.Fatal("default color cap changed", vector.Name, err)
				}
			} else if err != nil || !bytes.Equal(defaultArtifact, sourceFiles[vector.Default]) {
				t.Fatal("default palette selection changed", vector.Name, err)
			}
			again, _, err := texture(artifact, vector.Texture, raster, nil, "source", nil)
			if err != nil || !bytes.Equal(again, artifact) {
				t.Fatal("source color idempotence", vector.Name, err)
			}
			if out, pixels, err := texture(source, vector.Texture, nil, nil, "source", nil); err == nil || out != nil || pixels != nil {
				t.Fatal("source color export admitted", vector.Name)
			}
			if out, pixels, err := texture(source, vector.Texture, candidate, []image.Rectangle{image.Rect(0, candidate.Bounds().Dy()-1, 1, candidate.Bounds().Dy())}, "source", nil); err == nil || out != nil || pixels != nil || !strings.Contains(err.Error(), "outside approved") {
				t.Fatal("source projection hid raw outside edit", vector.Name, err)
			}
		}
		oldFloats := make([]byte, len(layer.Pix)*4)
		for i, value := range layer.Pix {
			binary.LittleEndian.PutUint32(oldFloats[i*4:], math.Float32bits(value))
		}
		if !bytes.Equal(oldFloats, styleFiles[styles.OldWord]) {
			t.Fatal("original Janky unrounded area layer")
		}
		for _, vector := range styles.Cases {
			started := time.Now()
			word, point, err := renderRuns(atlas, font, vector.Cell, nil)
			if err != nil || point != image.Pt(vector.Origin[0], vector.Origin[1]) || word.Rect != image.Rect(0, 0, vector.Shape[0], vector.Shape[1]) {
				t.Fatal("native style geometry", vector.Cell.ID, point, err)
			}
			raw := make([]byte, len(word.Pix)*4)
			for i, value := range word.Pix {
				binary.LittleEndian.PutUint32(raw[i*4:], math.Float32bits(value))
			}
			if vector.Word != "" && !bytes.Equal(raw, styleFiles[vector.Word]) {
				for i, value := range word.Pix {
					want := math.Float32frombits(binary.LittleEndian.Uint32(styleFiles[vector.Word][i*4:]))
					if math.Float32bits(value) != math.Float32bits(want) {
						t.Fatalf("native style float word %s channel%d got%.9g want%.9g", vector.Cell.ID, i, value, want)
					}
				}
				t.Fatal("native style float word length", vector.Cell.ID)
			}
			placed := make([]byte, vector.Canvas[0]*vector.Canvas[1]*16)
			if point.X < 0 || point.Y < 0 || point.X+word.Rect.Dx() > vector.Canvas[0] || point.Y+word.Rect.Dy() > vector.Canvas[1] {
				t.Fatal("native style oracle clips", vector.Cell.ID)
			}
			for y := 0; y < word.Rect.Dy(); y++ {
				at := ((y+point.Y)*vector.Canvas[0] + point.X) * 16
				copy(placed[at:at+word.Rect.Dx()*16], raw[y*word.Rect.Dx()*16:(y+1)*word.Rect.Dx()*16])
			}
			if !bytes.Equal(placed, styleFiles[vector.Placed]) {
				t.Fatal("native placed float layer", vector.Cell.ID)
			}
			if vector.WordPNG != "" {
				roundedImage, err := png.Decode(bytes.NewReader(styleFiles[vector.WordPNG]))
				if err != nil {
					t.Fatal(err)
				}
				rounded := image.NewNRGBA(roundedImage.Bounds())
				draw.Draw(rounded, rounded.Rect, roundedImage, roundedImage.Bounds().Min, draw.Src)
				for i, value := range word.Pix {
					if uint8(max(0, min(255, math.RoundToEven(float64(value))))) != rounded.Pix[i] {
						t.Fatal("native rounded style word", vector.Cell.ID, i)
					}
				}
			}
			if vector.Candidate != "" {
				panel := image.NewNRGBA(image.Rect(0, 0, vector.Canvas[0], vector.Canvas[1]))
				candidate, _, err := composeCells(panel, atlas, font, RasterComposition{Cells: []BitmapCell{vector.Cell}, Icons: nil})
				if err != nil || !bytes.Equal(candidate.Pix, styleFiles[vector.Candidate]) {
					t.Fatal("native float panel composition", vector.Cell.ID, err)
				}
			}
			t.Logf("native style %s %.3fs", vector.Cell.ID, time.Since(started).Seconds())
		}
		paintImage, err := png.Decode(bytes.NewReader(styleFiles[styles.Paint.Base]))
		if err != nil {
			t.Fatal(err)
		}
		paintBase := image.NewNRGBA(paintImage.Bounds())
		draw.Draw(paintBase, paintBase.Rect, paintImage, paintImage.Bounds().Min, draw.Src)
		paintBefore := bytes.Clone(paintBase.Pix)
		for _, policy := range []string{"float", "pillow"} {
			paintCell := styles.Cases[1].Cell
			paintCell.BackgroundRect = styles.Paint.Rect
			paintLayout := *paintCell.Layout
			paintLayout.Composite = policy
			paintCell.Layout = &paintLayout
			painted, _, err := composeCells(paintBase, atlas, font, RasterComposition{Cells: []BitmapCell{paintCell}, Icons: nil})
			if err != nil {
				t.Fatal("partial background composition", policy, err)
			}
			expectedName := styles.Paint.Float
			if policy == "pillow" {
				expectedName = styles.Paint.Pillow
			}
			expectedImage, err := png.Decode(bytes.NewReader(styleFiles[expectedName]))
			if err != nil {
				t.Fatal(err)
			}
			expected := image.NewNRGBA(expectedImage.Bounds())
			draw.Draw(expected, expected.Rect, expectedImage, expectedImage.Bounds().Min, draw.Src)
			if !bytes.Equal(painted.Pix, expected.Pix) || !bytes.Equal(paintBase.Pix, paintBefore) {
				t.Fatal("partial background alpha/hiddenRGB oracle", policy)
			}
			shifted := *paintBase
			shifted.Rect = paintBase.Rect.Add(image.Pt(1, 3))
			translated, _, err := composeCells(&shifted, atlas, font, RasterComposition{Cells: []BitmapCell{paintCell}, Icons: nil})
			if err != nil || !bytes.Equal(translated.Pix, expected.Pix) {
				t.Fatal("shifted partial background", policy, err)
			}
		}
		workBound := styles.Cases[2].Cell
		workLayout := *workBound.Layout
		workLayout.Size = 64
		workLayout.MaxWidth = 4096
		workLayout.At = []float64{2000, 128}
		workBound.Layout = &workLayout
		workBound.Rect = []int{0, 0, 4096, 256}
		workBound.Runs = []BitmapRun{{Text: "WWWWWWWW", Fill: []int{255, 255, 255, 255}}}
		if out, _, err := renderRuns(atlas, font, workBound, nil); err == nil || out != nil || !strings.Contains(err.Error(), "work bound") {
			t.Fatal("bounded native stroke work", err)
		}
		var tutorial TextureProfile
		tutorialData, err := os.ReadFile(styles.Profile)
		if err != nil || json.Unmarshal(tutorialData, &tutorial) != nil {
			t.Fatal("tutorial profile", err)
		}
		original := styleFiles[styles.Actual.Source]
		_, originalRaster, err := texture(original, tutorial.Texture, nil, nil, "", nil)
		if err != nil {
			t.Fatal("tutorial original", err)
		}
		originalBefore := bytes.Clone(originalRaster.Pix)
		tutorialCandidate, tutorialMask, err := composeCells(originalRaster, atlas, font, RasterComposition{Cells: tutorial.Render.Cells, Icons: nil})
		if err != nil {
			t.Fatal("tutorial float rendering", err)
		}
		artifact, _, err := texture(original, tutorial.Texture, tutorialCandidate, tutorialMask, tutorial.PalettePolicy, nil)
		if err != nil || !bytes.Equal(artifact, styleFiles[styles.Actual.Expected]) {
			t.Fatal("tutorial whole native artifact", err)
		}
		_, readback, err := texture(artifact, tutorial.Texture, nil, nil, "", nil)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(readback.Pix)) != styles.Actual.RGBA {
			t.Fatal("tutorial native RGBA", err)
		}
		changes := 0
		for i, value := range original {
			if value != artifact[i] {
				changes++
			}
		}
		if changes != styles.Actual.Changes || !bytes.Equal(originalRaster.Pix, originalBefore) || !bytes.Equal(atlas.Pix, styleAtlasBefore) {
			t.Fatal("tutorial native changes/preservation", changes)
		}
		for y := 0; y < readback.Rect.Dy(); y++ {
			for x := 0; x < readback.Rect.Dx(); x++ {
				if !image.Pt(x, y).In(tutorialMask[0]) && readback.NRGBAAt(x, y) != originalRaster.NRGBAAt(x, y) {
					t.Fatal("tutorial outside mask", x, y)
				}
			}
		}
		// The one sub-half-alpha fringe must refuse outside the strict float cell.
		narrow := tutorial.Render.Cells[0]
		narrow.Rect = []int{125, 84, 384, 26}
		narrowLayout := *narrow.Layout
		narrowLayout.At = []float64{192, 13}
		narrow.Layout = &narrowLayout
		if out, _, err := composeCells(originalRaster, atlas, font, RasterComposition{Cells: []BitmapCell{narrow}, Icons: nil}); err == nil || out != nil || !strings.Contains(err.Error(), "spills outside") {
			t.Fatal("unrounded tutorial fringe containment", err)
		}
		fitted := profile.Render.Cells[0]
		fitLayout := *fitted.Layout
		fitLayout.Size = 19.25
		fitted.Layout = &fitLayout
		fixed, fixedOrigin, err := renderRuns(atlas, font, fitted, nil)
		if err != nil || fixedOrigin != origin || !reflect.DeepEqual(fixed.Pix, layer.Pix) {
			t.Fatal("requested22 must derive canonical19.25 fit", err)
		}
		source := files["source.txd"]
		_, base, err := texture(source, profile.Texture, nil, nil, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		baseBefore, atlasBefore := bytes.Clone(base.Pix), bytes.Clone(atlas.Pix)
		candidate, rectangles, err := composeCells(base, atlas, font, RasterComposition{Cells: profile.Render.Cells, Icons: nil})
		if err != nil || len(rectangles) != 1 || rectangles[0] != image.Rect(100, 226, 416, 247) || !bytes.Equal(candidate.Pix, rasters["candidate.png"].Pix) {
			t.Fatal("native raw candidate/containment", err)
		}
		artifact, raster, err := texture(source, profile.Texture, candidate, rectangles, "", nil)
		if err != nil || !bytes.Equal(artifact, files["expected.txd"]) || fmt.Sprintf("%x", sha256.Sum256(artifact)) != oracle.TXD || fmt.Sprintf("%x", sha256.Sum256(raster.Pix)) != oracle.RGBA {
			t.Fatal("native whole TXD/RGBA golden", err)
		}
		var ledger []byte
		for at, old := range source {
			if artifact[at] != old {
				if at < 284 || at >= 284+512*512 {
					t.Fatal("native changed header/CLUT/metadata")
				}
				ledger = binary.LittleEndian.AppendUint32(ledger, uint32(at))
				ledger = append(ledger, old, artifact[at])
			}
		}
		changed := 0
		for y := 0; y < 512; y++ {
			for x := 0; x < 512; x++ {
				if base.NRGBAAt(x, y) != raster.NRGBAAt(x, y) {
					if !image.Pt(x, y).In(rectangles[0]) {
						t.Fatal("native pixels escaped cell")
					}
					changed++
				}
			}
		}
		if changed != 5371 || len(ledger) != 5371*6 || fmt.Sprintf("%x", sha256.Sum256(ledger)) != oracle.Ledger || !bytes.Equal(baseBefore, base.Pix) || !bytes.Equal(atlasBefore, atlas.Pix) {
			t.Fatal("native changed ledger/source preservation")
		}
		again, mask, err := composeCells(raster, atlas, font, RasterComposition{Cells: profile.Render.Cells, Icons: nil})
		if err != nil {
			t.Fatal(err)
		}
		repeated, _, err := texture(artifact, profile.Texture, again, mask, "", nil)
		if err != nil || !bytes.Equal(repeated, artifact) {
			t.Fatal("native repeated raster is not idempotent", err)
		}
		// A half-tie anchor must be rounded before adding the base's odd origin.
		shiftedBase, shiftedAtlas := *base, *atlas
		shiftedBase.Rect = base.Rect.Add(image.Pt(1, 3))
		shiftedAtlas.Rect = atlas.Rect.Add(image.Pt(-5, 7))
		tie := profile.Render.Cells[0]
		tieLayout := *tie.Layout
		tieLayout.At = []float64{159.255625, 9.5}
		tie.Layout = &tieLayout
		translated, mask, err := composeCells(&shiftedBase, &shiftedAtlas, font, RasterComposition{Cells: []BitmapCell{tie}, Icons: nil})
		if err != nil || !bytes.Equal(translated.Pix, candidate.Pix) || mask[0] != rectangles[0].Add(image.Pt(1, 3)) {
			t.Fatal("native shifted origin/ties-even placement", err)
		}
		for _, mutation := range []string{"fractional size", "nan size", "infinite scale", "zero width", "large width", "zero scale", "large scale", "negative stroke", "large stroke", "short anchor", "outside anchor", "missing layout", "no runs", "empty run", "missing glyph", "long text", "short color", "large color", "transparent color", "short background", "transparent background", "pixel text conflict", "pixel fill conflict", "font metrics", "font tile", "font left", "advance-only bearing", "spill top", "spill left", "tracking nan", "tracking bound", "tracking reverses", "minimum negative", "minimum fractional", "minimum large", "composition unknown", "strokes empty", "stroke conflict", "stroke count", "stroke source", "stroke order", "glyph stroke color", "glyph stroke radius", "stroke color absent", "stroke color large", "stroke alpha", "stroke radius nan", "stroke radius infinite", "stroke radius large", "background rect short", "background rect empty", "background rect outside", "background rect zero"} {
			var bad TextureProfile
			var badFont RasterFont
			if json.Unmarshal(profileData, &bad) != nil || json.Unmarshal(fontData, &badFont) != nil {
				t.Fatal("native mutation clone")
			}
			cell := &bad.Render.Cells[0]
			switch mutation {
			case "fractional size":
				cell.Layout.Size = 22.1
			case "nan size":
				cell.Layout.Size = math.NaN()
			case "infinite scale":
				cell.Layout.ScaleX = math.Inf(1)
			case "zero width":
				cell.Layout.MaxWidth = 0
			case "large width":
				cell.Layout.MaxWidth = 317
			case "zero scale":
				cell.Layout.ScaleX = 0
			case "large scale":
				cell.Layout.ScaleX = 3
			case "negative stroke":
				cell.Layout.Stroke = -1
			case "large stroke":
				cell.Layout.Stroke = 1
			case "short anchor":
				cell.Layout.At = []float64{1}
			case "outside anchor":
				cell.Layout.At[0] = 317
			case "missing layout":
				cell.Layout = nil
			case "no runs":
				cell.Runs = nil
			case "empty run":
				cell.Runs[0].Text = ""
			case "missing glyph":
				cell.Runs[0].Text = "’"
			case "long text":
				cell.Runs[0].Text = strings.Repeat("A", 129)
			case "short color":
				cell.Runs[0].Fill = []int{0, 0, 0}
			case "large color":
				cell.Runs[0].Fill[0] = 256
			case "transparent color":
				cell.Runs[0].Fill[3] = 0
			case "short background":
				cell.Background = []int{244, 195, 110}
			case "transparent background":
				cell.Background[3] = 0
			case "pixel text conflict":
				cell.Text = "A"
			case "pixel fill conflict":
				cell.Fill = []int{0, 0, 0, 255}
			case "font metrics":
				badFont.CapHeight = 25
			case "font tile":
				glyph := badFont.Glyphs["L"]
				glyph.Rect[2]--
				badFont.Glyphs["L"] = glyph
			case "font left":
				glyph := badFont.Glyphs["L"]
				glyph.Left = -1
				badFont.Glyphs["L"] = glyph
			case "advance-only bearing":
				glyph := badFont.Glyphs[" "]
				glyph.Left = 1
				badFont.Glyphs[" "] = glyph
			case "background rect short":
				cell.BackgroundRect = []int{100, 226, 316}
			case "background rect empty":
				cell.BackgroundRect = []int{}
			case "background rect outside":
				cell.BackgroundRect = []int{99, 226, 316, 21}
			case "background rect zero":
				cell.BackgroundRect = []int{100, 226, 0, 21}
			case "tracking nan":
				cell.Layout.Tracking = math.NaN()
			case "tracking bound":
				cell.Layout.Tracking = -1.1
			case "tracking reverses":
				cell.Layout.Size = 6
				cell.Layout.Tracking = -1
				g := badFont.Glyphs["L"]
				g.Advance = 1
				badFont.Glyphs["L"] = g
			case "minimum negative":
				cell.Layout.MinSize = -1
			case "minimum fractional":
				cell.Layout.MinSize = 16.1
			case "minimum large":
				cell.Layout.MinSize = 23
			case "composition unknown":
				cell.Layout.Composite = "fast"
			case "strokes empty":
				cell.Layout.Stroke = 0
				cell.Layout.Strokes = &[]BitmapStroke{}
			case "stroke conflict":
				cell.Layout.Strokes = &[]BitmapStroke{{Radius: .5, Source: "glyph"}}
			case "stroke count", "stroke source", "stroke order", "glyph stroke color", "glyph stroke radius", "stroke color absent", "stroke color large", "stroke alpha", "stroke radius nan", "stroke radius infinite", "stroke radius large":
				cell.Layout.Stroke = 0
				cell.Layout.Strokes = &[]BitmapStroke{{Radius: .65, Source: "color", Fill: []int{255, 207, 116, 255}}, {Radius: .5, Source: "glyph"}}
				outer := &(*cell.Layout.Strokes)[0]
				switch mutation {
				case "stroke count":
					*cell.Layout.Strokes = append(*cell.Layout.Strokes, BitmapStroke{Radius: .5, Source: "glyph"})
				case "stroke source":
					outer.Source = "unknown"
				case "stroke order":
					outer.Radius = .25
				case "glyph stroke color":
					(*cell.Layout.Strokes)[1].Fill = []int{0, 0, 0, 255}
				case "glyph stroke radius":
					outer.Radius = 2
					(*cell.Layout.Strokes)[1].Radius = 1.1
				case "stroke color absent":
					outer.Fill = nil
				case "stroke color large":
					outer.Fill[0] = 256
				case "stroke alpha":
					outer.Fill[3] = 0
				case "stroke radius nan":
					outer.Radius = math.NaN()
				case "stroke radius infinite":
					outer.Radius = math.Inf(1)
				case "stroke radius large":
					outer.Radius = 3.76
				}
			case "spill top":
				cell.Layout.At[1]--
			case "spill left":
				cell.Layout.At[0] -= 4
			}
			out, mask, err := composeCells(base, atlas, badFont, RasterComposition{Cells: bad.Render.Cells, Icons: nil})
			if err == nil || out != nil || mask != nil || !bytes.Equal(base.Pix, baseBefore) || !bytes.Equal(atlas.Pix, atlasBefore) {
				t.Fatal("native mutation admitted/inputs changed", mutation, err)
			}
			if strings.HasPrefix(mutation, "spill ") && !strings.Contains(err.Error(), "spills outside") {
				t.Fatal("native spill did not exercise unclipped containment", mutation, err)
			}
		}
	}
	t.Run("fixed-palette texture codec", func(t *testing.T) {
		var oracle struct {
			ZIP              string `json:"source_zip_sha256"`
			NibbleMap        string `json:"psmt4_map_sha256"`
			MultipageZIP     string `json:"multipage_psmt4_zip_sha256"`
			DirectZIP        string `json:"direct_rgba_zip_sha256"`
			DirectLayoutsZIP string `json:"direct_layouts_zip_sha256"`
			SmallPSMT8ZIP    string `json:"small_psmt8_zip_sha256"`
			ExactPalette     struct {
				ZIP   string `json:"source_zip_sha256"`
				Cases []struct {
					Policy  string `json:"palette_policy"`
					Texture string
					Key     string `json:"bundle_key"`
					Source  string `json:"source_sha256"`
					PNG     string
					PNGSHA  string `json:"png_sha256"`
					Colors  int
					Refuse  bool
					TXD     string   `json:"txd_sha256"`
					RGBA    string   `json:"rgba_sha256"`
					Palette string   `json:"palette_sha256"`
					Pixels  string   `json:"pixel_sha256"`
					Ranges  [][2]int `json:"allowed_byte_ranges"`
					Changed int      `json:"changed_bytes"`
				}
			} `json:"exact_palette"`
			Cases []struct {
				Name, Texture string
				Policy        string `json:"raster_policy"`
				Key           string `json:"bundle_key"`
				Source        string `json:"source_sha256"`
				Mutations     []struct {
					Offset int
					Hex    string
				} `json:"source_mutations"`
				Width, Height  int
				PalettePacket  int      `json:"palette_packet_offset"`
				PixelOffset    int      `json:"pixel_offset"`
				MetadataOffset int      `json:"metadata_offset"`
				Ramps          []string `json:"ramp_rgba_sha256"`
				RGBA           string   `json:"rgba_sha256"`
				Noop           string   `json:"noop_txd_sha256"`
				Edit           struct {
					Pixels []struct {
						X, Y int
						RGBA [4]uint8
					}
					TXD     string `json:"txd_sha256"`
					Raster  string `json:"rgba_sha256"`
					Changed int    `json:"changed_bytes"`
				}
			}
		}
		data, err := os.ReadFile("testdata/textures.json")
		if err != nil || json.Unmarshal(data, &oracle) != nil || len(oracle.Cases) != 44 || len(oracle.ExactPalette.Cases) != 35 {
			t.Fatal("missing texture oracle", err)
		}
		members := make(map[string][]byte)
		for _, bundle := range []struct{ path, hash string }{{"assets/cmb-members.zip", oracle.ZIP}, {"testdata/exact-palette.zip", oracle.ExactPalette.ZIP}, {"testdata/multipage-psmt4.zip", oracle.MultipageZIP}, {"testdata/direct-rgba.zip", oracle.DirectZIP}, {"testdata/direct-layouts.zip", oracle.DirectLayoutsZIP}, {"testdata/small-psmt8.zip", oracle.SmallPSMT8ZIP}} {
			data, err = os.ReadFile(bundle.path)
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != bundle.hash {
				t.Fatal("texture ZIP changed", err)
			}
			archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range archive.File {
				needed := false
				for _, c := range oracle.Cases {
					needed = needed || f.Name == c.Key
				}
				for _, c := range oracle.ExactPalette.Cases {
					needed = needed || f.Name == c.Key || f.Name == c.PNG
				}
				if !needed {
					continue
				}
				if f.UncompressedSize64 > 64<<20 {
					t.Fatal("oversized texture fixture")
				}
				r, err := f.Open()
				if err != nil {
					t.Fatal(err)
				}
				body, readErr := io.ReadAll(io.LimitReader(r, 64<<20+1))
				closeErr := r.Close()
				if readErr != nil || closeErr != nil {
					t.Fatal(readErr, closeErr)
				}
				members[f.Name] = body
			}
		}
		for _, c := range oracle.Cases {
			t.Run(c.Name, func(t *testing.T) {
				source := bytes.Clone(members[c.Key])
				if fmt.Sprintf("%x", sha256.Sum256(source)) != c.Source {
					t.Fatal("texture member changed")
				}
				for _, mutation := range c.Mutations {
					raw, err := hex.DecodeString(mutation.Hex)
					if err != nil || mutation.Offset < 0 || len(raw) > len(source)-mutation.Offset {
						t.Fatal("invalid oracle mutation")
					}
					copy(source[mutation.Offset:], raw)
				}
				before := bytes.Clone(source)
				if strings.HasPrefix(c.Name, "raw32") {
					if out, pixels, err := texture(source, c.Texture, image.NewNRGBA(image.Rect(0, 0, c.Width, c.Height)), nil, "source", nil); err == nil || out != nil || pixels != nil {
						t.Fatal("source policy admitted direct pixels")
					}
				}
				if c.Policy == "rgba" {
					if out, pixels, err := texture(source, c.Texture, nil, nil, "", nil); err == nil || out != nil || pixels != nil {
						t.Fatal("colored source admitted without explicit policy")
					}
				}
				artifact, raster, err := texture(source, c.Texture, nil, nil, c.Policy, nil)
				if err != nil || artifact != nil || raster == nil || raster.Bounds() != image.Rect(0, 0, c.Width, c.Height) || fmt.Sprintf("%x", sha256.Sum256(raster.Pix)) != c.RGBA {
					t.Fatalf("decode differs: %v", err)
				}
				var encoded bytes.Buffer
				if err := png.Encode(&encoded, raster); err != nil {
					t.Fatal(err)
				}
				candidate, err := png.Decode(&encoded)
				if err != nil {
					t.Fatal(err)
				}
				if strings.HasPrefix(c.Name, "std") || strings.HasPrefix(c.Name, "nohdr") {
					if out, pixels, err := texture(source, c.Texture, candidate, nil, "rgba", nil); err == nil || out != nil || pixels != nil {
						t.Fatal("rgba policy admitted indexed pixels")
					}
				}
				if !strings.HasPrefix(c.Name, "std8") {
					for _, policy := range []string{"exact", "quantize"} {
						if out, pixels, err := texture(source, c.Texture, candidate, nil, policy, nil); err == nil || out != nil || pixels != nil {
							t.Fatal("palette generation admitted an uncalibrated format", policy)
						}
					}
				}
				noop, readback, err := texture(source, c.Texture, candidate, nil, c.Policy, nil)
				if err != nil || !bytes.Equal(noop, source) || fmt.Sprintf("%x", sha256.Sum256(noop)) != c.Noop || !bytes.Equal(readback.Pix, raster.Pix) {
					t.Fatalf("PNG no-op changed TXD: %v", err)
				}
				var allowed []image.Rectangle
				for _, pixel := range c.Edit.Pixels {
					raster.SetNRGBA(pixel.X, pixel.Y, color.NRGBA{pixel.RGBA[0], pixel.RGBA[1], pixel.RGBA[2], pixel.RGBA[3]})
					allowed = append(allowed, image.Rect(pixel.X, pixel.Y, pixel.X+1, pixel.Y+1))
				}
				changed, readback, err := texture(source, c.Texture, raster, allowed, c.Policy, nil)
				if err != nil || fmt.Sprintf("%x", sha256.Sum256(changed)) != c.Edit.TXD || fmt.Sprintf("%x", sha256.Sum256(readback.Pix)) != c.Edit.Raster {
					t.Fatalf("palette edit differs: %v", err)
				}
				count := 0
				for i := range source {
					if changed[i] != source[i] {
						count++
					}
				}
				if count != c.Edit.Changed || !bytes.Equal(source, before) {
					t.Fatal("texture changed source or extra bytes")
				}
				for _, rectangles := range [][]image.Rectangle{{image.Rect(1, 1, 2, 2)}, {image.Rect(-1, 0, 1, 1)}, {image.Rect(0, 0, c.Width+1, 1)}, {image.Rect(1, 1, 1, 1)}} {
					if output, pixels, err := texture(source, c.Texture, raster, rectangles, c.Policy, nil); err == nil || output != nil || pixels != nil {
						t.Fatal("invalid/outside rectangle admitted")
					}
				}
				for _, selector := range []string{"", "absent"} {
					if output, pixels, err := texture(source, selector, nil, nil, c.Policy, nil); err == nil || output != nil || pixels != nil {
						t.Fatal("missing selector admitted")
					}
				}
				if output, pixels, err := texture(source, c.Texture, image.NewNRGBA(image.Rect(0, 0, c.Width+1, c.Height)), nil, c.Policy, nil); err == nil || output != nil || pixels != nil {
					t.Fatal("wrong PNG dimensions admitted")
				}
				if !bytes.Equal(source, before) {
					t.Fatal("refusal changed input")
				}
				if c.MetadataOffset != 0 {
					// Every finite mode keeps native fields, even on export.
					for _, change := range []struct {
						offset int
						bit    uint32
					}{
						{0, 1}, {4, 1}, {8, 1}, {12, 1}, {12, 1 << 16},
						{16, 1}, {16, 1 << 14}, {16, 1 << 20}, {16, 1 << 26},
						{20, 1}, {20, 1 << 2}, {20, 1 << 5}, {24, 1}, {28, 1},
						{48, 1}, {52, 1}, {56, 1},
					} {
						bad := bytes.Clone(source)
						at := c.MetadataOffset + change.offset
						binary.LittleEndian.PutUint32(bad[at:], binary.LittleEndian.Uint32(bad[at:])^change.bit)
						preimage := bytes.Clone(bad)
						if out, pixels, err := texture(bad, c.Texture, nil, nil, c.Policy, nil); err == nil || out != nil || pixels != nil || !bytes.Equal(bad, preimage) {
							t.Fatal("finite native field mutation admitted", change, err)
						}
					}
					if binary.LittleEndian.Uint16(source[c.MetadataOffset+14:]) == 2 {
						for at := c.PixelOffset - 0x50; at < c.PixelOffset; at += 8 {
							bad := bytes.Clone(source)
							binary.LittleEndian.PutUint64(bad[at:], binary.LittleEndian.Uint64(bad[at:])^1)
							preimage := bytes.Clone(bad)
							if out, pixels, err := texture(bad, c.Texture, nil, nil, c.Policy, nil); err == nil || out != nil || pixels != nil || !bytes.Equal(bad, preimage) {
								t.Fatal("direct upload packet mutation admitted", at, err)
							}
						}
					}
				}
				if len(c.Ramps) != 0 {
					if len(c.Ramps) != 5 {
						t.Fatal("missing independent fulladdress ramps")
					}
					for pass, want := range c.Ramps {
						ramp := bytes.Clone(source)
						for at := 0; at < c.Width*c.Height/2; at++ {
							ramp[c.PixelOffset+at] = byte((2*at>>(4*pass))&15 | ((2*at+1)>>(4*pass)&15)<<4)
						}
						_, pixels, err := texture(ramp, c.Texture, nil, nil, c.Policy, nil)
						if err != nil || fmt.Sprintf("%x", sha256.Sum256(pixels.Pix)) != want {
							t.Fatal("multipage address ramp differs", pass, err)
						}
						noop, _, err := texture(ramp, c.Texture, pixels, nil, c.Policy, nil)
						if err != nil || !bytes.Equal(noop, ramp) {
							t.Fatal("multipage address ramp no-op differs", pass, err)
						}
					}
					for _, shape := range [][2]uint32{{64, 32}, {128, 64}, {256, 256}, {512, 256}, {256, 512}, {1024, 512}} {
						bad := bytes.Clone(source)
						binary.LittleEndian.PutUint32(bad[144:], shape[0])
						binary.LittleEndian.PutUint32(bad[148:], shape[1])
						if out, pixels, err := texture(bad, c.Texture, nil, nil, c.Policy, nil); err == nil || out != nil || pixels != nil {
							t.Fatal("unproven PSMT4 shape admitted", shape)
						}
					}
					for _, change := range []struct {
						offset int
						value  uint32
					}{
						{152, 8}, {156, 0x4504}, {156, 0x14504}, {156, 0x22504}, {156, 0x24500},
						{160, 0x65410000}, {160, 0x65440000}, {160, 0x65520000}, {160, 0x61420000},
						{164, 0x00000006}, {164, 0x20080006}, {164, 0x20800006}, {164, 0x21000006},
						{168, 511}, {168, 513}, {172, 1}, {200, 34815}, {200, 34817},
						{192, 131151}, {196, 175}, {224, 0}, {236, 1}, {244, 0x52}, {252, 255}, {256, 255},
						{268, 1}, {276, 0x51}, {284, 8191}, {288, 0}, {292, 1},
						{131388, 1}, {131396, 0x52}, {131404, 7}, {131408, 2}, {131420, 1}, {131428, 0x51}, {131436, 5}, {131440, 0}, {131444, 1}, {131516, 0},
					} {
						bad := bytes.Clone(source)
						binary.LittleEndian.PutUint32(bad[change.offset:], change.value)
						if bytes.Equal(bad, source) {
							t.Fatal("multipage refusal fixture must change source", change)
						}
						preimage := bytes.Clone(bad)
						if out, pixels, err := texture(bad, c.Texture, nil, nil, c.Policy, nil); err == nil || out != nil || pixels != nil || !bytes.Equal(bad, preimage) {
							t.Fatal("unproven multipage metadata/packet admitted", change, err)
						}
					}
				}
				if c.PalettePacket != 0 {
					pixelPacket := c.PalettePacket - c.Width*c.Height - 0x50
					for _, change := range []struct {
						offset int
						value  uint64
					}{
						{c.PalettePacket + 16, 0},
						{c.PalettePacket + 16, binary.LittleEndian.Uint64(source[c.PalettePacket+16:]) ^ (1 << 32)},
						{c.PalettePacket + 16, binary.LittleEndian.Uint64(source[c.PalettePacket+16:]) ^ (1 << 48)},
						{c.PalettePacket + 16, 63 << 48},
						{c.PalettePacket + 16, 65 << 48},
						{c.PalettePacket + 16, 64<<48 | 1<<32},
						{c.PalettePacket + 16, 64<<48 | 1<<59},
						{c.PalettePacket + 24, 0x52},
						{c.PalettePacket + 32, 16 | 15<<32},
						{c.PalettePacket + 48, 1},
						{c.PalettePacket + 56, 0x51},
						{c.PalettePacket + 64, 0x080000000000003f},
						{c.PalettePacket + 72, 1},
						{pixelPacket + 16, 64 << 48},
					} {
						if binary.LittleEndian.Uint64(source[change.offset:]) == change.value {
							continue // Separate CLUT uploads already have destination zero.
						}
						bad := bytes.Clone(source)
						binary.LittleEndian.PutUint64(bad[change.offset:], change.value)
						preimage := bytes.Clone(bad)
						if output, pixels, err := texture(bad, c.Texture, nil, nil, c.Policy, nil); err == nil || output != nil || pixels != nil || !bytes.Equal(bad, preimage) {
							t.Fatalf("unproven shared-base packet admitted at%x: %x", change.offset, change.value)
						}
					}
				}
			})
		}
		for _, c := range oracle.ExactPalette.Cases {
			policy := c.Policy
			if policy == "" {
				policy = "exact"
			}
			source, candidateBytes := members[c.Key], members[c.PNG]
			if fmt.Sprintf("%x", sha256.Sum256(source)) != c.Source || fmt.Sprintf("%x", sha256.Sum256(candidateBytes)) != c.PNGSHA {
				t.Fatal("exact palette fixture changed")
			}
			candidate, err := png.Decode(bytes.NewReader(candidateBytes))
			if err != nil {
				t.Fatal(err)
			}
			before := bytes.Clone(source)
			artifact, raster, err := texture(source, c.Texture, candidate, nil, policy, nil)
			if c.Refuse {
				if err == nil || artifact != nil || raster != nil || !bytes.Equal(source, before) {
					t.Fatal("approximate candidate admitted by exact palette policy")
				}
				continue
			}
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(artifact)) != c.TXD || fmt.Sprintf("%x", sha256.Sum256(raster.Pix)) != c.RGBA {
				t.Fatalf("exact palette oracle differs for%s (%s): %v", c.PNG, policy, err)
			}
			if len(c.Ranges) != 2 || fmt.Sprintf("%x", sha256.Sum256(artifact[c.Ranges[0][0]:c.Ranges[0][1]])) != c.Pixels || fmt.Sprintf("%x", sha256.Sum256(artifact[c.Ranges[1][0]:c.Ranges[1][1]])) != c.Palette {
				t.Fatal("exact palette pixel/CLUT bytes differ")
			}
			changed := 0
			for i, old := range source {
				if artifact[i] == old {
					continue
				}
				changed++
				if !(c.Ranges[0][0] <= i && i < c.Ranges[0][1] || c.Ranges[1][0] <= i && i < c.Ranges[1][1]) {
					t.Fatal("exact palette changes unselected bytes")
				}
			}
			_, decoded, err := texture(artifact, c.Texture, nil, nil, "", nil)
			if err != nil || changed != c.Changed || !bytes.Equal(decoded.Pix, raster.Pix) || !bytes.Equal(source, before) {
				t.Fatal("exact palette readback/containment/source differs", err)
			}
			if policy == "exact" {
				fallback, pixels, err := texture(source, c.Texture, candidate, nil, "quantize", nil)
				if err != nil || !bytes.Equal(fallback, artifact) || !bytes.Equal(pixels.Pix, raster.Pix) {
					t.Fatal("quantize exact fallback differs", c.PNG, err)
				}
			}
			if policy != "quantize" && c.Texture != "mon0" && !strings.HasPrefix(c.PNG, "small-psmt8/") {
				continue
			}
			width := candidate.Bounds().Dx()
			dir := t.TempDir()
			profile := TextureProfile{SourceSHA256: c.Source, SourceSize: int64(len(source)), Texture: c.Texture, PNG: "candidate.png", PNGSHA256: c.PNGSHA, PalettePolicy: policy, Evidence: "Independent preimplementation palette oracle"}
			profileData, err := json.Marshal(profile)
			if err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string][]byte{"source.txd": source, "candidate.png": candidateBytes, "profile.json": profileData} {
				if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			output := filepath.Join(dir, "authored.txd")
			args := []string{"--source", filepath.Join(dir, "source.txd"), "--texture-profile", filepath.Join(dir, "profile.json")}
			for _, apply := range []bool{false, true} {
				command := slices.Clone(args)
				if apply {
					command = append(command, "--apply", "--output", output)
				}
				var out bytes.Buffer
				if err := run(command, &out); err != nil {
					t.Fatal(err)
				}
				var report map[string]any
				if err := json.Unmarshal(out.Bytes(), &report); err != nil || report["output_sha256"] != c.TXD || report["rgba_sha256"] != c.RGBA || report["palette_policy"] != policy || report["mode"] != "import_png" || report["applied"] != apply {
					t.Fatal("exact palette CLI report differs", err, out.String())
				}
				if apply {
					body, err := os.ReadFile(output)
					if err != nil || !bytes.Equal(body, artifact) {
						t.Fatal("exact palette CLI bytes differ", err)
					}
					out.Reset()
					if err := run(command, &out); err == nil || out.Len() != 0 {
						t.Fatal("exact palette CLI overwrote output")
					}
				} else if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatal("exact preview created output", err)
				}
			}
			for _, mutation := range []string{"unknown policy", "export policy", "rectangle policy", "source pin", "candidate pin"} {
				bad := profile
				switch mutation {
				case "unknown policy":
					bad.PalettePolicy = "other"
				case "export policy":
					bad.PNG, bad.PNGSHA256 = "", ""
				case "rectangle policy":
					bad.Rectangles = [][]int{{0, 0, width, candidate.Bounds().Dy()}}
				case "source pin":
					bad.SourceSHA256 = strings.Repeat("0", 64)
				case "candidate pin":
					bad.PNGSHA256 = strings.Repeat("0", 64)
				}
				body, err := json.Marshal(bad)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "profile.json"), body, 0600); err != nil {
					t.Fatal(err)
				}
				refused := filepath.Join(dir, "refused.txd")
				var out bytes.Buffer
				if err := run(append(slices.Clone(args), "--apply", "--output", refused), &out); err == nil || out.Len() != 0 {
					t.Fatal("exact palette CLI admitted", mutation)
				}
				if _, err := os.Stat(refused); !os.IsNotExist(err) {
					t.Fatal("refusal retained output", err)
				}
			}
			for name, want := range map[string][]byte{"source.txd": source, "candidate.png": candidateBytes} {
				got, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("palette CLI changed input", name, err)
				}
			}
			// Every alpha is independently normalized; hidden RGB collapses only in exact mode.
			for colors := 256; colors <= min(257, width*candidate.Bounds().Dy()); colors++ {
				ramp := image.NewNRGBA(candidate.Bounds())
				for x := 0; x < colors; x++ {
					ramp.SetNRGBA(x%width, x/width, color.NRGBA{uint8(x), uint8(x >> 8), 17, 255})
				}
				// Avoid an additional transparent color when testing the256-color ceiling.
				for y := 0; y < ramp.Bounds().Dy(); y++ {
					for x := 0; x < ramp.Bounds().Dx(); x++ {
						if y*width+x >= colors {
							ramp.SetNRGBA(x, y, color.NRGBA{0, 0, 17, 255})
						}
					}
				}
				out, _, err := texture(source, c.Texture, ramp, nil, "exact", nil)
				if (err == nil) != (colors == 256) || colors == 257 && out != nil {
					t.Fatal("exact palette color limit differs", colors, err)
				}
			}
			alphaRamp := image.NewNRGBA(candidate.Bounds())
			for a := 0; a < 256; a++ {
				alphaRamp.SetNRGBA(a%width, a/width, color.NRGBA{77, 11, 22, uint8(a)})
			}
			_, rounded, err := texture(source, c.Texture, alphaRamp, nil, "exact", nil)
			if err != nil {
				t.Fatal(err)
			}
			for a := 0; a < 256; a++ {
				want := color.NRGBA{77, 11, 22, uint8(min(255, 2*((a+1)/2)))}
				if a == 0 {
					want = color.NRGBA{}
				}
				if rounded.NRGBAAt(a%width, a/width) != want {
					t.Fatal("exact palette alpha/hidden RGB differs", a)
				}
			}
			for _, policy := range []string{"preserve", "EXACT", "other"} {
				if out, pixels, err := texture(source, c.Texture, candidate, nil, policy, nil); err == nil || out != nil || pixels != nil {
					t.Fatal("unknown palette policy admitted")
				}
			}
			for _, replacement := range []image.Image{nil, candidate} {
				var rectangles []image.Rectangle
				if replacement != nil {
					rectangles = []image.Rectangle{candidate.Bounds()}
				}
				for _, policy := range []string{"exact", "quantize"} {
					if out, pixels, err := texture(source, c.Texture, replacement, rectangles, policy, nil); err == nil || out != nil || pixels != nil {
						t.Fatal("palette export/rectangle mode admitted", policy)
					}
				}
			}
		}
		source := members[oracle.Cases[0].Key]
		for length := 0; length < min(len(source), 512); length++ {
			if _, _, err := texture(source[:length], oracle.Cases[0].Texture, nil, nil, "", nil); err == nil {
				t.Fatal("truncated texture admitted")
			}
		}
		for _, change := range []struct {
			offset int
			value  uint32
		}{{0, 0}, {4, 0xffffffff}, {16, 0xffffffff}, {32, 0xffffffff}, {24, 2}, {92, 1}, {132, 0}, {136, 0xffffffff}, {140, 4}, {144, 0x2a504}, {144, 0x23504}, {144, 0x24504}, {144, 0x20504}, {144, 0x32504}, {144, 0x62504}, {144, 0x22104}, {160, 4}, {160, 0x100}, {188, 0}, {188, 1}, {188, 67583}, {188, 67585}, {148, 0}, {152, 0x21000006}, {156, 0x404}, {180, 0}, {184, 0}, {200, 0xffffffff}, {240, 0}, {248, 0x53}, {272, 0}, {262464, 0}, {262472, 0x53}, {262496, 0}} {
			bad := bytes.Clone(source)
			binary.LittleEndian.PutUint32(bad[change.offset:], change.value)
			before := bytes.Clone(bad)
			if output, pixels, err := texture(bad, oracle.Cases[0].Texture, nil, nil, "", nil); err == nil || output != nil || pixels != nil || !bytes.Equal(bad, before) {
				t.Fatalf("malformed texture admitted at%x", change.offset)
			}
		}
		plate := members["GRAPHIC/SYSTEM.CMB/system/vlg_plt.txd"]
		mapping, err := os.ReadFile("testdata/psmt4-nibble-map.bin")
		if err != nil || len(mapping) != 8192 || fmt.Sprintf("%x", sha256.Sum256(mapping)) != oracle.NibbleMap {
			t.Fatal("missing independent GS table-join mapping", err)
		}
		for digit := 0; digit < 12; digit += 4 {
			ramp := bytes.Clone(plate)
			for index := 0; index < 16; index++ {
				copy(ramp[2408+4*index:], []byte{byte(index * 16), 0, 0, 128})
			}
			for index := 0; index < 2048; index++ {
				ramp[280+index] = byte((2*index>>digit)&15 | ((2*index+1)>>digit&15)<<4)
			}
			_, raster, err := texture(ramp, "vlg_plt73", nil, nil, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			for index := 0; index < 4096; index++ {
				key := binary.LittleEndian.Uint16(mapping[index*2:])
				if key >= 4096 || raster.NRGBAAt(index%128, index/128) != (color.NRGBA{byte(key>>digit&15) * 16, 0, 0, 255}) {
					t.Fatalf("PSMT4 map differs at%d, digit%d", index, digit)
				}
			}
			noop, _, err := texture(ramp, "vlg_plt73", raster, nil, "", nil)
			if err != nil || !bytes.Equal(noop, ramp) {
				t.Fatal("PSMT4 ramp no-op changed bytes", err)
			}
		}
		for _, change := range []struct {
			offset int
			value  uint32
		}{
			{124, 256}, {128, 128}, {132, 8}, {136, 0x22504}, {136, 0x25504}, {136, 0x2c504}, {136, 0x4504},
			{140, 0x5d404000}, {144, 0x21000005}, {148, 0}, {148, 0x20}, {152, 4}, {136, 0x34504}, {136, 0x24104}, {180, 0}, {180, 1}, {180, 2047}, {180, 2049}, {144, 0x00000005},
			{172, 2048}, {176, 144}, {232, 0}, {264, 0}, {2360, 0}, {2392, 0}, {2472, 0},
		} {
			bad := bytes.Clone(plate)
			binary.LittleEndian.PutUint32(bad[change.offset:], change.value)
			before := bytes.Clone(bad)
			if output, pixels, err := texture(bad, "vlg_plt73", nil, nil, "", nil); err == nil || output != nil || pixels != nil || !bytes.Equal(bad, before) {
				t.Fatalf("unsupported PSMT4 variant admitted at%x: %x", change.offset, change.value)
			}
		}

		for _, direct := range []struct {
			key, texture, policy string
			rgb                  [3]uint8
		}{
			{"GRAPHIC/SYSTEM.CMB/system/font.txd", "font2", "", [3]uint8{77, 77, 77}},
			{"npc_18_.txd", "NPC_18_0", "rgba", [3]uint8{77, 11, 22}},
		} {
			directSource := members[direct.key]
			_, candidate, err := texture(directSource, direct.texture, nil, nil, direct.policy, nil)
			if err != nil {
				t.Fatal(err)
			}
			expected := bytes.Clone(directSource)
			for alpha := 0; alpha < 256; alpha++ {
				candidate.SetNRGBA(alpha, 0, color.NRGBA{direct.rgb[0], direct.rgb[1], direct.rgb[2], uint8(alpha)})
				copy(expected[200+alpha*4:], []byte{direct.rgb[0], direct.rgb[1], direct.rgb[2], uint8((alpha + 1) / 2)})
			}
			actual, readback, err := texture(directSource, direct.texture, candidate, []image.Rectangle{image.Rect(0, 0, 256, 1)}, direct.policy, nil)
			if err != nil || !bytes.Equal(actual, expected) {
				t.Fatal("direct font alpha rounding or containment differs", err)
			}
			for alpha := 0; alpha < 256; alpha++ {
				if readback.NRGBAAt(alpha, 0) != (color.NRGBA{direct.rgb[0], direct.rgb[1], direct.rgb[2], uint8(min(255, 2*((alpha+1)/2)))}) {
					t.Fatalf("direct font displayed alpha differs at%d", alpha)
				}
			}
			ramp := bytes.Clone(directSource)
			for alpha := 0; alpha <= 128; alpha++ {
				copy(ramp[200+alpha*4:], []byte{31, 31, 31, uint8(alpha)})
			}
			_, candidate, err = texture(ramp, direct.texture, nil, nil, direct.policy, nil)
			if err != nil {
				t.Fatal(err)
			}
			var pngBytes bytes.Buffer
			if err := png.Encode(&pngBytes, candidate); err != nil {
				t.Fatal(err)
			}
			pngImage, err := png.Decode(&pngBytes)
			if err != nil {
				t.Fatal(err)
			}
			actual, _, err = texture(ramp, direct.texture, pngImage, nil, direct.policy, nil)
			if err != nil || !bytes.Equal(actual, ramp) {
				t.Fatal("native alpha/hidden monochrome PNG no-op changed bytes", err)
			}
			candidate.SetNRGBA(1, 0, color.NRGBA{31, 31, 31, 1})
			if output, pixels, err := texture(ramp, direct.texture, candidate, []image.Rectangle{image.Rect(2, 0, 3, 1)}, direct.policy, nil); err == nil || output != nil || pixels != nil {
				t.Fatal("outside-mask alpha change admitted despite identical rounded bytes")
			}
			if direct.policy == "" {
				candidate.SetNRGBA(1, 0, color.NRGBA{1, 2, 3, 255})
				if output, pixels, err := texture(ramp, direct.texture, candidate, nil, direct.policy, nil); err == nil || output != nil || pixels != nil {
					t.Fatal("unproven colored font candidate admitted")
				}
			}
			for _, change := range []struct {
				offset int
				value  uint32
			}{
				{124, 256}, {128, 256}, {132, 8}, {136, 0x20504}, {136, 0x1504}, {140, 0}, {144, 7}, {148, 4}, {152, 4}, {136, 0x10504}, {180, 0}, {180, 1}, {180, 262143}, {180, 262145}, {172, 1048575}, {176, 1024}, {200, 1}, {203, 129},
			} {
				if direct.policy == "rgba" && change.offset == 200 {
					continue
				} // RGBA deliberately permits a colored source pixel.
				bad := bytes.Clone(directSource)
				binary.LittleEndian.PutUint32(bad[change.offset:], change.value)
				before := bytes.Clone(bad)
				if output, pixels, err := texture(bad, direct.texture, nil, nil, direct.policy, nil); err == nil || output != nil || pixels != nil || !bytes.Equal(bad, before) {
					t.Fatalf("unproven raw font variant admitted at%x", change.offset)
				}
			}
			for _, alpha := range []uint8{129, 255} {
				bad := bytes.Clone(directSource)
				bad[203] = alpha
				for _, policy := range []string{"", "rgba"} {
					if out, pixels, err := texture(bad, direct.texture, nil, nil, policy, nil); err == nil || out != nil || pixels != nil {
						t.Fatal("source alpha outside native domain admitted", alpha, policy)
					}
				}
			}

		}

	})
	contextData, err := os.ReadFile("testdata/source-context-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	type sourceContextFixture struct {
		Glyphmap map[string]string
		Cases    []struct {
			Name, EN, Status string
			SourceAuthoring  string `json:"source_authoring"`
			SourceOffset     int    `json:"source_offset"`
			SourceHex        string `json:"source_hex"`
			ExpectedHex      string `json:"expected_hex"`
			RequireHDR       bool   `json:"require_hdr"`
			Canonical        bool
			Columns          int `json:"columns"`
			Rows             int `json:"rows"`
		}
		GlyphmapFixture   string `json:"glyphmap_fixture"`
		ExpectedAccepted  int    `json:"expected_accepted"`
		ExpectedRefused   int    `json:"expected_refused"`
		ExpectedCanonical int    `json:"expected_canonical"`
	}
	var contextOracle sourceContextFixture
	if err := json.Unmarshal(contextData, &contextOracle); err != nil {
		t.Fatal(err)
	}
	forward := make(map[uint16]string)
	reverse := make(map[rune]uint16)
	for key, value := range contextOracle.Glyphmap {
		word, err := strconv.ParseUint(key, 10, 16)
		if err != nil {
			t.Fatal(err)
		}
		forward[uint16(word)] = value
		if len([]rune(value)) == 1 {
			r := []rune(value)[0]
			if prev, ok := reverse[r]; !ok || uint16(word) < prev {
				reverse[r] = uint16(word)
			}
		}
	}
	{
		data, err := os.ReadFile("testdata/positional-labels.json")
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) != "2c87e318430bf9a801de81aad50f7de6be15ad433bd57bd0630f641209a93721" {
			t.Fatal("positional reference fixture changed without independent regeneration")
		}
		var reference struct {
			Cases []struct {
				Name        string
				SourceHex   string `json:"source_hex"`
				EN          string
				LabelRuns   int      `json:"label_runs"`
				ExpectedHex string   `json:"expected_hex"`
				Controls    []uint16 `json:"preserved_non_glyph_words"`
			}
		}
		if err := json.Unmarshal(data, &reference); err != nil || len(reference.Cases) != 128 {
			t.Fatalf("positional reference population: %v", err)
		}
		for _, c := range reference.Cases {
			source, err := hex.DecodeString(c.SourceHex)
			if err != nil {
				t.Fatal(err)
			}
			before := bytes.Clone(source)
			shape, err := controls(source, TextScanOptions{Decode: true, Glyphs: forward, PositionalLabels: true})
			if err != nil || !shape.PositionalLabels || len(shape.Tokens)*2 != len(source) {
				t.Fatalf("%s native word walk: %v", c.Name, err)
			}
			shapeBefore := fmt.Sprintf("%#v", shape)
			got, err := encode(c.EN, nil, reverse, TextEncodeOptions{Terminated: true, Source: &shape, LabelRuns: c.LabelRuns})
			if err != nil || hex.EncodeToString(got) != c.ExpectedHex {
				t.Fatalf("%s positional complete bytes: %x, %v", c.Name, got, err)
			}
			var stableControls []uint16
			for _, word := range c.Controls {
				if word != 0 { // English may add spaces inside a replaced glyph run.
					stableControls = append(stableControls, word)
				}
			}
			for _, stream := range [][]byte{source, got} {
				scanned, err := controls(stream, TextScanOptions{Terminated: true, PositionalLabels: true})
				if err != nil || !slices.Equal(scanned.Words, stableControls) {
					t.Fatalf("%s positional scaffold changed: %v", c.Name, err)
				}
			}
			if !bytes.Equal(source, before) || fmt.Sprintf("%#v", shape) != shapeBefore {
				t.Fatalf("%s positional encoding mutated source", c.Name)
			}
		}
	}
	{
		advances := map[uint16]int{0x14: 4}
		for word := uint16(1); word <= 10; word++ {
			advances[word] = 5 + int(word)
		}
		for lo := int32(-100); lo <= 100; lo += 5 {
			for hi := lo; hi <= 100; hi += 7 {
				data := []byte{0, 0x70, 0, 0xf8}
				before := bytes.Clone(data)
				shape, err := controls(data, TextScanOptions{Terminated: true, Advances: advances, NumericBounds: []*NumericRange{{Min: lo, Max: hi}}})
				if err != nil || shape.Lines != 1 || shape.Pages || !slices.Equal(shape.Words, []uint16{0x7000, 0xf800}) {
					t.Fatalf("numeric range %d..%d: %v", lo, hi, err)
				}
				for value := lo; value <= hi; value++ {
					width := 0
					for _, digit := range strconv.FormatInt(int64(value), 10) {
						word := uint16(digit-'0') + 1
						if digit == '-' {
							word = 0x14
						}
						width += advances[word]
					}
					if width > shape.Width {
						t.Fatalf("numeric %d exceeds bound for %d..%d: %d > %d", value, lo, hi, width, shape.Width)
					}
				}
				if !bytes.Equal(data, before) {
					t.Fatal("numeric scanner mutated input")
				}
			}
		}
		for _, mode := range []string{"zero digit", "negative digit", "missing minus", "no metrics", "decode", "fixed field", "missing range", "null range", "unused range"} {
			metrics := make(map[uint16]int, len(advances))
			for word, width := range advances {
				metrics[word] = width
			}
			options := TextScanOptions{Terminated: true, Advances: metrics, NumericBounds: []*NumericRange{{Min: -1, Max: 10}}}
			data := []byte{0, 0x70, 0, 0xf8}
			switch mode {
			case "zero digit":
				metrics[10] = 0
			case "negative digit":
				metrics[10] = -1
			case "missing minus":
				delete(metrics, 0x14)
			case "no metrics":
				options.Advances = nil
			case "decode":
				options.Decode, options.Glyphs = true, map[uint16]string{}
			case "fixed field":
				options.Terminated = false
			case "missing range":
				data = []byte{0, 0x70, 0, 0x70, 0, 0xf8}
			case "null range":
				options.NumericBounds[0] = nil
			case "unused range":
				options.NumericBounds = append(options.NumericBounds, &NumericRange{})
			}
			if got, err := controls(data, options); err == nil || !reflect.DeepEqual(got, TextShape{}) {
				t.Errorf("numeric scanner %s: expected empty refusal, got %+v, %v", mode, got, err)
			}
		}
	}
	formattedGoldens := make(map[string]struct {
		Hex           string
		Columns, Rows int
	})
	{
		text := "{{HL:0xb001}}A B{{HL:0xb002}}"
		source := []byte{1, 0xb0, 4, 0, 2, 0xb0, 0, 0x10, 0, 0xf8}
		shape, err := controls(source, TextScanOptions{Decode: true, Glyphs: map[uint16]string{4: "あ"}, English: &text})
		if err != nil {
			t.Fatal(err)
		}
		for _, options := range []TextEncodeOptions{
			{Terminated: true, Source: &shape, Columns: 1, Rows: 1},
			{Terminated: true, Columns: 1, Rows: 1},
			{Terminated: true, Source: &shape, Columns: 1},
			{Terminated: true, Source: &shape, Rows: 1},
			{NativeWidth: 10, Rows: 1, Advances: map[uint16]int{0: 14, 1: 13}},
			{Terminated: true, NativeWidth: 10, Rows: 1},
			{Terminated: true, Rows: 1, Advances: map[uint16]int{0: 14, 1: 13}},
			{Terminated: true, NativeWidth: 10, Columns: 1, Rows: 1, Advances: map[uint16]int{0: 14, 1: 13}},
			{Terminated: true, ExactControls: true, NativeWidth: 10, Rows: 1, Advances: map[uint16]int{0: 14, 1: 13}},
			{Terminated: true, NativeWidth: 10, Rows: 1, Advances: map[uint16]int{1: 13}},
			{Terminated: true, NativeWidth: 10, Rows: 1, Advances: map[uint16]int{0: 14}},
			{Terminated: true, NumericBounds: []*NumericRange{{Min: 0, Max: 9}}},
		} {
			if got, err := encode(text, nil, map[rune]uint16{'A': 1, 'B': 2}, options); err == nil || got != nil {
				t.Fatalf("accepted split highlight or invalid format options: %+v, %v", options, err)
			}
		}
	}
	{
		alternating := make([]uint16, 2048)
		for i := 0; i < len(alternating); i += 2 {
			alternating[i] = 1
		}
		hardLines := make([]uint16, 4095)
		hardLines[0] = 0x2800
		for i := 1; i < len(hardLines); i++ {
			hardLines[i] = 0x0800
		}
		for _, c := range []struct {
			name    string
			words   []uint16
			columns int
			rows    int
			refuse  bool
		}{
			{"excessive cut search", alternating, 3, 2, true},
			{"excessive hard-line search", hardLines, 3, 2048, true},
			{"large fitting hard lines", hardLines, 3, 4096, false},
			{"zero columns", []uint16{1}, 0, 1, true},
			{"zero rows", []uint16{1}, 1, 0, true},
			{"oversized input", make([]uint16, maxStreamBytes/2+1), 1, 1, true},
		} {
			before := slices.Clone(c.words)
			got, err := wrapPages(c.words, nil, c.columns, c.rows, nil, nil, nil)
			if c.refuse && (err == nil || got != nil) || !c.refuse && (err != nil || !slices.Equal(got, before)) {
				t.Errorf("%s: unexpected output or refusal: %v", c.name, err)
			}
			if !slices.Equal(before, c.words) {
				t.Fatalf("%s: mutated wrapping input", c.name)
			}
		}
		for _, c := range []struct {
			name    string
			widths  map[uint16]int
			glyphs  map[uint16]rune
			advance map[uint16]int
			want    []uint16
		}{
			{"explicit zero estimates", map[uint16]int{0x2001: 0, 0x2002: 0}, nil, nil, []uint16{0x2001, 1, 0, 2, 0x2002}},
			{"one character argument", map[uint16]int{0x2001: 0, 0x2002: 1}, nil, nil, []uint16{0x2001, 1, 0x0800, 2, 0x2002}},
			{"glyph collision", map[uint16]int{0x2001: 0}, map[uint16]rune{0x2001: 'A'}, nil, nil},
			{"structural collision", map[uint16]int{0x1000: 0}, nil, nil, nil},
			{"ordinary glyph collision", map[uint16]int{1: 0}, nil, nil, nil},
			{"negative estimate", map[uint16]int{0x2001: -1}, nil, nil, nil},
			{"unknown estimate", map[uint16]int{0x2001: 2}, nil, nil, nil},
			{"native estimate forbidden", map[uint16]int{0x2001: 0}, nil, map[uint16]int{0: 1, 1: 1, 2: 1}, nil},
		} {
			words := []uint16{0x2001, 1, 0, 2, 0x2002}
			before := slices.Clone(words)
			got, err := wrapPages(words, c.glyphs, 3, 2, c.advance, nil, c.widths)
			if c.want == nil && (err == nil || got != nil) || c.want != nil && (err != nil || !slices.Equal(got, c.want)) || !slices.Equal(words, before) {
				t.Errorf("%s: output %x, error %v, want %x; source preserved=%v", c.name, got, err, c.want, slices.Equal(words, before))
			}
		}
	}
	{
		data, err := os.ReadFile("testdata/wrapping-canonical.json")
		if err != nil {
			t.Fatal(err)
		}
		var reference struct {
			Glyphmap map[string]string
			Cases    []struct {
				Name          string
				InputHex      string `json:"input_hex"`
				ExpectedHex   string `json:"expected_hex"`
				Columns, Rows int
				TrailingPause bool `json:"trailing_pause"`
			}
		}
		if err := json.Unmarshal(data, &reference); err != nil {
			t.Fatal(err)
		}
		glyphs := make(map[uint16]rune)
		for _, table := range []map[string]string{contextOracle.Glyphmap, reference.Glyphmap} {
			for key, text := range table {
				if len([]rune(text)) != 1 {
					continue
				}
				word, err := strconv.ParseUint(key, 10, 16)
				if err != nil {
					t.Fatal(err)
				}
				glyphs[uint16(word)] = []rune(text)[0]
			}
		}
		for _, c := range reference.Cases {
			if strings.HasPrefix(c.Name, "0x") {
				formattedGoldens[c.Name] = struct {
					Hex           string
					Columns, Rows int
				}{c.ExpectedHex, c.Columns, c.Rows}
				// Canonical inputs are exercised below through source-context encode.
				continue
			}
			data, err := hex.DecodeString(c.InputHex)
			if err != nil {
				t.Fatal(err)
			}
			words := make([]uint16, len(data)/2)
			for i := range words {
				words[i] = binary.LittleEndian.Uint16(data[i*2:])
			}
			if words[len(words)-1] != 0xf800 {
				t.Fatal("missing fixture END")
			}
			words = words[:len(words)-1]
			if c.TrailingPause {
				if words[len(words)-1] != 0x1000 {
					t.Fatal("missing fixture source pause")
				}
				words = words[:len(words)-1]
			}
			before := slices.Clone(words)
			got, err := wrapPages(words, glyphs, c.Columns, c.Rows, nil, nil, nil)
			if err != nil {
				t.Errorf("%s: %v", c.Name, err)
				continue
			}
			if !slices.Equal(before, words) {
				t.Fatal("mutated wrapping input")
			}
			if c.TrailingPause {
				got = append(got, 0x1000)
			}
			got = append(got, 0xf800)
			var encoded []byte
			for _, word := range got {
				encoded = binary.LittleEndian.AppendUint16(encoded, word)
			}
			if hex.EncodeToString(encoded) != c.ExpectedHex {
				t.Errorf("%s wrapping differs: %x; want %s", c.Name, encoded, c.ExpectedHex)
			}
		}
	}

	{
		data, err := os.ReadFile("testdata/source-context-whitespace.json")
		if err != nil {
			t.Fatal(err)
		}
		var oracle struct {
			SourceHex  string `json:"source_hex"`
			Whitespace []rune `json:"python_whitespace"`
			Cases      []struct {
				Format      string
				ExpectedHex string `json:"expected_hex"`
			}
		}
		if err := json.Unmarshal(data, &oracle); err != nil {
			t.Fatal(err)
		}
		source, err := hex.DecodeString(oracle.SourceHex)
		if err != nil {
			t.Fatal(err)
		}
		if len(oracle.Whitespace) != 29 || len(oracle.Cases) != 4 {
			t.Fatal("incomplete Python whitespace reference")
		}
		for _, c := range oracle.Cases {
			for _, space := range oracle.Whitespace {
				text := fmt.Sprintf(c.Format, string(space), string(space))
				shape, err := controls(source, TextScanOptions{Decode: true, Glyphs: map[uint16]string{1: "A"}, English: &text})
				if err != nil {
					t.Fatal(err)
				}
				got, err := encode(text, nil, map[rune]uint16{'A': 1, 'B': 2}, TextEncodeOptions{Terminated: true, Source: &shape})
				if err != nil || hex.EncodeToString(got) != c.ExpectedHex {
					t.Errorf("source whitespace %U in %q: %x, %v; want %s", space, c.Format, got, err, c.ExpectedHex)
				}
			}
		}
		for _, space := range []rune{'\x1c', '\x1d', '\x1e', '\x1f', '\u180e', '\u200b', '\ufeff'} {
			text := "A" + string(space) + "B"
			shape, err := controls(source, TextScanOptions{Decode: true, Glyphs: map[uint16]string{1: "A"}, English: &text})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := encode(text, nil, map[rune]uint16{'A': 1, 'B': 2}, TextEncodeOptions{Terminated: true, Source: &shape}); err == nil {
				t.Fatalf("trimmed or accepted internal non-glyph %U", space)
			}
			if _, err := encode(string(space)+"A", nil, map[rune]uint16{'A': 1}, TextEncodeOptions{Terminated: true}); err == nil {
				t.Fatalf("source trimming changed literal mode for %U", space)
			}
		}
	}

	var prologues struct{ Groups []sourceContextFixture }
	prologueData, err := os.ReadFile("testdata/source-prologues.json")
	if err != nil || json.Unmarshal(prologueData, &prologues) != nil || len(prologues.Groups) != 2 {
		t.Fatal("original source-prologue fixture", err)
	}
	colourData, err := os.ReadFile("testdata/source-colours.json")
	var colours struct{ Groups []sourceContextFixture }
	if err != nil || json.Unmarshal(colourData, &colours) != nil || len(colours.Groups) != 2 {
		t.Fatal("original source-colour fixture", err)
	}
	prologues.Groups = append(prologues.Groups, colours.Groups...)
	orderedData, err := os.ReadFile("testdata/source-ordered.json")
	var ordered struct{ Groups []sourceContextFixture }
	if err != nil || json.Unmarshal(orderedData, &ordered) != nil || len(ordered.Groups) != 3 {
		t.Fatal("independent ordered-source fixture", err)
	}
	prologues.Groups = append(prologues.Groups, ordered.Groups...)
	contextOracle.ExpectedAccepted, contextOracle.ExpectedRefused, contextOracle.ExpectedCanonical = 168, 80, 69
	for _, oracle := range append([]sourceContextFixture{contextOracle}, prologues.Groups...) {
		if oracle.GlyphmapFixture != "" {
			if oracle.GlyphmapFixture != "source-context-oracle.json" || oracle.Glyphmap != nil {
				t.Fatal("unexpected source-prologue glyph owner")
			}
			oracle.Glyphmap = contextOracle.Glyphmap
		}
		glyphData, err := json.Marshal(oracle.Glyphmap)
		if err != nil {
			t.Fatal(err)
		}
		reverse, forward, err := glyphMaps(glyphData, true)
		if err != nil {
			t.Fatal("source-context glyph maps", err)
		}
		nativeRefusals := map[string]string{
			"speaker-header":               "stream header must lead",
			"ordered-setup-speaker-header": "ready terminated stream",
			"leading-HL":                   "ready terminated stream",
			"duplicate-source-speaker":     "speaker must immediately follow",
			"mixed-leading-param8":         "unsupported source-context token param8",
			"mixed-body-param8":            "unsupported source-context token param8",
			"out-of-range-speaker-English": "unsupported source-context speaker",
		}
		accepted, refused, canonical := 0, 0, 0
		for _, c := range oracle.Cases {
			source, err := hex.DecodeString(c.SourceHex)
			if err != nil {
				t.Fatal(err)
			}
			before := bytes.Clone(source)
			shape, err := controls(source, TextScanOptions{Decode: true, Glyphs: forward, English: &c.EN, RequireHDR: c.RequireHDR})
			var got []byte
			if err == nil {
				for i := range shape.Tokens {
					shape.Tokens[i].Offset += c.SourceOffset
				}
				snapshot, marshalErr := json.Marshal(shape)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				got, err = encode(c.EN, nil, reverse, TextEncodeOptions{Terminated: true, Source: &shape, Columns: c.Columns, Rows: c.Rows, SourceAuthoring: c.SourceAuthoring})
				after, marshalErr := json.Marshal(shape)
				if marshalErr != nil || !bytes.Equal(snapshot, after) {
					t.Fatal("source encoder mutated decoded caller context", c.Name, marshalErr)
				}
			}
			if !bytes.Equal(source, before) {
				t.Fatalf("source context mutated its source: %s", c.Name)
			}
			family, _, _ := strings.Cut(c.Name, "--")
			if reason := nativeRefusals[family]; reason != "" {
				if err == nil || !strings.Contains(err.Error(), reason) {
					t.Errorf("native source-context refusal %s: %v; want %s", c.Name, err, reason)
				}
				refused++
			} else if c.Status == "refuse" {
				refused++
				if err == nil {
					t.Errorf("source context accepted original refusal %s: %x", c.Name, got)
				}
			} else if err != nil || hex.EncodeToString(got) != c.ExpectedHex {
				t.Errorf("source context %s: %x, %v; want %s", c.Name, got, err, c.ExpectedHex)
			} else {
				accepted++
				if c.Canonical {
					canonical++
					gold, ok := formattedGoldens[strings.TrimPrefix(c.Name, "canonical-")]
					if !ok {
						t.Fatalf("%s: missing original formatted golden", c.Name)
					}
					formatted, err := encode(c.EN, nil, reverse, TextEncodeOptions{Terminated: true, Source: &shape, Columns: gold.Columns, Rows: gold.Rows})
					if err != nil || hex.EncodeToString(formatted) != gold.Hex {
						t.Errorf("%s formatted source context differs: %x, %v; want %s", c.Name, formatted, err, gold.Hex)
					}
				}
			}
		}
		if len(oracle.Cases) != oracle.ExpectedAccepted+oracle.ExpectedRefused || accepted != oracle.ExpectedAccepted || refused != oracle.ExpectedRefused || canonical != oracle.ExpectedCanonical {
			t.Fatalf("source-context fixture population: total=%d accepted=%d refused=%d canonical=%d", len(oracle.Cases), accepted, refused, canonical)
		}
	}

	for _, name := range []string{"native wrap", "automatic true state", "wording cap", "output cap", "source cap", "occurrence exhaustion", "wrong source role", "broken source coordinate", "short opaque payload", "long opaque payload", "read-only source", "unknown glyph identity", "exact byte limit"} {
		data := []byte{1, 0x40, 4, 0, 0, 0x10, 0, 0xf8}
		text := "{{STATE:0x4001}}A"
		if name == "source cap" {
			data = nil
			for i := 0; i < 4097; i++ {
				data = binary.LittleEndian.AppendUint16(data, 0x4001)
			}
			data = append(data, 4, 0, 0, 0xf8)
		}
		if name == "short opaque payload" || name == "long opaque payload" {
			data, _ = hex.DecodeString("0028040000b0111100f800102222040000f8")
			text = "A{{PARAM:0xb000}}B"
		}
		if name == "exact byte limit" {
			data = []byte{0, 0x28, 4, 0, 0, 0xf8}
			text = strings.Repeat("A", 4094)
		}
		shape, err := controls(data, TextScanOptions{Decode: true, Glyphs: map[uint16]string{4: "J"}, English: &text})
		if err != nil {
			t.Fatal("ordered resource fixture", name, err)
		}
		options := TextEncodeOptions{Terminated: true, Source: &shape, SourceAuthoring: "ordered"}
		glyphs := map[rune]uint16{'A': 1, 'B': 2}
		switch name {
		case "native wrap":
			options.NativeWidth, options.Rows, options.Advances = 1, 1, map[uint16]int{0: 1, 1: 1}
		case "automatic true state":
			options.Columns, options.Rows = 10, 2
		case "wording cap":
			text += strings.Repeat("A", maxStreamBytes*4)
		case "output cap":
			text += strings.Repeat("A", 4096)
		case "occurrence exhaustion":
			for word := uint16(0x0801); word < 0x2800; word++ {
				glyphs[rune(word+0x4000)] = word
			}
		case "wrong source role":
			shape.Tokens[0].Word = 0xa000
		case "broken source coordinate":
			shape.Tokens[1].Offset += 2
		case "short opaque payload":
			shape.Tokens[2].Payload = shape.Tokens[2].Payload[:6]
		case "long opaque payload":
			shape.Tokens[2].Payload = append(shape.Tokens[2].Payload, 0, 0)
		case "read-only source":
			shape.Readiness = "blocked_pinned_reader"
		case "unknown glyph identity":
			shape.glyphText = nil
		}
		before := bytes.Clone(data)
		got, err := encode(text, nil, glyphs, options)
		if name == "exact byte limit" {
			want := []byte{0, 0x28}
			for i := 0; i < 4094; i++ {
				want = append(want, 1, 0)
			}
			want = append(want, 0, 0xf8)
			if err != nil || !bytes.Equal(got, want) || len(got) != maxStreamBytes {
				t.Fatal("ordered exact byte limit", len(got), err)
			}
		} else if err == nil || got != nil {
			t.Fatal("ordered resource or source guard admitted", name, err)
		}
		if !bytes.Equal(data, before) {
			t.Fatal("ordered resource check changed input", name)
		}
	}

	for _, name := range []string{"duplicate prefix speaker", "prefix body glyph", "prefix early END", "prefix opaque word", "prefix scale", "prefix cap", "literal setup", "unknown authoring", "plain without source", "plain fixed", "plain opaque", "plain labels", "forged colour prefix", "plain bad readiness"} {
		text := "A"
		data := []byte{1, 0x40, 4, 0, 0, 0x10, 0, 0xf8}
		if name == "duplicate prefix speaker" {
			data = []byte{1, 0x40, 1, 0x38, 2, 0x38, 4, 0, 0, 0x10, 0, 0xf8}
		}
		if name == "prefix cap" {
			data = nil
			for i := 0; i < 4097; i++ {
				data = binary.LittleEndian.AppendUint16(data, 0x4001)
			}
			data = append(data, 4, 0, 0, 0xf8)
		}
		shape, err := controls(data, TextScanOptions{Decode: true, Glyphs: map[uint16]string{4: "J"}, English: &text})
		if err != nil {
			t.Fatal("invalid prefix guard source", name, err)
		}
		options := TextEncodeOptions{Terminated: true, Source: &shape}
		switch name {
		case "unknown authoring":
			options.SourceAuthoring = "automatic"
		case "plain without source":
			options.SourceAuthoring, options.Source = "plain", nil
		case "plain fixed":
			options.SourceAuthoring, options.Terminated = "plain", false
		case "plain opaque":
			options.SourceAuthoring, options.ExactControls = "plain", true
		case "plain labels":
			options.SourceAuthoring, options.LabelRuns = "plain", 1
		case "plain bad readiness":
			options.SourceAuthoring, shape.Readiness = "plain", "unknown-control"
		case "forged colour prefix":
			options.SourceAuthoring = "plain"
			shape.Tokens[0].Word = 0xa000
		case "prefix body glyph":
			shape.Tokens[0].Word = 1
		case "prefix early END":
			shape.Tokens[0].Word = 0xf800
		case "prefix opaque word":
			shape.Tokens[0].Word = 0x4800
		case "prefix scale":
			shape.Tokens[0].Word = 0xe85a
		case "literal setup":
			options.Source = nil
			text = "<0x4001>A"
		}
		if got, err := encode(text, nil, map[rune]uint16{'A': 1}, options); err == nil || got != nil {
			t.Fatal("source prefix guard accepted invalid input", name, got, err)
		}
	}

	for _, name := range []string{"negative count", "over count", "short field", "long field", "odd field", "without decode", "without glyphs", "terminated", "native", "positional", "header", "wording", "opaque", "padded", "numeric", "END word", "unknown last word", "default still needs END"} {
		data := make([]byte, 16)
		options := TextScanOptions{Decode: true, Glyphs: map[uint16]string{1: "A"}, FixedWords: 8}
		text := "A"
		switch name {
		case "negative count":
			options.FixedWords = -1
		case "over count":
			options.FixedWords = 4097
		case "short field":
			data = data[:14]
		case "long field":
			data = append(data, 0, 0)
		case "odd field":
			data = data[:15]
		case "without decode":
			options.Decode = false
		case "without glyphs":
			options.Glyphs = nil
		case "terminated":
			options.Terminated = true
		case "native":
			options.Advances = map[uint16]int{}
		case "positional":
			options.PositionalLabels = true
		case "header":
			options.RequireHDR = true
		case "wording":
			options.English = &text
		case "opaque":
			options.ExactControls = true
		case "padded":
			options.Padded = true
		case "numeric":
			options.NumericBounds = []*NumericRange{{Min: 0, Max: 1}}
		case "END word":
			binary.LittleEndian.PutUint16(data[14:], 0xf800)
		case "unknown last word":
			binary.LittleEndian.PutUint16(data[14:], 2)
		case "default still needs END":
			options.FixedWords = 0
		}
		before := bytes.Clone(data)
		if got, err := controls(data, options); err == nil || !reflect.DeepEqual(got, TextShape{}) || !bytes.Equal(data, before) {
			t.Fatal("fixed scan accepted incompatible input or mutated bytes", name, got, err)
		}
	}
	{
		data := make([]byte, 8192)
		binary.LittleEndian.PutUint16(data[8190:], 1)
		shape, err := controls(data, TextScanOptions{Decode: true, Glyphs: map[uint16]string{1: "A"}, FixedWords: 4096})
		if err != nil || len(shape.Tokens) != 4096 || shape.Tokens[4095].Word != 1 || shape.Tokens[4095].Offset != 8190 {
			t.Fatal("fixed scanner failed bounded final word", err)
		}
	}

	for _, c := range []struct {
		text, hex string
		prefix    []string
		literal   bool
	}{
		{"<0023><0000><0x000c><0100>", "230000000c00000100f8", nil, false},
		{"<7000>{{PARAM:0x8800}}<0xa000>", "0070008800a000f8", nil, false},
		{"<d829><d82a><d82b><d82c><d82d><d82f><d830><d832><d833><d834><d835><d837><d838><d83a><d83b><d87e><e04a>", "29d82ad82bd82cd82dd82fd830d832d833d834d835d837d838d83ad83bd87ed84ae000f8", nil, false},
		{"[spk 0x3800]A//<3801>B|[spk 0x3fff]A", "003801000010013802000008ff3f010000f8", []string{"0x2800"}, false},
		{"<A>", "230001002400", nil, true},
		{"A//B", "0100160016000200", nil, true},
		{"", "", nil, true},
	} {
		want, err := hex.DecodeString(c.hex)
		if err != nil {
			t.Fatal(err)
		}
		if len(c.prefix) != 0 {
			want = append([]byte{0, 0x28}, want...)
		}
		got, err := encode(c.text, c.prefix, map[rune]uint16{'>': 0x24, '/': 0x16, '<': 0x23, ':': 0x0c, '@': 0x100, 'A': 1, 'B': 2}, TextEncodeOptions{Terminated: !c.literal})
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("codec golden %q: %x, %v", c.text, got, err)
		}
	}
	// Freeze reviewed table bytes separately from encoder-generated results. New tables must enter this coverage set.
	data, err := os.ReadFile("testdata/runtime-tables.json")
	if err != nil {
		t.Fatal(err)
	}
	var pins struct {
		Profiles  map[string]string `json:"profiles"`
		Resources map[string]string `json:"resources"`
	}
	if err := json.Unmarshal(data, &pins); err != nil {
		t.Fatal(err)
	}
	paths := []string{"analysis/pointer-checks.json", "analysis/current-pointer-checks.json", "analysis/current-unregistered-short-check.json", "analysis/unregistered-short-rebuild-recipe.json"}
	if err := filepath.WalkDir("recipes", func(path string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() && filepath.Ext(path) == ".json" {
			paths = append(paths, path)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(paths) != len(pins.Profiles)+len(pins.Resources) {
		t.Fatal("runtime table coverage set changed; review the new or removed tables")
	}
	for _, recipePath := range paths {
		data, err := os.ReadFile(recipePath)
		if err != nil {
			t.Fatal(err)
		}
		profileSHA, profile := pins.Profiles[recipePath]
		resourceSHA, resource := pins.Resources[recipePath]
		if profile == resource {
			t.Fatalf("%s: runtime table must have exactly one declared role", recipePath)
		}
		wantSHA := profileSHA
		if resource {
			wantSHA = resourceSHA
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) != wantSHA {
			t.Fatalf("%s: differs from independently reviewed runtime table", recipePath)
		}
		if resource {
			// Input schemas belong to their consumers; this guard pins reviewed facts.
			continue
		}
		var r Recipes
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&r); err != nil {
			t.Fatal(err)
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			t.Fatalf("%s: expected exactly one table", recipePath)
		}
		if r.Operation == "reuse_table" {
			base, err := os.ReadFile(filepath.Join(filepath.Dir(recipePath), r.BaseRecipe))
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(base)) != r.BaseSHA256 {
				t.Fatalf("%s: pinned base recipe missing or changed: %v", recipePath, err)
			}
			continue
		}
		if r.Operation == "cmb_member_replace" || r.Operation == "iso_file_replace" {
			bundle, err := os.ReadFile(filepath.Join(filepath.Dir(recipePath), r.BundlePath))
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(bundle)) != r.BundleSHA256 {
				t.Fatalf("%s: pinned bundle missing or changed: %v", recipePath, err)
			}
			continue
		}
		if recipePath == "analysis/current-unregistered-short-check.json" || recipePath == "analysis/unregistered-short-rebuild-recipe.json" || r.Operation == "stream_append" && r.Placement == "registry_landing" {
			continue
		}
		switch r.Operation {
		case "pointer_check", "registry_markup", "text_shapes", "reference_candidates", "reference_observed", "elf_layout", "registry_export", "registry_status", "registry_add":
			// Exact selectors are frozen above; shared lifecycle fixtures exercise dynamic inputs.
			continue
		}
		if strings.HasPrefix(recipePath, "recipes/text/fixed-ui/") || strings.HasPrefix(recipePath, "recipes/text/original-short/") {
			fixturePath := "testdata/fixed-ui-original.json"
			if strings.HasPrefix(recipePath, "recipes/text/original-short/") {
				fixturePath = "testdata/original-short.json"
			}
			if recipePath == "recipes/text/original-short/03-unregistered-short.json" {
				fixturePath = "testdata/unregistered-short.json"
			}
			data, err := os.ReadFile(fixturePath)
			if err != nil {
				t.Fatal(err)
			}
			var gold struct {
				SourceSHA256   string `json:"source_sha256"`
				SourceSize     int64  `json:"source_size"`
				GlyphmapSHA256 string `json:"glyphmap_sha256"`
				Tables         map[string]struct {
					Operation string `json:"operation"`
					Entries   map[string]struct {
						EN            string `json:"en"`
						Offset        int64  `json:"offset"`
						OldHex        string `json:"old_hex"`
						NewHex        string `json:"new_hex"`
						EncodedSHA256 string `json:"encoded_sha256"`
					} `json:"entries"`
				} `json:"tables"`
			}
			if err := json.Unmarshal(data, &gold); err != nil {
				t.Fatal(err)
			}
			table, exists := gold.Tables[recipePath]
			if !exists || r.Operation != table.Operation || r.SourceSHA256 != gold.SourceSHA256 || r.SourceSize != gold.SourceSize || r.GlyphmapSHA256 != gold.GlyphmapSHA256 || len(r.Entries) != len(table.Entries) {
				t.Fatalf("%s: original-image recipe differs from frozen source identity", recipePath)
			}
			var registry Registry
			for id, entry := range table.Entries {
				row, exists := r.Entries[id]
				if !exists || row.ExpectedHex != entry.OldHex || row.EncodedSHA256 != entry.EncodedSHA256 {
					t.Fatalf("%s: original-image preimage or output pin differs at %s", recipePath, id)
				}
				if entry.EN != "" {
					registry.Entries = append(registry.Entries, RegistryEntry{ID: id, EN: entry.EN})
				}
			}
			glyphs := []byte(`{"2":"1","3":"2","4":"3","5":"4","12":":","23":"?","43":"a","46":"d","47":"e","50":"h","55":"m","56":"n","58":"p","60":"r","62":"t","70":"B","73":"E","75":"G","77":"I","80":"L","81":"M","84":"P","92":"X"}`)
			if recipePath == "recipes/text/original-short/03-unregistered-short.json" {
				glyphs, err = os.ReadFile("testdata/unregistered-short-glyphs.json")
				if err != nil {
					t.Fatal(err)
				}
			}
			r.GlyphmapSHA256 = fmt.Sprintf("%x", sha256.Sum256(glyphs))
			edits, err := plan([]Recipes{r}, registry, glyphs, nil)
			if err != nil || len(edits) != len(table.Entries) {
				t.Fatalf("%s: original-image golden plan: %v", recipePath, err)
			}
			for _, edit := range edits {
				entry, exists := table.Entries[edit.ID]
				if !exists || edit.Offset != entry.Offset || hex.EncodeToString(edit.Old) != entry.OldHex || hex.EncodeToString(edit.New) != entry.NewHex {
					t.Fatalf("%s: original-image edit differs at %s", recipePath, edit.ID)
				}
			}
			continue
		}
		if r.Operation == "registry_merge" {
			data, err := os.ReadFile(filepath.Join("testdata", strings.TrimSuffix(filepath.Base(recipePath), ".json")+"-registry.json"))
			if err != nil {
				t.Fatal(err)
			}
			var reference struct {
				SourceSHA256 string                                `json:"profile_source_sha256"`
				SourceSize   int64                                 `json:"profile_source_size"`
				Updated      string                                `json:"updated"`
				Updates      map[string]map[string]json.RawMessage `json:"registry_updates"`
				Source       json.RawMessage                       `json:"source"`
				Expected     json.RawMessage                       `json:"expected"`
			}
			if err := json.Unmarshal(data, &reference); err != nil {
				t.Fatal(err)
			}
			updates, _ := json.Marshal(r.RegistryUpdates)
			wantUpdates, _ := json.Marshal(reference.Updates)
			if r.SourceSHA256 != reference.SourceSHA256 || r.SourceSize != reference.SourceSize || r.Updated != reference.Updated || !bytes.Equal(updates, wantUpdates) {
				t.Fatalf("%s: registry policy differs from frozen historical oracle", recipePath)
			}
			dir := t.TempDir()
			sourcePath, profilePath, output := filepath.Join(dir, "source.json"), filepath.Join(dir, "profile.json"), filepath.Join(dir, "output.json")
			r.SourceSize, r.SourceSHA256 = int64(len(reference.Source)), fmt.Sprintf("%x", sha256.Sum256(reference.Source))
			profile, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			for path, content := range map[string][]byte{sourcePath: reference.Source, profilePath: profile} {
				if err := os.WriteFile(path, content, 0600); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"--source", sourcePath, "--recipes", profilePath}
			if err := run(args, io.Discard); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("registry policy preview created output")
			}
			if err := run(append(append([]string{}, args...), "--apply", "--output", output), io.Discard); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			var normalized [][]byte
			for _, raw := range [][]byte{got, reference.Expected} {
				decoder := json.NewDecoder(bytes.NewReader(raw))
				decoder.UseNumber()
				var document any
				if err := decoder.Decode(&document); err != nil {
					t.Fatal(err)
				}
				value, err := json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				normalized = append(normalized, value)
			}
			preserved, err := os.ReadFile(sourcePath)
			if err != nil || !bytes.Equal(preserved, reference.Source) || !bytes.Equal(normalized[0], normalized[1]) {
				t.Fatalf("%s: policy output or source preservation differs from original", recipePath)
			}
			continue
		}
		if r.Operation == "stream_grow" || r.Operation == "stream_allocate" {
			data, err := os.ReadFile(filepath.Join("testdata", filepath.Base(recipePath)))
			if err != nil {
				t.Fatal(err)
			}
			var reference struct {
				SourceSHA256   string `json:"source_sha256"`
				SourceSize     int64  `json:"source_size"`
				GlyphmapSHA256 string `json:"glyphmap_sha256"`
				Growth         Growth `json:"growth"`
				ExpectedEdits  []struct {
					Offset int64  `json:"offset"`
					Old    string `json:"old_hex"`
					New    string `json:"new_hex"`
				} `json:"expected_edits"`
				ZeroTail struct {
					Offset int64 `json:"offset"`
					Length int   `json:"length"`
				} `json:"zero_tail"`
				SourceFixture string `json:"source_fixture"`
				Padding       struct {
					Offset int64 `json:"offset"`
					Length int   `json:"length"`
				} `json:"padding"`
				SourceBlocks []struct {
					Offset int64  `json:"offset"`
					Hex    string `json:"hex"`
				} `json:"source_blocks"`
			}
			if err := json.Unmarshal(data, &reference); err != nil {
				t.Fatal(err)
			}
			metadataCount := 6
			if r.Operation == "stream_allocate" {
				metadataCount = 2
				if reference.SourceFixture != "initialized-growth.json" || reference.Padding.Offset != 0x4d90b0 || reference.Padding.Length != 1872 {
					t.Fatal("allocation fixture profile differs")
				}
				shared, err := os.ReadFile(filepath.Join("testdata", reference.SourceFixture))
				if err != nil {
					t.Fatal(err)
				}
				var blocks struct {
					SourceBlocks json.RawMessage `json:"source_blocks"`
				}
				if err := json.Unmarshal(shared, &blocks); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(blocks.SourceBlocks, &reference.SourceBlocks); err != nil {
					t.Fatal(err)
				}
			}
			if r.SourceSHA256 != reference.SourceSHA256 || r.SourceSize != reference.SourceSize || r.GlyphmapSHA256 != reference.GlyphmapSHA256 || r.Growth == nil || *r.Growth != reference.Growth || len(reference.ExpectedEdits) != metadataCount || len(reference.SourceBlocks) != 18 {
				t.Fatal("production growth recipe/reference identity differs")
			}
			image := make([]byte, reference.ZeroTail.Offset+int64(reference.ZeroTail.Length))
			for _, block := range reference.SourceBlocks {
				old, err := hex.DecodeString(block.Hex)
				if err != nil || block.Offset < 0 || block.Offset > int64(len(image)-len(old)) {
					t.Fatal("invalid frozen production source block")
				}
				copy(image[block.Offset:], old)
			}
			if r.Operation == "stream_allocate" {
				// Reuse captured directory topology, reverting only the independently frozen original metadata.
				for _, gold := range reference.ExpectedEdits {
					old, err := hex.DecodeString(gold.Old)
					if err != nil {
						t.Fatal(err)
					}
					copy(image[gold.Offset:], old)
				}
			}
			copy(image[reference.ZeroTail.Offset:], bytes.Repeat([]byte{0xcc}, reference.ZeroTail.Length))
			// This bounded reader tests production arithmetic; full source identity/copy checks have separate evidence.
			glyphs := []byte(`{}`)
			r.GlyphmapSHA256 = fmt.Sprintf("%x", sha256.Sum256(glyphs))
			edits, err := plan([]Recipes{r}, Registry{}, glyphs, bytes.NewReader(image))
			expectedCount := metadataCount + 1
			if reference.Padding.Length != 0 {
				expectedCount++
			}
			if err != nil || len(edits) != expectedCount {
				t.Fatalf("production growth plan: %v", err)
			}
			for i, gold := range reference.ExpectedEdits {
				edit := edits[i]
				if edit.Offset != gold.Offset || edit.Operation != "stream_capacity" || hex.EncodeToString(edit.Old) != gold.Old || hex.EncodeToString(edit.New) != gold.New {
					t.Fatalf("production growth metadata differs at%#x", gold.Offset)
				}
			}
			if reference.Padding.Length != 0 {
				pad := edits[metadataCount]
				if pad.Offset != reference.Padding.Offset || len(pad.New) != reference.Padding.Length || bytes.Count(pad.New, []byte{0}) != len(pad.New) || !bytes.Equal(pad.Old, pad.New) {
					t.Fatal("production leading padding differs")
				}
			}
			tail := edits[len(edits)-1]
			if tail.Offset != reference.ZeroTail.Offset || len(tail.New) != reference.ZeroTail.Length || bytes.Count(tail.New, []byte{0}) != len(tail.New) || bytes.Count(tail.Old, []byte{0xcc}) != len(tail.Old) {
				t.Fatal("production growth tail differs")
			}
			for _, edit := range edits {
				copy(image[edit.Offset:], edit.New)
			}
			states := []string{"completed", "disc grown loader old"}
			if r.Operation == "stream_allocate" {
				states = []string{"completed", "allocated live content"}
			}
			for _, state := range states {
				if state == "allocated live content" {
					image[reference.ZeroTail.Offset] = 0xaa
				}
				if state == "disc grown loader old" {
					for _, gold := range reference.ExpectedEdits[2:] {
						old, _ := hex.DecodeString(gold.Old)
						copy(image[gold.Offset:], old)
					}
					image[reference.ZeroTail.Offset] = 0xaa
				}
				done, err := plan([]Recipes{r}, Registry{}, glyphs, bytes.NewReader(image))
				if err != nil || len(done) != metadataCount {
					t.Fatalf("production growth %s: %v", state, err)
				}
				for i, edit := range done {
					gold := reference.ExpectedEdits[i]
					if edit.Offset != gold.Offset || hex.EncodeToString(edit.New) != gold.New || (state == "completed" && !bytes.Equal(edit.Old, edit.New)) {
						t.Fatalf("production %s metadata differs", state)
					}
				}
			}
			continue
		}
		var reference struct {
			GlyphmapSHA256   string            `json:"glyphmap_sha256"`
			FontFixture      string            `json:"font_fixture"`
			AdvanceOverrides map[string]int    `json:"advance_overrides"`
			Glyphs           json.RawMessage   `json:"glyphs"`
			FontTableVMA     string            `json:"font_table_vma"`
			SpaceWords       map[string]string `json:"space_words"`
			RuneGlyphs       map[string]uint16 `json:"rune_glyphs"`
			Advances         map[string]int    `json:"advances"`
			ProtectedFields  map[string]string `json:"protected_fields"`
			Entries          map[string]struct {
				EN             string          `json:"en"`
				JP             json.RawMessage `json:"jp"`
				MaxNewBytes    int             `json:"max_new_bytes"`
				ReadBytes      int             `json:"read_bytes"`
				MaxWidth       int             `json:"max_width"`
				MaxLines       int             `json:"max_lines"`
				Columns, Rows  int
				NumericBounds  []*NumericRange `json:"numeric_bounds"`
				LabelRuns      int             `json:"label_runs"`
				EncodedSHA256  string          `json:"encoded_sha256"`
				Hex            string          `json:"new_hex"`
				Old            string          `json:"old_hex"`
				Offset         int64           `json:"offset"`
				SourceWidth    int             `json:"source_width"`
				SourceLines    int             `json:"source_lines"`
				EnglishWidth   int             `json:"english_width"`
				EnglishLines   int             `json:"english_lines"`
				StableControls []uint16        `json:"stable_controls"`
				Boundaries     []Boundary      `json:"boundaries"`
				Pages          bool            `json:"pages"`
			} `json:"entries"`
		}
		data, err = os.ReadFile(filepath.Join("testdata", filepath.Base(recipePath)))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &reference); err != nil {
			t.Fatal(err)
		}
		if len(reference.Entries) == 0 || len(r.Entries) != len(reference.Entries) || reference.GlyphmapSHA256 != r.GlyphmapSHA256 {
			t.Fatalf("%s: incomplete or stale golden fixture", recipePath)
		}
		if r.Operation == "stream_append" {
			if reference.FontFixture != "" {
				// Reuse source-native font facts without duplicating hundreds of metrics.
				entries, overrides := reference.Entries, reference.AdvanceOverrides
				// Unmarshal merges maps; keep the child entry set separate from the font fixture.
				reference.Entries = nil
				data, err := os.ReadFile(filepath.Join("testdata", reference.FontFixture))
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(data, &reference); err != nil {
					t.Fatal(err)
				}
				reference.Entries = entries
				for word, advance := range overrides {
					reference.Advances[word] = advance
				}
			}
			if r.Layout == nil || r.Layout.FontTableVMA != reference.FontTableVMA || len(reference.RuneGlyphs) == 0 || len(reference.Advances) == 0 {
				t.Fatal("incomplete initialized layout golden")
			}
			if len(reference.SpaceWords) != 8 || len(r.Layout.SpaceWords) != len(reference.SpaceWords) {
				t.Fatal("missing frozen native space instructions")
			}
			for vma, expected := range reference.SpaceWords {
				word, err := number(expected)
				advance := map[uint64]int{0x4160: 14, 0x41c0: 24}[word&0xffff]
				if err != nil || r.Layout.SpaceWords[vma] != expected || advance == 0 || reference.Advances["0x0000"] != advance {
					t.Fatal("native space words or metric differs from source golden")
				}
			}
			glyphs := make(map[rune]uint16)
			for text, word := range reference.RuneGlyphs {
				runes := []rune(text)
				if len(runes) != 1 {
					t.Fatal("invalid frozen rune")
				}
				glyphs[runes[0]] = word
			}
			advances := make(map[uint16]int)
			for key, advance := range reference.Advances {
				word, err := number(key)
				if err != nil || word >= 0x0800 || advance <= 0 {
					t.Fatal("invalid frozen advance")
				}
				advances[uint16(word)] = advance
			}
			base, err := number(r.ISOELFOffset)
			if err != nil {
				t.Fatal(err)
			}
			delta, err := number(r.ELFVMADelta)
			if err != nil {
				t.Fatal(err)
			}
			for id, gold := range reference.Entries {
				vma, err := number(id)
				if err != nil || vma < delta {
					t.Fatal("invalid initialized source target")
				}
				row, exists := r.Entries[id]
				offset := int64(base + vma - delta)
				if row.SourcePointer != "" {
					origin, err := number(row.SourcePointer)
					if err != nil || origin < 0x04000000 || r.Stream == nil {
						t.Fatal("invalid frozen source origin")
					}
					offset = ((int64(base) + r.Stream.RetailELFSize + 2047) &^ 2047) + int64(origin-0x04000000)
				}
				if offset != gold.Offset {
					t.Fatal("initialized source target differs from golden")
				}
				if !exists || row.ExpectedHex != "" && row.ExpectedHex != gold.Old {
					t.Fatal("initialized JP differs from independent golden")
				}
				old, err := hex.DecodeString(gold.Old)
				if err != nil {
					t.Fatal(err)
				}
				prefix := row.PrefixWords
				if row.ExpectedHex == "" && len(prefix) == 0 && binary.LittleEndian.Uint16(old) == 0x2800 {
					prefix = []string{"0x2800"}
				}
				options := TextEncodeOptions{Terminated: true, LabelRuns: row.LabelRuns}
				if r.SourceContext || row.LabelRuns != 0 {
					text := gold.EN
					scan := TextScanOptions{Decode: true, Glyphs: forward, English: &text}
					if row.LabelRuns != 0 {
						scan.PositionalLabels, scan.English = true, nil
					}
					shape, err := controls(old, scan)
					if err != nil {
						t.Fatal(err)
					}
					options.Source, options.Columns, options.Rows = &shape, r.Layout.Columns, r.Layout.Rows
				}
				if options.Columns != gold.Columns || options.Rows != gold.Rows || row.MaxLines != gold.MaxLines || row.LabelRuns != gold.LabelRuns || !reflect.DeepEqual(row.NumericBounds, gold.NumericBounds) {
					t.Fatalf("%s: formatter or numeric policy differs from frozen golden", id)
				}
				got, err := encode(gold.EN, prefix, glyphs, options)
				if err != nil || hex.EncodeToString(got) != gold.Hex {
					t.Fatalf("%s: initialized encoding: %v", id, err)
				}
				if row.MaxWidth != 0 || row.EncodedSHA256 != "" || gold.MaxWidth != 0 || gold.EncodedSHA256 != "" {
					if row.MaxNewBytes != gold.MaxNewBytes || row.ReadBytes != gold.ReadBytes || row.MaxWidth != gold.MaxWidth || row.EncodedSHA256 != gold.EncodedSHA256 || gold.EncodedSHA256 != fmt.Sprintf("%x", sha256.Sum256(got)) {
						t.Fatalf("%s: reviewed encoding/consumer policy differs from independent golden", id)
					}
				}
				measurement := TextScanOptions{Terminated: true, Advances: advances, NumericBounds: row.NumericBounds}
				if row.LabelRuns != 0 {
					measurement = TextScanOptions{Terminated: true, PositionalLabels: true}
				}
				a, err := controls(old, measurement)
				if err != nil {
					t.Fatal(err)
				}
				b, err := controls(got, measurement)
				if err != nil {
					t.Fatal(err)
				}
				if a.Width != gold.SourceWidth || a.Lines != gold.SourceLines || b.Width != gold.EnglishWidth || b.Lines != gold.EnglishLines || a.Pages != gold.Pages || b.Pages != gold.Pages {
					t.Fatalf("%s: frozen source/EN shape differs", id)
				}
				for _, shape := range []TextShape{a, b} {
					if !slices.Equal(shape.Words, gold.StableControls) || !slices.Equal(shape.Boundaries, gold.Boundaries) {
						t.Fatalf("%s: frozen control/boundary signature differs", id)
					}
				}
			}
			continue
		}
		var registry Registry
		for id, value := range reference.Entries {
			var entry RegistryEntry
			entry.ID, entry.EN, entry.JP = id, value.EN, value.JP
			registry.Entries = append(registry.Entries, entry)
		}
		r.GlyphmapSHA256 = fmt.Sprintf("%x", sha256.Sum256(reference.Glyphs))
		edits, err := plan([]Recipes{r}, registry, reference.Glyphs, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(edits) != len(reference.Entries) {
			t.Fatal("missing recipe")
		}
		for _, edit := range edits {
			gold, exists := reference.Entries[edit.ID]
			if !exists || edit.Offset != gold.Offset || hex.EncodeToString(edit.Old) != gold.Old || hex.EncodeToString(edit.New) != gold.Hex {
				t.Errorf("%s: original bytes, target offset or replacement differs from reviewed golden", edit.ID)
			}
			for id, span := range reference.ProtectedFields {
				vma, err := number(id)
				if err != nil {
					t.Fatal(err)
				}
				base, _ := number(r.ISOELFOffset)
				delta, _ := number(r.ELFVMADelta)
				offset := int64(base + vma - delta)
				if edit.Offset < offset+int64(len(span)/2) && offset < edit.Offset+int64(len(edit.New)) {
					t.Errorf("%s overlaps protected field %s", edit.ID, id)
				}
			}
		}
	}
	// Pinned Python tokens cover opaque payloads, leading state and both token limits.
	{
		var structured struct {
			Glyphs    map[uint16]string `json:"glyphs"`
			WordKinds []struct {
				Start, End uint16
				Kind       string
			} `json:"word_kinds"`
			Cases []struct {
				Name   string
				Chunks []struct {
					Hex    string
					Repeat int
				}
				Glyphs       map[uint16]string
				RequireHDR   bool `json:"require_hdr"`
				Error        bool
				TokenCount   int    `json:"token_count"`
				TokenSHA256  string `json:"token_sha256"`
				ContentStart int    `json:"content_start"`
			}
		}
		raw, err := os.ReadFile("testdata/structured-text.json")
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &structured); err != nil {
			t.Fatal(err)
		}
		for _, c := range structured.Cases {
			var data []byte
			for _, chunk := range c.Chunks {
				block, err := hex.DecodeString(chunk.Hex)
				if err != nil {
					t.Fatal(err)
				}
				data = append(data, bytes.Repeat(block, chunk.Repeat)...)
			}
			before := append([]byte(nil), data...)
			glyphs := structured.Glyphs
			if c.Glyphs != nil {
				glyphs = c.Glyphs
			}
			got, err := controls(data, TextScanOptions{Decode: true, Glyphs: glyphs, RequireHDR: c.RequireHDR})
			if !bytes.Equal(before, data) {
				t.Fatalf("%s mutated input", c.Name)
			}
			if c.Error {
				if err == nil {
					t.Fatalf("%s accepted refused reference input", c.Name)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			tokenHash := sha256.New()
			for _, token := range got.Tokens {
				fmt.Fprintf(tokenHash, "%s:%04x:%d:%x\n", token.Kind, token.Word, token.Offset, token.Payload)
			}
			if len(got.Tokens) != c.TokenCount || got.ContentStart != c.ContentStart || fmt.Sprintf("%x", tokenHash.Sum(nil)) != c.TokenSHA256 {
				t.Fatalf("%s token content/order/offset/payload or content start differs from Python", c.Name)
			}
			for _, token := range got.Tokens {
				if len(token.Payload) != 0 {
					payloadBefore := append([]byte(nil), token.Payload...)
					data[token.Offset+2] ^= 0xff
					if !bytes.Equal(token.Payload, payloadBefore) {
						t.Fatalf("%s retained mutable input payload", c.Name)
					}
					break
				}
			}
		}
		for word := 0; word <= 0xffff; word++ {
			expected := ""
			for _, interval := range structured.WordKinds {
				if uint16(word) >= interval.Start && uint16(word) <= interval.End {
					expected = interval.Kind
					break
				}
			}
			if expected == "" {
				t.Fatal("incomplete reference word partition")
			}
			if expected == "unclassified" {
				if word >= 0x3800 && word <= 0x3fff {
					expected = "speaker"
				} else if structured.Glyphs[uint16(word)] != "" {
					expected = "glyph"
				}
			}
			data := make([]byte, 4)
			if expected == "param8" {
				data = make([]byte, 12)
				copy(data[2:], []byte{0, 0xf8, 0, 0x98, 0, 0xb0, 0, 0xe0})
			}
			binary.LittleEndian.PutUint16(data, uint16(word))
			binary.LittleEndian.PutUint16(data[len(data)-2:], 0xf800)
			got, err := controls(data, TextScanOptions{Decode: true, Glyphs: structured.Glyphs})
			if expected == "unclassified" {
				if err == nil {
					t.Fatalf("unknown word %#x accepted", word)
				}
				continue
			}
			if err != nil || len(got.Tokens) == 0 || got.Tokens[0].Kind != expected || got.Tokens[0].Word != uint16(word) || got.Tokens[0].Offset != 0 {
				t.Fatalf("word %#x expected %s: %+v, %v", word, expected, got.Tokens, err)
			}
			count := 2
			if expected == "end" {
				count = 1
			}
			if len(got.Tokens) != count {
				t.Fatalf("word %#x decoded opaque payload or missed END", word)
			}
		}
		for _, options := range []TextScanOptions{
			{English: new(string)},
			{Decode: true},
			{Decode: true, Terminated: true, Glyphs: structured.Glyphs},
			{Decode: true, Advances: map[uint16]int{1: 1}, Glyphs: structured.Glyphs},
			{RequireHDR: true},
			{Glyphs: structured.Glyphs},
		} {
			if _, err := controls([]byte{0, 0xf8}, options); err == nil {
				t.Fatalf("accepted incompatible scan options %+v", options)
			}
		}
	}

	{
		data, err := os.ReadFile("testdata/markup-analysis.json")
		if err != nil {
			t.Fatal(err)
		}
		var oracle struct {
			Chunks    []string
			Prefixes  []string
			MaxLength int `json:"max_length"`
			Accepted  int `json:"accepted_streams"`
			Refused   int `json:"refused_streams"`
			Cases     int `json:"analysis_cases"`
			SHA256    string
		}
		if err := json.Unmarshal(data, &oracle); err != nil {
			t.Fatal(err)
		}
		shapeData, err := os.ReadFile("testdata/text-shape-analysis.json")
		if err != nil {
			t.Fatal(err)
		}
		var shapeOracle struct{ SHA256 string }
		if err := json.Unmarshal(shapeData, &shapeOracle); err != nil {
			t.Fatal(err)
		}
		shapeHash := sha256.New()
		hash := sha256.New()
		accepted, refused, cases := 0, 0, 0
		glyphs := map[uint16]string{0: " ", 1: "A", 2: "B"}
		for _, prefix := range oracle.Prefixes {
			combinations := 1
			for length := 0; length <= oracle.MaxLength; length++ {
				for n := 0; n < combinations; n++ {
					chunks, index := make([]string, length), n
					for i := length - 1; i >= 0; i-- {
						chunks[i] = oracle.Chunks[index%len(oracle.Chunks)]
						index /= len(oracle.Chunks)
					}
					raw, err := hex.DecodeString(prefix + strings.Join(chunks, "") + "00f8")
					if err != nil {
						t.Fatal(err)
					}
					shape, err := controls(raw, TextScanOptions{Decode: true, Glyphs: glyphs})
					if err != nil {
						refused++
						fmt.Fprintln(hash, "REFUSE")
						continue
					}
					accepted++
					fmt.Fprintf(shapeHash, "%d:%d:%t:%t:%t:%d:%d\n", shape.Clusters, shape.Targets, shape.TextBeforeFirst, shape.TextAfterLast, shape.TextBetweenClusters, shape.HLCount, shape.HLCleanPairs)
					var markers, wrong, values []string
					for _, token := range shape.Tokens {
						hl := token.Kind == "hl" || token.Kind == "pen0" && token.Word >= 0xe800 && token.Word <= 0xefff
						if !hl && token.Kind != "icon" && token.Kind != "param8" {
							continue
						}
						family := "PARAM"
						if hl {
							family = "HL"
						}
						marker := fmt.Sprintf("{{%s:0x%04x}}", family, token.Word)
						markers = append(markers, marker)
						wrong = append(wrong, "{{"+family+":0xffff}}")
						if !hl {
							values = append(values, marker)
						}
					}
					correct := strings.Join(markers, "")
					slices.Reverse(markers)
					english := []string{"", "Words", correct, strings.ReplaceAll(correct, "PARAM:", "ICON:"), strings.Join(markers, ""), strings.Join(wrong, ""), strings.Join(values, ""), correct + "{{bogus}}", "{{HL:0xb001}}", "{{ICON:0xa000}}", "{" + correct + "{", "{{ICON:0x10000000000000000}}", strings.ReplaceAll(correct, ":0x", ":0x0000")}
					for _, text := range english {
						got, err := controls(raw, TextScanOptions{Decode: true, Glyphs: glyphs, English: &text})
						if err != nil {
							t.Fatalf("analysis %x/%q: %v", raw, text, err)
						}
						fmt.Fprintf(hash, "%s:%s:%d:%d\n", got.Readiness, strings.Join(got.Kinds, ","), got.Targets, got.Clusters)
						cases++
					}
				}
				combinations *= len(oracle.Chunks)
			}
		}
		if fmt.Sprintf("%x", shapeHash.Sum(nil)) != shapeOracle.SHA256 {
			t.Fatalf("Python cluster/highlight report facts: %x", shapeHash.Sum(nil))
		}
		if accepted != oracle.Accepted || refused != oracle.Refused || cases != oracle.Cases || fmt.Sprintf("%x", hash.Sum(nil)) != oracle.SHA256 {
			t.Fatalf("Python source analysis oracle: accepted/refused/cases=%d/%d/%d digest=%x", accepted, refused, cases, hash.Sum(nil))
		}
	}

	// ICON/PARAM spelling names the same self-contained source token, never an opaque payload.
	for word := uint32(0); word <= 0xffff; word++ {
		icon := word >= 0x6800 && word <= 0x97ff || word >= 0xa000 && word <= 0xa7ff
		for _, tag := range []string{"PARAM", "ICON"} {
			encoded, err := encode(fmt.Sprintf("{{%s:0x%04x}}", tag, word), nil, nil, TextEncodeOptions{Terminated: true})
			if !icon {
				if err == nil {
					t.Fatalf("%s accepted non-ICON source code %#x", tag, word)
				}
				continue
			}
			if err != nil || len(encoded) != 4 || binary.LittleEndian.Uint16(encoded) != uint16(word) || binary.LittleEndian.Uint16(encoded[2:]) != 0xf800 {
				t.Fatalf("%s source code %#x: %x %v", tag, word, encoded, err)
			}
			if _, err := controls(encoded, TextScanOptions{Terminated: true, Advances: map[uint16]int{}}); err == nil || !strings.Contains(err.Error(), "substitution/position semantics") {
				t.Fatalf("unbounded value %#x acquired a measured layout: %v", word, err)
			}
		}
	}

}

func TestMisalignedTargetAndWriterBoundary(t *testing.T) {
	// Every operation reserves its full extent before the following edit is checked.
	for _, edit := range []Edit{
		{Operation: "stream_pointer", Old: []byte{0x10, 0, 0, 0}, New: []byte{0x20, 0, 0, 4}},
		{Operation: "stream_payload", Old: make([]byte, 4), New: []byte{1, 0, 0, 0xf8}},
		{Operation: "stream_padding", Old: make([]byte, 2), New: make([]byte, 2)},
		{Operation: "pointer_check", Old: []byte{0x10, 0, 0, 0}, New: []byte{0x10, 0, 0, 0}},
		{Operation: "stream_capacity", Old: make([]byte, 4), New: []byte{1, 0, 0, 0}},
		{Operation: "guarded_words", Old: make([]byte, 4), New: []byte{1, 0, 0, 0}},
		{Operation: "same_length_stream", Old: []byte{1, 0, 0, 0xf8}, New: []byte{2, 0, 0, 0xf8}},
		{Operation: "fixed_field", Old: []byte{1, 0}, New: []byte{2, 0}},
		{Operation: "stream_slot", Old: []byte{1, 0, 0, 0xf8, 0, 0}, New: []byte{2, 0, 0, 0xf8, 0, 0}},
	} {
		edit.ID, edit.Offset = "0x10", 16
		end := edit.Offset + int64(len(edit.New))
		if err := validateEdits([]Edit{edit}, end); err != nil {
			t.Fatalf("%s rejected at source boundary: %v", edit.Operation, err)
		}
		if err := validateEdits([]Edit{edit}, end-1); err == nil {
			t.Fatalf("%s accepted beyond source boundary", edit.Operation)
		}
		for _, gap := range []int64{-2, 0, 2} {
			tail := Edit{ID: "0x20", Operation: "fixed_field", Offset: end + gap, Old: []byte{1, 0}, New: []byte{2, 0}}
			if err := validateEdits([]Edit{edit, tail}, 64); (err != nil) != (gap < 0) {
				t.Fatalf("%s following edit gap=%d: %v", edit.Operation, gap, err)
			}
			if gap >= 0 {
				if err := validateEdits([]Edit{tail, edit}, 64); err == nil {
					t.Fatalf("%s accepted reversed edit order", edit.Operation)
				}
			}
		}
	}
	r, registry, glyphs, image := fixture(t, "same_length_stream")
	recipe := r.Entries["0x10"]
	delete(r.Entries, "0x10")
	r.Entries["0x11"] = recipe
	registry.Entries[0].ID = "0x11"
	if _, err := plan([]Recipes{r}, registry, glyphs, nil); err == nil {
		t.Fatal("accepted odd VMA")
	}
	delete(r.Entries, "0x11")
	r.Entries["0x10"] = recipe
	registry.Entries[0].ID = "0x10"
	r.ISOELFOffset = "0x1"
	if _, err := plan([]Recipes{r}, registry, glyphs, nil); err == nil {
		t.Fatal("accepted odd offset")
	}
	r.ISOELFOffset = "0x0"
	edits, err := plan([]Recipes{r}, registry, glyphs, nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "source.iso")
	if err := os.WriteFile(path, image, 0600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	for _, bad := range [][]Edit{
		nil,
		{{ID: "0x10", Operation: "same_length_stream", Offset: -2, Old: edits[0].Old, New: edits[0].New}},
		{{ID: "0x10", Operation: "same_length_stream", Offset: 17, Old: edits[0].Old, New: edits[0].New}},
		{{ID: "0x10", Operation: "same_length_stream", Offset: 64, Old: edits[0].Old, New: edits[0].New}},
		{{ID: "0x10", Operation: "same_length_stream", Offset: 16, Old: edits[0].Old, New: append(bytes.Clone(edits[0].New), 0, 0)}},
		{{ID: "0x10", Operation: "same_length_stream", Offset: 16, Old: edits[0].Old, New: []byte{0, 8, 0, 0xf8}}},
		{edits[0], edits[0]},
		{{ID: "0x10", Operation: "same_length_stream", Offset: 16, Old: edits[0].Old, New: []byte{2, 0, 0, 0xf8}}},
		{{ID: "0x10", Operation: "same_length_stream", Offset: 16, Old: []byte{9, 0, 0, 0xf8}, New: edits[0].Old}},
		{{ID: "0x20", Operation: "same_length_stream", Offset: 16, Old: edits[0].Old, New: edits[0].New}},
		{{ID: "0x10", Offset: 16, Old: []byte{1, 0, 0, 0}, New: []byte{2, 0, 0, 0}}},
		{{ID: "0x10", Operation: "same_length_stream", Offset: 16, Old: []byte{1, 0, 0, 0}, New: []byte{2, 0, 0, 0}}},
	} {
		output := filepath.Join(dir, "bad.iso")
		if _, err := patchCopy(source, output, []Recipes{r}, bad, registry, glyphs); err == nil {
			t.Fatal("writer accepted invalid edit")
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("created invalid output")
		}
	}
	for _, operation := range []string{"fixed_field", "unknown"} {
		r.Operation = operation
		if _, err := patchCopy(source, filepath.Join(dir, "wrong-format.iso"), []Recipes{r}, edits, registry, glyphs); err == nil {
			t.Fatalf("writer accepted terminated stream with operation %s", operation)
		}
	}
	// Match the source bytes and hash so format checks cannot hide behind a byte mismatch.
	copy(image[16:20], []byte{1, 0, 0, 0})
	if err := os.WriteFile(path, image, 0600); err != nil {
		t.Fatal(err)
	}
	r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
	r.Operation = "same_length_stream"
	recipe = r.Entries["0x10"]
	recipe.ExpectedHex = "01000000"
	r.Entries["0x10"] = recipe
	for _, operation := range []string{"fixed_field", "same_length_stream"} {
		bad := []Edit{{ID: "0x10", Offset: 16, Old: []byte{1, 0, 0, 0}, New: []byte{2, 0, 0, 0}, Operation: operation}}
		output := filepath.Join(dir, "no-end.iso")
		if _, err := patchCopy(source, output, []Recipes{r}, bad, registry, glyphs); err == nil {
			t.Fatalf("writer accepted no-END stream with operation=%s", operation)
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("created no-END output")
		}
	}
}

func TestRecipeSchemaRefusals(t *testing.T) {
	r, registry, glyphs, image := fixture(t, "same_length_stream")
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	regData, _ := json.Marshal(registry)
	recipeData, _ := json.Marshal(r)
	recipePath := filepath.Join(dir, "recipes.json")
	args := []string{"--source", write("source.iso", image), "--registry", write("registry.json", regData), "--glyphmap", write("glyphs.json", glyphs), "--recipes", recipePath}
	for _, raw := range []string{
		string(recipeData) + `{}`,
		strings.TrimSuffix(string(recipeData), "}") + `,"ignored_safety_guard":1}`,
		`null`,
	} {
		write("recipes.json", []byte(raw))
		if err := run(args, io.Discard); err == nil {
			t.Fatal("accepted malformed or unsupported recipe schema")
		}
	}
	r.Operation = "fixed_field"
	recipe := r.Entries["0x10"]
	recipe.ExpectedHex = "04000000"
	r.Entries["0x10"] = recipe
	image[18], image[19] = 0, 0
	r.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(image))
	recipeData, _ = json.Marshal(r)
	write("recipes.json", recipeData)
	write("source.iso", image)
	if err := run(args, io.Discard); err != nil {
		t.Fatalf("valid fixed-field CLI: %v", err)
	}
	for _, raw := range []string{
		`{"entries":[{"id":"0x10"}]}`,
		`{"entries":[{"id":"0x10","en":null}]}`,
		`{"entries":[{"id":"0x10","en":""}]}`,
	} {
		write("registry.json", []byte(raw))
		output := filepath.Join(dir, "must-not-exist.iso")
		if err := run(append(args, "--apply", "--output", output), io.Discard); err == nil {
			t.Fatal("accepted absent or empty canonical wording")
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("created output for missing wording")
		}
	}
	r, registry, glyphs, image = fixture(t, "stream_reflow_numeric")
	recipe = r.Entries["0x100"]
	recipe.NumericBounds[0] = nil
	r.Entries["0x100"] = recipe
	recipeData, _ = json.Marshal(r)
	regData, _ = json.Marshal(registry)
	write("recipes.json", recipeData)
	write("registry.json", regData)
	write("glyphs.json", glyphs)
	write("source.iso", image)
	output := filepath.Join(dir, "null-bound.iso")
	if err := run(append(args, "--apply", "--output", output), io.Discard); err == nil || !strings.Contains(err.Error(), "numeric argument bound must be an object") {
		t.Fatalf("null numeric bound: expected range refusal, got %v", err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("created output for a null numeric bound")
	}
	original, err := os.ReadFile(filepath.Join(dir, "source.iso"))
	if err != nil || !bytes.Equal(original, image) {
		t.Fatal("null-bound refusal changed source")
	}

}
