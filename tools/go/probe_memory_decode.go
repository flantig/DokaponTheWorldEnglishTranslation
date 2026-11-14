package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
)

// decodeProbeMemory consumes an already validated finite acquired read set.
// It never follows pointers or paths; invalid native observations remain
// unsupported. Acquisition/admission and complete read-set validation are callers' duties.
func decodeProbeMemory(requests map[string]ProbeMemoryRequest, payloads map[string][]byte, values map[string]uint64, decoders []ProbeMemoryDecoder) ([]ProbeMemoryDecoded, error) {
	decoded := []ProbeMemoryDecoded{}
	for _, decoder := range decoders {
		result := ProbeMemoryDecoded{ID: decoder.ID, Kind: decoder.Kind, Status: "KNOWN"}
		var data []byte
		for _, id := range decoder.Requests {
			data = append(data, payloads[id]...)
		}
		first := requests[decoder.Requests[0]]
		switch decoder.Kind {
		case "scalar":
			if len(decoder.Requests) != 1 {
				return decoded, fmt.Errorf("scalar decoder requires one read")
			}
			value := values[first.ID]
			result.Value = &value
		case "frame_tags":
			if len(decoder.Requests) != 3 {
				return decoded, fmt.Errorf("frame tags require three source reads")
			}
			expectedAddresses := []uint32{0x56581c, 0x56b598, 0x56b18c}
			expectedOpcodes := []uint8{1, 1, 0}
			for i, id := range decoder.Requests {
				request := requests[id]
				if *request.Address != expectedAddresses[i] || *request.Opcode != expectedOpcodes[i] {
					return decoded, fmt.Errorf("frame tag source layout differs")
				}
				result.FrameTags = append(result.FrameTags, values[id])
			}
		case "fixed", "stream":
			_, glyphs, mapErr := glyphMaps(decoder.Glyphmap, true)
			if decoder.Kind == "fixed" && (mapErr != nil || len(data) != 16) {
				return decoded, fmt.Errorf("fixed decoder requires16 source bytes and a valid glyphmap")
			}
			if decoder.Kind == "stream" && (mapErr != nil || len(data) < 2 || len(data) > 4096 || len(data)%2 != 0) {
				return decoded, fmt.Errorf("stream decoder requires2..4096 whole source bytes and a valid glyphmap")
			}
			next := uint64(*first.Address)
			for _, id := range decoder.Requests {
				request := requests[id]
				if uint64(*request.Address) != next {
					if decoder.Kind == "stream" {
						return decoded, fmt.Errorf("stored stream reads must be contiguous")
					}
					return decoded, fmt.Errorf("fixed field reads must be contiguous")
				}
				next += uint64(1) << *request.Opcode
			}
			scan := TextScanOptions{Decode: true, Glyphs: glyphs}
			if decoder.Kind == "fixed" {
				scan.FixedWords = 8
			}
			shape, scanErr := controls(data, scan)
			if scanErr != nil {
				if decoder.Kind == "stream" {
					return decoded, fmt.Errorf("unsupported stored stream: %w", scanErr)
				}
				return decoded, fmt.Errorf("unsupported fixed memory field: %w", scanErr)
			}
			if decoder.Kind == "stream" && shape.Tokens[len(shape.Tokens)-1].Offset != len(data)-2 {
				return decoded, fmt.Errorf("stored stream requires first END at final byte offset%d", len(data)-2)
			}
			var text strings.Builder
			for _, token := range shape.Tokens {
				switch token.Kind {
				case "space":
					text.WriteByte(' ')
				case "glyph":
					text.WriteString(glyphs[token.Word])
				case "line":
					text.WriteByte('|')
				case "page":
					text.WriteString("//")
				case "end":
				case "hl", "icon":
					// Preserve only qualified stored syntax. A000 stays opaque;
					// this is not substitution or native rendering semantics.
					if token.Word != 0xa000 && (token.Word < 0xb001 || token.Word > 0xb009) {
						return decoded, fmt.Errorf("unsupported stored stream token %#x at byte%d", token.Word, token.Offset)
					}
					fmt.Fprintf(&text, "<0x%04x>", token.Word)
				default:
					return decoded, fmt.Errorf("unsupported stored stream token %#x at byte%d", token.Word, token.Offset)
				}
			}
			value := text.String()
			if decoder.Kind == "fixed" {
				value = strings.TrimRight(value, sourceWhitespace)
			} else {
				result.Tokens = shape.Tokens
				result.Reason = "stored syntax only; A000 is opaque and no native expansion is inferred"
			}
			result.Text = &value
		case "player":
			if len(data) != 508 || len(decoder.Requests) != 127 {
				return decoded, fmt.Errorf("player decoder requires the complete508-byte native record")
			}
			for i, id := range decoder.Requests {
				request := requests[id]
				if *request.Opcode != 2 || uint64(*request.Address) != uint64(*first.Address)+uint64(i*4) {
					return decoded, fmt.Errorf("player record reads must preserve complete contiguous u32 layout")
				}
			}
			control, square, money, flags := uint32(data[241]), uint32(data[250]), binary.LittleEndian.Uint32(data[304:]), uint32(data[0])
			player := ProbeSavedPlayer{Control: &control, Square: &square, Money: &money, TutorialFlags: &flags, RecordSHA256: fmt.Sprintf("%x", sha256.Sum256(data)), NameWords: []uint32{}}
			for offset := 252; offset < 272; offset += 4 {
				player.NameWords = append(player.NameWords, binary.LittleEndian.Uint32(data[offset:]))
			}
			initialized := bytes.Clone(data)
			initialized[0] |= 1
			player.TutorialInitializedSHA256 = fmt.Sprintf("%x", sha256.Sum256(initialized))
			result.Player = &player
		case "cursor":
			base := *first.Address
			if base < 0x100000 || base > 0x2000000-0x50 {
				result.Status, result.Reason = "UNSUPPORTED", "native cursor pointer outside source bounds"
				break
			}
			if len(decoder.Requests) != 5 {
				return decoded, fmt.Errorf("cursor decoder requires five source fields")
			}
			offsets := []uint32{0, 0x16, 0x18, 0x1a, 0x1c}
			for i, id := range decoder.Requests {
				request := requests[id]
				opcode := uint8(1)
				if i == 0 {
					opcode = 0
				}
				if *request.Address != base+offsets[i] || *request.Opcode != opcode {
					return decoded, fmt.Errorf("cursor source field layout differs")
				}
			}
			cursor := values[decoder.Requests[0]]*(values[decoder.Requests[2]]+values[decoder.Requests[4]]) + values[decoder.Requests[1]] + values[decoder.Requests[3]]
			result.Cursor = &cursor
		case "texture":
			primitive := values[first.ID]
			if *first.Opcode != 2 || primitive&3 != 0 || primitive < 0x100000 || primitive > 0x2000000-0x20 {
				result.Status, result.Reason = "UNSUPPORTED", "native image primitive outside source bounds"
				break
			}
			if len(decoder.Requests) < 2 {
				return decoded, fmt.Errorf("texture decoder lacks its pointer read")
			}
			textureRequest := requests[decoder.Requests[1]]
			texture := values[textureRequest.ID]
			if *textureRequest.Opcode != 2 || uint64(*textureRequest.Address) != primitive+8 {
				return decoded, fmt.Errorf("texture pointer source layout differs")
			}
			if texture&3 != 0 || texture < 0x100000 || texture > 0x2000000-0x60 {
				result.Status, result.Reason = "UNSUPPORTED", "native texture pointer outside source bounds"
				break
			}
			if len(decoder.Requests) != 6 {
				return decoded, fmt.Errorf("texture decoder requires its complete32-byte name")
			}
			var name []byte
			for i, id := range decoder.Requests[2:] {
				request := requests[id]
				if *request.Opcode != 3 || uint64(*request.Address) != texture+0x10+uint64(i*8) {
					return decoded, fmt.Errorf("texture name source layout differs")
				}
				name = append(name, payloads[id]...)
			}
			end := bytes.IndexByte(name, 0)
			if end < 0 {
				result.Status, result.Reason = "UNSUPPORTED", "native texture name lacks ASCII terminator"
				break
			}
			ascii := true
			for _, value := range name[:end] {
				if value > 127 {
					ascii = false
				}
			}
			if !ascii {
				result.Status, result.Reason = "UNSUPPORTED", "native texture name lacks ASCII terminator"
				break
			}
			value := string(name[:end])
			result.Text = &value
		case "char":
			node := values[first.ID]
			if *first.Opcode != 2 || node < 0x100000 || node > 0x2000000-0x20 {
				result.Status, result.Reason = "UNSUPPORTED", "native glyph node outside source bounds"
				break
			}
			if len(decoder.Requests) != 3 {
				return decoded, fmt.Errorf("glyph node decoder requires two native label words")
			}
			var label []byte
			for i, id := range decoder.Requests[1:] {
				request := requests[id]
				if *request.Opcode != 3 || uint64(*request.Address) != node+0x10+uint64(i*8) {
					return decoded, fmt.Errorf("glyph node source layout differs")
				}
				label = append(label, payloads[id]...)
			}
			if end := bytes.IndexByte(label, 0); end >= 0 {
				label = label[:end]
			}
			if len(label) <= 4 || !bytes.HasPrefix(label, []byte("char")) {
				result.Status, result.Reason = "UNSUPPORTED", "native glyph label is not charN"
				break
			}
			digits := true
			for _, value := range label[4:] {
				if value < '0' || value > '9' {
					digits = false
				}
			}
			_, _, mapErr := glyphMaps(decoder.Glyphmap, true)
			var sourceGlyphs map[string]string
			_ = json.Unmarshal(decoder.Glyphmap, &sourceGlyphs)
			value := sourceGlyphs[string(label[4:])]
			if !digits || mapErr != nil || value == "" {
				result.Status, result.Reason = "UNSUPPORTED", "native glyph label is unknown"
				break
			}
			result.Text = &value
		}
		decoded = append(decoded, result)
	}
	return decoded, nil
}
