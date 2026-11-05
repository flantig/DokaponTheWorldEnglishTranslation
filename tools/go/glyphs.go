package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// glyphMaps preserves source aliases and chooses the lowest glyph index for encoding.
// The decode policy also validates multi-rune source aliases; literal patch behavior stays unchanged.
func glyphMaps(data []byte, decodeSource bool) (map[rune]uint16, map[uint16]string, error) {
	var gm map[string]string
	if err := json.Unmarshal(data, &gm); err != nil {
		return nil, nil, err
	}
	glyphs := make(map[rune]uint16)
	forwardGlyphs := make(map[uint16]string)
	for key, value := range gm {
		if !decodeSource && utf8.RuneCountInString(value) != 1 {
			continue
		}
		base := 10
		if strings.HasPrefix(key, "0x") {
			base = 16
			key = key[2:]
		}
		word, err := strconv.ParseUint(key, base, 16)
		if err != nil || word >= 0x0800 {
			return nil, nil, fmt.Errorf("invalid glyph index %q", key)
		}
		if decodeSource {
			if previous, ok := forwardGlyphs[uint16(word)]; ok && previous != value {
				return nil, nil, fmt.Errorf("conflicting source glyph aliases for %#x", word)
			}
			forwardGlyphs[uint16(word)] = value
		}
		if utf8.RuneCountInString(value) != 1 {
			continue
		}
		r, _ := utf8.DecodeRuneInString(value)
		if prev, ok := glyphs[r]; !ok || uint16(word) < prev {
			glyphs[r] = uint16(word)
		}
	}
	return glyphs, forwardGlyphs, nil
}
