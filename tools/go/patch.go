package main

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// sentinelBase is the address protocol recognized by the installed translation route.
const sentinelBase uint64 = 0x04000000
const maxStreamBytes = 8192

var mipsRegisters = strings.Fields("$zero $at $v0 $v1 $a0 $a1 $a2 $a3 $t0 $t1 $t2 $t3 $t4 $t5 $t6 $t7 $s0 $s1 $s2 $s3 $s4 $s5 $s6 $s7 $t8 $t9 $k0 $k1 $gp $sp $fp $ra")

// number parses addresses and words as 32-bit hexadecimal, even without a 0x prefix.
func number(text string) (uint64, error) {
	return strconv.ParseUint(strings.TrimPrefix(strings.ToLower(text), "0x"), 16, 32)
}

var positionalMarkup = regexp.MustCompile(`\{\{(HL|PARAM|ICON):(0x[0-9a-fA-F]+)\}\}`)

var markup = regexp.MustCompile(`^(?:\{\{(HL|PARAM|ICON|STATE|INIT):(0x[0-9a-fA-F]{4})\}\}|\[spk (0x[0-9a-fA-F]{4})\]|<(?:0x)?([0-9a-fA-F]{4})>)`)

// encode emits nonterminated fields as literal glyphs, including metacharacters.
// Terminated text parses control markup. Source context preserves the source prologue
// and adds its final pause, even after English //. State prefixes keep source order
// outside body wrapping/validation. Plain source authoring retains leading colour;
// markers (default) requires positional markup. Ordered source authoring consumes
// one control tape; payloads remain indivisible through layout, then expand once.
// INIT declares persistent prefix state; HL declares a pair, even before content.
// Encoding does not establish native fit or patch authority. Optional budgets wrap
// before highlight validation and the final source pause. Positional labels replace
// source glyph runs without moving controls; fit belongs to the reviewed encoding.
func encode(text string, prefix []string, glyphs map[rune]uint16, options TextEncodeOptions) ([]byte, error) {
	terminated, source := options.Terminated, options.Source
	plainSource := options.SourceAuthoring == "plain"
	orderedSource := options.SourceAuthoring == "ordered"
	switch options.SourceAuthoring {
	case "", "markers", "plain", "ordered":
	default:
		return nil, fmt.Errorf("source authoring must be markers, plain or ordered")
	}
	if options.SourceAuthoring != "" && (source == nil || !terminated || options.LabelRuns != 0 || options.ExactControls) {
		return nil, fmt.Errorf("source authoring requires terminated narrative context without opaque policy")
	}
	if plainSource && strings.Contains(text, "{{") {
		return nil, fmt.Errorf("plain source authoring cannot contain positional markup")
	}
	nativeWrapping := options.NativeWidth != 0 || options.Advances != nil
	wrapping := options.Columns != 0 || options.Rows != 0 || nativeWrapping
	if len(options.NumericBounds) != 0 && !nativeWrapping {
		return nil, fmt.Errorf("encoding numeric bounds require native wrapping")
	}
	if nativeWrapping && (!terminated || options.NativeWidth < 1 || options.Advances == nil || options.Columns != 0 || options.Rows < 1 || options.ExactControls) {
		return nil, fmt.Errorf("native wrapping requires terminated text, advances, positive width/rows and no character or opaque policy")
	}
	if options.LabelRuns != 0 {
		if options.LabelRuns < 1 || options.LabelRuns > 4096 || !terminated || source == nil || !source.PositionalLabels || source.Readiness != "ready_as_is" || len(prefix) != 0 || wrapping || len(source.Tokens) == 0 || source.Tokens[len(source.Tokens)-1].Kind != "end" {
			return nil, fmt.Errorf("positional labels require a decoded template, positive run count and no prefix or wrapping")
		}
		labels := strings.Split(strings.ReplaceAll(text, ": ", " / "), " / ")
		if len(labels) != options.LabelRuns {
			return nil, fmt.Errorf("canonical label count differs from reviewed source runs")
		}
		var out []byte
		run, inRun := 0, false
		for _, token := range source.Tokens {
			if len(token.Payload) != 0 {
				return nil, fmt.Errorf("positional labels cannot contain inline argument payloads")
			}
			if token.Kind == "glyph" {
				if !inRun {
					if run == len(labels) || labels[run] == "" {
						return nil, fmt.Errorf("source label count differs or canonical label is empty")
					}
					if strings.ContainsAny(labels[run], "/:") {
						return nil, fmt.Errorf("ambiguous canonical label delimiter")
					}
					label, err := encode(labels[run], nil, glyphs, TextEncodeOptions{})
					if err != nil {
						return nil, err
					}
					out = append(out, label...)
					run++
				}
				inRun = true
				continue
			}
			inRun = false
			out = binary.LittleEndian.AppendUint16(out, token.Word)
		}
		if run != options.LabelRuns {
			return nil, fmt.Errorf("source label count differs from reviewed count")
		}
		if _, err := controls(out, TextScanOptions{Terminated: true, PositionalLabels: true}); err != nil {
			return nil, err
		}
		return out, nil
	}
	if source != nil && source.PositionalLabels {
		return nil, fmt.Errorf("positional source requires a reviewed label count")
	}
	if wrapping && !nativeWrapping && (source == nil || options.Columns < 1 || options.Rows < 1) {
		return nil, fmt.Errorf("character budgets require source context and positive columns/rows")
	}
	// Python str.strip includes U+001C–U+001F beyond Go's Unicode whitespace.
	const sourceWhitespace = "\t\n\v\f\r\x1c\x1d\x1e\x1f \u0085\u00a0\u1680" +
		"\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a" +
		"\u2028\u2029\u202f\u205f\u3000"
	if !terminated && len(prefix) != 0 {
		return nil, fmt.Errorf("fixed fields cannot have a stream prefix")
	}
	var words []uint16
	var statePrefix []uint16
	var sourceBytes []byte
	type sourceAtom struct {
		TextToken
		id             uint16
		boundary       uint16 // Body speakers retain their declared LINE/PAGE context through layout.
		prefix, paired bool
	}
	var atoms []sourceAtom
	var atomWidths map[uint16]int
	var atomIndex map[uint16]int
	var forwardGlyphs map[uint16]string
	atomCursor, lastFixed := 0, -1
	contentSeen := false
	trailingPause := false
	if source != nil {
		if !terminated || len(prefix) != 0 || source.Readiness == "blocked_pinned_reader" || (!orderedSource && source.Readiness != "ready_as_is" && !(plainSource && source.Readiness == "no_markup_yet")) || source.ContentStart < 0 || source.ContentStart >= len(source.Tokens) || source.Tokens[len(source.Tokens)-1].Kind != "end" {
			return nil, fmt.Errorf("source context requires a ready terminated stream without an independent prefix")
		}
		if orderedSource && (len(text) > maxStreamBytes*4 || len(source.Tokens) > maxStreamBytes/2) {
			return nil, fmt.Errorf("ordered source authoring exceeds bounded input")
		}
		pages := strings.Split(text, "//")
		for i, page := range pages {
			lines := strings.Split(page, "|")
			for j := range lines {
				lines[j] = strings.Trim(lines[j], sourceWhitespace)
			}
			pages[i] = strings.Join(lines, "|")
		}
		text = strings.Join(pages, "//")
		var speaker uint16
		if m := markup.FindStringSubmatch(text); m != nil && m[3] != "" {
			word, _ := number(m[3])
			if word < 0x3800 || word > 0x3fff {
				return nil, fmt.Errorf("unsupported source-context speaker")
			}
			speaker = uint16(word)
			text = strings.Trim(text[len(m[0]):], sourceWhitespace)
		}
		if orderedSource {
			if nativeWrapping {
				return nil, fmt.Errorf("ordered source atoms do not establish native wrapping widths")
			}
			forwardGlyphs = make(map[uint16]string, len(glyphs)+len(source.glyphText))
			occupied := make(map[uint16]bool, len(glyphs)+len(source.Tokens))
			for glyph, word := range glyphs {
				occupied[word] = true
				forwardGlyphs[word] = string(glyph)
			}
			for word, glyph := range source.glyphText {
				forwardGlyphs[word] = glyph
			}
			origin := source.Tokens[0].Offset
			if origin < 0 || origin%2 != 0 {
				return nil, fmt.Errorf("ordered source needs aligned token coordinates")
			}
			for _, token := range source.Tokens {
				if token.Offset < origin || token.Offset-origin != len(sourceBytes) || len(token.Payload) != 0 && (token.Kind != "param8" || len(token.Payload) != 8) || token.Kind == "param8" && len(token.Payload) != 8 || len(sourceBytes)+2+len(token.Payload) > maxStreamBytes {
					return nil, fmt.Errorf("inconsistent or oversized ordered source token")
				}
				sourceBytes = binary.LittleEndian.AppendUint16(sourceBytes, token.Word)
				sourceBytes = append(sourceBytes, token.Payload...)
				occupied[token.Word] = true
			}
			decoded, err := controls(sourceBytes, TextScanOptions{Decode: true, Glyphs: forwardGlyphs})
			if err != nil || decoded.ContentStart != source.ContentStart || len(decoded.Tokens) != len(source.Tokens) || decoded.Tokens[len(decoded.Tokens)-1].Offset+2 != len(sourceBytes) {
				return nil, fmt.Errorf("ordered source grammar or physical extent differs: %v", err)
			}
			for i, token := range decoded.Tokens {
				expected := source.Tokens[i]
				expected.Offset -= origin
				if !reflect.DeepEqual(token, expected) {
					return nil, fmt.Errorf("ordered source token role differs at %d", i)
				}
			}
			atomWidths, atomIndex = make(map[uint16]int), make(map[uint16]int)
			nextID, seenSpeaker := uint16(0x0801), false
			for i, token := range source.Tokens {
				weight := 0
				hl := token.Kind == "hl" || token.Kind == "pen0" && token.Word >= 0xe800 && token.Word <= 0xefff
				switch token.Kind {
				case "glyph", "space", "line", "page", "end":
					continue
				case "hdr", "speaker":
				case "hl", "icon", "param8", "setup", "pen0":
				default:
					return nil, fmt.Errorf("unsupported ordered source token %s", token.Kind)
				}
				if (token.Kind == "setup" || token.Kind == "pen0" && !hl) && wrapping {
					return nil, fmt.Errorf("ordered setup/pen requires explicitly authored breaks without automatic wrapping")
				}
				if token.Kind == "icon" || token.Kind == "param8" {
					weight = 1
				}
				inPrefix := i < source.ContentStart
				var boundary uint16
				if !inPrefix && token.Kind == "speaker" {
					if i == 0 || source.Tokens[i-1].Kind != "line" && source.Tokens[i-1].Kind != "page" {
						return nil, fmt.Errorf("ordered source body speaker needs a LINE or PAGE anchor")
					}
					boundary = source.Tokens[i-1].Word
				}
				if inPrefix && token.Kind != "icon" && token.Kind != "param8" && !hl {
					lastFixed = len(atoms)
				}
				if inPrefix && token.Kind == "speaker" {
					if seenSpeaker {
						return nil, fmt.Errorf("duplicate ordered source prefix speaker")
					}
					seenSpeaker = true
					if speaker != 0 {
						token.Word = speaker
					}
				}
				for nextID < 0x2800 && (nextID == 0x1000 || occupied[nextID]) {
					nextID++
				}
				if nextID == 0x2800 {
					return nil, fmt.Errorf("ordered source occurrence IDs exhausted")
				}
				atomWidths[nextID], atomIndex[nextID] = weight, len(atoms)
				atoms = append(atoms, sourceAtom{TextToken: token, id: nextID, prefix: inPrefix, boundary: boundary})
				nextID++
			}
			if speaker != 0 && !seenSpeaker {
				return nil, fmt.Errorf("ordered authoring cannot create a prefix speaker")
			}
		} else {
			seenSpeaker, hasState, mixedPrefix := false, false, false
			for i, token := range source.Tokens {
				if plainSource && (len(token.Payload) != 0 || token.Kind == "icon" || token.Kind == "hl" && i >= source.ContentStart) {
					return nil, fmt.Errorf("plain source authoring requires colour only in a payload-free prefix")
				}
				switch token.Kind {
				case "hdr", "speaker", "glyph", "space", "line", "page", "end", "hl", "icon":
				case "setup", "pen0":
					if i >= source.ContentStart || len(token.Payload) != 0 || token.Word >= 0xe800 && token.Word <= 0xefff && (!plainSource || nativeWrapping) {
						return nil, fmt.Errorf("unsupported source-context state outside a payload-free prefix")
					}
					hasState = true
				default:
					// shortcut: opaque arguments need proven payload semantics; prefix copying must never drop them.
					return nil, fmt.Errorf("unsupported source-context token %s", token.Kind)
				}

				positional := token.Kind == "icon" || token.Kind == "hl" && !plainSource
				if i < source.ContentStart && positional {
					mixedPrefix = true
				}
				if i >= source.ContentStart || positional {
					continue
				}
				word := token.Word
				if token.Kind == "speaker" {
					seenSpeaker = true
					if speaker != 0 {
						word = speaker
					}
				}
				words = append(words, word)
			}
			if speaker != 0 && !seenSpeaker {
				words = append(words, speaker)
			}

			if hasState || plainSource {
				if mixedPrefix {
					return nil, fmt.Errorf("state prefix with colour or icons requires a separate source policy")
				}
				statePrefix = slices.Clone(words)
			}
		}
		trailingPause = len(source.Tokens) > 1 && source.Tokens[len(source.Tokens)-2].Kind == "page"
	}
	if len(prefix) > 0 {
		if len(prefix) != 1 || prefix[0] != "0x2800" {
			return nil, fmt.Errorf("unsupported stream prefix")
		}
		words = append(words, 0x2800)
	}
	for {
		// Structural anchors flush only until the next unconsumed explicit atom.
		for orderedSource && atomCursor < len(atoms) && atoms[atomCursor].prefix && (atoms[atomCursor].Kind == "hdr" || atoms[atomCursor].Kind == "speaker") {
			words = append(words, atoms[atomCursor].id)
			atomCursor++
		}
		if len(text) == 0 {
			break
		}
		if terminated {
			if strings.HasPrefix(text, "//") {
				if orderedSource && atomCursor <= lastFixed {
					return nil, fmt.Errorf("content precedes a pending fixed source prefix")
				}
				contentSeen = true
				words = append(words, 0x1000)
				text = text[2:]
				continue
			}
			if m := markup.FindStringSubmatch(text); m != nil {
				code := m[2]
				if m[3] != "" {
					code = m[3]
				}
				if m[4] != "" {
					code = m[4]
				}
				word, _ := number(code)
				if orderedSource {
					if atomCursor == len(atoms) || m[4] != "" || uint16(word) != atoms[atomCursor].Word {
						return nil, fmt.Errorf("ordered marker differs from the next source occurrence")
					}
					token := atoms[atomCursor]
					hl := token.Kind == "hl" || token.Kind == "pen0" && token.Word >= 0xe800 && token.Word <= 0xefff
					valid := false
					switch m[1] {
					case "HL":
						valid = hl
						atoms[atomCursor].paired = true
					case "INIT":
						valid = hl && atoms[atomCursor].prefix && !contentSeen
					case "STATE":
						valid = (token.Kind == "setup" || token.Kind == "pen0" && !hl) && (!atoms[atomCursor].prefix || !contentSeen)
					case "PARAM", "ICON":
						valid = token.Kind == "icon" || token.Kind == "param8"
					case "":
						valid = m[3] != "" && token.Kind == "speaker" && !atoms[atomCursor].prefix && len(words) != 0 && words[len(words)-1] == atoms[atomCursor].boundary
					}
					if !valid {
						return nil, fmt.Errorf("ordered marker has an invalid source role or placement")
					}
					words = append(words, atoms[atomCursor].id)
					atomCursor++
					text = text[len(m[0]):]
					if m[3] != "" {
						text = strings.TrimLeft(text, sourceWhitespace)
					}
					continue
				}
				if m[1] == "STATE" || m[1] == "INIT" {
					return nil, fmt.Errorf("STATE and INIT require ordered source authoring")
				}
				if m[1] == "HL" && (word < 0xb001 || word > 0xb009) {
					return nil, fmt.Errorf("unsupported colour code %s", code)
				}
				if m[1] == "PARAM" || m[1] == "ICON" {
					tokenBytes := binary.LittleEndian.AppendUint16(nil, uint16(word))
					tokenBytes = binary.LittleEndian.AppendUint16(tokenBytes, 0xf800)
					token, err := controls(tokenBytes, TextScanOptions{Decode: true, Glyphs: map[uint16]string{}})
					if err != nil || token.Tokens[0].Kind != "icon" {
						return nil, fmt.Errorf("unsupported argument code %s", code)
					}
				}
				if source != nil && (m[4] != "" || m[3] != "" && (len(words) == 0 || words[len(words)-1] != 0x1000)) {
					return nil, fmt.Errorf("source context requires positional markers and page-leading speakers")
				}
				if m[3] != "" && (word < 0x3800 || word > 0x3fff) {
					return nil, fmt.Errorf("unsupported speaker code %s", code)
				}
				if word < 0x0800 {
					// shortcut: raw glyphs use canonical rune indices; preserve forward membership when a family needs aliases.
					known := word == 0
					for _, glyph := range glyphs {
						known = known || uint64(glyph) == word
					}
					if !known {
						return nil, fmt.Errorf("unknown raw glyph %s", code)
					}
				}
				words = append(words, uint16(word))
				text = text[len(m[0]):]
				if source != nil && m[3] != "" {
					text = strings.TrimLeft(text, sourceWhitespace)
				}
				continue
			}
			if strings.HasPrefix(text, "<") || strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
				return nil, fmt.Errorf("unsupported markup: %q", text)
			}
		}
		r, n := utf8.DecodeRuneInString(text)
		word, ok := glyphs[r]
		if r == '|' && terminated {
			word, ok = 0x0800, true
		} else if r == ' ' {
			word, ok = 0, true
		}
		if !ok || (r == utf8.RuneError && n == 1) {
			return nil, fmt.Errorf("missing glyph: %q", r)
		}
		if orderedSource && atomCursor <= lastFixed {
			return nil, fmt.Errorf("content precedes a pending fixed source prefix")
		}
		contentSeen = true
		words = append(words, word)
		text = text[n:]
	}
	if orderedSource && atomCursor != len(atoms) {
		return nil, fmt.Errorf("ordered authoring omitted source control occurrences")
	}
	if wrapping {
		forward := make(map[uint16]rune, len(glyphs))
		for glyph, word := range glyphs {
			if old, exists := forward[word]; !exists || glyph < old {
				forward[word] = glyph
			}
		}
		var err error
		width := options.Columns
		if nativeWrapping {
			width = options.NativeWidth
		}
		words, err = wrapPages(words[len(statePrefix):], forward, width, options.Rows, options.Advances, options.NumericBounds, atomWidths)
		if err != nil {
			return nil, err
		}
		if len(statePrefix) != 0 {
			words = append(statePrefix, words...)
		}
	}
	if source != nil || nativeWrapping {
		openHL := false
		for _, word := range words[len(statePrefix):] {
			paired := word >= 0xb001 && word <= 0xb009
			if orderedSource {
				at, exists := atomIndex[word]
				paired = exists && atoms[at].paired
			}
			if paired {
				openHL = !openHL
			} else if word == 0x1000 && openHL {
				return nil, fmt.Errorf("source-context highlight crosses a page")
			}
		}
		if openHL {
			return nil, fmt.Errorf("unpaired source-context highlight")
		}
	}
	if trailingPause {
		// The reference appends a source pause even when English already ends with PAGE.
		words = append(words, 0x1000)
	}
	if terminated {
		words = append(words, 0xf800)
	}
	outputBytes := len(words) * 2
	if orderedSource {
		for _, token := range atoms {
			outputBytes += len(token.Payload)
		}
		if outputBytes > maxStreamBytes {
			return nil, fmt.Errorf("ordered output exceeds bounded stream size")
		}
	}
	out := make([]byte, 0, outputBytes)
	emitted := 0
	for i, word := range words {
		if at, exists := atomIndex[word]; exists {
			if at != emitted {
				return nil, fmt.Errorf("layout changed source occurrence identity or order")
			}
			if boundary := atoms[at].boundary; boundary != 0 && (i == 0 || words[i-1] != boundary) {
				return nil, fmt.Errorf("layout changed a source speaker boundary")
			}
			out = binary.LittleEndian.AppendUint16(out, atoms[at].Word)
			out = append(out, atoms[at].Payload...)
			emitted++
		} else {
			out = binary.LittleEndian.AppendUint16(out, word)
		}
	}
	if orderedSource {
		if emitted != len(atoms) {
			return nil, fmt.Errorf("layout omitted source control occurrences")
		}
		decoded, err := controls(out, TextScanOptions{Decode: true, Glyphs: forwardGlyphs})
		if err != nil || decoded.Tokens[len(decoded.Tokens)-1].Offset+2 != len(out) {
			return nil, fmt.Errorf("ordered output grammar or physical extent differs: %v", err)
		}
		at, same := 0, len(decoded.Tokens) == len(source.Tokens)
		for i, token := range decoded.Tokens {
			switch token.Kind {
			case "glyph", "space", "line", "page", "end":
			default:
				if at == len(atoms) || token.Kind != atoms[at].Kind || token.Word != atoms[at].Word || !bytes.Equal(token.Payload, atoms[at].Payload) {
					return nil, fmt.Errorf("ordered output changed its declared source control tape")
				}
				at++
			}
			if same {
				original := source.Tokens[i]
				same = token.Kind == original.Kind && bytes.Equal(token.Payload, original.Payload)
				if token.Kind == "glyph" && same {
					same = forwardGlyphs[token.Word] != "" && forwardGlyphs[token.Word] == source.glyphText[original.Word]
				} else {
					same = same && token.Word == original.Word
				}
			}
		}
		if at != len(atoms) {
			return nil, fmt.Errorf("ordered output lost a source control")
		}
		if same {
			return sourceBytes, nil
		}
		return out, nil
	}

	if len(statePrefix) != 0 {
		// Source state can persist across pages; only authored body highlights form pairs.
		prefixBytes := append(slices.Clone(out[:len(statePrefix)*2]), 0, 0xf8)
		prefix, err := controls(prefixBytes, TextScanOptions{Decode: true, Glyphs: map[uint16]string{}})
		if err != nil || len(statePrefix) > 4096 || prefix.ContentStart != len(prefix.Tokens)-1 || prefix.Tokens[len(prefix.Tokens)-1].Offset+2 != len(prefixBytes) {
			return nil, fmt.Errorf("invalid bounded source state prefix: %v", err)
		}
		header, speaker := false, false
		for _, token := range prefix.Tokens[:len(prefix.Tokens)-1] {
			switch token.Kind {
			case "hdr":
				if header {
					return nil, fmt.Errorf("duplicate source prefix header")
				}
				header = true
			case "speaker":
				if speaker {
					return nil, fmt.Errorf("duplicate source prefix speaker")
				}
				speaker = true
			case "hl":
				if !plainSource {
					return nil, fmt.Errorf("source prefix colour requires plain authoring")
				}
			case "setup":
			case "pen0":
				if token.Word >= 0xe800 && token.Word <= 0xefff && (!plainSource || nativeWrapping) {
					return nil, fmt.Errorf("source prefix scale needs a separate policy")
				}
			default:
				return nil, fmt.Errorf("unsupported source prefix token %s", token.Kind)
			}
		}
	}
	if _, err := controls(out[len(statePrefix)*2:], TextScanOptions{Terminated: terminated, ExactControls: options.ExactControls}); err != nil {
		return nil, err
	}
	return out, nil
}

// controls decodes source grammar or validates patch bytes using distinct allowlists.
// Decode needs a forward glyph map and stops at the first END. Validation checks the
// full extent; Advances refuses unresolved substitution and position widths.
// PositionalLabels uses the reviewed UI word walker, whose arguments are external;
// it preserves controls but does not measure a screen as a flowing narrative line.
// ExactControls preserves each opaque control's word and offset, without claiming
// to interpret it; callers must also pin the complete encoded result. Padded slots
// retain the default control allowlist and validate the zero-filled tail. ReadPin
// verifies exact one-word roles through local surrogates; it restores original
// tokens before summaries and leaves source authoring/native eligibility blocked.
func controls(data []byte, options TextScanOptions) (TextShape, error) {
	var rawRoles map[int]TextToken
	if pin := options.ReadPin; pin != nil {
		if !options.Decode || options.Glyphs == nil {
			return TextShape{}, fmt.Errorf("pinned raw reading requires decoding with a glyphmap")
		}
		if options.FixedWords != 0 || options.PositionalLabels || options.RequireHDR || options.English != nil || options.Terminated || options.Advances != nil || options.ExactControls || options.Padded || len(options.NumericBounds) != 0 {
			return TextShape{}, fmt.Errorf("pinned raw reading requires decoding without authoring, layout or other grammar policies")
		}
		if pin.Words < 1 || pin.Words > 4096 || len(data) != pin.Words*2 {
			return TextShape{}, fmt.Errorf("pinned raw reading requires an exact word count within1..4096")
		}
		if pin.EndOffset == nil || *pin.EndOffset != len(data)-2 {
			return TextShape{}, fmt.Errorf("pinned raw reading requires the explicit final END byte offset")
		}
		if pin.Roles == nil || len(pin.Roles) > pin.Words {
			return TextShape{}, fmt.Errorf("pinned raw reading requires a bounded explicit role list")
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) != pin.SHA256 {
			return TextShape{}, fmt.Errorf("pinned raw span identity differs")
		}
		for at := 0; at < len(data); at += 2 {
			end := binary.LittleEndian.Uint16(data[at:]) == 0xf800
			if end != (at == *pin.EndOffset) {
				return TextShape{}, fmt.Errorf("pinned raw first END differs from declared final word")
			}
		}
		rawRoles = make(map[int]TextToken)
		for _, role := range pin.Roles {
			switch role.Kind {
			case "rawarg", "rawcontrol":
			default:
				return TextShape{}, fmt.Errorf("pinned word role must be rawarg or rawcontrol")
			}
			if role.Payload != nil {
				return TextShape{}, fmt.Errorf("pinned one-word roles cannot contain payloads")
			}
			if role.Offset < 0 || role.Offset%2 != 0 || role.Offset >= *pin.EndOffset {
				return TextShape{}, fmt.Errorf("pinned role needs an even byte offset before END")
			}
			if _, duplicate := rawRoles[role.Offset]; duplicate {
				return TextShape{}, fmt.Errorf("pinned raw roles overlap at byte %#x", role.Offset)
			}
			if binary.LittleEndian.Uint16(data[role.Offset:]) != role.Word {
				return TextShape{}, fmt.Errorf("pinned raw word differs at byte %#x", role.Offset)
			}
			rawRoles[role.Offset] = role
		}
		// A local one-word surrogate reuses the decoder; caller bytes stay intact.
		data = slices.Clone(data)
		for at := range rawRoles {
			binary.LittleEndian.PutUint16(data[at:], 0x4801)
		}
	}
	fixed := options.FixedWords != 0
	if fixed && (!options.Decode || options.FixedWords < 1 || options.FixedWords > 4096 || len(data) != options.FixedWords*2 || options.PositionalLabels || options.RequireHDR || options.English != nil || options.ExactControls || options.Padded || len(options.NumericBounds) != 0) {
		return TextShape{}, fmt.Errorf("fixed decoding requires an exact bounded glyph field without narrative policies")
	}
	if options.Decode && (options.Glyphs == nil || options.Terminated || options.Advances != nil) || !options.Decode && (options.Glyphs != nil || options.RequireHDR || options.English != nil) {
		return TextShape{}, fmt.Errorf("incompatible text scan options")
	}
	if options.PositionalLabels && (options.Advances != nil || options.RequireHDR || options.English != nil || len(options.NumericBounds) != 0 || !options.Decode && !options.Terminated) {
		return TextShape{}, fmt.Errorf("positional labels require decoding or complete validation without narrative layout options")
	}
	if options.ExactControls && (options.Decode || !options.Terminated || options.Advances != nil || options.PositionalLabels || len(options.NumericBounds) != 0) {
		return TextShape{}, fmt.Errorf("exact controls require complete stream validation without layout or decoding")
	}
	if options.Padded && !options.ExactControls {
		return TextShape{}, fmt.Errorf("padded slots require exact control tokens without layout or decoding")
	}
	if len(options.NumericBounds) != 0 && (options.Decode || !options.Terminated || options.Advances == nil) {
		return TextShape{}, fmt.Errorf("numeric bounds require terminated native layout validation")
	}
	terminated, advances := options.Terminated, options.Advances
	if len(data) == 0 && !options.Decode && !terminated && advances == nil {
		return TextShape{}, nil
	}
	if len(data) == 0 || !options.Decode && len(data)%2 != 0 {
		return TextShape{}, fmt.Errorf("stream must contain whole words")
	}
	var result TextShape
	result.PositionalLabels = options.PositionalLabels
	leading, seenHDR, seenSpeaker := true, false, false
	leadingCount, bodyCount := 0, 0
	if options.Decode {
		result.ContentStart = -1
		if options.PositionalLabels || fixed {
			result.ContentStart, leading = 0, false
		}
	}
	width, lines := 0, 1
	if advances != nil {
		result.LineWidths = [][]int{{0}}
		result.Lines = 1
	}
	numericAt := 0
	for i := 0; i < len(data); i += 2 {
		if i+2 > len(data) {
			return TextShape{}, fmt.Errorf("truncated text word")
		}
		w := binary.LittleEndian.Uint16(data[i:])
		if fixed && (w >= 0x0800 || w != 0 && options.Glyphs[w] == "") {
			return TextShape{}, fmt.Errorf("unsupported fixed glyph word %#x at %#x", w, i)
		}
		kind := ""
		switch {
		case w == 0:
			kind = "space"
		case w == 0x0800:
			kind = "line"
		case w == 0x1000:
			kind = "page"
		case w == 0x2800:
			kind = "hdr"
		case w == 0xf800:
			kind = "end"
		case w >= 0x3800 && w <= 0x3fff:
			kind = "speaker"
		case w >= 0x4000 && w <= 0x47ff || w >= 0xa800 && w <= 0xafff:
			kind = "setup"
		case w == 0x4800 || w == 0xb000 || w == 0xd800:
			kind = "param8"
		case w >= 0xb001 && w <= 0xb7ff:
			kind = "hl"
		case w >= 0x6800 && w <= 0x97ff || w >= 0xa000 && w <= 0xa7ff:
			kind = "icon"
		case w >= 0x4801 && w <= 0x4fff || w >= 0xb800 && w <= 0xd7ff || w >= 0xd801 && w <= 0xdfff || w >= 0xe001 && w <= 0xefff:
			kind = "pen0"
		}
		if options.PositionalLabels {
			switch {
			case w == 0xb000:
				kind = "hl"
			case w == 0xd800 || w == 0xe000:
				kind = "pen0"
			case !(w < 0x0800 || w == 0xa000 || w >= 0xb001 && w <= 0xb009 || w >= 0xb800 && w <= 0xefff || w == 0xf800):
				return TextShape{}, fmt.Errorf("unsupported positional label word %#x", w)
			}
			if !options.Decode {
				if w >= 0x0800 {
					result.Words = append(result.Words, w)
				}
				if kind == "end" && i+2 != len(data) {
					return TextShape{}, fmt.Errorf("data after positional label END")
				}
				continue
			}
		}
		if options.Decode {
			inLeading := leading && leadingCount < 4096 && (kind == "hdr" && !seenHDR || kind == "speaker" && !seenSpeaker || kind == "setup" || kind == "hl" || kind == "pen0")
			if inLeading {
				leadingCount++
				seenHDR = seenHDR || kind == "hdr"
				seenSpeaker = seenSpeaker || kind == "speaker"
			} else {
				if leading && options.RequireHDR && !seenHDR {
					return TextShape{}, fmt.Errorf("missing HDR in leading control run")
				}
				leading = false
				if bodyCount == 4096 {
					return TextShape{}, fmt.Errorf("no END within 4096 body tokens")
				}
				bodyCount++
				if kind == "hdr" {
					kind = ""
				}
			}
			if kind == "" {
				if options.Glyphs[w] == "" {
					return TextShape{}, fmt.Errorf("unknown text word %#x at %#x", w, i)
				}
				kind = "glyph"
			}
			if kind == "glyph" {
				if result.glyphText == nil {
					result.glyphText = make(map[uint16]string)
				}
				result.glyphText[w] = options.Glyphs[w]
			}
			step := 2
			var payload []byte
			if kind == "param8" {
				step = 10
				if i+step > len(data) {
					return TextShape{}, fmt.Errorf("truncated param8 payload")
				}
				payload = append([]byte(nil), data[i+2:i+step]...)
			}
			if result.ContentStart < 0 && (kind == "glyph" || kind == "page" || kind == "line" || kind == "space" || kind == "end") {
				result.ContentStart = len(result.Tokens)
			}
			result.Tokens = append(result.Tokens, TextToken{Kind: kind, Word: w, Offset: i, Payload: payload})
			if kind == "page" {
				if i+4 > len(data) {
					return TextShape{}, fmt.Errorf("truncated word after PAGE")
				}
				speaker := binary.LittleEndian.Uint16(data[i+2:])
				if speaker >= 0x3800 && speaker <= 0x3fff {
					result.Tokens = append(result.Tokens, TextToken{Kind: "speaker", Word: speaker, Offset: i + 2})
					step = 4
				}
			}
			if kind == "end" {
				break
			}
			i += step - 2
			continue
		}
		if advances != nil {
			switch {
			case w < 0x0800 || w == 0x7000 && len(options.NumericBounds) != 0:
				advance, ok := advances[w]
				if w == 0x7000 {
					if numericAt == len(options.NumericBounds) {
						return TextShape{}, fmt.Errorf("missing numeric argument bound")
					}
					bound := options.NumericBounds[numericAt]
					numericAt++
					if bound == nil {
						return TextShape{}, fmt.Errorf("numeric argument bound must be an object")
					}
					if bound.Min > bound.Max || bound.Min < -999999999 || bound.Max > 999999999 {
						return TextShape{}, fmt.Errorf("numeric argument exceeds the nine-digit formatter domain")
					}
					// Its divisor starts at 10^8; larger quotients index beyond decimal digits.
					digitWidth := 0
					for glyph := uint16(1); glyph <= 10; glyph++ {
						if advances[glyph] <= 0 {
							return TextShape{}, fmt.Errorf("missing decimal font advance for %#x", glyph)
						}
						digitWidth = max(digitWidth, advances[glyph])
					}
					magnitude := max(int64(bound.Max), -int64(bound.Min))
					advance, ok = len(strconv.FormatInt(magnitude, 10))*digitWidth, true
					if bound.Min < 0 {
						if advances[0x14] <= 0 {
							return TextShape{}, fmt.Errorf("missing minus-sign font advance")
						}
						advance += advances[0x14]
					}
				}
				if !ok || advance <= 0 {
					return TextShape{}, fmt.Errorf("missing font advance for %#x", w)
				}
				width += advance
				page := result.LineWidths[len(result.LineWidths)-1]
				page[len(page)-1] = width
				result.Width, result.Lines = max(result.Width, width), max(result.Lines, lines)
			case w == 0x0800:
				page := len(result.LineWidths) - 1
				result.LineWidths[page] = append(result.LineWidths[page], 0)
				width = 0
				lines++
				result.Lines = max(result.Lines, lines)
			case w == 0x1000:
				result.LineWidths = append(result.LineWidths, []int{0})
				result.Pages = true
				width, lines = 0, 1
			case kind == "icon" || w >= 0xd800 && w != 0xf800:
				return TextShape{}, fmt.Errorf("layout needs substitution/position semantics for %#x", w)
			}
		}
		if w < 0x0800 {
			continue
		}
		if !terminated {
			return TextShape{}, fmt.Errorf("control word in fixed field: %#x", w)
		}
		if w == 0xf800 && i != len(data)-2 {
			if !options.Padded || bytes.Count(data[i+2:], []byte{0}) != len(data)-i-2 {
				return TextShape{}, fmt.Errorf("early END or nonzero slot tail")
			}
			data = data[:i+2]
		}
		if w == 0x2800 && i != 0 {
			return TextShape{}, fmt.Errorf("stream header must lead")
		}
		if w >= 0x3800 && w <= 0x3fff && i != 0 {
			previous := binary.LittleEndian.Uint16(data[i-2:])
			if previous != 0x0800 && previous != 0x1000 && !(i == 2 && previous == 0x2800) {
				return TextShape{}, fmt.Errorf("speaker must immediately follow a stream, line or page boundary")
			}
		}
		if options.ExactControls && !options.Padded {
			result.Tokens = append(result.Tokens, TextToken{Word: w, Offset: i})
			continue
		}
		switch w {
		case 0x0800, 0x1000, 0x2800, 0xf800,
			0xd829, 0xd82a, 0xd82b, 0xd82c, 0xd82d, 0xd82f, 0xd830,
			0xd832, 0xd833, 0xd834, 0xd835, 0xd837, 0xd838, 0xd83a, 0xd83b, 0xd87e, 0xe04a:
		default:
			if kind != "speaker" && kind != "icon" && !(w >= 0xb001 && w <= 0xb009) {
				return TextShape{}, fmt.Errorf("unsupported control word %#x", w)
			}
		}
		if options.Padded {
			result.Tokens = append(result.Tokens, TextToken{Word: w, Offset: i})
			continue
		}
		if advances != nil && (w == 0x0800 || w == 0x1000) {
			before, after := i-2, i+2
			for before >= 0 {
				word := binary.LittleEndian.Uint16(data[before:])
				if word != 0 && !(word >= 0xb001 && word <= 0xb009) {
					break
				}
				before -= 2
			}
			for after < len(data) {
				word := binary.LittleEndian.Uint16(data[after:])
				if word != 0 && !(word >= 0xb001 && word <= 0xb009) {
					break
				}
				after += 2
			}
			// Only content-to-content breaks move; neutral colors/spaces cannot hide an empty page or pause.
			if before >= 0 && after < len(data) {
				a, b := binary.LittleEndian.Uint16(data[before:]), binary.LittleEndian.Uint16(data[after:])
				beforeText := a > 0 && a < 0x0800 || a == 0x7000 && len(options.NumericBounds) != 0
				afterText := b > 0 && b < 0x0800 || b == 0x7000 && len(options.NumericBounds) != 0
				if beforeText && afterText {
					continue
				}
			}
			neighbors := [2]string{"edge", "edge"}
			for j, at := range []int{before, after} {
				if at >= 0 && at < len(data) {
					word := binary.LittleEndian.Uint16(data[at:])
					neighbors[j] = "text"
					if word >= 0x0800 {
						neighbors[j] = fmt.Sprintf("%#x", word)
					}
				}
			}
			result.Boundaries = append(result.Boundaries, Boundary{Word: w, Before: neighbors[0], After: neighbors[1]})
		}
		result.Words = append(result.Words, w)
	}
	if options.Decode {
		if pin := options.ReadPin; pin != nil {
			if len(result.Tokens) != pin.Words || result.Tokens[len(result.Tokens)-1].Kind != "end" {
				return TextShape{}, fmt.Errorf("shared decoder disagrees with pinned one-word extent")
			}
			restored := 0
			for i := range result.Tokens {
				token := &result.Tokens[i]
				if token.Offset != i*2 {
					return TextShape{}, fmt.Errorf("shared decoder skipped a pinned word")
				}
				if role, exists := rawRoles[token.Offset]; exists {
					if token.Kind != "pen0" || token.Word != 0x4801 || token.Payload != nil {
						return TextShape{}, fmt.Errorf("shared decoder changed a pinned raw surrogate")
					}
					*token = role
					restored++
				}
			}
			if restored != len(rawRoles) {
				return TextShape{}, fmt.Errorf("shared decoder omitted a pinned role")
			}
			// Surrogate-derived context summaries must never authorize encoding.
			result.Readiness = "blocked_pinned_reader"
			return result, nil
		}
		if fixed {
			result.Readiness = "ready_as_is"
			return result, nil
		}
		if len(result.Tokens) == 0 || result.Tokens[len(result.Tokens)-1].Kind != "end" {
			return TextShape{}, fmt.Errorf("missing END")
		}
		if options.PositionalLabels {
			result.Readiness = "ready_as_is"
			return result, nil
		}
		kinds := make(map[string]bool)
		cluster, openHL, between, onlyTargets, mechanical := false, false, false, true, true
		textSeen, reportOpenHL, reportText, reportOnlyText := false, false, false, true
		for _, token := range result.Tokens[result.ContentStart:] {
			kind := token.Kind
			if kind == "hl" || kind == "icon" || kind == "pen0" || kind == "param8" || kind == "setup" {
				kinds[kind] = true
			}
			if kind == "glyph" || kind == "space" {
				cluster = false
				textSeen = true
				result.TextAfterLast = result.Targets > 0
			} else if kind == "icon" || kind == "pen0" || kind == "param8" {
				if result.Targets == 0 {
					result.TextBeforeFirst = textSeen
				}
				result.TextAfterLast = false
				result.Targets++
				if !cluster {
					result.Clusters++
					cluster = true
				}
			}
			// Report pairs slide after a failed match; readiness keeps its alternating-pair rule.
			if kind == "hl" {
				result.HLCount++
				if reportOpenHL && reportText && reportOnlyText {
					result.HLCleanPairs++
					reportOpenHL = false
				} else {
					reportOpenHL = true
				}
				reportText, reportOnlyText = false, true
			} else if reportOpenHL {
				text := kind == "glyph" || kind == "space"
				reportText = reportText || text
				reportOnlyText = reportOnlyText && text
			}
			if kind == "hl" {
				if openHL && between && !onlyTargets {
					mechanical = false
				}
				openHL = !openHL
				between, onlyTargets = false, true
			} else if openHL {
				between = true
				onlyTargets = onlyTargets && (kind == "icon" || kind == "param8")
			}
		}
		result.TextBetweenClusters = result.Clusters > 1
		for kind := range kinds {
			result.Kinds = append(result.Kinds, kind)
		}
		slices.Sort(result.Kinds)
		if options.English == nil {
			return result, nil
		}
		var sequence []TextToken
		guard, unresolved := "", false
		for i, token := range result.Tokens {
			hl := token.Kind == "hl" || token.Kind == "pen0" && token.Word >= 0xe800 && token.Word <= 0xefff
			if hl || token.Kind == "icon" || token.Kind == "param8" {
				sequence = append(sequence, token)
			}
			unresolved = unresolved || token.Kind == "param8" && (token.Word == 0xb000 || token.Word == 0x4800 || token.Word == 0xd800)
			if i >= result.ContentStart && guard == "" {
				if token.Kind == "pen0" && !hl {
					guard = "blocked_true_pen0_position"
				} else if token.Kind == "setup" {
					guard = "blocked_midstream_setup"
				}
			}
		}
		markers := positionalMarkup.FindAllStringSubmatch(*options.English, -1)
		matches, values := len(markers) == len(sequence), 0
		for i, marker := range markers {
			if marker[1] != "HL" {
				values++
			}
			if i < len(sequence) {
				token := sequence[i]
				hl := token.Kind == "hl" || token.Kind == "pen0" && token.Word >= 0xe800 && token.Word <= 0xefff
				word, err := strconv.ParseUint(marker[2][2:], 16, 64)
				matches = matches && err == nil && word == uint64(token.Word) && (marker[1] == "HL") == hl
			}
		}
		valueTargets := 0
		for _, token := range sequence {
			if token.Kind == "icon" || token.Kind == "param8" {
				valueTargets++
			}
		}
		switch {
		case guard == "" && matches && !strings.Contains(positionalMarkup.ReplaceAllString(*options.English, "\ue000"), "{{"):
			result.Readiness = "ready_as_is"
		case guard != "":
			result.Readiness = guard
		case unresolved:
			result.Readiness = "blocked_param8_semantics_unresolved"
		case len(markers) == 0:
			result.Readiness = "no_markup_yet"
		case len(markers) == len(sequence):
			result.Readiness = "existing_markup_order_or_value_mismatch"
		case values != valueTargets:
			result.Readiness = "marker_count_mismatch"
		case mechanical:
			result.Readiness = "needs_hl_backfill_mechanical"
		default:
			result.Readiness = "needs_hl_backfill_translator_judgment"
		}
		return result, nil
	}
	if terminated && binary.LittleEndian.Uint16(data[len(data)-2:]) != 0xf800 {
		return TextShape{}, fmt.Errorf("missing END")
	}
	if numericAt != len(options.NumericBounds) {
		return TextShape{}, fmt.Errorf("unused numeric argument bound")
	}
	return result, nil
}

// plan builds sorted, non-overlapping edits from canonical wording and pinned recipes
// without writing. Append tables normally allocate in table/ID order; reviewed
// registry landing placement preserves exact target offsets. verifySource checks
// the complete source hash separately.
// pointer_check emits same-byte data/instruction guards for declared sites only;
// instruction guards reuse guarded_words, while the table still forbids apply.
func plan(tables []Recipes, registry Registry, glyphData []byte, source io.ReaderAt) ([]Edit, error) {
	if len(tables) == 0 {
		return nil, fmt.Errorf("no recipe tables")
	}
	if len(tables) == 1 && (tables[0].Operation == "cmb_member_replace" || tables[0].Operation == "iso_file_replace") {
		return planBundle(tables[0], source)
	}
	recipes := tables[0]
	decodeSource := false
	orderedIDs := make([][]string, len(tables))
	var allocationProfile *Recipes
	for tableIndex, table := range tables {
		if table.Sentinel != nil || table.AddressRanges != nil || table.RegistryColumns != nil || table.RegistryInputs != nil {
			return nil, fmt.Errorf("report fields cannot be used in an image transaction")
		}
		if table.WordingField != "" && (table.Operation != "stream_slot" || table.WordingField != "jp") {
			return nil, fmt.Errorf("wording_field requires jp on a slot table")
		}
		if table.BaseRecipe != "" || table.BaseSHA256 != "" {
			return nil, fmt.Errorf("source-table aliases must be resolved before planning")
		}
		if table.BundlePath != "" || table.BundleSHA256 != "" || table.TargetReferenceSHA256 != "" || len(table.Archives) != 0 || len(table.Files) != 0 {
			return nil, fmt.Errorf("bundle fields require one named replacement table")
		}
		if table.OutputSHA256 != recipes.OutputSHA256 || table.OutputSHA256 != "" && table.Operation != "guarded_words" && table.Operation != "stream_slot" {
			return nil, fmt.Errorf("output pins must agree across word/slot tables")
		}
		decodeSource = decodeSource || table.SourceContext
		if table.References != nil {
			return nil, fmt.Errorf("reference discovery cannot be used in an image transaction")
		}
		if table.RegistryUpdates != nil || table.Updated != "" {
			return nil, fmt.Errorf("registry updates cannot be used in an image transaction")
		}
		if table.Operation == "stream_allocate" {
			if allocationProfile != nil {
				return nil, fmt.Errorf("only one disc allocation table per transaction")
			}
			allocationProfile = &table
		}
		switch table.Operation {
		case "same_length_stream", "exact_control_stream", "fixed_field", "pointer_check",
			"stream_append", "stream_grow", "stream_allocate", "guarded_words", "stream_slot":
		default:
			return nil, fmt.Errorf("invalid operation")
		}
		if table.Placement != "" && (table.Operation != "stream_append" || table.Placement != "registry_landing") {
			return nil, fmt.Errorf("invalid stream placement")
		}
		if table.Placement == "registry_landing" && table.Stream != nil && len(table.Stream.AllowedPointers) != 0 {
			return nil, fmt.Errorf("canonical placement derives pointer ranges from pinned registry sites")
		}
		if table.PointerState != "" && (table.Operation != "pointer_check" || table.PointerState != "registry_landing") {
			return nil, fmt.Errorf("invalid pointer check state")
		}
		if table.SourceSize <= 0 {
			return nil, fmt.Errorf("invalid operation, entries or source size")
		}
		if table.SourceContext && (table.Operation != "stream_append" || table.Layout == nil) {
			return nil, fmt.Errorf("source context requires stream append with measured layout")
		}
		if table.Layout != nil && (table.Layout.Columns != 0 || table.Layout.Rows != 0) && (!table.SourceContext || table.Layout.Columns < 1 || table.Layout.Rows < 1) {
			return nil, fmt.Errorf("character budgets require source context and positive columns/rows")
		}
		allocation := table.Operation == "stream_grow" || table.Operation == "stream_allocate"
		if table.Operation == "stream_append" || allocation {
			if table.Stream == nil || source == nil || (table.Operation == "stream_grow" && len(tables) != 1) || table.Evidence == "" {
				return nil, fmt.Errorf("stream operation requires a reviewed profile and source; growth requires one table")
			}
		} else if table.Stream != nil || table.Layout != nil {
			return nil, fmt.Errorf("stream/layout profile on non-append table")
		}
		if allocation != (table.Growth != nil) || (table.Growth != nil && table.Layout != nil) {
			return nil, fmt.Errorf("allocation transition requires growth data without text layout")
		}
		if table.Operation != "guarded_words" && (len(table.Values) != 0 || len(table.WordBlocks) != 0) {
			return nil, fmt.Errorf("word values on a non-word table")
		}
		if table.Operation == "pointer_check" {
			pin, err := hex.DecodeString(table.ScopeSHA256)
			if len(table.Entries) != 0 || table.RegistryPatchRef == "" || table.Evidence == "" || err != nil || len(pin) != sha256.Size {
				return nil, fmt.Errorf("pointer checks require a selector, evidence and scope hash; explicit entries are forbidden")
			}
		} else if (allocation && len(table.Entries) != 0) || (!allocation && len(table.Entries) == 0) || table.RegistryPatchRef != "" || table.ScopeSHA256 != "" && table.Operation != "stream_append" {
			return nil, fmt.Errorf("text tables require entries and forbid pointer selectors")
		}
		pins := []string{table.SourceSHA256, table.GlyphmapSHA256}
		if table.OutputSHA256 != "" {
			pins = append(pins, table.OutputSHA256)
		}
		for _, digest := range pins {
			b, err := hex.DecodeString(digest)
			if err != nil || len(b) != sha256.Size {
				return nil, fmt.Errorf("invalid SHA-256 pin")
			}
		}
		if table.SourceSHA256 != recipes.SourceSHA256 || table.SourceSize != recipes.SourceSize || table.GlyphmapSHA256 != recipes.GlyphmapSHA256 {
			return nil, fmt.Errorf("recipe tables have incompatible source or glyphmap pins")
		}
		if table.Operation != recipes.Operation && (table.Operation == "stream_append" || recipes.Operation == "stream_append") {
			return nil, fmt.Errorf("initialized append composes only with other append tables")
		}
		if table.Operation == "stream_append" && len(tables) > 1 {
			if table.ISOELFOffset != recipes.ISOELFOffset || table.ELFVMADelta != recipes.ELFVMADelta || (table.Layout == nil) != (recipes.Layout == nil) {
				return nil, fmt.Errorf("append tables have incompatible native mapping or layout")
			}
			// Scopes belong to each table; allocation and native rendering must agree.
			a, b := *table.Stream, *recipes.Stream
			a.AllowedPointers, a.AllowedLandings, b.AllowedPointers, b.AllowedLandings = nil, nil, nil, nil
			if !reflect.DeepEqual(a, b) {
				return nil, fmt.Errorf("append tables have incompatible native stream profiles")
			}
			if table.Layout != nil {
				a, b := *table.Layout, *recipes.Layout
				a.Columns, a.Rows, b.Columns, b.Rows = 0, 0, 0, 0
				if !reflect.DeepEqual(a, b) {
					return nil, fmt.Errorf("append tables have incompatible native font profiles")
				}
			}
		}
		var ids []string
		for idText := range table.Entries {
			decodeSource = decodeSource || table.Entries[idText].LabelRuns != 0 || table.Entries[idText].LinePageReflow
			if _, err := number(idText); err != nil {
				return nil, err
			}
			ids = append(ids, idText)
		}
		sort.Slice(ids, func(i, j int) bool {
			a, _ := number(ids[i])
			b, _ := number(ids[j])
			if a == b {
				return ids[i] < ids[j]
			}
			return a < b
		})
		orderedIDs[tableIndex] = ids
	}
	if fmt.Sprintf("%x", sha256.Sum256(glyphData)) != recipes.GlyphmapSHA256 {
		return nil, fmt.Errorf("glyphmap hash mismatch")
	}
	if recipes.Operation == "stream_grow" {
		state, err := inspect(source, nil, &recipes)
		if err != nil {
			return nil, err
		}
		sort.Slice(state.Edits, func(i, j int) bool { return state.Edits[i].Offset < state.Edits[j].Offset })
		return state.Edits, validateEdits(state.Edits, recipes.SourceSize)
	}
	glyphs, forwardGlyphs, err := glyphMaps(glyphData, decodeSource)
	if err != nil {
		return nil, err
	}
	byID := make(map[uint64]RegistryEntry)
	for _, entry := range registry.Entries {
		id, err := number(entry.ID)
		if err != nil {
			return nil, fmt.Errorf("invalid registry ID %q", entry.ID)
		}
		if _, exists := byID[id]; exists {
			return nil, fmt.Errorf("duplicate registry ID %s", entry.ID)
		}
		byID[id] = entry
	}
	var edits []Edit
	var metadataRanges [][2]uint64
	seen := make(map[uint64]bool)
	var cursor int64
	var references map[uint64][]uint64
	for tableIndex, recipes := range tables {
		if recipes.Operation == "stream_allocate" {
			state, err := inspect(source, nil, &recipes)
			if err != nil {
				return nil, err
			}
			edits = append(edits, state.Edits...)
			metadataRanges = state.MetadataRanges
			continue
		}
		terminated := recipes.Operation == "same_length_stream" || recipes.Operation == "exact_control_stream" || recipes.Operation == "stream_slot" || recipes.Operation == "stream_append"
		values := make(map[string]uint64)
		usedValues := make(map[string]bool)
		usedBlocks := make(map[string]bool)
		for name, block := range recipes.WordBlocks {
			if name == "" || block.Authoring != "" || block.Use != "" || block.ExpectedHex != "" || block.SourcePointer != "" || block.MaxNewBytes != 0 || block.ReadBytes != 0 || block.MaxWidth != 0 || block.MaxLines != 0 || len(block.NumericBounds) != 0 || block.EncodedSHA256 != "" || len(block.PrefixWords) != 0 || len(block.Words) == 0 {
				return nil, fmt.Errorf("invalid one-level word block %q", name)
			}
		}
		for name, text := range recipes.Values {
			value, err := number(text)
			if name == "" || err != nil {
				return nil, fmt.Errorf("invalid named word value %q", name)
			}
			values[name] = value
		}
		base, err := number(recipes.ISOELFOffset)
		if err != nil {
			return nil, err
		}
		delta, err := number(recipes.ELFVMADelta)
		if err != nil {
			return nil, err
		}
		if recipes.Operation == "pointer_check" {
			start := len(edits)
			for id, entry := range byID {
				if entry.PatchRef != recipes.RegistryPatchRef {
					continue
				}
				if seen[id] || len(entry.RefSites) == 0 || entry.RefType == "gp_relative" {
					return nil, fmt.Errorf("%s: duplicate ID or invalid canonical pointer scope", entry.ID)
				}
				seen[id] = true
				value := id
				if recipes.PointerState == "registry_landing" {
					value, err = number(entry.LandingVMA)
					if entry.LandingVMA == "" || err != nil || value < sentinelBase || value > 0xffffffff || value%16 != 0 {
						return nil, fmt.Errorf("%s: invalid canonical pointer landing", entry.ID)
					}
				}
				for _, site := range entry.RefSites {
					geometry, err := normalizeReference(entry.RefType, site, delta)
					if err != nil {
						return nil, fmt.Errorf("%s: %w", entry.ID, err)
					}
					for i, vma := range geometry.VMAs {
						word, operation := uint32(value), "pointer_check"
						if entry.RefType == "code_immediate" {
							reg := geometry.Register
							word = (0x3c00|reg)<<16 | uint32((value+0x8000)>>16)&0xffff
							if i == 1 {
								word = (0x2400|reg<<5|reg)<<16 | uint32(value)&0xffff
							}
							operation = "guarded_words"
						}
						old := binary.LittleEndian.AppendUint32(nil, word)
						edits = append(edits, Edit{ID: fmt.Sprintf("0x%x", id), Offset: int64(base + vma - delta), Old: old, New: bytes.Clone(old), Operation: operation})
					}
				}
			}
			selected := edits[start:]
			sort.Slice(selected, func(i, j int) bool { return selected[i].Offset < selected[j].Offset })
			if err := validateEdits(selected, recipes.SourceSize); err != nil {
				return nil, err
			}
			// Pin expected physical words/sites; data-only scope hashes stay unchanged.
			var projection []byte
			for _, edit := range selected {
				projection = append(projection, edit.Old...)
				projection = binary.LittleEndian.AppendUint32(projection, uint32(uint64(edit.Offset)-base+delta))
			}
			if fmt.Sprintf("%x", sha256.Sum256(projection)) != recipes.ScopeSHA256 {
				return nil, fmt.Errorf("canonical pointer scope hash mismatch")
			}
			continue
		}
		ids := orderedIDs[tableIndex]
		var initialized Inspection
		var scopeBytes []byte

		if recipes.Operation == "stream_append" {
			if recipes.Placement == "registry_landing" {
				profile := *recipes.Stream
				for _, idText := range ids {
					id, _ := number(idText)
					entry, exists := byID[id]
					if !exists || entry.RefType != "pointer_array" && entry.RefType != "struct_table_field" || len(entry.RefSites) == 0 {
						return nil, fmt.Errorf("%s: canonical placement requires data-pointer sites", idText)
					}
					for _, site := range entry.RefSites {
						pointer, err := number(site.PointerVMA)
						if err != nil || pointer%4 != 0 || pointer > 0xffffffff-4 {
							return nil, fmt.Errorf("%s: invalid canonical pointer site", idText)
						}
						profile.AllowedPointers = append(profile.AllowedPointers, AddressRange{Start: fmt.Sprintf("0x%x", pointer), End: fmt.Sprintf("0x%x", pointer+4)})
					}
				}
				recipes.Stream = &profile
			}
			initialized, err = inspect(source, nil, &recipes)
			if err != nil {
				return nil, err
			}
			if references == nil {
				cursor = int64(len(bytes.TrimRight(initialized.Blob, "\x00"))+15) &^ 15
				if cursor > initialized.Capacity {
					return nil, fmt.Errorf("existing stream content exceeds translation capacity")
				}
				references = make(map[uint64][]uint64)
				for id := range byID {
					references[id] = nil
				}
				// Reserve every old consumer span before any table allocates a new payload.
				for tableIndex, table := range tables {
					for _, idText := range orderedIDs[tableIndex] {
						row := table.Entries[idText]
						if row.SourcePointer == "" {
							continue
						}
						origin, err := number(row.SourcePointer)
						if err != nil {
							return nil, err
						}
						references[origin] = nil
						if row.ReadBytes > 0 && origin >= sentinelBase {
							start := origin - sentinelBase
							if start > uint64(initialized.Capacity) || uint64(row.ReadBytes) > uint64(initialized.Capacity)-start {
								return nil, fmt.Errorf("%s: source read span outside capacity", idText)
							}
							cursor = max(cursor, (int64(start)+int64(row.ReadBytes)+15)&^15)
						}
					}
				}
				for at := 0; at+4 <= len(initialized.ELF); at += 4 {
					id := uint64(binary.LittleEndian.Uint32(initialized.ELF[at:]))
					if _, exists := references[id]; exists {
						references[id] = append(references[id], delta+uint64(at))
					}
				}
			}
		}

		for _, idText := range ids {
			recipe := recipes.Entries[idText]
			if recipe.Authoring != "" && recipe.Authoring != "markers" && recipe.Authoring != "plain" && recipe.Authoring != "ordered" {
				return nil, fmt.Errorf("%s: unsupported source authoring policy", idText)
			}
			if recipe.Authoring != "" && (!recipes.SourceContext || len(recipe.PrefixWords) != 0 || recipe.LabelRuns != 0) {
				return nil, fmt.Errorf("%s: source authoring requires narrative source context without independent prefix or labels", idText)
			}
			if recipe.Authoring == "ordered" && (recipe.ExpectedHex == "" || recipe.EncodedSHA256 == "" || recipe.MaxNewBytes == 0) {
				return nil, fmt.Errorf("%s: ordered source authoring requires complete preimage, encoding pin and byte bound", idText)
			}
			id, err := number(idText)
			if err != nil || seen[id] {
				return nil, fmt.Errorf("invalid/duplicate recipe ID %q", idText)
			}
			seen[id] = true
			copyBounds := recipe.MaxNewBytes != 0 || recipe.ReadBytes != 0
			exactControls := recipes.Operation == "exact_control_stream" || recipes.Operation == "stream_slot"
			layoutBound := recipe.MaxWidth != 0 || recipe.MaxLines != 0 || recipe.EncodedSHA256 != "" && !exactControls
			if recipe.LinePageReflow && (recipes.Operation != "stream_append" || recipes.Layout == nil || recipe.MaxWidth <= 0 || recipe.MaxLines <= 0 || recipe.MaxNewBytes == 0 || recipe.EncodedSHA256 == "") {
				return nil, fmt.Errorf("%s: line/page reflow requires reviewed append encoding, byte and layout bounds", idText)
			}
			positionalLabels := recipe.LabelRuns != 0
			if positionalLabels {
				switch {
				case recipe.LabelRuns < 1 || recipe.LabelRuns > 4096:
					return nil, fmt.Errorf("%s: invalid positional label count", idText)
				case recipes.Operation != "stream_append" || recipes.SourceContext || recipes.Layout == nil:
					return nil, fmt.Errorf("%s: positional labels require reviewed append layout without narrative context", idText)
				case recipes.Layout.Columns != 0 || recipes.Layout.Rows != 0 || recipe.MaxWidth != 0 || recipe.MaxLines != 0 || len(recipe.NumericBounds) != 0 || len(recipe.PrefixWords) != 0:
					return nil, fmt.Errorf("%s: positional labels cannot use narrative formatting", idText)
				case recipe.ExpectedHex == "" || recipe.EncodedSHA256 == "" || recipe.MaxNewBytes == 0:
					return nil, fmt.Errorf("%s: positional labels require a complete template, encoding pin and byte bound", idText)
				}
			}
			if len(recipe.NumericBounds) != 0 && (recipes.Operation != "stream_append" || recipes.Layout == nil || !layoutBound) {
				return nil, fmt.Errorf("%s: numeric bounds require reviewed native stream layout", idText)
			}
			if recipes.Layout != nil && recipes.Layout.Columns != 0 && !layoutBound {
				return nil, fmt.Errorf("%s: character formatting requires a reviewed encoded SHA-256 and byte limit", idText)
			}
			if (recipe.SourcePointer != "" || copyBounds || layoutBound) && recipes.Operation != "stream_append" {
				return nil, fmt.Errorf("%s: stream source/copy bounds on a non-append recipe", idText)
			}
			if copyBounds && (recipe.MaxNewBytes < 2 || recipe.MaxNewBytes > maxStreamBytes || recipe.MaxNewBytes%2 != 0 || recipe.ReadBytes != 0 && (recipe.MaxNewBytes > recipe.ReadBytes || recipe.ReadBytes > maxStreamBytes || recipe.ReadBytes%2 != 0)) {
				return nil, fmt.Errorf("%s: invalid stream source/copy bounds", idText)
			}
			// Exceptional geometry belongs to the reviewed encoding, not arbitrary future wording.
			encodedPin, pinErr := hex.DecodeString(recipe.EncodedSHA256)
			if layoutBound && (recipes.Layout == nil || recipe.MaxWidth < 0 || recipe.MaxLines < 0 || recipe.MaxLines > maxStreamBytes/2 || recipe.MaxNewBytes == 0 || pinErr != nil || len(encodedPin) != sha256.Size) {
				return nil, fmt.Errorf("%s: reviewed encoding/width requires source layout, byte limit and encoded SHA-256", idText)
			}
			if exactControls && (len(recipe.PrefixWords) != 0 || recipe.ExpectedHex == "" || pinErr != nil || len(encodedPin) != sha256.Size) {
				return nil, fmt.Errorf("%s: exact control stream requires a full preimage and encoded SHA-256 without prefix", idText)
			}
			if recipe.Evidence == "" && recipes.Evidence == "" {
				return nil, fmt.Errorf("%s: missing evidence", idText)
			}
			vma := id
			if vma < delta || vma%2 != 0 {
				return nil, fmt.Errorf("%s: invalid target VMA", idText)
			}
			old, err := hex.DecodeString(recipe.ExpectedHex)
			if err != nil {
				return nil, err
			}
			origin, originBase, original := id, delta, initialized.ELF
			if recipe.SourcePointer != "" {
				origin, err = number(recipe.SourcePointer)
				if err != nil || origin < sentinelBase || origin%16 != 0 || recipe.ExpectedHex == "" || id-delta >= uint64(len(initialized.ELF)) {
					return nil, fmt.Errorf("%s: invalid explicit source pointer/preimage", idText)
				}
				originBase, original = sentinelBase, initialized.Blob
			}
			if recipes.Operation == "stream_append" && recipe.ExpectedHex == "" {
				start := id - delta
				end := min(start+maxStreamBytes, uint64(len(initialized.ELF)))
				for at := start; at+2 <= end; at += 2 {
					if binary.LittleEndian.Uint16(initialized.ELF[at:]) == 0xf800 {
						old = bytes.Clone(initialized.ELF[start : at+2])
						break
					}
				}
				if len(old) == 0 {
					return nil, fmt.Errorf("%s: no bounded source stream END", idText)
				}
				if !recipes.SourceContext && len(recipe.PrefixWords) == 0 && binary.LittleEndian.Uint16(old) == 0x2800 {
					recipe.PrefixWords = []string{"0x2800"}
				}
			}
			if recipes.Operation == "guarded_words" {
				prefix := recipes.WordBlocks[recipe.Use]
				if recipe.Use != "" {
					if len(prefix.Words) == 0 {
						return nil, fmt.Errorf("%s: unknown word block %q", idText, recipe.Use)
					}
					usedBlocks[recipe.Use] = true
				}
				words := append(slices.Clone(prefix.Words), recipe.Words...)
				if vma%4 != 0 || len(recipe.PrefixWords) != 0 || len(words) == 0 || len(words) > len(old)/4 || len(old) != len(words)*4 {
					return nil, fmt.Errorf("%s: invalid guarded word block", idText)
				}
				var next []byte
				for _, word := range words {
					value, err := number(word.Hex)
					if err != nil || strings.TrimSpace(word.Assembly) == "" {
						return nil, fmt.Errorf("%s: invalid or undocumented machine word", idText)
					}
					next = binary.LittleEndian.AppendUint32(next, uint32(value))
				}
				fixed := make(map[uint64]bool)
				for i, fixups := range []map[string]WordFixup{prefix.Fixups, recipe.Fixups} {
					limit := len(next)
					if i == 0 {
						limit = 4 * len(prefix.Words)
					}
					for text, fixup := range fixups {
						at, err := number(text)
						value, exists := values[fixup.Value]
						if err != nil || at%4 != 0 || limit < 4 || at > uint64(limit-4) || fixed[at] || !exists || fixup.Shift > 31 || fixup.Bits == 0 || fixup.Bits > 32 || fixup.LSB > 31 || fixup.Bits > 32-fixup.LSB {
							return nil, fmt.Errorf("%s: invalid word fixup", idText)
						}
						fixed[at], usedValues[fixup.Value] = true, true
						mask := uint32((uint64(1)<<fixup.Bits - 1) << fixup.LSB)
						word := binary.LittleEndian.Uint32(next[at:])
						if word&mask != 0 {
							return nil, fmt.Errorf("%s: fixup field is not zero", idText)
						}
						binary.LittleEndian.PutUint32(next[at:], word|(uint32(value>>fixup.Shift)<<fixup.LSB)&mask)
					}
				}
				edits = append(edits, Edit{ID: idText, Offset: int64(base + vma - delta), Old: old, New: next, Operation: recipes.Operation})
				continue
			}
			if len(recipe.Words) != 0 || len(recipe.Fixups) != 0 || recipe.Use != "" {
				return nil, fmt.Errorf("%s: machine words on a text recipe", idText)
			}
			entry, exists := byID[id]
			text := entry.EN
			if recipes.WordingField == "jp" {
				text = ""
				if !utf8.Valid(entry.JP) || json.Unmarshal(entry.JP, &text) != nil {
					return nil, fmt.Errorf("%s: original wording requires a UTF-8 JSON string", idText)
				}
			}
			if !exists || text == "" {
				return nil, fmt.Errorf("%s: missing entry or selected registry wording", idText)
			}
			var landing uint64
			if recipes.Placement == "registry_landing" {
				landing, err = number(entry.LandingVMA)
				if entry.LandingVMA == "" || err != nil {
					return nil, fmt.Errorf("%s: missing or invalid canonical landing", idText)
				}
			}
			var context *TextShape
			if recipes.SourceContext || positionalLabels {
				scan := TextScanOptions{Decode: true, Glyphs: forwardGlyphs, English: &text}
				if positionalLabels {
					scan.PositionalLabels, scan.English = true, nil
				}
				shape, err := controls(old, scan)
				if err != nil {
					return nil, fmt.Errorf("%s: source context: %w", idText, err)
				}
				if recipe.Authoring == "ordered" && shape.Tokens[len(shape.Tokens)-1].Offset+2 != len(old) {
					return nil, fmt.Errorf("%s: ordered source preimage must end at its physical END", idText)
				}
				context = &shape
			}
			encoding := TextEncodeOptions{Terminated: terminated, ExactControls: exactControls, Source: context, SourceAuthoring: recipe.Authoring, LabelRuns: recipe.LabelRuns}
			if recipes.Layout != nil {
				encoding.Columns, encoding.Rows = recipes.Layout.Columns, recipes.Layout.Rows
			}
			newBytes, err := encode(text, recipe.PrefixWords, glyphs, encoding)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", idText, err)
			}
			if layoutBound || exactControls {
				encodedHash := sha256.Sum256(newBytes)
				if !bytes.Equal(encodedPin, encodedHash[:]) {
					return nil, fmt.Errorf("%s: canonical encoding differs from reviewed layout", idText)
				}
			}
			if recipes.Operation == "stream_append" {
				start, sourceSpan := origin-originBase, max(len(old), recipe.ReadBytes)
				if len(old) > maxStreamBytes || sourceSpan > len(original) || start > uint64(len(original)-sourceSpan) || !bytes.Equal(old, original[start:start+uint64(len(old))]) || entry.RefType != "pointer_array" && entry.RefType != "struct_table_field" && entry.RefType != "code_immediate" || len(entry.RefSites) == 0 || entry.RefType == "struct_table_field" && recipe.ReadBytes == 0 {
					return nil, fmt.Errorf("%s: invalid original stream or canonical references", idText)
				}
				if recipe.MaxNewBytes != 0 && len(newBytes) > recipe.MaxNewBytes {
					return nil, fmt.Errorf("%s: encoded stream exceeds consumer copy bound", idText)
				}
				if recipe.SourcePointer != "" {
					if start > uint64(initialized.Capacity) || uint64(sourceSpan) > uint64(initialized.Capacity)-start || len(references[id]) != 0 {
						return nil, fmt.Errorf("%s: source outside capacity or obsolete ID reference remains", idText)
					}
				}
				measurement := TextScanOptions{Terminated: true, Advances: initialized.Advances, NumericBounds: recipe.NumericBounds}
				if positionalLabels {
					// Screen geometry is bound to the reviewed whole encoding, not narrative line widths.
					measurement = TextScanOptions{Terminated: true, PositionalLabels: true}
				}
				a, err := controls(old, measurement)
				if err != nil {
					return nil, err
				}
				b, err := controls(newBytes, measurement)
				sameControls := slices.Equal(a.Words, b.Words) && slices.Equal(a.Boundaries, b.Boundaries)
				if recipe.LinePageReflow {
					// Only authored page/line breaks may move; every other control keeps its order.
					var sourceControls, targetControls []uint16
					for _, word := range a.Words {
						if word != 0x0800 && word != 0x1000 {
							sourceControls = append(sourceControls, word)
						}
					}
					for _, word := range b.Words {
						if word != 0x0800 && word != 0x1000 {
							targetControls = append(targetControls, word)
						}
					}
					sameControls = slices.Equal(sourceControls, targetControls) && slices.Equal(a.Boundaries, b.Boundaries)
					decoded, err := controls(newBytes, TextScanOptions{Decode: true, Glyphs: forwardGlyphs})
					if err != nil {
						return nil, fmt.Errorf("%s: reflow target decode: %w", idText, err)
					}
					insideHighlight := false
					for _, token := range decoded.Tokens {
						switch {
						case token.Kind == "hl" && token.Word >= 0xb001 && token.Word <= 0xb007:
							insideHighlight = true
						case token.Kind == "hl" && token.Word == 0xb008:
							insideHighlight = false
						case token.Kind == "page" && insideHighlight:
							return nil, fmt.Errorf("%s: PAGE within active highlight needs consumer proof", idText)
						}
					}
				}
				if err != nil || !sameControls {
					return nil, fmt.Errorf("%s: unsupported stream or changed ordered controls", idText)
				}
				width, height := a.Width, a.Lines
				if recipe.MaxWidth != 0 {
					width = recipe.MaxWidth
				}
				if recipe.MaxLines != 0 {
					height = recipe.MaxLines
				}
				if !positionalLabels && recipes.Layout != nil && (b.Width > width || b.Lines > height || b.Pages && !a.Pages && !recipe.LinePageReflow) {
					return nil, fmt.Errorf("%s: reflow exceeds reviewed width/height or introduces unsupported pages", idText)
				}
				var sites []uint64
				var current uint32
				code := entry.RefType == "code_immediate"
				codeWords := make(map[uint64]uint32)
				pairs := make(map[[2]uint64]bool)
				if code {
					scopeBytes = binary.LittleEndian.AppendUint32(scopeBytes, uint32(id))
					scopeBytes = binary.LittleEndian.AppendUint32(scopeBytes, uint32(len(entry.RefSites)))
				}
				for i, site := range entry.RefSites {
					geometry, err := normalizeReference(entry.RefType, site, delta)
					if err != nil {
						return nil, fmt.Errorf("%s: %w", idText, err)
					}
					if code {
						key := [2]uint64{geometry.VMAs[0], geometry.VMAs[1]}
						if pairs[key] {
							return nil, fmt.Errorf("%s: invalid canonical code pair", idText)
						}
						pairs[key] = true
					}
					words := make([]uint32, len(geometry.VMAs))
					for j, vma := range geometry.VMAs {
						allowed := false
						for _, interval := range initialized.PointerRanges {
							allowed = allowed || vma >= interval[0] && vma+4 <= interval[1]
						}
						if !allowed || vma < delta || len(initialized.ELF) < 4 || vma-delta > uint64(len(initialized.ELF))-4 {
							return nil, fmt.Errorf("%s: reference outside reviewed consumer ranges", idText)
						}
						words[j] = binary.LittleEndian.Uint32(initialized.ELF[vma-delta:])
						if code {
							codeWords[vma] = words[j]
						}
					}
					word, err := referenceTarget(geometry, words)
					if err != nil {
						return nil, fmt.Errorf("%s: %w", idText, err)
					}
					if i != 0 && word != current {
						if code {
							return nil, fmt.Errorf("%s: partial or conflicting code reference state", idText)
						}
						return nil, fmt.Errorf("%s: partial or conflicting pointer state", idText)
					}
					current = word
					if code {
						scopeBytes = binary.LittleEndian.AppendUint32(scopeBytes, uint32(geometry.VMAs[0]))
						scopeBytes = binary.LittleEndian.AppendUint32(scopeBytes, uint32(geometry.VMAs[1]))
						scopeBytes = append(scopeBytes, byte(geometry.Register))
					} else {
						sites = append(sites, geometry.VMAs[0])
					}
				}
				slices.Sort(sites)
				if len(slices.Compact(slices.Clone(sites))) != len(sites) {
					return nil, fmt.Errorf("%s: duplicate canonical pointer site", idText)
				}
				if recipes.Placement == "registry_landing" {
					if code || recipes.ScopeSHA256 == "" {
						return nil, fmt.Errorf("%s: canonical landing requires pinned data-pointer scope", idText)
					}
					scopeBytes = binary.LittleEndian.AppendUint32(scopeBytes, uint32(id))
					scopeBytes = binary.LittleEndian.AppendUint32(scopeBytes, uint32(landing))
					scopeBytes = binary.LittleEndian.AppendUint32(scopeBytes, uint32(len(sites)))
					for _, site := range sites {
						scopeBytes = binary.LittleEndian.AppendUint32(scopeBytes, uint32(site))
					}
				}
				target := uint64(current)
				pending := target == origin
				readSpan := max(len(newBytes), recipe.ReadBytes)
				span := readSpan
				bookend := (readSpan+15)&^15 > (len(newBytes)+15)&^15
				if bookend {
					span = (readSpan + 15) &^ 15
					if span-readSpan < 2 {
						span += 16
					}
				}
				if recipes.Placement == "registry_landing" {
					if !pending && target != landing {
						return nil, fmt.Errorf("%s: missing or conflicting canonical landing", idText)
					}
					target = landing
					// A merged allowed range cannot let one stream consume its neighbor's bytes.
					var next uint64
					for _, other := range registry.Entries {
						if other.LandingVMA == "" {
							continue
						}
						vma, err := number(other.LandingVMA)
						if err != nil {
							return nil, fmt.Errorf("%s: invalid canonical neighbor landing", idText)
						}
						if vma == target && other.ID != entry.ID {
							return nil, fmt.Errorf("%s: canonical landing shared with %s", idText, other.ID)
						}
						if vma > target && (next == 0 || vma < next) {
							next = vma
						}
					}
					if next != 0 && uint64(span) > next-target {
						return nil, fmt.Errorf("%s: stream overlaps next canonical landing", idText)
					}
				}
				if pending {
					if !code && !slices.Equal(sites, references[origin]) || code && len(references[origin]) != 0 {
						return nil, fmt.Errorf("%s: incomplete raw pointer coverage", idText)
					}
					if recipes.Placement == "" {
						target = sentinelBase + uint64(cursor)
					}
				} else if len(references[origin]) != 0 {
					return nil, fmt.Errorf("%s: unrecorded original pointer remains", idText)
				}
				allowed := false
				for _, interval := range initialized.LandingRanges {
					allowed = allowed || (target >= interval[0] && target+uint64(span) <= interval[1])
				}
				if !allowed || target < sentinelBase || target%16 != 0 || target-sentinelBase > uint64(initialized.Capacity) || uint64(span) > uint64(initialized.Capacity)-(target-sentinelBase) {
					return nil, fmt.Errorf("%s: target outside reviewed landing/capacity", idText)
				}
				at := target - sentinelBase
				stored := initialized.Blob[at : at+uint64(len(newBytes))]
				if pending {
					if bytes.Count(stored, []byte{0}) != len(stored) {
						return nil, fmt.Errorf("%s: append destination is not zero", idText)
					}
					operation := "stream_payload"
					if positionalLabels {
						operation = "stream_label_payload"
					}
					edits = append(edits, Edit{ID: idText, Offset: initialized.BlobOffset + int64(at), Old: bytes.Clone(stored), New: newBytes, Operation: operation})
					cursor = max(cursor, (int64(at)+int64(span)+15)&^15)
				} else if !bytes.Equal(stored, newBytes) {
					return nil, fmt.Errorf("%s: existing sentinel stream differs from canonical encoding", idText)
				}
				if span > len(newBytes) {
					padding := make([]byte, span-len(newBytes))
					// A terminator outside every consumer read preserves the reservation for later tables.
					if bookend {
						binary.LittleEndian.PutUint16(padding[len(padding)-2:], 0xf800)
					}
					tail := initialized.Blob[at+uint64(len(newBytes)) : at+uint64(span)]
					if pending && bytes.Count(tail, []byte{0}) != len(tail) || !pending && !bytes.Equal(tail, padding) {
						return nil, fmt.Errorf("%s: consumer read padding/reservation differs", idText)
					}
					edits = append(edits, Edit{ID: idText, Offset: initialized.BlobOffset + int64(at) + int64(len(newBytes)), Old: bytes.Clone(tail), New: padding, Operation: "stream_padding"})
				}
				for _, pointer := range sites {
					edits = append(edits, Edit{ID: idText, Offset: int64(base + pointer - delta), Old: binary.LittleEndian.AppendUint32(nil, current), New: binary.LittleEndian.AppendUint32(nil, uint32(target)), Operation: "stream_pointer"})
				}
				for vma, word := range codeWords {
					next := word & 0xffff0000
					if word>>26 == 15 {
						next |= uint32((target+0x8000)>>16) & 0xffff
					} else {
						next |= uint32(target) & 0xffff
					}
					edits = append(edits, Edit{ID: idText, Offset: int64(base + vma - delta), Old: binary.LittleEndian.AppendUint32(nil, word), New: binary.LittleEndian.AppendUint32(nil, next), Operation: "guarded_words"})
				}
				continue
			}

			if (!terminated || recipes.Operation == "stream_slot") && len(newBytes) < len(old) {
				newBytes = append(newBytes, make([]byte, len(old)-len(newBytes))...)
			}
			offset := int64(base + vma - delta)
			edits = append(edits, Edit{ID: idText, Offset: offset, Old: old, New: newBytes, Operation: recipes.Operation})
		}
		if recipes.Operation == "stream_append" && (len(scopeBytes) != 0 || recipes.ScopeSHA256 != "") && (len(scopeBytes) == 0 || fmt.Sprintf("%x", sha256.Sum256(scopeBytes)) != recipes.ScopeSHA256) {
			return nil, fmt.Errorf("canonical append reference scope hash mismatch")
		}
		if len(usedBlocks) != len(recipes.WordBlocks) {
			return nil, fmt.Errorf("unused word block")
		}
		if len(usedValues) != len(values) {
			return nil, fmt.Errorf("unused named word value")
		}
	}
	if allocationProfile != nil {
		base, _ := number(allocationProfile.ISOELFOffset)
		for _, edit := range edits {
			if edit.Operation == "stream_capacity" {
				continue
			}
			start, end := uint64(edit.Offset), uint64(edit.Offset)+uint64(len(edit.New))
			if edit.Offset < 0 || start < base || end > base+uint64(allocationProfile.Stream.RetailELFSize) {
				return nil, fmt.Errorf("composed disc-allocation edits must stay inside the retail ELF")
			}
			for _, span := range metadataRanges {
				if start < span[1] && span[0] < end {
					return nil, fmt.Errorf("composed edit changes inspected ISO metadata")
				}
			}
		}
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].Offset < edits[j].Offset })
	if err := validateEdits(edits, recipes.SourceSize); err != nil {
		return nil, err
	}
	return edits, nil
}

// validateEdits requires edits sorted by offset and checks bounds and byte contracts.
// It does not establish source identity or that the edits match their recipes.
func validateEdits(edits []Edit, size int64) error {
	if len(edits) == 0 {
		return fmt.Errorf("no edits")
	}
	var previousEnd int64
	for _, edit := range edits {
		named := edit.Operation == "cmb_member_replace" || edit.Operation == "iso_file_replace"
		if len(edit.Old) != len(edit.New) || len(edit.Old) == 0 || edit.Offset < previousEnd || !named && edit.Offset%2 != 0 || edit.Offset > size-int64(len(edit.New)) {
			return fmt.Errorf("%s: invalid length, alignment, bounds or overlap", edit.ID)
		}
		switch edit.Operation {
		case "cmb_member_replace", "iso_file_replace":
			if edit.ID == "" || len(edit.New) > 64<<20 || edit.Operation == "iso_file_replace" && edit.Offset%isoSector != 0 {
				return fmt.Errorf("invalid named bundle edit")
			}
		case "stream_pointer", "stream_payload", "stream_label_payload":
			id, err := number(edit.ID)
			if err != nil {
				return err
			}
			if edit.Operation == "stream_pointer" {
				if len(edit.New) != 4 {
					return fmt.Errorf("%s: invalid stream pointer size", edit.ID)
				}
				old := binary.LittleEndian.Uint32(edit.Old)
				if edit.Offset%4 != 0 || uint64(binary.LittleEndian.Uint32(edit.New)) < sentinelBase || binary.LittleEndian.Uint32(edit.New)%16 != 0 || (old != uint32(id) && !bytes.Equal(edit.Old, edit.New) && !(uint64(old) >= sentinelBase && old%16 == 0)) {
					return fmt.Errorf("%s: invalid stream pointer", edit.ID)
				}
			} else if _, err := controls(edit.New, TextScanOptions{Terminated: true, PositionalLabels: edit.Operation == "stream_label_payload"}); err != nil || edit.Offset%16 != 0 || bytes.Count(edit.Old, []byte{0}) != len(edit.Old) {
				return fmt.Errorf("%s: invalid stream append payload", edit.ID)
			}
		case "stream_padding":
			zero := bytes.Count(edit.New, []byte{0}) == len(edit.New)
			bookend := len(edit.New) >= 2 && binary.LittleEndian.Uint16(edit.New[len(edit.New)-2:]) == 0xf800 && bytes.Count(edit.New[:len(edit.New)-2], []byte{0}) == len(edit.New)-2
			if len(edit.New)%2 != 0 || !zero && !bookend || bytes.Count(edit.Old, []byte{0}) != len(edit.Old) && !bytes.Equal(edit.Old, edit.New) {
				return fmt.Errorf("invalid stream read padding/reservation")
			}
		case "pointer_check":
			id, err := number(edit.ID)
			if err != nil || edit.Offset%4 != 0 || len(edit.Old) != 4 || !bytes.Equal(edit.Old, edit.New) {
				return fmt.Errorf("%s: invalid read-only pointer check", edit.ID)
			}
			word := binary.LittleEndian.Uint32(edit.Old)
			if word != uint32(id) && (uint64(word) < sentinelBase || word%16 != 0) {
				return fmt.Errorf("%s: invalid read-only pointer check", edit.ID)
			}
		case "stream_capacity":
			// The verifier independently replans the complete coupled transition before any output exists.
			zeroExtent := bytes.Count(edit.New, []byte{0}) == len(edit.New) && (edit.Offset%2048 == 0 && len(edit.New)%2048 == 0 || len(edit.New) < 2048 && (edit.Offset+int64(len(edit.New)))%2048 == 0)
			if len(edit.New) != 4 && len(edit.New) != 8 && len(edit.New) != 16 && !zeroExtent {
				return fmt.Errorf("invalid capacity edit")
			}
		case "guarded_words":
			if edit.Offset%4 != 0 || len(edit.New)%4 != 0 {
				return fmt.Errorf("invalid guarded word alignment")
			}
		case "same_length_stream", "exact_control_stream", "fixed_field", "stream_slot":
			slot := edit.Operation == "stream_slot"
			if slot && len(edit.Old) > maxStreamBytes {
				return fmt.Errorf("%s: slot exceeds bounded stream size", edit.ID)
			}
			scan := TextScanOptions{Terminated: edit.Operation != "fixed_field", ExactControls: edit.Operation == "exact_control_stream" || slot, Padded: slot}
			a, err := controls(edit.Old, scan)
			if err != nil {
				return err
			}
			b, err := controls(edit.New, scan)
			if err != nil {
				return err
			}
			if slot {
				// Only line/page/END positions may move within the reviewed, fixed capacity.
				for _, tokens := range [][]TextToken{a.Tokens, b.Tokens} {
					for i := range tokens {
						if tokens[i].Word == 0x0800 || tokens[i].Word == 0x1000 || tokens[i].Word == 0xf800 {
							tokens[i].Offset = 0
						}
					}
				}
			}
			if !slices.Equal(a.Words, b.Words) || !slices.Equal(a.Boundaries, b.Boundaries) || scan.ExactControls && !reflect.DeepEqual(a.Tokens, b.Tokens) {
				return fmt.Errorf("%s: changed controls", edit.ID)
			}
		default:
			return fmt.Errorf("unknown edit operation %q", edit.Operation)
		}
		previousEnd = edit.Offset + int64(len(edit.New))
	}
	return nil
}

// inspect reads ELF mappings, native font facts or stream readiness, and classifies edits.
// ELF mappings use PT_LOAD, split initialized bytes from BSS, and refuse overlapping
// memory segments. Optional sentinel facts prove the installed dispatch and physical
// loaded extent separately through PT_LOAD-only instruction reads. Neither mapping
// establishes native execution or safe patch placement.
// Font-only inspection needs a bounded ELF, never allocation or consumer scopes.
// No mode verifies the complete image hash; transaction callers retain that check.
func inspect(image io.ReaderAt, edits []Edit, recipes *Recipes) (Inspection, error) {
	result := Inspection{States: make([]string, len(edits))}
	if recipes != nil && recipes.Operation == "elf_layout" {
		allowed := Recipes{Operation: "elf_layout", SourceSize: recipes.SourceSize, SourceSHA256: recipes.SourceSHA256, Evidence: recipes.Evidence, AddressRanges: recipes.AddressRanges, Sentinel: recipes.Sentinel}
		if image == nil || len(edits) != 0 || !reflect.DeepEqual(*recipes, allowed) || recipes.Evidence == "" || recipes.SourceSize < 52 || recipes.SourceSize > 64<<20 || len(recipes.AddressRanges) > 1024 {
			return Inspection{}, fmt.Errorf("ELF layout requires one bounded source and at most 1024 named ranges without patch fields")
		}
		native, err := elf.NewFile(io.NewSectionReader(image, 0, recipes.SourceSize))
		if err != nil {
			return Inspection{}, err
		}
		if native.Class != elf.ELFCLASS32 || native.Data != elf.ELFDATA2LSB || native.Machine != elf.EM_MIPS || native.Type != elf.ET_EXEC || len(native.Progs) > 4096 {
			return Inspection{}, fmt.Errorf("ELF layout requires a little-endian ELF32 MIPS executable with at most 4096 program headers")
		}
		result.ELFEntry = native.Entry
		// GP is an optional file fact. Bad metadata must not change ordinary mappings.
		var reginfo *elf.Section
		reginfoIndex, reginfoCount := 0, 0
		for i, section := range native.Sections {
			if section.Type == 0x70000006 { // SHT_MIPS_REGINFO is absent from debug/elf's constants.
				reginfo, reginfoIndex = section, i
				reginfoCount++
			}
		}
		if reginfoCount != 0 {
			info := &ELFRegisterInfo{}
			result.RegisterInfo = info
			switch {
			case len(native.Sections) > 4096 || reginfoCount != 1:
				info.Error = "ELF GP requires one unambiguous MIPS register-info section within4096headers"
			case reginfo.Flags&elf.SHF_COMPRESSED != 0 || reginfo.Size != 24 || reginfo.Offset%4 != 0 || reginfo.Offset > uint64(recipes.SourceSize) || 24 > uint64(recipes.SourceSize)-reginfo.Offset:
				info.Error = "ELF GP requires one complete aligned uncompressed24byte record"
			default:
				info.SectionIndex, info.FileRange = &reginfoIndex, &[2]uint64{reginfo.Offset, reginfo.Offset + 24}
				var record [24]byte
				if n, err := image.ReadAt(record[:], int64(reginfo.Offset)); err != nil || n != len(record) {
					info.Error = "ELF GP metadata could not be read completely"
				} else {
					gp := binary.LittleEndian.Uint32(record[20:])
					info.GlobalPointer = &gp
				}
			}
		}
		byStart := make(map[uint64]int)
		var starts []uint64
		for i, segment := range native.Progs {
			result.ELFSegments = append(result.ELFSegments, segment.ProgHeader)
			if segment.Type != elf.PT_LOAD {
				continue
			}
			if segment.Filesz > segment.Memsz || segment.Off > uint64(recipes.SourceSize) || segment.Filesz > uint64(recipes.SourceSize)-segment.Off || segment.Vaddr+segment.Memsz > 1<<32 ||
				segment.Align > 1 && (segment.Align&(segment.Align-1) != 0 || segment.Vaddr%segment.Align != segment.Off%segment.Align) {
				return Inspection{}, fmt.Errorf("program header %d: invalid LOAD file, memory or alignment bounds", i)
			}
			if segment.Filesz != 0 {
				var last [1]byte
				if _, err := image.ReadAt(last[:], int64(segment.Off+segment.Filesz-1)); err != nil {
					return Inspection{}, fmt.Errorf("program header %d: truncated LOAD payload: %w", i, err)
				}
			}
			if segment.Memsz == 0 {
				continue
			}
			if _, duplicate := byStart[segment.Vaddr]; duplicate {
				return Inspection{}, fmt.Errorf("overlapping LOAD memory ranges")
			}
			byStart[segment.Vaddr] = i
			starts = append(starts, segment.Vaddr)
		}
		if len(starts) == 0 {
			return Inspection{}, fmt.Errorf("ELF layout requires a nonempty LOAD memory range")
		}
		slices.Sort(starts)
		for i := 1; i < len(starts); i++ {
			previous := result.ELFSegments[byStart[starts[i-1]]]
			if previous.Vaddr+previous.Memsz > starts[i] {
				return Inspection{}, fmt.Errorf("overlapping LOAD memory ranges")
			}
		}
		if layout := recipes.Sentinel; layout != nil {
			if layout.RetailELFSize < 52 || layout.RetailELFSize%4 != 0 || layout.RetailELFSize >= recipes.SourceSize || len(layout.LoaderVMAs) != 4 || len(layout.WindowBases) != 2 || len(layout.WindowSizes) != 2 {
				return Inspection{}, fmt.Errorf("sentinel layout requires retail EOF and exactly 4 loader, 2 base and 2 length sites")
			}
			blobStart := (uint64(layout.RetailELFSize) + 2047) &^ uint64(2047)
			if blobStart >= uint64(recipes.SourceSize) || (uint64(recipes.SourceSize)-blobStart)%2048 != 0 {
				return Inspection{}, fmt.Errorf("sentinel physical trailer must contain complete sectors after aligned retail EOF")
			}
			for _, segment := range native.Progs {
				if segment.Type == elf.PT_LOAD && segment.Filesz != 0 && segment.Off+segment.Filesz > uint64(layout.RetailELFSize) {
					return Inspection{}, fmt.Errorf("sentinel retail EOF must contain every initialized LOAD")
				}
			}
			type instructionSite struct {
				role, text string
				add        uint64
				shape      uint32
			}
			var sites []instructionSite
			for _, group := range []struct {
				role  string
				vmas  []string
				shape [2]uint32
			}{{"base", layout.WindowBases, [2]uint32{0x3c01, 0x3421}}, {"length", layout.WindowSizes, [2]uint32{0x3c09, 0x3529}}} {
				for i, text := range group.vmas {
					for j, instruction := range []string{"LUI", "ORI"} {
						sites = append(sites, instructionSite{fmt.Sprintf("%s%c.%s", group.role, 'A'+i, instruction), text, uint64(j * 4), group.shape[j]})
					}
				}
			}
			for i, role := range []string{"bytes.LUI", "bytes.ORI", "sectors.A", "sectors.B"} {
				sites = append(sites, instructionSite{role, layout.LoaderVMAs[i], 0, []uint32{0x3c05, 0x34a5, 0x240e, 0x240e}[i]})
			}
			wordRanges := make(map[string]AddressRange)
			used := make(map[uint64]bool)
			for _, site := range sites {
				vma, err := number(site.text)
				if err != nil || vma > 0xfffffffc-site.add || vma%4 != 0 || used[vma+site.add] {
					return Inspection{}, fmt.Errorf("%s: sentinel instruction site must be unique/aligned/bounded", site.role)
				}
				vma += site.add
				used[vma] = true
				wordRanges[site.role] = AddressRange{Start: fmt.Sprintf("0x%x", vma), End: fmt.Sprintf("0x%x", vma+4)}
			}
			byteLUI, _ := number(layout.LoaderVMAs[0])
			byteORI, _ := number(layout.LoaderVMAs[1])
			if byteORI != byteLUI+4 {
				return Inspection{}, fmt.Errorf("sentinel loader byte-count LUI/ORI must be adjacent")
			}
			// Sentinel=nil makes this one bounded PT_LOAD-only proof, never self-backing.
			words, err := inspect(image, nil, &Recipes{Operation: "elf_layout", SourceSize: recipes.SourceSize, SourceSHA256: recipes.SourceSHA256, Evidence: recipes.Evidence, AddressRanges: wordRanges})
			if err != nil {
				return Inspection{}, err
			}
			allocation := &SentinelAllocation{Words: make(map[string]uint32), WordMappings: words.ELFMappings}
			for _, site := range sites {
				pieces := words.ELFMappings[site.role]
				if len(pieces) != 1 || pieces[0].Storage != "file_backed" || pieces[0].FileRange == nil || pieces[0].FileRange[1] > uint64(layout.RetailELFSize) {
					return Inspection{}, fmt.Errorf("%s: complete sentinel instruction word must be file-backed before retail EOF", site.role)
				}
				var raw [4]byte
				if _, err := image.ReadAt(raw[:], int64(pieces[0].FileRange[0])); err != nil {
					return Inspection{}, err
				}
				word := binary.LittleEndian.Uint32(raw[:])
				if word>>16 != site.shape {
					return Inspection{}, fmt.Errorf("%s: unrecognized sentinel instruction opcode/registers", site.role)
				}
				allocation.Words[site.role] = word
			}
			values := make(map[string]uint64)
			for _, role := range []string{"baseA", "baseB", "lengthA", "lengthB", "bytes"} {
				values[role] = uint64(allocation.Words[role+".LUI"]&0xffff)<<16 | uint64(allocation.Words[role+".ORI"]&0xffff)
			}
			base, length := values["baseA"], values["lengthA"]
			sectors := uint64(allocation.Words["sectors.A"] & 0xffff)
			if base != sentinelBase || base != values["baseB"] || length != values["lengthB"] || length == 0 || length%2 != 0 || length > 1<<32-base {
				return Inspection{}, fmt.Errorf("sentinel dispatch copies must agree on the recognized bounded address protocol")
			}
			if sectors == 0 || sectors > 0x7fff || allocation.Words["sectors.A"] != allocation.Words["sectors.B"] || values["bytes"] != sectors*2048 || values["bytes"] != uint64(recipes.SourceSize)-blobStart || values["bytes"] > length {
				return Inspection{}, fmt.Errorf("sentinel loader counts, physical trailer and dispatch capacity disagree")
			}
			for _, segment := range native.Progs {
				if segment.Type == elf.PT_LOAD && segment.Memsz != 0 && segment.Vaddr < base+length && base < segment.Vaddr+segment.Memsz {
					return Inspection{}, fmt.Errorf("sentinel dispatch overlaps ordinary LOAD memory")
				}
			}
			padding := make([]byte, blobStart-uint64(layout.RetailELFSize))
			if _, err := image.ReadAt(padding, layout.RetailELFSize); err != nil || bytes.Count(padding, []byte{0}) != len(padding) {
				return Inspection{}, fmt.Errorf("sentinel retail alignment padding must be readable zero bytes")
			}
			var last [1]byte
			if _, err := image.ReadAt(last[:], recipes.SourceSize-1); err != nil {
				return Inspection{}, fmt.Errorf("sentinel physical trailer is truncated: %w", err)
			}
			allocation.DispatchRange = [2]uint64{base, base + length}
			allocation.Loaded = ELFMapping{VMA: [2]uint64{base, base + values["bytes"]}, Storage: "sentinel_blob", FileRange: &[2]uint64{blobStart, uint64(recipes.SourceSize)}}
			result.Sentinel = allocation
		}
		// One interval projector preserves every original PH boundary and index.
		regions := make(map[uint64]ELFMapping)
		var regionStarts []uint64
		for _, address := range starts {
			index := byStart[address]
			segment := result.ELFSegments[index]
			for _, region := range []ELFMapping{
				{VMA: [2]uint64{segment.Vaddr, segment.Vaddr + segment.Filesz}, Storage: "file_backed", ProgramHeader: &index, FileRange: &[2]uint64{segment.Off, segment.Off + segment.Filesz}},
				{VMA: [2]uint64{segment.Vaddr + segment.Filesz, segment.Vaddr + segment.Memsz}, Storage: "bss", ProgramHeader: &index},
			} {
				if region.VMA[0] < region.VMA[1] {
					regions[region.VMA[0]] = region
					regionStarts = append(regionStarts, region.VMA[0])
				}
			}
		}
		if result.Sentinel != nil {
			region := result.Sentinel.Loaded
			regions[region.VMA[0]] = region
			regionStarts = append(regionStarts, region.VMA[0])
		}
		slices.Sort(regionStarts)
		result.ELFMappings = make(map[string][]ELFMapping)
		var names []string
		for name := range recipes.AddressRanges {
			names = append(names, name)
		}
		slices.Sort(names)
		totalMappings := 0
		for _, name := range names {
			query := recipes.AddressRanges[name]
			start, startErr := number(query.Start)
			// The exclusive end may equal 2^32, unlike a 32-bit address.
			end, endErr := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(query.End), "0x"), 16, 64)
			if name == "" || startErr != nil || endErr != nil || start >= end || end > 1<<32 {
				return Inspection{}, fmt.Errorf("%s: invalid half-open VMA range", name)
			}
			var pieces []ELFMapping
			cursor := start
			for _, address := range regionStarts {
				region := regions[address]
				if region.VMA[1] <= cursor {
					continue
				}
				if address >= end {
					break
				}
				if cursor < address {
					pieces = append(pieces, ELFMapping{VMA: [2]uint64{cursor, address}, Storage: "unmapped"})
					cursor = address
				}
				pieceEnd := min(end, region.VMA[1])
				piece := region
				piece.VMA = [2]uint64{cursor, pieceEnd}
				if region.FileRange != nil {
					fileStart := region.FileRange[0] + cursor - address
					piece.FileRange = &[2]uint64{fileStart, fileStart + pieceEnd - cursor}
				}
				pieces = append(pieces, piece)
				cursor = pieceEnd
			}
			if cursor < end {
				pieces = append(pieces, ELFMapping{VMA: [2]uint64{cursor, end}, Storage: "unmapped"})
			}
			totalMappings += len(pieces)
			if totalMappings > 65536 {
				return Inspection{}, fmt.Errorf("ELF range report exceeds 65536 mapping pieces")
			}
			result.ELFMappings[name] = pieces
		}
		return result, nil
	}
	if recipes != nil {
		if recipes.Sentinel != nil {
			return Inspection{}, fmt.Errorf("sentinel mapping facts require read-only ELF layout")
		}
		if recipes.Operation == "font_metrics" {
			allowed := Recipes{Operation: "font_metrics", SourceSize: recipes.SourceSize, ELFVMADelta: recipes.ELFVMADelta, Layout: recipes.Layout}
			if image == nil || len(edits) != 0 || !reflect.DeepEqual(*recipes, allowed) || recipes.Layout == nil || recipes.Layout.Columns != 0 || recipes.Layout.Rows != 0 || recipes.SourceSize < 12 || recipes.SourceSize > 64<<20 {
				return Inspection{}, fmt.Errorf("font inspection requires one bounded ELF and native font facts without patch fields")
			}
			result.ELF = make([]byte, recipes.SourceSize)
			if _, err := image.ReadAt(result.ELF, 0); err != nil {
				return Inspection{}, err
			}
		} else {
			profile := recipes.Stream
			allocationOnly := recipes.Operation == "stream_allocate"
			if image == nil || profile == nil {
				return Inspection{}, fmt.Errorf("incomplete initialized stream profile")
			}
			if allocationOnly {
				if recipes.Growth == nil || recipes.Growth.FromSectors != 0 || recipes.Growth.LoaderRange != (AddressRange{}) || recipes.Layout != nil || len(profile.LoaderVMAs)+len(profile.WindowLUIVMAs)+len(profile.WindowSRLWords)+len(profile.AllowedPointers)+len(profile.AllowedLandings) != 0 {
					return Inspection{}, fmt.Errorf("disc-only initialization forbids loader/window/consumer readiness data")
				}
			} else if len(profile.LoaderVMAs) != 4 || len(profile.WindowLUIVMAs) != 2 || len(profile.WindowSRLWords) != 7 {
				return Inspection{}, fmt.Errorf("incomplete initialized stream profile")
			}
			base, err := number(recipes.ISOELFOffset)
			if err != nil || base%2048 != 0 || profile.RetailELFSize <= 0 || profile.RetailELFSize%4 != 0 || profile.RetailELFSize > recipes.SourceSize || base > uint64(recipes.SourceSize-profile.RetailELFSize) {
				return Inspection{}, fmt.Errorf("invalid retail ELF extent")
			}
			delta, err := number(recipes.ELFVMADelta)
			if err != nil {
				return Inspection{}, err
			}
			if sentinelBase < delta+uint64(profile.RetailELFSize) {
				return Inspection{}, fmt.Errorf("invalid sentinel base")
			}
			zeroEnd, err := number(profile.ZeroEnd)
			if err != nil || zeroEnd > uint64(recipes.SourceSize) {
				return Inspection{}, fmt.Errorf("invalid ZERO end")
			}
			var directory []uint64
			var records [][]byte
			for _, text := range []string{profile.ELFRecordOffset, profile.ZeroRecordOffset} {
				offset, err := number(text)
				if err != nil || recipes.SourceSize < 18 || offset > uint64(recipes.SourceSize-18) {
					return Inspection{}, fmt.Errorf("invalid directory record offset")
				}
				data := make([]byte, 18)
				if _, err := image.ReadAt(data, int64(offset)); err != nil {
					return Inspection{}, err
				}
				records = append(records, data)
				for _, at := range []int{2, 10} {
					le := binary.LittleEndian.Uint32(data[at:])
					if le != binary.BigEndian.Uint32(data[at+4:]) {
						return Inspection{}, fmt.Errorf("directory endian mismatch")
					}
					directory = append(directory, uint64(le))
				}
			}
			blobStart := (base + uint64(profile.RetailELFSize) + 2047) &^ uint64(2047)
			blobEnd := directory[2] * 2048
			if directory[0]*2048 != base || blobEnd < blobStart || blobEnd > uint64(recipes.SourceSize) || blobEnd+directory[3] != zeroEnd {
				return Inspection{}, fmt.Errorf("inconsistent initialized disc allocation")
			}
			elfSize := blobEnd - base
			if blobEnd == blobStart {
				elfSize = uint64(profile.RetailELFSize)
			}
			if directory[1] != elfSize || blobEnd == blobStart && !allocationOnly {
				return Inspection{}, fmt.Errorf("inconsistent stream allocation size")
			}
			result.BlobOffset = int64(blobStart)
			result.Capacity = int64(blobEnd - blobStart)
			margin := uint64(16 * 2048)
			if allocationOnly {
				margin = 0
			}
			if growth := recipes.Growth; growth != nil {
				from, to, disc := uint64(growth.FromSectors), uint64(growth.ToSectors), (blobEnd-blobStart)/2048
				if from >= to || !allocationOnly && to > 0x7fff || disc != from && disc != to || from == 0 && !allocationOnly || allocationOnly && from != 0 {
					return Inspection{}, fmt.Errorf("unsupported allocation transition")
				}
				if blobStart+to*2048+margin > zeroEnd {
					return Inspection{}, fmt.Errorf("growth exceeds ZERO extent including safety margin")
				}
			}
			padding := make([]byte, blobStart-base-uint64(profile.RetailELFSize))
			if _, err := image.ReadAt(padding, int64(base)+profile.RetailELFSize); err != nil {
				return Inspection{}, err
			}
			if bytes.Count(padding, []byte{0}) != len(padding) {
				return Inspection{}, fmt.Errorf("nonzero leading stream padding")
			}
			if allocationOnly && blobEnd == blobStart && len(padding) != 0 {
				at := int64(base) + profile.RetailELFSize
				result.Edits = append(result.Edits, Edit{ID: fmt.Sprintf("0x%x", at), Offset: at, Old: padding, New: make([]byte, len(padding)), Operation: "stream_capacity"})
			}
			var loader []uint32
			if !allocationOnly {
				result.ELF = make([]byte, profile.RetailELFSize)
				if _, err := image.ReadAt(result.ELF, int64(base)); err != nil {
					return Inspection{}, err
				}
				readinessSites := make(map[uint64]bool)
				var shifts []string
				for vma := range profile.WindowSRLWords {
					shifts = append(shifts, vma)
				}
				slices.Sort(shifts)
				for i, text := range append(append(append([]string{}, profile.LoaderVMAs...), profile.WindowLUIVMAs...), shifts...) {
					vma, err := number(text)
					if err != nil || readinessSites[vma] || vma < delta || vma%4 != 0 || vma-delta > uint64(len(result.ELF))-4 {
						return Inspection{}, fmt.Errorf("invalid loader/window site")
					}
					readinessSites[vma] = true
					word := binary.LittleEndian.Uint32(result.ELF[vma-delta:])
					switch {
					case i < 4:
						loader = append(loader, word)
					case i < 6:
						if word>>16 != 0x3c09 || word&0xffff == 0 {
							return Inspection{}, fmt.Errorf("invalid translation-window LUI")
						}
						result.Capacity = min(result.Capacity, int64(word&0xffff)<<16)
					default:
						expected, err := number(profile.WindowSRLWords[text])
						if err != nil || word>>21 != 0 || word&0x3f != 2 || word>>16&31 == 0 || word>>11&31 == 0 || uint64(word)&0xfffff83f != expected&0xfffff83f {
							return Inspection{}, fmt.Errorf("invalid translation-window shift")
						}
						result.Capacity = min(result.Capacity, int64(1)<<((word>>6)&31))
					}
				}
				sectors := loader[2] & 0xffff
				if loader[0]>>16 != 0x3c05 || loader[1]>>16 != 0x34a5 || loader[2]>>16 != 0x240e || loader[2] != loader[3] || sectors == 0 || sectors > 0x7fff || (uint64(loader[0]&0xffff)<<16|uint64(loader[1]&0xffff)) != uint64(sectors)*2048 || sentinelBase+uint64(sectors)*2048 > 1<<32 {
					return Inspection{}, fmt.Errorf("inconsistent initialized loader/allocation")
				}
				if recipes.Growth == nil && uint64(sectors)*2048 != blobEnd-blobStart {
					return Inspection{}, fmt.Errorf("inconsistent initialized loader/allocation")
				}
				if growth := recipes.Growth; growth != nil {
					from, to, disc := uint64(growth.FromSectors), uint64(growth.ToSectors), (blobEnd-blobStart)/2048
					if (uint64(sectors) != from && uint64(sectors) != to) || uint64(sectors) > disc {
						return Inspection{}, fmt.Errorf("unsupported initialized growth state")
					}
				}
				result.Capacity = min(result.Capacity, int64(sectors)*2048)
				if recipes.Growth == nil {
					result.Blob = make([]byte, blobEnd-blobStart)
					if _, err := image.ReadAt(result.Blob, result.BlobOffset); err != nil {
						return Inspection{}, err
					}
				}
			}
			if growth := recipes.Growth; growth != nil {
				to := uint64(growth.ToSectors)
				targetEnd := blobStart + to*2048
				claimStart := blobStart
				if allocationOnly {
					claimStart = base + uint64(profile.RetailELFSize)
				}
				if !allocationOnly {
					start, startErr := number(growth.LoaderRange.Start)
					end, endErr := number(growth.LoaderRange.End)
					if startErr != nil || endErr != nil || start < delta || start >= end || start%4 != 0 || end%4 != 0 || end-delta > uint64(len(result.ELF)) {
						return Inspection{}, fmt.Errorf("invalid loader scan range")
					}
					loaderSites := make(map[uint64]bool)
					for _, text := range profile.LoaderVMAs {
						vma, _ := number(text)
						if vma < start || vma >= end {
							return Inspection{}, fmt.Errorf("loader site outside scan range")
						}
						loaderSites[vma] = true
					}
					for vma := start; vma < end; vma += 4 {
						word := binary.LittleEndian.Uint32(result.ELF[vma-delta:])
						op, imm := word>>26, word&0xffff
						for _, count := range []uint32{growth.FromSectors, growth.ToSectors} {
							if !loaderSites[vma] && ((op == 15 && imm == count*2048>>16) || (op == 13 && word>>16&31 == 5 && imm == count*2048&0xffff) || ((op == 8 || op == 9) && imm == count)) {
								return Inspection{}, fmt.Errorf("unaccounted loader size instruction at %#x", vma)
							}
						}
					}
				}
				// Walk reachable ISO9660 records, including nested directories, before claiming ZERO sectors.
				pvd := make([]byte, 2048)
				if _, err := image.ReadAt(pvd, 16*2048); err != nil {
					return Inspection{}, err
				}
				if !bytes.Equal(pvd[:7], []byte{1, 'C', 'D', '0', '0', '1', 1}) || binary.LittleEndian.Uint16(pvd[128:]) != 2048 || binary.BigEndian.Uint16(pvd[130:]) != 2048 || pvd[156] < 34 {
					return Inspection{}, fmt.Errorf("invalid ISO9660 primary volume")
				}
				if allocationOnly {
					result.MetadataRanges = append(result.MetadataRanges, [2]uint64{16 * 2048, 17 * 2048})
				}
				volumeBytes := uint64(binary.LittleEndian.Uint32(pvd[80:])) * 2048
				pathBytes := uint64(binary.LittleEndian.Uint32(pvd[132:]))
				if volumeBytes == 0 || volumeBytes != uint64(binary.BigEndian.Uint32(pvd[84:]))*2048 || volumeBytes > uint64(recipes.SourceSize) || zeroEnd > volumeBytes || pathBytes == 0 || pathBytes != uint64(binary.BigEndian.Uint32(pvd[136:])) {
					return Inspection{}, fmt.Errorf("invalid ISO9660 volume/path-table size")
				}
				for i, lba := range []uint32{binary.LittleEndian.Uint32(pvd[140:]), binary.LittleEndian.Uint32(pvd[144:]), binary.BigEndian.Uint32(pvd[148:]), binary.BigEndian.Uint32(pvd[152:])} {
					if lba == 0 && i%2 != 0 {
						continue
					}
					start := uint64(lba) * 2048
					end := start + (pathBytes+2047)&^uint64(2047)
					if lba == 0 || end > volumeBytes || (start < targetEnd+margin && claimStart < end) {
						return Inspection{}, fmt.Errorf("invalid or overlapping ISO9660 path table")
					}
					if allocationOnly {
						result.MetadataRanges = append(result.MetadataRanges, [2]uint64{start, end})
					}
				}
				pending := []struct{ offset, size, parent, parentSize uint64 }{{16*2048 + 156, uint64(pvd[156]), 0, 0}}
				seenDirectories := make(map[uint64]bool)
				found := make(map[uint64]bool)
				elfRecord, _ := number(profile.ELFRecordOffset)
				zeroRecord, _ := number(profile.ZeroRecordOffset)
				for len(pending) != 0 {
					dir := pending[len(pending)-1]
					pending = pending[:len(pending)-1]
					names := make(map[string]bool)
					for chunk := uint64(0); chunk < dir.size; chunk += 2048 {
						block := make([]byte, min(uint64(2048), dir.size-chunk))
						if _, err := image.ReadAt(block, int64(dir.offset+chunk)); err != nil {
							return Inspection{}, err
						}
						for at := 0; at < len(block); {
							n := int(block[at])
							if n == 0 {
								if bytes.Count(block[at:], []byte{0}) != len(block)-at {
									return Inspection{}, fmt.Errorf("nonzero directory padding")
								}
								break
							}
							if n < 34 || n > len(block)-at {
								return Inspection{}, fmt.Errorf("invalid directory record length")
							}
							record := block[at : at+n]
							offset := dir.offset + chunk + uint64(at)
							at += n
							nameLength := int(record[32])
							if nameLength == 0 || 33+nameLength+(1-nameLength%2) > n || record[1] != 0 || record[26] != 0 || record[27] != 0 || record[25]&128 != 0 || binary.LittleEndian.Uint16(record[28:]) != binary.BigEndian.Uint16(record[30:]) {
								return Inspection{}, fmt.Errorf("unsupported ISO9660 directory record")
							}
							lba, size := uint64(binary.LittleEndian.Uint32(record[2:])), uint64(binary.LittleEndian.Uint32(record[10:]))
							if lba != uint64(binary.BigEndian.Uint32(record[6:])) || size != uint64(binary.BigEndian.Uint32(record[14:])) || lba*2048 > volumeBytes || size > volumeBytes-lba*2048 {
								return Inspection{}, fmt.Errorf("invalid ISO9660 extent/endian fields")
							}
							name := string(record[33 : 33+nameLength])
							root := offset == 16*2048+156
							if !root && (name == "\x00" || name == "\x01") {
								wantOffset, wantSize := dir.offset, dir.size
								if name == "\x01" {
									wantOffset, wantSize = dir.parent, dir.parentSize
								}
								if record[25]&2 == 0 || lba*2048 != wantOffset || size != wantSize {
									return Inspection{}, fmt.Errorf("invalid directory self/parent reference")
								}
							}
							if names[name] {
								return Inspection{}, fmt.Errorf("duplicate directory name")
							}
							names[name] = true
							if offset == elfRecord || offset == zeroRecord {
								wantName := "SLPM_657.50;1"
								if offset == zeroRecord {
									wantName = "ZERO.BIN;1"
								}
								if name != wantName || record[25]&2 != 0 || found[offset] {
									return Inspection{}, fmt.Errorf("allocation record identity mismatch")
								}
								found[offset] = true
							} else if size != 0 && lba*2048 < targetEnd+margin && claimStart < lba*2048+(size+2047)&^uint64(2047) {
								return Inspection{}, fmt.Errorf("other extent overlaps stream growth")
							}
							if record[25]&2 != 0 && (root || name != "\x00" && name != "\x01") {
								if size == 0 || seenDirectories[lba] {
									return Inspection{}, fmt.Errorf("invalid or repeated directory extent")
								}
								seenDirectories[lba] = true
								if allocationOnly {
									result.MetadataRanges = append(result.MetadataRanges, [2]uint64{lba * 2048, lba*2048 + (size+2047)&^uint64(2047)})
								}
								parent, parentSize := dir.offset, dir.size
								if root {
									parent, parentSize = lba*2048, size
								}
								pending = append(pending, struct{ offset, size, parent, parentSize uint64 }{lba * 2048, size, parent, parentSize})
							} else if root {
								return Inspection{}, fmt.Errorf("root record is not a directory")
							}
						}
					}
					if dir.offset != 16*2048+156 && (!names["\x00"] || !names["\x01"]) {
						return Inspection{}, fmt.Errorf("missing directory self/parent record")
					}
				}
				if !found[elfRecord] || !found[zeroRecord] {
					return Inspection{}, fmt.Errorf("allocation records absent from reachable directory tree")
				}
				for i, text := range profile.LoaderVMAs {
					vma, _ := number(text)
					word := []uint32{0x3c050000 | uint32(to*2048>>16), 0x34a50000 | uint32(to*2048&0xffff), 0x240e0000 | uint32(to), 0x240e0000 | uint32(to)}[i]
					old := binary.LittleEndian.AppendUint32(nil, loader[i])
					result.Edits = append(result.Edits, Edit{ID: text, Offset: int64(base + vma - delta), Old: old, New: binary.LittleEndian.AppendUint32(nil, word), Operation: "stream_capacity"})
				}
				for i, offset := range []uint64{elfRecord + 10, zeroRecord + 2} {
					var next []byte
					var old []byte
					if i == 0 {
						old = records[0][10:18]
						next = binary.LittleEndian.AppendUint32(next, uint32(targetEnd-base))
						next = binary.BigEndian.AppendUint32(next, uint32(targetEnd-base))
					} else {
						old = records[1][2:18]
						for _, value := range []uint32{uint32(targetEnd / 2048), uint32(zeroEnd - targetEnd)} {
							next = binary.LittleEndian.AppendUint32(next, value)
							next = binary.BigEndian.AppendUint32(next, value)
						}
					}
					result.Edits = append(result.Edits, Edit{ID: fmt.Sprintf("0x%x", offset), Offset: int64(offset), Old: old, New: next, Operation: "stream_capacity"})
				}
				if blobEnd < targetEnd {
					old := make([]byte, targetEnd-blobEnd)
					if _, err := image.ReadAt(old, int64(blobEnd)); err != nil {
						return Inspection{}, err
					}
					result.Edits = append(result.Edits, Edit{ID: fmt.Sprintf("0x%x", blobEnd), Offset: int64(blobEnd), Old: old, New: make([]byte, len(old)), Operation: "stream_capacity"})
				}
			}
			for _, ranges := range []struct {
				input  []AddressRange
				output *[][2]uint64
			}{{profile.AllowedPointers, &result.PointerRanges}, {profile.AllowedLandings, &result.LandingRanges}} {
				if len(ranges.input) == 0 {
					if recipes.Growth != nil {
						continue
					}
					return Inspection{}, fmt.Errorf("missing reviewed consumer ranges")
				}
				for _, interval := range ranges.input {
					start, err := number(interval.Start)
					end, endErr := number(interval.End)
					if err != nil || endErr != nil || start >= end || start%4 != 0 || end%4 != 0 {
						return Inspection{}, fmt.Errorf("invalid reviewed consumer range")
					}
					*ranges.output = append(*ranges.output, [2]uint64{start, end})
				}
			}
		}
		if recipes.Layout != nil {
			delta, err := number(recipes.ELFVMADelta)
			if err != nil || delta+uint64(len(result.ELF)) > 1<<32 {
				return Inspection{}, fmt.Errorf("invalid native font mapping")
			}
			table, err := number(recipes.Layout.FontTableVMA)
			if err != nil || table%4 != 0 || table < delta || len(result.ELF) < 12 || table-delta > uint64(len(result.ELF)-12) {
				return Inspection{}, fmt.Errorf("invalid font page table")
			}
			exceptionVMA, addressErr := number(recipes.Layout.UnflooredGlyphVMA)
			exceptionGlyph, glyphErr := number(recipes.Layout.UnflooredGlyph)
			if addressErr != nil || glyphErr != nil || exceptionVMA%2 != 0 || exceptionVMA < delta || exceptionVMA-delta > uint64(len(result.ELF)-2) || exceptionGlyph < 1 || exceptionGlyph >= 3*441 {
				return Inspection{}, fmt.Errorf("native advance exception requires a bounded aligned source and literal glyph1..1322")
			}
			if binary.LittleEndian.Uint16(result.ELF[exceptionVMA-delta:]) != uint16(exceptionGlyph) {
				return Inspection{}, fmt.Errorf("native advance exception source differs from profile")
			}
			result.Advances = make(map[uint16]int, 3*441)
			for page := 0; page < 3; page++ {
				vma := uint64(binary.LittleEndian.Uint32(result.ELF[table-delta+uint64(page*4):]))
				if vma < delta || len(result.ELF) < 441*3 || vma-delta > uint64(len(result.ELF)-441*3) {
					return Inspection{}, fmt.Errorf("font metrics outside retail ELF")
				}
				for glyph := 0; glyph < 441; glyph++ {
					at := vma - delta + uint64(glyph*3)
					left, ink := int(result.ELF[at]), int(result.ELF[at+1])
					advance := left + ink + 3
					if uint64(page*441+glyph) != exceptionGlyph {
						advance = max(22, advance)
					}
					result.Advances[uint16(page*441+glyph)] = advance - left
				}
			}
			if len(recipes.Layout.SpaceWords) != 8 {
				return Inspection{}, fmt.Errorf("layout requires all eight native space instructions")
			}
			space, sites := 0, make(map[uint64]bool)
			for text, expectedText := range recipes.Layout.SpaceWords {
				vma, addressErr := number(text)
				expected, wordErr := number(expectedText)
				if addressErr != nil || wordErr != nil || sites[vma] || vma%4 != 0 || vma < delta || vma-delta > uint64(len(result.ELF)-4) {
					return Inspection{}, fmt.Errorf("invalid native space instruction site")
				}
				sites[vma] = true
				word := binary.LittleEndian.Uint32(result.ELF[vma-delta:])
				advance := map[uint32]int{0x4160: 14, 0x41c0: 24}[word&0xffff]
				if word != uint32(expected) || word>>16 != 0x3c02 && word>>16 != 0x3c03 || advance == 0 || space != 0 && advance != space {
					return Inspection{}, fmt.Errorf("unknown, changed or inconsistent native space instructions")
				}
				space = advance
			}
			result.Advances[0] = space
		}
	}
	for i, edit := range edits {
		data := make([]byte, len(edit.Old))
		if _, err := image.ReadAt(data, edit.Offset); err != nil {
			return Inspection{}, err
		}
		switch {
		case bytes.Equal(data, edit.New):
			result.States[i] = "already patched"
		case bytes.Equal(data, edit.Old):
			result.States[i] = "pending"
		default:
			return Inspection{}, fmt.Errorf("%s: unexpected image bytes", edit.ID)
		}
	}
	return result, nil
}

// verifySource replans and matches every supplied edit, then checks the full source
// hash and preimages. Hashing leaves the source cursor at EOF; later copies must rewind.
func verifySource(source *os.File, tables []Recipes, edits []Edit, registry Registry, glyphData []byte) error {
	if len(tables) == 0 {
		return fmt.Errorf("no recipe tables")
	}
	recipes := tables[0]
	info, err := source.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != recipes.SourceSize {
		return fmt.Errorf("source size/type mismatch")
	}
	expected, err := plan(tables, registry, glyphData, source)
	if err != nil {
		return err
	}
	if len(edits) != len(expected) {
		return fmt.Errorf("edit count does not match recipe tables")
	}
	for i, edit := range edits {
		want := expected[i]
		sameID := edit.ID == want.ID
		if edit.Operation != "cmb_member_replace" && edit.Operation != "iso_file_replace" {
			id, err := number(edit.ID)
			wantID, _ := number(want.ID)
			sameID = err == nil && id == wantID
		}
		if !sameID || edit.Offset != want.Offset || edit.Operation != want.Operation || !bytes.Equal(edit.Old, want.Old) || !bytes.Equal(edit.New, want.New) {
			return fmt.Errorf("%s: edit identity/format/target/bytes do not match planned recipe", edit.ID)
		}
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(h, source); err != nil {
		return err
	}
	if fmt.Sprintf("%x", h.Sum(nil)) != recipes.SourceSHA256 {
		return fmt.Errorf("source hash mismatch")
	}
	_, err = inspect(source, edits, nil)
	return err
}

// patchCopy verifies the source and writes an exclusive new copy, then checks readback
// and enforces any pinned output SHA-256. Failure removes only its own output inode.
func patchCopy(source *os.File, output string, tables []Recipes, edits []Edit, registry Registry, glyphData []byte) (digest string, err error) {
	for _, table := range tables {
		if table.Operation == "pointer_check" {
			return "", fmt.Errorf("pointer_check is verification-only; apply refused")
		}
	}
	if err = verifySource(source, tables, edits, registry, glyphData); err != nil {
		return "", err
	}
	recipes := tables[0]
	target, err := os.OpenFile(output, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	created, _ := target.Stat()
	defer func() {
		if closeErr := target.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			if current, statErr := os.Lstat(output); statErr == nil && created != nil && os.SameFile(created, current) {
				_ = os.Remove(output)
			}
		}
	}()
	if _, err = source.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	h := sha256.New()
	var n int64
	n, err = io.Copy(io.MultiWriter(target, h), source)
	if err != nil {
		return "", err
	}
	if n != recipes.SourceSize || fmt.Sprintf("%x", h.Sum(nil)) != recipes.SourceSHA256 {
		return "", fmt.Errorf("source changed during copy")
	}
	if _, err = inspect(target, edits, nil); err != nil {
		return "", err
	}
	for _, edit := range edits {
		if _, err = target.WriteAt(edit.New, edit.Offset); err != nil {
			return "", err
		}
	}
	if err = target.Sync(); err != nil {
		return "", err
	}
	var inspection Inspection
	if inspection, err = inspect(target, edits, nil); err != nil {
		return "", err
	}
	for _, state := range inspection.States {
		if state != "already patched" {
			return "", fmt.Errorf("readback failed")
		}
	}
	if _, err = target.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	h.Reset()
	if _, err = io.Copy(h, target); err != nil {
		return "", err
	}
	digest = fmt.Sprintf("%x", h.Sum(nil))
	if recipes.OutputSHA256 != "" && digest != recipes.OutputSHA256 {
		return "", fmt.Errorf("output hash mismatch")
	}
	return digest, nil
}
