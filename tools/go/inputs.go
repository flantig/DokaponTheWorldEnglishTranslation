package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"unicode/utf8"
)

// readInput reads a bounded regular artifact and rejects size/mtime drift.
// Callers own encoding and identity checks; large images use streaming readers.
func readInput(path string, limit int64) ([]byte, error) {
	if limit < 1 || limit > 128<<20 {
		return nil, fmt.Errorf("invalid input byte limit")
	}
	// Known special files must be rejected before open can wait for a producer.
	pathInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Size() < 1 || pathInfo.Size() > limit {
		return nil, fmt.Errorf("input must be a bounded regular file: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > limit ||
		!os.SameFile(pathInfo, before) || pathInfo.Size() != before.Size() || pathInfo.ModTime() != before.ModTime() {
		file.Close()
		return nil, fmt.Errorf("input must be a bounded regular file: %s", path)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	after, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil || int64(len(data)) != before.Size() || after.Size() != before.Size() || after.ModTime() != before.ModTime() {
		return nil, fmt.Errorf("input changed or could not be read: %s", path)
	}
	return data, nil
}

// checkJSON rejects duplicate owned keys and unpaired Unicode escapes. Opaque
// registry metadata keeps its old selective policy; allObjects owns every key.
// Nonempty input must already be JSON; legacy refusal wording is preserved.
func checkJSON(input checkedJSON) error {
	if len(input.raw) != 0 && (!utf8.Valid(input.raw) || !json.Valid(input.raw)) {
		return fmt.Errorf("input must be valid UTF-8 JSON")
	}
	data := input.raw
	depth, inEntries := 0, false
	keys := make(map[int]map[string]bool)
	for start := 0; start < len(data); start++ {
		if input.nonNull && data[start] == 'n' && len(data)-start >= 4 && string(data[start:start+4]) == "null" {
			return fmt.Errorf("input must omit unused fields instead of null")
		}
		if data[start] == '{' || data[start] == '[' {
			depth++
			if data[start] == '{' {
				keys[depth] = make(map[string]bool)
			}
		} else if data[start] == '}' || data[start] == ']' {
			if data[start] == '}' {
				for _, field := range input.requiredByDepth[depth] {
					if !keys[depth][field] {
						return fmt.Errorf("missing required object key %q", field)
					}
				}
			}
			depth--
		}
		if data[start] != '"' {
			continue
		}
		end := start + 1
		for data[end] != '"' {
			if data[end] == '\\' {
				end++
			}
			end++
		}
		quoted := data[start : end+1]
		text := quoted[1 : len(quoted)-1]
		start = end
		next := end + 1
		for next < len(data) && (data[next] == ' ' || data[next] == '\n' || data[next] == '\r' || data[next] == '\t') {
			next++
		}
		isKey := next < len(data) && data[next] == ':'
		var key string
		if isKey {
			_ = json.Unmarshal(quoted, &key)
			if slices.Contains(input.nonNullByDepth[depth], key) && bytes.HasPrefix(bytes.TrimSpace(data[next+1:]), []byte("null")) {
				return fmt.Errorf("input must omit unused fields instead of null")
			}
			for _, canonical := range input.aliasesByDepth[depth] {
				if key != canonical && strings.EqualFold(key, canonical) {
					return fmt.Errorf("noncanonical object key %q", key)
				}
			}
			if fields := input.fieldsByDepth[depth]; fields != nil && !slices.Contains(fields, key) {
				return fmt.Errorf("unexpected object key %q", key)
			}
			if depth == 1 {
				inEntries = !input.updates && key == "entries" || input.updates && key == "registry_updates"
			}
		}
		rewritten := isKey && (slices.Contains(input.aliasesByDepth[depth], key) || input.requiredByDepth[depth] != nil || input.allObjects || depth == 1 || input.records && depth == 2 || inEntries && (depth == 3 || input.updates && depth == 2))
		if rewritten {
			if keys[depth][key] {
				return fmt.Errorf("duplicate registry object key %q", key)
			}
			keys[depth][key] = true
		}
		if !rewritten && !input.text {
			continue
		}
		for at := 0; at < len(text); at++ {
			if text[at] != '\\' {
				continue
			}
			at++
			if text[at] != 'u' {
				continue
			}
			unit, _ := number(string(text[at+1 : at+5]))
			at += 4
			if unit >= 0xd800 && unit <= 0xdbff {
				if at+7 > len(text) || text[at+1] != '\\' || text[at+2] != 'u' {
					return fmt.Errorf("registry keys and author text require paired Unicode surrogates")
				}
				low, _ := number(string(text[at+3 : at+7]))
				if low < 0xdc00 || low > 0xdfff {
					return fmt.Errorf("registry keys and author text require paired Unicode surrogates")
				}
				at += 6
			} else if unit >= 0xdc00 && unit <= 0xdfff {
				return fmt.Errorf("registry keys and author text require paired Unicode surrogates")
			}
		}
	}
	return nil
}
