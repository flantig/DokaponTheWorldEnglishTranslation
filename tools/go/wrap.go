package main

import (
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// wrapPages shares word/page placement for character or native-advance budgets.
// Input omits END and the source's implicit final pause. Native atoms use controls
// for glyph/numeric bounds. atomWidths supplies source-bound opaque occurrence
// estimates, including explicit zero; these estimates cannot measure native fit.
func wrapPages(words []uint16, glyphs map[uint16]rune, columns, rows int, advances map[uint16]int, numericBounds []*NumericRange, atomWidths map[uint16]int) ([]uint16, error) {
	if columns < 1 || rows < 1 || len(words) > maxStreamBytes/2 || advances == nil && len(numericBounds) != 0 {
		return nil, fmt.Errorf("invalid or oversized page-layout input")
	}
	if len(atomWidths) > maxStreamBytes/2 || atomWidths != nil && advances != nil {
		return nil, fmt.Errorf("opaque occurrence estimates cannot supply native advances")
	}
	for word, width := range atomWidths {
		if word <= 0x0800 || word >= 0x2800 || word == 0x1000 || width < 0 || width > 1 {
			return nil, fmt.Errorf("invalid opaque occurrence estimate")
		}
		if _, collision := glyphs[word]; collision {
			return nil, fmt.Errorf("opaque occurrence collides with a glyph")
		}
	}
	space := 1
	if advances != nil {
		space = advances[0]
		if space < 1 {
			return nil, fmt.Errorf("native wrapping requires a measured space advance")
		}
	}
	type atom struct {
		words []uint16
		block int
		width int
	}
	type state struct{ at, pages, lines int }
	type choice struct{ cost, end, lines int }
	var out []uint16
	numericAt := 0
	for pageStart := 0; pageStart <= len(words); {
		pageEnd := pageStart
		for pageEnd < len(words) && words[pageEnd] != 0x1000 {
			pageEnd++
		}
		prefixEnd := pageStart
		for prefixEnd < pageEnd && (words[prefixEnd] == 0x2800 || words[prefixEnd] >= 0x3800 && words[prefixEnd] <= 0x3fff) {
			prefixEnd++
		}
		var atoms []atom
		start, block := prefixEnd, 0
		for at := prefixEnd; at <= pageEnd; at++ {
			if at < pageEnd && words[at] != 0 && words[at] != 0x0800 {
				continue
			}
			width := 0
			if advances != nil {
				var encoded []byte
				numericEnd := numericAt
				for _, word := range words[start:at] {
					encoded = binary.LittleEndian.AppendUint16(encoded, word)
					if word == 0x7000 {
						numericEnd++
					}
				}
				if numericEnd > len(numericBounds) {
					return nil, fmt.Errorf("missing numeric argument bound for wrapping")
				}
				encoded = binary.LittleEndian.AppendUint16(encoded, 0xf800)
				shape, err := controls(encoded, TextScanOptions{Terminated: true, Advances: advances, NumericBounds: numericBounds[numericAt:numericEnd]})
				if err != nil {
					return nil, err
				}
				width, numericAt = shape.Width, numericEnd
			} else {
				for _, word := range words[start:at] {
					if estimate, exists := atomWidths[word]; exists {
						width += estimate
					} else if word < 0xb001 || word > 0xb009 {
						width++
					}
				}
			}
			atoms = append(atoms, atom{words[start:at], block, width})
			if at < pageEnd && words[at] == 0x0800 {
				block++
			}
			start = at + 1
		}
		n := len(atoms)
		// Greedy next-line links represent every span without copying its line list.
		nextLine, remainingLines := make([]int, n), make([]int, n+1)
		for start := n - 1; start >= 0; start-- {
			end, width := start+1, atoms[start].width
			for end < n && atoms[end].block == atoms[end-1].block && width+space+atoms[end].width <= columns {
				width += space + atoms[end].width
				end++
			}
			nextLine[start] = end
			remainingLines[start] = 1 + remainingLines[end]
		}
		var base []int
		for at := 0; at < n; at = nextLine[at] {
			base = append(base, at)
		}
		cutCosts := make(map[int]int)
		for i := 1; i < n; i++ {
			previous, next := atoms[i-1], atoms[i]
			if previous.block == next.block && (len(previous.words) == 0 || len(next.words) == 0) {
				continue
			}
			last := rune(0)
			for at := len(previous.words) - 1; at >= 0; at-- {
				last = glyphs[previous.words[at]]
				if !strings.ContainsRune("\"')]}»”’", last) {
					break
				}
				last = 0
			}
			first := rune(0)
			if len(next.words) > 0 {
				first = glyphs[next.words[0]]
			}
			cost := 9
			switch {
			case last != 0 && strings.ContainsRune(".!?…", last) && !unicode.IsLower(first) && !unicode.Is(unicode.Other_Lowercase, first):
				cost = 0
			case last != 0 && strings.ContainsRune(",;:—–", last):
				cost = 4
			}
			if previous.block != next.block {
				cost = min(cost, 1)
			}
			cutCosts[i] = cost
		}
		var chunks [][]int
		if len(base) <= rows {
			chunks = append(chunks, append(slices.Clone(base), n))
		} else {
			minimumPages := (len(base) + rows - 1) / rows
			workRemaining := 1 << 20
			for pages := minimumPages; pages <= len(base) && len(cutCosts) >= pages-1 && chunks == nil; pages++ {
				// State fixes the start, page count and total lines. Cost is cuts + 2*sum(L²);
				// subtract 2*T²/K once below to score balance without floating-point ties.
				dp := make(map[state]choice)
				for k := 1; k <= pages; k++ {
					for at := n - 1; at >= 0; at-- {
						if k == 1 {
							if lines := remainingLines[at]; lines <= rows {
								dp[state{at, k, lines}] = choice{2 * lines * lines, n, lines}
							}
							continue
						}
						lineEnd, lines := nextLine[at], 1
						for end := at + 1; end <= n; end++ {
							// Storage limits alone do not bound searches with few legal cuts.
							workRemaining--
							if workRemaining < 0 {
								return nil, fmt.Errorf("page-layout work budget exceeded")
							}
							if end > lineEnd {
								lines++
								lineEnd = nextLine[lineEnd]
							}
							if lines > rows {
								break
							}
							cutCost, allowed := cutCosts[end]
							if !allowed {
								continue
							}
							for total := lines + 1; total <= k*rows; total++ {
								workRemaining--
								if workRemaining < 0 {
									return nil, fmt.Errorf("page-layout work budget exceeded")
								}
								sub, found := dp[state{end, k - 1, total - lines}]
								if !found {
									continue
								}
								key := state{at, k, total}
								cost := cutCost + 2*lines*lines + sub.cost
								if old, exists := dp[key]; !exists || cost <= old.cost {
									// Ascending ends and <= retain the reference's latest-cut tie break.
									dp[key] = choice{cost, end, lines}
								}
							}
							if len(dp) > 1<<18 {
								return nil, fmt.Errorf("page-layout state budget exceeded")
							}
						}
					}
				}
				bestTotal, bestScore := 0, 0
				for total := len(base); total <= pages*rows; total++ {
					if c, found := dp[state{0, pages, total}]; found {
						score := c.cost*pages - 2*total*total
						if bestTotal == 0 || score < bestScore {
							bestTotal, bestScore = total, score
						}
					}
				}
				if bestTotal != 0 {
					at, total := 0, bestTotal
					for k := pages; k > 0; k-- {
						c := dp[state{at, k, total}]
						var breaks []int
						for i := at; i < c.end; i = nextLine[i] {
							breaks = append(breaks, i)
						}
						chunks = append(chunks, append(breaks, c.end))
						at, total = c.end, total-c.lines
					}
				}
			}
			if chunks == nil {
				for at := 0; at < len(base); at += rows {
					end := n
					if at+rows < len(base) {
						end = base[at+rows]
					}
					chunks = append(chunks, append(slices.Clone(base[at:min(at+rows, len(base))]), end))
				}
			}
		}
		if pageStart != 0 {
			out = append(out, 0x1000)
		}
		out = append(out, words[pageStart:prefixEnd]...)
		for page, breaks := range chunks {
			if page > 0 {
				out = append(out, 0x1000)
			}
			for line := 0; line+1 < len(breaks); line++ {
				if line > 0 {
					out = append(out, 0x0800)
				}
				lineStart := len(out)
				for i := breaks[line]; i < breaks[line+1]; i++ {
					if i > breaks[line] {
						out = append(out, 0)
					}
					out = append(out, atoms[i].words...)
				}
				start, end := lineStart, len(out)
				for start < end && out[start] == 0 {
					start++
				}
				for end > start && out[end-1] == 0 {
					end--
				}
				out = append(out[:lineStart], out[start:end]...)
			}
		}
		if pageEnd == len(words) {
			break
		}
		pageStart = pageEnd + 1
	}
	if numericAt != len(numericBounds) {
		return nil, fmt.Errorf("unused numeric argument bound for wrapping")
	}
	return out, nil
}
