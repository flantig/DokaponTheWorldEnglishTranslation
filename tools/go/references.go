package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// references reports strict declared observations or advisory discovery matches.
// The legacy 64-instruction high-half heuristic does not prove liveness, reachability,
// or the absence of other references. Its results never authorize patch writes.
// GP indexing keeps metadata-assumed arithmetic/effective addresses separate from
// retained or loaded values and shares the existing ELF metadata/mapping owner.
// Instruction indexing retains unsupported effects and local transfer alternatives.
// Optional pure register-flow queries consume these facts without another decoder.
// Cohorts preserve pointer occurrences and measure an explicit nominal policy through
// inspect and controls. Their separate source-policy phase uses bounded raw buckets
// and shared instruction/graph facts. Limited buckets remain incomplete, and known
// hazards outrank unknown paths. Neither phase proves native fit or authorizes writes.
func references(data, registryData, glyphData, sidecarData []byte, profile Recipes) (ReferenceReport, error) {
	report := ReferenceReport{Operation: profile.Operation, SourceSHA256: profile.SourceSHA256,
		RegistrySHA256: profile.ScopeSHA256, GlyphmapSHA256: profile.GlyphmapSHA256,
		Summaries: map[string]ReferenceSummary{},
		Queries:   map[string][]ReferenceRow{}, Limits: "Read-only candidates; 64-instruction high-half matching is not register-liveness, control-flow or exhaustive-reference proof. Content matches are advisory; structural rows use declared layouts. No registry updates or patch authorization."}
	scan := profile.References
	flowSpec := profile.ReferenceFlow
	if profile.Operation == "reference_cohort" {
		// This is a nominal source-policy report, never native fit or write admission.
		allowed := Recipes{Operation: profile.Operation, SourceSize: profile.SourceSize, SourceSHA256: profile.SourceSHA256,
			Evidence: profile.Evidence, ELFVMADelta: profile.ELFVMADelta, References: scan, Layout: profile.Layout,
			RegistryInputs: profile.RegistryInputs, ReferenceFlow: flowSpec}
		if !reflect.DeepEqual(profile, allowed) || scan == nil || profile.Layout == nil || profile.Evidence == "" ||
			profile.SourceSize < 52 || profile.SourceSize > 64<<20 || int64(len(data)) != profile.SourceSize || len(registryData)+len(glyphData) != 0 ||
			scan.SkipWords != 0 || scan.PointerMinVMA != "" || scan.DecodeWords < 1 || scan.DecodeWords > 100 ||
			scan.AdvanceFloor < 1 || scan.AdvanceFloor > 4096 || scan.SpaceAdvance < 1 || scan.SpaceAdvance > 4096 || scan.MissingAdvance < 1 || scan.MissingAdvance > 4096 ||
			len(scan.Queries) < 1 || len(scan.Queries) > 8 {
			return ReferenceReport{}, fmt.Errorf("cohort report requires bounded nominal font and pointer-table facts without registry or patch fields")
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) != profile.SourceSHA256 {
			return ReferenceReport{}, fmt.Errorf("cohort source hash mismatch")
		}
		delta, deltaErr := number(profile.ELFVMADelta)
		blobBase, blobErr := number(scan.SidecarVMA)
		if deltaErr != nil || blobErr != nil || delta+uint64(len(data)) > 1<<32 || blobBase < delta+uint64(len(data)) || blobBase+uint64(len(sidecarData)) > 1<<32 {
			return ReferenceReport{}, fmt.Errorf("cohort source domains overlap or wrap")
		}
		if len(profile.RegistryInputs) > 1 || len(profile.RegistryInputs) != 0 && profile.RegistryInputs["sentinel"].Path == "" {
			return ReferenceReport{}, fmt.Errorf("cohort inputs permit only the pinned sentinel role")
		}
		if pin, exists := profile.RegistryInputs["sentinel"]; exists {
			if pin.Size < 1 || pin.Size > 64<<20 || int64(len(sidecarData)) != pin.Size || blobBase+uint64(pin.Size) > 1<<32 || fmt.Sprintf("%x", sha256.Sum256(sidecarData)) != pin.SHA256 {
				return ReferenceReport{}, fmt.Errorf("cohort sentinel input size or hash mismatch")
			}
			report.BlobSHA256, report.BlobSize = pin.SHA256, pin.Size
		} else if len(sidecarData) != 0 {
			return ReferenceReport{}, fmt.Errorf("cohort sentinel bytes require a declared pin")
		}
		font, err := inspect(bytes.NewReader(data), nil, &Recipes{Operation: "font_metrics", SourceSize: profile.SourceSize, ELFVMADelta: profile.ELFVMADelta, Layout: profile.Layout})
		if err != nil {
			return ReferenceReport{}, err
		}
		advances := make(map[uint16]int, 2048)
		for glyph := uint16(0); glyph < 2048; glyph++ {
			advance := scan.MissingAdvance
			if metric, exists := font.GlyphMetrics[glyph]; exists {
				advance = max(scan.AdvanceFloor, int(metric[0])+int(metric[1])+3) - int(metric[0])
			}
			if glyph == 0 {
				advance = scan.SpaceAdvance
			}
			if advance <= 0 {
				return ReferenceReport{}, fmt.Errorf("cohort nominal advances must be positive")
			}
			advances[glyph] = advance
		}
		report.Measurement = "historical_nominal_pen_units"
		report.NominalPolicy = map[string]int{"advance_floor": scan.AdvanceFloor, "space_advance": scan.SpaceAdvance, "missing_advance": scan.MissingAdvance, "max_words_including_end": scan.DecodeWords}
		report.Limits = "Read-only pointer occurrences and declared historical nominal policy. LINE resets pen width; the result is the maximum line, not their sum. Raw metric admission is stricter than legacy buffer reads. These units are not native grid, PS2 arithmetic, physical fit, exhaustive ownership or patch authorization."
		var names []string
		for name := range scan.Queries {
			if name == "" || len(name) > 64 || !utf8.ValidString(name) {
				return ReferenceReport{}, fmt.Errorf("cohort query names require 1..64 UTF-8 bytes")
			}
			names = append(names, name)
		}
		slices.Sort(names)
		// Admit all geometry before allocating rows or walking any stream.
		total, tableCount := uint64(0), 0
		for _, name := range names {
			query := scan.Queries[name]
			allowedQuery := ReferenceQuery{ContentRange: query.ContentRange, PointerTables: query.PointerTables, ExpectedCount: query.ExpectedCount,
				ExpectedMaxWidth: query.ExpectedMaxWidth, NominalScale: query.NominalScale, ScaledLimit: query.ScaledLimit}
			lo, loErr := number(query.ContentRange.Start)
			hi, hiErr := number(query.ContentRange.End)
			if !reflect.DeepEqual(query, allowedQuery) || loErr != nil || hiErr != nil || lo < delta || lo >= hi || hi > blobBase ||
				query.ExpectedCount < 1 || query.ExpectedCount > 4096 || query.ExpectedMaxWidth < 0 || query.ExpectedMaxWidth > 1<<24 ||
				math.IsNaN(query.NominalScale) || math.IsInf(query.NominalScale, 0) || query.NominalScale <= 0 || query.NominalScale > 1e6 ||
				math.IsNaN(query.ScaledLimit) || math.IsInf(query.ScaledLimit, 0) || query.ScaledLimit < 0 || query.ScaledLimit > 1<<30 || len(query.PointerTables) == 0 {
				return ReferenceReport{}, fmt.Errorf("cohort query requires exclusive pointer tables, retail domain and bounded nominal comparisons")
			}
			seenTables := make(map[string]bool)
			for _, table := range query.PointerTables {
				a, aErr := number(table.Start)
				b, bErr := number(table.End)
				if aErr != nil || bErr != nil || table.Name == "" || len(table.Name) > 64 || !utf8.ValidString(table.Name) || seenTables[table.Name] ||
					table.Stride < 4 || table.Stride > 4096 || table.Stride%4 != 0 || a%4 != 0 || a < delta || a >= b || b > delta+uint64(len(data)) || (b-a)%uint64(table.Stride) != 0 {
					return ReferenceReport{}, fmt.Errorf("cohort pointer tables require distinct names and bounded aligned half-open slots")
				}
				seenTables[table.Name] = true
				total += (b - a) / uint64(table.Stride)
				tableCount++
				if total > 4096 || tableCount > 32 {
					return ReferenceReport{}, fmt.Errorf("cohort report exceeds 32 tables or 4096 occurrences")
				}
			}
		}
		// A target is measured once, while every source occurrence keeps its own slot.
		measured := make(map[uint64]ReferenceRow)
		for _, name := range names {
			query := scan.Queries[name]
			lo, _ := number(query.ContentRange.Start)
			hi, _ := number(query.ContentRange.End)
			rows := []ReferenceRow{}
			summary := ReferenceSummary{ByType: map[string]int{"raw_pointer": 0}, Diagnostics: []string{}}
			maximum, complete := 0, true
			for _, table := range query.PointerTables {
				a, _ := number(table.Start)
				b, _ := number(table.End)
				for slot, index := a, 0; slot < b; slot, index = slot+uint64(table.Stride), index+1 {
					pointer := uint64(binary.LittleEndian.Uint32(data[slot-delta:]))
					row := ReferenceRow{Method: "pointer-table", RefType: "raw_pointer", Target: fmt.Sprintf("0x%x", pointer), Diagnostics: []string{}}
					if !(lo <= pointer && pointer < hi || blobBase <= pointer && pointer < blobBase+uint64(len(sidecarData))) {
						row.Diagnostics = append(row.Diagnostics, "pointer_outside_domain")
					} else if cached, exists := measured[pointer]; exists {
						row = cached
					} else {
						backing, offset := data, pointer-delta
						row.BackingSource = "retail"
						if pointer >= blobBase {
							backing, offset, row.BackingSource = sidecarData, pointer-blobBase, "sentinel"
						}
						start, terminated := offset, false
						for count := 0; count < scan.DecodeWords; count++ {
							if offset > uint64(len(backing)) || uint64(len(backing))-offset < 2 {
								row.Diagnostics = append(row.Diagnostics, "truncated_read")
								break
							}
							word := binary.LittleEndian.Uint16(backing[offset:])
							offset += 2
							row.WordCount++
							if word == 0xf800 {
								terminated = true
								break
							}
							if word >= 0x0800 && word != 0x0800 {
								row.Diagnostics = append(row.Diagnostics, "unsupported_control")
								break
							}
						}
						if len(row.Diagnostics) == 0 && !terminated {
							row.Diagnostics = append(row.Diagnostics, "unterminated")
						}
						if terminated {
							shape, err := controls(backing[start:offset], TextScanOptions{Terminated: true, Advances: advances})
							if err != nil {
								return ReferenceReport{}, fmt.Errorf("cohort bounded grammar: %w", err)
							}
							row.LineWidths = shape.LineWidths[0]
							row.NominalMaximum = &shape.Width
						}
						measured[pointer] = row
					}
					row.ID, row.TableName = fmt.Sprintf("0x%x", slot), table.Name
					// Keep the index value independent of the loop's later increments.
					ordinal := index
					row.Occurrence = &ordinal
					row.Sites = []ReferenceCandidate{{ReferenceSite: ReferenceSite{PointerVMA: row.ID}}}
					rows = append(rows, row)
					summary.Total++
					summary.ByType["raw_pointer"]++
					if row.NominalMaximum == nil {
						complete = false
						summary.Unresolved++
						for _, issue := range row.Diagnostics {
							summary.Diagnostics = append(summary.Diagnostics, row.ID+":"+issue)
						}
					} else {
						summary.Resolved++
						maximum = max(maximum, *row.NominalMaximum)
					}
				}
			}
			policyOK := complete
			if summary.Total != query.ExpectedCount {
				summary.Diagnostics = append(summary.Diagnostics, "occurrence_count_mismatch")
				policyOK = false
			}
			if complete {
				scaled := float64(maximum) * query.NominalScale
				summary.NominalMaximum, summary.NominalScaled = &maximum, &scaled
				if maximum != query.ExpectedMaxWidth {
					summary.Diagnostics = append(summary.Diagnostics, "maximum_mismatch")
					policyOK = false
				}
				if scaled > query.ScaledLimit {
					summary.Diagnostics = append(summary.Diagnostics, "scaled_limit_exceeded")
					policyOK = false
				}
			}
			summary.NominalPolicyOK = &policyOK
			report.Queries[name], report.Summaries[name] = rows, summary
		}
		if flowSpec != nil {
			const maxSourceBucketSites = 256
			if len(flowSpec.EntryVMAs) < 1 || len(flowSpec.EntryVMAs) > 256 || len(flowSpec.Entries) < 1 || len(flowSpec.Entries) > 16 || flowSpec.MaxVisitedStates < 1 || flowSpec.MaxVisitedStates > 100000 || flowSpec.CallRules != nil {
				return ReferenceReport{}, fmt.Errorf("cohort source policy requires bounded entries, targets and work without consumer call rules")
			}
			textStart, textErr := number(scan.FileRange.Start)
			textEnd, textEndErr := number(scan.FileRange.End)
			rawStart, rawErr := number(scan.RawFileRange.Start)
			rawEnd, rawEndErr := number(scan.RawFileRange.End)
			pointerStart, pointerErr := number(scan.RawPointerRange.Start)
			pointerEnd, pointerEndErr := number(scan.RawPointerRange.End)
			dataStart, dataErr := number(scan.DataRange.Start)
			dataEnd, dataEndErr := number(scan.DataRange.End)
			if textErr != nil || textEndErr != nil || rawErr != nil || rawEndErr != nil || pointerErr != nil || pointerEndErr != nil || dataErr != nil || dataEndErr != nil ||
				textStart%4 != 0 || textEnd%4 != 0 || textStart >= textEnd || textEnd > uint64(len(data)) || rawStart%4 != 0 || rawEnd%4 != 0 || rawStart >= rawEnd || rawEnd > uint64(len(data)) ||
				pointerStart >= pointerEnd || pointerEnd-pointerStart > 1<<20 || pointerStart != blobBase || dataStart >= dataEnd || dataStart < rawStart+delta || dataEnd > rawEnd+delta {
				return ReferenceReport{}, fmt.Errorf("cohort ownership requires bounded text, raw scan, data and raw-pointer domains")
			}
			seenEntries := make(map[uint64]bool)
			for _, text := range flowSpec.EntryVMAs {
				vma, err := number(text)
				if err != nil || vma%4 != 0 || vma < delta+textStart || vma >= delta+textEnd || seenEntries[vma] {
					return ReferenceReport{}, fmt.Errorf("cohort ownership entries must be distinct selected words")
				}
				seenEntries[vma] = true
			}
			var targets []uint32
			policies := make(map[uint32]ReferenceFlowRecipe)
			declaredPointers := make(map[uint32]map[uint64]bool)
			labels := make(map[uint32]string)
			for name, recipe := range flowSpec.Entries {
				target, err := number(name)
				_, duplicate := policies[uint32(target)]
				if err != nil || duplicate || recipe.ExpectedPairs == nil || recipe.ExpectedPointers == nil || len(recipe.ExpectedPairs)+len(recipe.ExpectedPointers) > maxSourceBucketSites ||
					recipe.BenignReaderPairs != nil || recipe.ZeroPaddingAllowance != 0 || recipe.ConsumerSeeds != nil {
					return ReferenceReport{}, fmt.Errorf("cohort source policy requires distinct targets and explicit expected pair/pointer buckets")
				}
				seenPairs, seenPointers := make(map[[3]uint32]bool), make(map[uint64]bool)
				for _, pair := range recipe.ExpectedPairs {
					key := [3]uint32{pair.LUIVMA, pair.LowerVMA, pair.Opcode}
					if pair.Target != uint32(target) || pair.Opcode != 9 && pair.Opcode != 13 || pair.LUIVMA%4 != 0 || pair.LowerVMA%4 != 0 ||
						uint64(pair.LUIVMA) < delta+textStart || uint64(pair.LUIVMA) >= delta+textEnd || uint64(pair.LowerVMA) < delta+textStart || uint64(pair.LowerVMA) >= delta+textEnd || seenPairs[key] {
						return ReferenceReport{}, fmt.Errorf("cohort expected pairs require distinct selected ADDIU/ORI coordinates and the declared target")
					}
					seenPairs[key] = true
				}
				for _, text := range recipe.ExpectedPointers {
					vma, err := number(text)
					if err != nil || vma%4 != 0 || vma < dataStart || vma >= dataEnd || seenPointers[vma] {
						return ReferenceReport{}, fmt.Errorf("cohort expected raw pointers require distinct data words")
					}
					seenPointers[vma] = true
				}
				targets = append(targets, uint32(target))
				policies[uint32(target)], labels[uint32(target)] = recipe, name
				declaredPointers[uint32(target)] = seenPointers
			}
			slices.Sort(targets)
			// One raw-word pass preserves the legacy SENT-only index scope.
			rawPointers := make(map[uint32][]uint32)
			rawProblems := make(map[uint32][]string)
			rawLimited := make(map[uint32]bool)
			rawUnexpected := make(map[uint32]uint32)
			rawOverflowText := make(map[uint32]uint32)
			for at := rawStart; at < rawEnd; at += 4 {
				value := binary.LittleEndian.Uint32(data[at:])
				if _, selected := policies[value]; !selected || uint64(value) < pointerStart || uint64(value) >= pointerEnd {
					continue
				}
				vma := uint32(at + delta)
				inData := uint64(vma) >= dataStart && uint64(vma) < dataEnd
				if inData && !declaredPointers[value][uint64(vma)] {
					if _, found := rawUnexpected[value]; !found {
						rawUnexpected[value] = vma
					}
				}
				if len(rawPointers[value])+len(rawProblems[value]) >= maxSourceBucketSites {
					rawLimited[value] = true
					// Later matches retain only bounded numeric witnesses, never more site strings.
					if !inData {
						if _, found := rawOverflowText[value]; !found {
							rawOverflowText[value] = vma
						}
					}
					continue
				}
				if inData {
					rawPointers[value] = append(rawPointers[value], vma)
				} else {
					rawProblems[value] = append(rawProblems[value], fmt.Sprintf("raw_pointer_inside_text:0x%x", vma))
				}
			}
			words := make(map[uint32]InstructionObservation)
			batch := RegisterFlowSpec{EntryVMAs: flowSpec.EntryVMAs, Queries: map[string]RegisterFlowQuery{}}
			lowSites := make(map[uint32][]uint32)
			wantedHigh := make(map[[2]uint32]uint32)
			graphLimit := ""
			if (textEnd-textStart)/4 > 32768 {
				graphLimit = "source_policy_word_limit"
			} else {
				facts, err := indexInstructions(data, Recipes{Operation: "instruction_index", SourceSize: profile.SourceSize, SourceSHA256: profile.SourceSHA256,
					Evidence: profile.Evidence, References: &ReferenceScan{FileRange: scan.FileRange}})
				if err != nil {
					return ReferenceReport{}, err
				}
				report.InstructionIndex = facts.InstructionIndex
				wantedBases := make(map[[2]uint32]bool)
				for _, word := range facts.InstructionIndex.Instructions {
					if word.VMA != word.FileOffset+delta {
						return ReferenceReport{}, fmt.Errorf("cohort ownership scan disagrees with declared affine source mapping")
					}
					words[uint32(word.VMA)] = word
					if word.Opcode != 9 && word.Opcode != 13 && (word.Opcode < 0x20 || word.Opcode > 0x3f) {
						continue
					}
					for _, target := range targets {
						if word.Word&0xffff != target&0xffff {
							continue
						}
						lowSites[target] = append(lowSites[target], uint32(word.VMA))
						label := fmt.Sprintf("defs/%d/0x%x", word.RS, word.VMA)
						batch.Queries[label] = RegisterFlowQuery{Kind: "reaching_defs", Register: word.RS, VMA: fmt.Sprintf("0x%x", word.VMA), Context: "any_reachable", MaxVisitedStates: flowSpec.MaxVisitedStates}
						want := (uint64(target) + 0x8000) >> 16 & 0xffff
						if word.Opcode == 13 {
							want = uint64(target >> 16)
						}
						wantedHigh[[2]uint32{target, uint32(word.VMA)}] = uint32(want)
						wantedBases[[2]uint32{word.RS, uint32(want)}] = true
					}
				}
				for _, word := range facts.InstructionIndex.Instructions {
					if word.Opcode == 15 && word.RS == 0 && word.RT != 0 && wantedBases[[2]uint32{word.RT, word.Word & 0xffff}] {
						label := fmt.Sprintf("uses/%d/0x%x", word.RT, word.VMA)
						batch.Queries[label] = RegisterFlowQuery{Kind: "uses_after", Register: word.RT, VMA: fmt.Sprintf("0x%x", word.VMA), Context: "any_reachable", MaxVisitedStates: flowSpec.MaxVisitedStates}
					}
				}
				if len(batch.Queries) > 64 {
					graphLimit = "source_policy_query_limit"
				}
			}
			graph := RegisterFlowReport{Queries: map[string]RegisterFlowResult{}}
			if graphLimit == "" && len(batch.Queries) != 0 {
				var err error
				graph, err = queryRegisterFlow(report.InstructionIndex.Instructions, batch)
				if err != nil {
					return ReferenceReport{}, err
				}
				report.InstructionIndex.RegisterFlow = &graph
			}
			report.SourcePolicy = make(map[string]ReferenceFlowRow)
			for _, target := range targets {
				pointers := append([]uint32{}, rawPointers[target]...)
				result := ReferenceFlowRow{CallerDisposition: "eligible_under_declared_source_policy", RawPointerSites: &pointers, RawIndexStatus: "within_declared_index",
					Diagnostics: append([]string{}, rawProblems[target]...), DefinitionQueries: map[string]string{}, UseQueries: map[string]string{},
					ConstructedTargets: []ReferenceFlowTarget{}, Readers: []ReferenceFlowReader{}, CanonicalPairErrors: map[string]string{}}
				var unknown []string
				if rawLimited[target] {
					result.RawIndexStatus = "limited"
					unknown = append(unknown, "raw_pointer_site_limit")
				}
				if at, found := rawOverflowText[target]; found {
					result.Diagnostics = append(result.Diagnostics, fmt.Sprintf("raw_pointer_inside_text:0x%x", at))
				}
				if uint64(target) < pointerStart || uint64(target) >= pointerEnd {
					result.RawIndexStatus = "outside_declared_index"
					unknown = append(unknown, "raw_pointer_index_out_of_scope")
				}
				if graphLimit != "" {
					unknown = append(unknown, graphLimit)
				}
				owned := make(map[uint32]map[uint32]bool)
				for _, low := range lowSites[target] {
					if graphLimit != "" {
						break
					}
					word := words[low]
					label := fmt.Sprintf("defs/%d/0x%x", word.RS, low)
					result.DefinitionQueries[fmt.Sprintf("0x%x", low)] = label
					query := graph.Queries[label]
					for _, reason := range query.IncompleteReasons {
						unknown = append(unknown, fmt.Sprintf("definition_unknown:0x%x:%s", low, reason))
					}
					if len(query.IncomingEntrySites) != 0 {
						unknown = append(unknown, fmt.Sprintf("definition_incoming_entry:0x%x", low))
					}
					var hits []uint32
					want := wantedHigh[[2]uint32{target, low}]
					for _, at := range query.KnownFactSites {
						high := words[at]
						if high.Opcode == 15 && high.RT == word.RS && high.Word&0xffff == want {
							hits = append(hits, at)
						}
					}
					if len(hits) == 0 {
						continue
					}
					if len(hits) != len(query.KnownFactSites)+len(query.IncomingEntrySites) {
						result.Diagnostics = append(result.Diagnostics, fmt.Sprintf("ambiguous_definition:0x%x", low))
						continue
					}
					if word.Opcode != 9 && word.Opcode != 13 {
						result.Diagnostics = append(result.Diagnostics, fmt.Sprintf("direct_memory_reader:0x%x", low))
						continue
					}
					// Unlike canonical patch policy, all equal matching LUI definitions are retained.
					slices.Sort(hits)
					for _, high := range hits {
						if owned[high] == nil {
							owned[high] = make(map[uint32]bool)
						}
						owned[high][low] = true
						result.ConstructedTargets = append(result.ConstructedTargets, ReferenceFlowTarget{LUIVMA: high, LowerVMA: low, Target: target, Opcode: word.Opcode})
					}
				}
				var highs []uint32
				for high := range owned {
					highs = append(highs, high)
				}
				slices.Sort(highs)
				for _, high := range highs {
					label := fmt.Sprintf("uses/%d/0x%x", words[high].RT, high)
					result.UseQueries[fmt.Sprintf("0x%x", high)] = label
					query := graph.Queries[label]
					for _, use := range query.KnownFactSites {
						relation := "owned"
						if !owned[high][use] {
							relation = "foreign"
							result.Diagnostics = append(result.Diagnostics, fmt.Sprintf("foreign_use:0x%x:0x%x", high, use))
						}
						result.Readers = append(result.Readers, ReferenceFlowReader{LUIVMA: high, UseVMA: use, Relation: relation, Owners: map[string]string{}})
					}
					for _, reason := range query.IncompleteReasons {
						unknown = append(unknown, fmt.Sprintf("later_use_unknown:0x%x:%s", high, reason))
					}
				}
				// Coordinate/opcode membership is deterministic; source Python set order is not promised.
				policy := policies[target]
				for _, pair := range result.ConstructedTargets {
					if !slices.Contains(policy.ExpectedPairs, pair) {
						result.Diagnostics = append(result.Diagnostics, fmt.Sprintf("unexpected_pair:0x%x:0x%x:%d", pair.LUIVMA, pair.LowerVMA, pair.Opcode))
					}
				}
				for _, pair := range policy.ExpectedPairs {
					if !slices.Contains(result.ConstructedTargets, pair) {
						unknown = append(unknown, fmt.Sprintf("expected_pair_not_observed:0x%x:0x%x:%d", pair.LUIVMA, pair.LowerVMA, pair.Opcode))
					}
				}
				expectedPointers := make([]uint32, 0, len(policy.ExpectedPointers))
				for vma := range declaredPointers[target] {
					expectedPointers = append(expectedPointers, uint32(vma))
				}
				slices.Sort(expectedPointers)
				_, unexpectedPointer := rawUnexpected[target]
				if unexpectedPointer || result.RawIndexStatus == "within_declared_index" && !slices.Equal(pointers, expectedPointers) {
					result.Diagnostics = append(result.Diagnostics, "raw_pointer_bucket_mismatch")
				}
				if at, found := rawUnexpected[target]; found {
					result.Diagnostics = append(result.Diagnostics, fmt.Sprintf("raw_pointer_unexpected_site:0x%x", at))
				}
				if len(result.Diagnostics) != 0 {
					result.CallerDisposition = "refuse"
				} else if len(unknown) != 0 {
					result.CallerDisposition = "unknown"
				}
				result.Diagnostics = append(result.Diagnostics, unknown...)
				report.SourcePolicy[labels[target]] = result
			}
			report.Limits += " Source-policy buckets use the declared raw-index window and one bounded existing instruction/graph producer. Sorted equal-definition pairs normalize Python set order. Unknown call/entry/unsupported/work-limit paths remain unknown, and known problems outrank unknowns. No corrected whole-program ownership parity or landing approval is claimed."
		} else if scan.FileRange != (AddressRange{}) || scan.RawFileRange != (AddressRange{}) || scan.RawPointerRange != (AddressRange{}) || scan.DataRange != (AddressRange{}) {
			return ReferenceReport{}, fmt.Errorf("cohort ownership domains require an explicit source-policy request")
		}
		return report, nil
	}
	if len(sidecarData) != 0 || scan != nil && (scan.AdvanceFloor != 0 || scan.SpaceAdvance != 0 || scan.MissingAdvance != 0 || scan.SidecarVMA != "" || scan.RawFileRange != (AddressRange{}) || scan.RawPointerRange != (AddressRange{}) || scan.DataRange != (AddressRange{})) {
		return ReferenceReport{}, fmt.Errorf("nominal cohort facts and sentinel bytes belong only to reference_cohort")
	}
	if scan != nil {
		for _, query := range scan.Queries {
			if query.PointerTables != nil || query.ExpectedCount != 0 || query.ExpectedMaxWidth != 0 || query.NominalScale != 0 || query.ScaledLimit != 0 {
				return ReferenceReport{}, fmt.Errorf("pointer-table comparisons belong only to reference_cohort")
			}
			for _, table := range query.StructRows {
				if table.Name != "" {
					return ReferenceReport{}, fmt.Errorf("named pointer tables cannot replace registry struct rows")
				}
			}
		}
	}
	if flowSpec != nil {
		for _, entry := range flowSpec.Entries {
			if entry.ExpectedPairs != nil || entry.ExpectedPointers != nil {
				return ReferenceReport{}, fmt.Errorf("source-policy expected sites belong only to reference_cohort")
			}
		}
	}
	inline := profile.Operation == "reference_inline16"
	observed := profile.Operation == "reference_observed" || inline
	gpIndex := profile.Operation == "reference_gp_index"
	wordIndex := profile.Operation == "instruction_index"
	indexed := gpIndex || wordIndex
	label := "GP"
	if wordIndex {
		label = "Instruction"
	}
	if observed {
		allowed := Recipes{Operation: profile.Operation, SourceSize: profile.SourceSize, SourceSHA256: profile.SourceSHA256, ScopeSHA256: profile.ScopeSHA256, Evidence: profile.Evidence, RegistryPatchRef: profile.RegistryPatchRef}
		if !reflect.DeepEqual(profile, allowed) || profile.RegistryPatchRef == "" || profile.Evidence == "" || profile.SourceSize < 52 || profile.SourceSize > 64<<20 || int64(len(data)) != profile.SourceSize || len(registryData) > 64<<20 || len(glyphData) != 0 {
			return ReferenceReport{}, fmt.Errorf("observed report requires a bounded ELF, pinned registry and one family without search or patch fields")
		}
	} else if indexed {
		if scan == nil {
			return ReferenceReport{}, fmt.Errorf("%s index requires a declared file range", label)
		}
		allowed := Recipes{Operation: profile.Operation, SourceSize: profile.SourceSize, SourceSHA256: profile.SourceSHA256, Evidence: profile.Evidence, References: &ReferenceScan{FileRange: scan.FileRange}, AddressRanges: profile.AddressRanges}
		if wordIndex {
			allowed.AddressRanges = nil
			allowed.RegisterFlow = profile.RegisterFlow
		}
		if !reflect.DeepEqual(profile, allowed) || profile.Evidence == "" || profile.SourceSize < 52 || profile.SourceSize > 64<<20 || int64(len(data)) != profile.SourceSize || len(registryData)+len(glyphData) != 0 || len(profile.AddressRanges) > 8 {
			if wordIndex {
				return ReferenceReport{}, fmt.Errorf("Instruction index requires one bounded ELF and file range without point queries, registry, glyphs or patch fields")
			}
			return ReferenceReport{}, fmt.Errorf("GP index requires one bounded ELF, a file range and at most eight point queries without registry, glyphs or patch fields")
		}
		for name := range profile.AddressRanges {
			if name == "" || len(name) > 128 {
				return ReferenceReport{}, fmt.Errorf("GP point query names require 1..128 bytes")
			}
		}
	} else if profile.RegisterFlow != nil || profile.Sentinel != nil || profile.RegistryInputs != nil || profile.RegistryImport != nil || profile.RegistryColumns != nil || profile.AddressRanges != nil || profile.WordingField != "" || profile.Operation != "reference_candidates" || scan == nil || profile.Evidence == "" || profile.SourceContext ||
		profile.RegistryUpdates != nil || profile.Updated != "" || profile.RegistryPatchRef != "" || profile.Stream != nil || profile.Layout != nil || profile.Growth != nil ||
		len(profile.Entries)+len(profile.Values)+len(profile.WordBlocks) != 0 || profile.ISOELFOffset != "0x0" ||
		profile.SourceSize <= 0 || profile.SourceSize > 64<<20 || int64(len(data)) != profile.SourceSize || len(registryData) > 64<<20 {
		return ReferenceReport{}, fmt.Errorf("reference report requires one bounded ELF profile without patch fields")
	}
	if flowSpec != nil {
		allowed := Recipes{Operation: "reference_candidates", SourceSize: profile.SourceSize, SourceSHA256: profile.SourceSHA256,
			ScopeSHA256: profile.ScopeSHA256, GlyphmapSHA256: profile.GlyphmapSHA256, Evidence: profile.Evidence,
			ISOELFOffset: "0x0", ELFVMADelta: profile.ELFVMADelta, References: scan, ReferenceFlow: flowSpec, PointerState: profile.PointerState}
		if !reflect.DeepEqual(profile, allowed) || profile.SourceSize < 52 || len(glyphData) > 64<<20 ||
			len(flowSpec.Entries) < 1 || len(flowSpec.Entries) > 64 || len(flowSpec.EntryVMAs) < 1 || len(flowSpec.EntryVMAs) > 256 ||
			flowSpec.MaxVisitedStates < 1 || flowSpec.MaxVisitedStates > 100000 || profile.PointerState != "" && profile.PointerState != "registry_landing" {
			return ReferenceReport{}, fmt.Errorf("reference flow requires a bounded pinned reference profile, entries and work limit")
		}
		if err := checkJSON(checkedJSON{raw: registryData, text: true, aliasesByDepth: map[int][]string{
			1: {"entries"}, 3: {"id", "en", "jp", "status", "ref_type", "ref_sites", "landing_vma", "source_pool", "chapter", "patch_ref"},
			5: {"pointer_vma", "struct_vma", "field_offset", "lui_vma", "addiu_vma", "reg"}}}); err != nil {
			return ReferenceReport{}, err
		}
		if err := checkJSON(checkedJSON{raw: glyphData, text: true, allObjects: true}); err != nil {
			return ReferenceReport{}, err
		}
	}
	for _, input := range []struct {
		name string
		data []byte
		pin  string
	}{{"source", data, profile.SourceSHA256}, {"registry", registryData, profile.ScopeSHA256}, {"glyphmap", glyphData, profile.GlyphmapSHA256}} {
		if observed && input.name == "glyphmap" || indexed && input.name != "source" {
			continue
		}
		if fmt.Sprintf("%x", sha256.Sum256(input.data)) != input.pin {
			return ReferenceReport{}, fmt.Errorf("reference %s hash mismatch", input.name)
		}
	}
	if indexed {
		indexReport, err := indexInstructions(data, profile)
		if err != nil {
			return ReferenceReport{}, err
		}
		report = indexReport

		if wordIndex && profile.RegisterFlow != nil {
			flow, err := queryRegisterFlow(report.InstructionIndex.Instructions, *profile.RegisterFlow)
			if err != nil {
				return ReferenceReport{}, err
			}
			report.InstructionIndex.RegisterFlow = &flow
			report.Limits = strings.Replace(report.Limits, "No CFG, reaching definitions, later-use/liveness, memory values, ABI, placement or patch authority.", "No memory values, ABI, placement or patch authority.", 1)
			report.Limits += " Optional register-flow facts are conditional on asserted normal entries and the supported low32 execution model; whole-program scope remains unproved. No synthesized call returns or ABI clobbers."
		}
		return report, nil
	}
	if observed {
		if err := checkJSON(checkedJSON{raw: registryData, text: true, aliasesByDepth: map[int][]string{1: {"entries"}}}); err != nil {
			return ReferenceReport{}, err
		}
		var document struct {
			Entries []json.RawMessage `json:"entries"`
		}
		if err := json.Unmarshal(registryData, &document); err != nil || document.Entries == nil {
			return ReferenceReport{}, fmt.Errorf("observed registry requires an entries array")
		}
		entries := make(map[uint64]RegistryEntry)
		rawEntries := make(map[uint64]json.RawMessage)
		var ids []uint64
		for _, raw := range document.Entries {
			if err := checkJSON(checkedJSON{raw: raw, aliasesByDepth: map[int][]string{1: {"id", "en", "jp", "patch_ref", "landing_vma", "ref_type", "ref_sites"}}}); err != nil {
				return ReferenceReport{}, err
			}
			var entry RegistryEntry
			if err := json.Unmarshal(raw, &entry); err != nil {
				return ReferenceReport{}, err
			}
			id, err := number(entry.ID)
			if _, duplicate := entries[id]; err != nil || duplicate {
				return ReferenceReport{}, fmt.Errorf("invalid or duplicate observed ID %q", entry.ID)
			}
			entries[id], rawEntries[id] = entry, raw
			ids = append(ids, id)
		}
		slices.Sort(ids)
		rows := []ReferenceRow{}
		siteRanges := make(map[string]AddressRange)
		siteCount := 0
		gpRelative := false
		for _, id := range ids {
			entry := entries[id]
			if entry.PatchRef != profile.RegistryPatchRef {
				continue
			}
			gpRelative = gpRelative || entry.RefType == "gp_relative"
			siteCount += len(entry.RefSites)
			if len(rows) >= 256 || siteCount > 256 {
				return ReferenceReport{}, fmt.Errorf("observed report exceeds 256 entries or declared sites")
			}
			var raw struct {
				Sites []json.RawMessage `json:"ref_sites"`
			}
			if err := json.Unmarshal(rawEntries[id], &raw); err != nil {
				return ReferenceReport{}, err
			}
			siteNames := []string{"pointer_vma", "struct_vma", "field_offset", "lui_vma", "addiu_vma", "reg"}
			if inline {
				siteNames = append(siteNames, "stride")
			}
			for _, site := range raw.Sites {
				if err := checkJSON(checkedJSON{raw: site, aliasesByDepth: map[int][]string{1: siteNames}}); err != nil {
					return ReferenceReport{}, err
				}
			}
			if inline {
				if entry.RefType != "struct_table_field" || len(entry.RefSites) != 1 {
					return ReferenceReport{}, fmt.Errorf("%s: inline16 requires one declared struct field", entry.ID)
				}
				var field struct {
					Stride string `json:"stride"`
				}
				if err := json.Unmarshal(raw.Sites[0], &field); err != nil {
					return ReferenceReport{}, err
				}
				stride, strideErr := number(field.Stride)
				object, objectErr := number(entry.RefSites[0].StructVMA)
				if strideErr != nil || stride != 16 || objectErr != nil || object != id {
					return ReferenceReport{}, fmt.Errorf("%s: inline16 stride/object ownership differs", entry.ID)
				}
			}
			row := ReferenceRow{ID: entry.ID, RefType: entry.RefType, Method: "declared-observed", Sites: []ReferenceCandidate{}}
			if inline {
				row.Method = "declared-inline16"
			}
			if len(entry.RefSites) == 0 {
				row.Note = "no declared sites; no target inferred"
			}
			for ordinal, site := range entry.RefSites {
				observation := ReferenceObservation{Ordinal: ordinal, Site: site}
				kind := entry.RefType
				if inline {
					kind = "inline16"
				}
				geometry, err := normalizeReference(kind, site, 0)
				if err != nil {
					observation.Error = err.Error()
				} else {
					observation.Geometry = geometry
					for wordIndex, vma := range geometry.VMAs {
						name := fmt.Sprintf("%d/%d/%d", len(rows), ordinal, wordIndex)
						siteRanges[name] = AddressRange{Start: fmt.Sprintf("0x%x", vma), End: fmt.Sprintf("0x%x", vma+4)}
					}
				}
				row.ObservedSites = append(row.ObservedSites, observation)
			}
			rows = append(rows, row)
		}
		if len(rows) == 0 {
			return ReferenceReport{}, fmt.Errorf("observed family selects no registry entries")
		}
		mappingProfile := Recipes{Operation: "elf_layout", SourceSize: profile.SourceSize, SourceSHA256: profile.SourceSHA256, Evidence: profile.Evidence, AddressRanges: siteRanges}
		mapped, err := inspect(bytes.NewReader(data), nil, &mappingProfile)
		if err != nil {
			return ReferenceReport{}, err
		}
		targetRanges := make(map[string]AddressRange)
		if gpRelative {
			report.RegisterInfo = mapped.RegisterInfo
		}
		summary := ReferenceSummary{ByType: make(map[string]int)}
		for rowIndex := range rows {
			row := &rows[rowIndex]
			failed := len(row.ObservedSites) == 0
			for i := range row.ObservedSites {
				observation := &row.ObservedSites[i]
				summary.ObservedSites++
				words := make([]uint32, len(observation.Geometry.VMAs))
				for j := range observation.Geometry.VMAs {
					pieces := mapped.ELFMappings[fmt.Sprintf("%d/%d/%d", rowIndex, i, j)]
					observation.WordMappings = append(observation.WordMappings, pieces)
					var word *uint32
					if len(pieces) == 1 && pieces[0].Storage == "file_backed" {
						at := pieces[0].FileRange[0]
						words[j] = binary.LittleEndian.Uint32(data[at : at+4])
						word = &words[j]
					} else if observation.Error == "" {
						observation.Error = "complete site word is not file-backed"
					}
					observation.Words = append(observation.Words, word)
				}
				if observation.Error == "" && row.RefType == "gp_relative" {
					if mapped.RegisterInfo == nil || mapped.RegisterInfo.GlobalPointer == nil || mapped.RegisterInfo.Error != "" {
						observation.Error = "GP-relative target requires unique readable ELF register-info metadata"
					} else {
						observation.Geometry.GlobalPointer = mapped.RegisterInfo.GlobalPointer
					}
				}
				if observation.Error == "" && !inline {
					target, err := referenceTarget(observation.Geometry, words)
					if err != nil {
						observation.Error = err.Error()
					} else {
						observation.Target = &target
						if !slices.Contains(row.ObservedTargets, target) {
							row.ObservedTargets = append(row.ObservedTargets, target)
						}
						targetRanges[fmt.Sprintf("%d/%d", rowIndex, i)] = AddressRange{Start: fmt.Sprintf("0x%x", target), End: fmt.Sprintf("0x%x", uint64(target)+1)}
					}
				}
				if observation.Error != "" {
					failed = true
					summary.FailedSites++
				}
			}
			row.Divergent = len(row.ObservedTargets) > 1
			summary.Total++
			summary.ByType[row.RefType]++
			if failed {
				summary.Unresolved++
			} else {
				summary.Resolved++
			}
			if len(row.ObservedSites) > 1 {
				summary.MultiSite++
			}
			if row.Divergent {
				summary.DivergentRows++
			}
		}
		if len(targetRanges) != 0 {
			mappingProfile.AddressRanges = targetRanges
			mapped, err = inspect(bytes.NewReader(data), nil, &mappingProfile)
			if err != nil {
				return ReferenceReport{}, err
			}
			for rowIndex := range rows {
				for i := range rows[rowIndex].ObservedSites {
					observation := &rows[rowIndex].ObservedSites[i]
					if observation.Target != nil {
						observation.TargetMapping = mapped.ELFMappings[fmt.Sprintf("%d/%d", rowIndex, i)]
					}
				}
			}
		}
		report.Queries[profile.RegistryPatchRef], report.Summaries[profile.RegistryPatchRef] = rows, summary
		report.Limits = "Read-only declared site facts, not discovered/exhaustive references, register liveness, agreed targets or patch authorization. Resolved means all declared words interpreted; divergent targets remain explicit and repeated sites stay ordered. Null words/targets are unknown, never ID fallback. Target mappings classify one byte only, not a whole stream, sentinel transport, wording, fit or gameplay."
		if inline {
			report.Limits = "Read-only declared inline16 fields, not pointers or execution proof. Geometry maps four raw u32 words covering16bytes; no target is encoded, so target/target_mapping stay null. Resolved means every declared field word is file-backed. No registry-ID target fallback, wording/fit/gameplay or patch authority."
		}
		if gpRelative {
			report.Limits += " GP-relative targets use a unique bounded ELF register-info value and exact ADDIU register bits, not a live GP observation. Shared targets do not establish separate display ownership."
		}
		encoded, err := json.Marshal(report)
		if err != nil || len(encoded) > 64<<20 {
			return ReferenceReport{}, fmt.Errorf("observed report exceeds JSON bound: %v", err)
		}
		return report, nil
	}
	start, startErr := number(scan.FileRange.Start)
	end, endErr := number(scan.FileRange.End)
	delta, deltaErr := number(profile.ELFVMADelta)
	pointerMin, pointerErr := number(scan.PointerMinVMA)
	if startErr != nil || endErr != nil || deltaErr != nil || pointerErr != nil || start%4 != 0 || end%4 != 0 || start >= end ||
		end > uint64(len(data)) || delta+end > 1<<32 || pointerMin%4 != 0 || pointerMin >= delta+end ||
		scan.SkipWords < 1 || scan.SkipWords > 32 || scan.DecodeWords < 1 || scan.DecodeWords > 4096 || len(scan.Queries) < 1 || len(scan.Queries) > 8 {
		return ReferenceReport{}, fmt.Errorf("invalid reference scan bounds or query count")
	}
	// The optional caller report consumes the same finite producer as indexing.
	flowWords := make(map[uint32]InstructionObservation)
	if flowSpec != nil {
		facts, err := indexInstructions(data, Recipes{Operation: "instruction_index", SourceSize: profile.SourceSize,
			SourceSHA256: profile.SourceSHA256, Evidence: profile.Evidence, References: &ReferenceScan{FileRange: scan.FileRange}})
		if err != nil {
			return ReferenceReport{}, err
		}
		report.InstructionIndex = facts.InstructionIndex
		for _, word := range facts.InstructionIndex.Instructions {
			if word.VMA != word.FileOffset+delta {
				return ReferenceReport{}, fmt.Errorf("reference flow scan mappings disagree with declared flat delta")
			}
			flowWords[uint32(word.VMA)] = word
		}
	}
	var document struct {
		Entries []struct {
			RegistryEntry
			JP         string          `json:"jp"`
			SourcePool string          `json:"source_pool"`
			Chapter    string          `json:"chapter"`
			Landing    json.RawMessage `json:"landing_vma"`
			Status     json.RawMessage `json:"status"`
		} `json:"entries"`
	}
	var rawGlyphs map[string]string
	if !utf8.Valid(registryData) || !utf8.Valid(glyphData) || json.Unmarshal(registryData, &document) != nil || document.Entries == nil ||
		json.Unmarshal(glyphData, &rawGlyphs) != nil || rawGlyphs == nil {
		return ReferenceReport{}, fmt.Errorf("reference registry/glyphmap must be valid UTF-8 objects")
	}
	byID := make(map[uint64]int)
	var ids []uint64
	for i, entry := range document.Entries {
		id, err := number(entry.ID)
		if _, duplicate := byID[id]; err != nil || duplicate {
			return ReferenceReport{}, fmt.Errorf("invalid or duplicate reference ID %q", entry.ID)
		}
		byID[id] = i
		ids = append(ids, id)
	}
	flowRecipes := make(map[uint64]ReferenceFlowRecipe)
	var flowIDs []uint64
	flowSelected := make(map[uint64]bool)
	if flowSpec != nil {
		for text, recipe := range flowSpec.Entries {
			id, err := number(text)
			at, exists := byID[id]
			_, duplicate := flowRecipes[id]
			if err != nil || !exists || duplicate || document.Entries[at].RefType != "code_immediate" || len(document.Entries[at].RefSites) == 0 ||
				recipe.ZeroPaddingAllowance < 0 || recipe.ZeroPaddingAllowance > scan.SkipWords*2 || profile.PointerState != "" && recipe.ZeroPaddingAllowance != 0 || len(recipe.BenignReaderPairs) > 256 {
				return ReferenceReport{}, fmt.Errorf("reference flow requires distinct selected code IDs and bounded recipe facts")
			}
			flowRecipes[id] = recipe
			flowIDs = append(flowIDs, id)
		}
		slices.Sort(flowIDs)
	}
	slices.Sort(ids)
	var names []string
	for name := range scan.Queries {
		names = append(names, name)
	}
	slices.Sort(names)
	// This projection deliberately mirrors the old advisory glyph-only check, not controls().
	stripMarkup := regexp.MustCompile(`\{\{[^}]*\}\}|\[spk [^\]]*\]`)
	for _, name := range names {
		query := scan.Queries[name]
		lo, loErr := number(query.ContentRange.Start)
		hi, hiErr := number(query.ContentRange.End)
		selectLo, selectHi := uint64(0), uint64(1)<<32
		var selectLoErr, selectHiErr error
		if query.IDRange != nil {
			selectLo, selectLoErr = number(query.IDRange.Start)
			selectHi, selectHiErr = number(query.IDRange.End)
		}
		if name == "" || loErr != nil || hiErr != nil || selectLoErr != nil || selectHiErr != nil || lo >= hi || selectLo >= selectHi ||
			lo < delta || hi > delta+uint64(len(data)) || query.SourcePool == "" && query.Chapter == "" && query.IDRange == nil {
			return ReferenceReport{}, fmt.Errorf("%s: invalid reference query", name)
		}
		omitted := make(map[uint64]bool)
		for _, text := range query.OmitIDs {
			id, err := number(text)
			if err != nil || omitted[id] {
				return ReferenceReport{}, fmt.Errorf("%s: invalid or duplicate omitted ID", name)
			}
			omitted[id] = true
		}
		excluded, flagged := make(map[uint64]string), make(map[uint64]string)
		for i, values := range []map[string]string{query.Excluded, query.Flagged} {
			for text, note := range values {
				id, err := number(text)
				target := excluded
				if i == 1 {
					target = flagged
				}
				if err != nil || note == "" || target[id] != "" {
					return ReferenceReport{}, fmt.Errorf("%s: invalid or duplicate exception ID", name)
				}
				target[id] = note
			}
		}
		var tables [][3]uint64
		for _, table := range query.StructRows {
			a, aErr := number(table.Start)
			b, bErr := number(table.End)
			if aErr != nil || bErr != nil || table.Stride < 2 || table.Stride > 4096 || table.Stride%2 != 0 ||
				a < delta || a >= b || b > delta+uint64(len(data)) || (b-a)%uint64(table.Stride) != 0 {
				return ReferenceReport{}, fmt.Errorf("%s: invalid structural row range", name)
			}
			tables = append(tables, [3]uint64{a, b, uint64(table.Stride)})
		}
		rows := []ReferenceRow{}
		var targets [][]uint64
		wanted := make(map[uint32]bool)
		for _, id := range ids {
			entry := document.Entries[byID[id]]
			if omitted[id] || id < selectLo || id >= selectHi || query.SourcePool != "" && entry.SourcePool != query.SourcePool ||
				query.Chapter != "" && entry.Chapter != query.Chapter || query.UnlandedOnly && len(entry.Landing) != 0 && string(entry.Landing) != "null" {
				continue
			}
			if id < delta || id%2 != 0 || id-delta+2 > uint64(len(data)) {
				return ReferenceReport{}, fmt.Errorf("%s: selected ID %s is outside source words", name, entry.ID)
			}
			if _, requested := flowRecipes[id]; requested {
				if excluded[id] != "" {
					return ReferenceReport{}, fmt.Errorf("reference flow ID cannot be excluded")
				}
				flowSelected[id] = true
			}
			row := ReferenceRow{ID: entry.ID, Method: "unresolved", RefType: "unknown", Sites: []ReferenceCandidate{}, Note: flagged[id]}
			candidates := []uint64{id}
			for k := 0; k < scan.SkipWords; k++ {
				at := id - delta + uint64(k*2)
				if at+2 > uint64(len(data)) {
					break
				}
				if binary.LittleEndian.Uint16(data[at:]) != 0 {
					row.ContentStart = fmt.Sprintf("0x%x", at+delta)
					if k != 0 {
						candidates = append(candidates, at+delta)
					} else if query.Backward {
						for back := 1; back <= scan.SkipWords && uint64(back*2) <= id-delta; back++ {
							before := id - delta - uint64(back*2)
							if binary.LittleEndian.Uint16(data[before:]) != 0 {
								break
							}
							candidates = append(candidates, before+delta)
						}
					}
					break
				}
			}
			for _, table := range tables {
				if id >= table[0] && id < table[1] && (id-table[0])%table[2] == 0 {
					if len(row.Sites) != 0 {
						return ReferenceReport{}, fmt.Errorf("%s: overlapping structural rows", name)
					}
					row.Method, row.RefType, row.Target = "struct-row", "struct_table_field", entry.ID
					row.Sites = []ReferenceCandidate{{ReferenceSite: ReferenceSite{StructVMA: entry.ID, FieldOffset: "0x00"}, Stride: fmt.Sprintf("0x%x", table[2])}}
				}
			}
			if excluded[id] != "" {
				row.Method, row.RefType, row.Target, row.Note, row.Sites = "excluded", "unknown", "", excluded[id], []ReferenceCandidate{}
			}
			for _, target := range candidates {
				wanted[uint32(target)] = true
			}
			rows, targets = append(rows, row), append(targets, candidates)
		}
		pointers, chains := make(map[uint32][]ReferenceCandidate), make(map[uint32][]ReferenceCandidate)
		for at := start; at+4 <= end; at++ {
			target := binary.LittleEndian.Uint32(data[at:])
			if wanted[target] {
				pointers[target] = append(pointers[target], ReferenceCandidate{ReferenceSite: ReferenceSite{PointerVMA: fmt.Sprintf("0x%x", at+delta)}, Word: fmt.Sprintf("0x%08x", target), Target: fmt.Sprintf("0x%x", target)})
			}
		}
		// shortcut: preserve the historical candidate heuristic; replace with proven dataflow before using matches as patch authority.
		var highs [32]struct {
			high, vma uint64
			remaining int
		}
		for at := start; at+4 <= end; at += 4 {
			var word, op, rs, rt uint32
			if flowSpec != nil {
				facts := flowWords[uint32(at+delta)]
				word, op, rs, rt = facts.Word, facts.Opcode, facts.RS, facts.RT
			} else {
				word = binary.LittleEndian.Uint32(data[at:])
				op, rs, rt = word>>26, word>>21&31, word>>16&31
			}
			imm := word & 0xffff
			fresh := uint32(32)
			switch op {
			case 0x0f:
				highs[rt].high, highs[rt].vma, highs[rt].remaining = uint64(imm), at+delta, 64
				fresh = rt
			case 0x09, 0x0d:
				base := highs[rs]
				highs[rs].remaining = 0
				if base.remaining > 0 {
					target := uint32(base.high<<16) + uint32(int32(int16(imm)))
					if op == 0x0d {
						target = uint32(base.high<<16) | imm
					}
					if wanted[target] {
						upper := binary.LittleEndian.Uint32(data[base.vma-delta:])
						chains[target] = append(chains[target], ReferenceCandidate{ReferenceSite: ReferenceSite{LUIVMA: fmt.Sprintf("0x%x", base.vma), ADDIUVMA: fmt.Sprintf("0x%x", at+delta), Register: mipsRegisters[rt]}, Word: fmt.Sprintf("0x%08x", upper), LowerWord: fmt.Sprintf("0x%08x", word), Target: fmt.Sprintf("0x%x", target)})
					}
					highs[rt].high, highs[rt].vma, highs[rt].remaining = base.high, base.vma, 64
					fresh = rt
				}
			}
			for r := range highs {
				if uint32(r) != fresh && highs[r].remaining > 0 {
					highs[r].remaining--
					if op != 0x0f && op != 0x01 && op != 0x02 && op != 0x03 && rt == uint32(r) {
						highs[r].remaining = 0
					}
				}
			}
		}
		for i := range rows {
			row := &rows[i]
			id, _ := number(row.ID)
			if row.Method == "unresolved" {
				for _, target := range targets[i] {
					if target < lo || target >= hi {
						continue
					}
					var sites []ReferenceCandidate
					for _, site := range pointers[uint32(target)] {
						vma, _ := number(site.PointerVMA)
						if vma%4 == 0 && vma >= pointerMin {
							sites = append(sites, site)
						}
					}
					pointerCount := len(sites)
					sites = append(sites, chains[uint32(target)]...)
					if len(sites) == 0 {
						continue
					}
					row.Sites, row.Target, row.RefType, row.Method = sites, fmt.Sprintf("0x%x", target), "code_immediate", "direct"
					if pointerCount != 0 {
						row.RefType, row.Hybrid = "pointer_array", pointerCount != len(sites)
					}
					if target > id {
						row.Method = fmt.Sprintf("forward(%dw)", (target-id)/2)
					} else if target < id {
						row.Method = fmt.Sprintf("backward(%dB)", id-target)
					}
					break
				}
			}
			if row.RefType == "unknown" {
				row.UnfilteredSites = append(slices.Clone(pointers[uint32(id)]), chains[uint32(id)]...)
				continue
			}
			decodeAt, _ := number(row.ContentStart)
			words := scan.DecodeWords
			if row.Method == "struct-row" {
				decodeAt = id
				stride, _ := number(row.Sites[0].Stride)
				words = int(stride / 2)
			} else if row.ContentStart == "" {
				decodeAt = id
			}
			if query.DecodeTarget && row.Method != "struct-row" {
				decodeAt, _ = number(row.Target)
			}
			var decoded strings.Builder
			for k := 0; k < words && decodeAt-delta+uint64(k*2)+2 <= uint64(len(data)); k++ {
				word := binary.LittleEndian.Uint16(data[decodeAt-delta+uint64(k*2):])
				if word == 0xf800 || row.Method == "struct-row" && word == 0 {
					break
				}
				if word>>11 == 0 || row.Method == "struct-row" {
					text, known := rawGlyphs[fmt.Sprint(word)]
					if word == 0 {
						text = " "
					} else if word == 24 {
						text = "~"
					} else if !known {
						text = "?"
					}
					decoded.WriteString(text)
				}
			}
			row.Decoded = decoded.String()
			core := stripMarkup.ReplaceAllString(document.Entries[byID[id]].JP, "")
			core = strings.ReplaceAll(strings.ReplaceAll(core, "|", ""), "//", "")
			match := row.Decoded == core
			row.ContentOK = &match
		}
		report.Queries[name] = rows
	}
	// Index ownership once for both canonical sites and newly discovered rows.
	type siteOwner struct {
		id    string
		sites []ReferenceSite
		row   *ReferenceRow
	}
	var owned []siteOwner
	for _, entry := range document.Entries {
		owned = append(owned, siteOwner{entry.ID, entry.RefSites, nil})
	}
	for _, name := range names {
		for i := range report.Queries[name] {
			row := &report.Queries[name][i]
			var sites []ReferenceSite
			for _, candidate := range row.Sites {
				sites = append(sites, candidate.ReferenceSite)
			}
			owned = append(owned, siteOwner{row.ID, sites, row})
		}
	}
	owners := make(map[string][]string)
	lowerOwners := make(map[uint32]map[string]bool)
	keys := make(map[*ReferenceRow][]string)
	for _, owner := range owned {
		for _, site := range owner.sites {
			if flowSpec != nil && site.ADDIUVMA != "" {
				lower, err := number(site.ADDIUVMA)
				if err != nil || lower > 0xffffffff {
					return ReferenceReport{}, fmt.Errorf("reference flow lower owner is outside 32-bit addresses")
				}
				if lowerOwners[uint32(lower)] == nil {
					lowerOwners[uint32(lower)] = make(map[string]bool)
				}
				lowerOwners[uint32(lower)][owner.id] = true
			}
			for _, component := range [][2]string{{"pointer", site.PointerVMA}, {"struct", site.StructVMA}, {"code", site.LUIVMA}} {
				if component[1] == "" {
					continue
				}
				address, err := number(component[1])
				if err != nil {
					return ReferenceReport{}, fmt.Errorf("%s: invalid reference ownership address", owner.id)
				}
				kind := component[0]
				if kind == "struct" && site.FieldOffset != "" {
					offset, err := number(site.FieldOffset)
					if err != nil || address+offset >= 1<<32 {
						return ReferenceReport{}, fmt.Errorf("%s: invalid reference field offset", owner.id)
					}
					address += offset
				}
				if kind == "pointer" || kind == "struct" {
					kind = "memory"
				}
				key := fmt.Sprintf("%s/%x", kind, address)
				if component[0] == "code" {
					lower, err := number(site.ADDIUVMA)
					if err != nil {
						return ReferenceReport{}, fmt.Errorf("%s: missing reference lower instruction", owner.id)
					}
					key += fmt.Sprintf("/%x", lower)
				}
				owners[key] = append(owners[key], owner.id)
				if owner.row != nil {
					keys[owner.row] = append(keys[owner.row], key)
				}
			}
		}
	}
	if flowSpec != nil {
		batch := RegisterFlowSpec{EntryVMAs: flowSpec.EntryVMAs, Queries: map[string]RegisterFlowQuery{}}
		benign := make(map[uint64]map[[2]uint32]bool)
		callRules := make(map[uint32]ConsumerCallRule)
		if len(flowSpec.CallRules) > 64 {
			return ReferenceReport{}, fmt.Errorf("consumer call rules require at most 64 targets")
		}
		for text, rule := range flowSpec.CallRules {
			target, err := number(text)
			_, duplicate := callRules[uint32(target)]
			if err != nil || target%4 != 0 || duplicate || rule.AllowedRegisters == nil || len(rule.AllowedRegisters) > 8 || strings.TrimSpace(rule.Evidence) == "" || len(rule.Evidence) > 4096 {
				return ReferenceReport{}, fmt.Errorf("consumer call rules require distinct aligned targets, explicit EE arguments and evidence")
			}
			seen := make(map[uint32]bool)
			for _, register := range rule.AllowedRegisters {
				if register < 4 || register > 11 || seen[register] {
					return ReferenceReport{}, fmt.Errorf("consumer call rule arguments must be distinct EE registers4..11")
				}
				seen[register] = true
			}
			callRules[uint32(target)] = rule
		}
		for _, id := range flowIDs {
			if !flowSelected[id] {
				return ReferenceReport{}, fmt.Errorf("reference flow ID must be selected by an existing query")
			}
			entry := document.Entries[byID[id]]
			if len(flowRecipes[id].ConsumerSeeds) > 8 {
				return ReferenceReport{}, fmt.Errorf("consumer flow requires at most eight seeds per registry ID")
			}
			for name, seed := range flowRecipes[id].ConsumerSeeds {
				if name == "" || len(name) > 64 || !utf8.ValidString(name) || seed.Kind != "" || seed.MaxVisitedStates != 0 {
					return ReferenceReport{}, fmt.Errorf("consumer seeds require 1..64 byte names and inherit kind/work limit")
				}
				seed.Kind, seed.MaxVisitedStates = "pointer_consumers", flowSpec.MaxVisitedStates
				batch.Queries[fmt.Sprintf("consumer/0x%x/%s", id, name)] = seed
			}
			for _, site := range entry.RefSites {
				lui, highErr := number(site.LUIVMA)
				lower, lowErr := number(site.ADDIUVMA)
				_, highInside := flowWords[uint32(lui)]
				word, lowInside := flowWords[uint32(lower)]
				if highErr != nil || lowErr != nil || lui > 0xffffffff || lower > 0xffffffff || !highInside || !lowInside {
					return ReferenceReport{}, fmt.Errorf("reference flow declared code pair must be full selected words")
				}
				label := fmt.Sprintf("defs/%d/0x%x", word.RS, lower)
				batch.Queries[label] = RegisterFlowQuery{Kind: "reaching_defs", Register: word.RS, VMA: fmt.Sprintf("0x%x", lower), Context: "any_reachable", MaxVisitedStates: flowSpec.MaxVisitedStates}
			}
			benign[id] = make(map[[2]uint32]bool)
			for _, pair := range flowRecipes[id].BenignReaderPairs {
				lui, highErr := number(pair.LUIVMA)
				use, useErr := number(pair.UseVMA)
				word, highInside := flowWords[uint32(lui)]
				_, useInside := flowWords[uint32(use)]
				key := [2]uint32{uint32(lui), uint32(use)}
				if highErr != nil || useErr != nil || lui > 0xffffffff || use > 0xffffffff || !highInside || !useInside || word.Opcode != 15 || word.RS != 0 || word.RT == 0 || strings.TrimSpace(pair.Evidence) == "" || benign[id][key] {
					return ReferenceReport{}, fmt.Errorf("reference flow benign facts require distinct exact selected LUI/use pairs and evidence")
				}
				benign[id][key] = true
			}
		}
		// Preplan every possible selected LUI, not just registered high halves.
		for _, word := range report.InstructionIndex.Instructions {
			if word.Opcode == 15 && word.RS == 0 && word.RT != 0 {
				label := fmt.Sprintf("uses/%d/0x%x", word.RT, word.VMA)
				batch.Queries[label] = RegisterFlowQuery{Kind: "uses_after", Register: word.RT, VMA: fmt.Sprintf("0x%x", word.VMA), Context: "any_reachable", MaxVisitedStates: flowSpec.MaxVisitedStates}
			}
		}
		if len(batch.Queries) > 64 {
			return ReferenceReport{}, fmt.Errorf("reference flow requires at most 64 deduplicated definition/use queries")
		}
		graph, err := queryRegisterFlow(report.InstructionIndex.Instructions, batch)
		if err != nil {
			return ReferenceReport{}, err
		}
		report.InstructionIndex.RegisterFlow = &graph
		for _, id := range flowIDs {
			entry := document.Entries[byID[id]]
			result := &ReferenceFlowRow{CallerDisposition: "eligible_under_declared_policy", Diagnostics: []string{},
				DefinitionQueries: map[string]string{}, UseQueries: map[string]string{}, ConstructedTargets: []ReferenceFlowTarget{},
				Readers: []ReferenceFlowReader{}, CanonicalPairErrors: map[string]string{}}
			if len(flowRecipes[id].ConsumerSeeds) != 0 {
				result.Consumers = make(map[string]ReferenceConsumerAssessment)
			}
			for name := range flowRecipes[id].ConsumerSeeds {
				label := fmt.Sprintf("consumer/0x%x/%s", id, name)
				query := graph.Queries[label]
				assessment := ReferenceConsumerAssessment{Query: label, Classification: "UNRESOLVED", CallPolicies: []ReferenceConsumerCallPolicy{}}
				rank := 1
				if query.Consumer != nil && len(query.Consumer.Events) != 0 && query.CompleteWithinAssertedScope {
					rank = 0
				}
				if query.Consumer != nil {
					for ordinal, event := range query.Consumer.Events {
						eventRank := 1
						switch event.Kind {
						case "pointee_read", "pointee_write":
							eventRank = 2
						case "call_argument":
							policy := ReferenceConsumerCallPolicy{Event: ordinal, Classification: "unknown"}
							if event.Target != nil {
								if rule, present := callRules[*event.Target]; present {
									policy.Classification, policy.Evidence, eventRank = "risky_under_declared_policy", rule.Evidence, 2
									if slices.Contains(rule.AllowedRegisters, event.Register) {
										policy.Classification, eventRank = "allowed_under_declared_policy", 0
									}
								}
							}
							assessment.CallPolicies = append(assessment.CallPolicies, policy)
						}
						rank = max(rank, eventRank)
					}
				}
				assessment.Classification = []string{"SAFE_UNDER_DECLARED_POLICY", "UNRESOLVED", "RISKY"}[rank]
				result.Consumers[name] = assessment
			}
			// Bucket order follows the full diagnostic audit, not site_plan's first refusal.
			var issues [6][]string
			expected, targetKnown := uint32(id), true
			if profile.PointerState == "registry_landing" {
				var text string
				decodeErr := json.Unmarshal(entry.Landing, &text)
				landing, numberErr := number(text)
				if decodeErr != nil || numberErr != nil || text == "" || landing > 0xffffffff || landing == 0 {
					targetKnown = false
					issues[3] = append(issues[3], "target_unknown:registry_landing")
				} else {
					expected = uint32(landing)
				}
			}
			registered := make(map[uint32][]uint32)
			var lowers []uint32
			for _, site := range entry.RefSites {
				high, _ := number(site.LUIVMA)
				low, _ := number(site.ADDIUVMA)
				lui, lower := uint32(high), uint32(low)
				if _, exists := registered[lower]; !exists {
					lowers = append(lowers, lower)
				}
				registered[lower] = append(registered[lower], lui)
				geometry, err := normalizeReference("code_immediate", site, 0)
				if err == nil {
					_, err = referenceTarget(geometry, []uint32{flowWords[lui].Word, flowWords[lower].Word})
				}
				key := fmt.Sprintf("0x%x/0x%x", lui, lower)
				if err != nil && result.CanonicalPairErrors[key] == "" {
					result.CanonicalPairErrors[key] = err.Error()
				}
			}
			slices.Sort(lowers)
			defs := make(map[uint32][]uint32)
			allDefs := make(map[uint32]bool)
			var highSites []uint32
			for _, lower := range lowers {
				word := flowWords[lower]
				label := fmt.Sprintf("defs/%d/0x%x", word.RS, lower)
				result.DefinitionQueries[fmt.Sprintf("0x%x", lower)] = label
				query, exists := graph.Queries[label]
				if !exists {
					issues[1] = append(issues[1], fmt.Sprintf("definition_query_missing:0x%x", lower))
					continue
				}
				if word.Opcode != 9 && word.Opcode != 13 {
					issues[0] = append(issues[0], fmt.Sprintf("unsupported_lower_instruction:0x%x", lower))
				}
				if word.RS == 0 {
					issues[0] = append(issues[0], fmt.Sprintf("zero_lower_source:0x%x", lower))
				}
				for _, incoming := range query.IncomingEntrySites {
					issues[0] = append(issues[0], fmt.Sprintf("incoming_entry_definition:0x%x", incoming))
				}
				for _, at := range query.KnownFactSites {
					high := flowWords[at]
					if high.Opcode != 15 || high.RS != 0 || high.RT != word.RS {
						issues[0] = append(issues[0], fmt.Sprintf("non_lui_definition:0x%x", at))
						continue
					}
					defs[lower] = append(defs[lower], at)
					if !allDefs[at] {
						allDefs[at] = true
						highSites = append(highSites, at)
					}
				}
				for _, reason := range query.IncompleteReasons {
					issues[1] = append(issues[1], "definition_unknown:"+reason)
				}
				slices.Sort(registered[lower])
				for _, at := range slices.Compact(registered[lower]) {
					if !slices.Contains(defs[lower], at) {
						issues[2] = append(issues[2], fmt.Sprintf("registered_lui_missing:0x%x", at))
					}
				}
				if len(defs[lower]) > 1 {
					var sites []string
					for _, at := range defs[lower] {
						sites = append(sites, fmt.Sprintf("0x%x", at))
					}
					issues[2] = append(issues[2], "branch_shared_definitions:"+strings.Join(sites, ","))
				}
			}
			slices.Sort(highSites)
			for _, lui := range highSites {
				high := flowWords[lui]
				for _, lower := range lowers {
					word := flowWords[lower]
					if !slices.Contains(defs[lower], lui) || word.Opcode != 9 && word.Opcode != 13 {
						continue
					}
					// Observed arithmetic is broader than the unchanged canonical patch grammar.
					target := (high.Word & 0xffff) << 16
					if word.Opcode == 9 {
						target += uint32(int32(int16(word.Word)))
					} else {
						target |= word.Word & 0xffff
					}
					result.ConstructedTargets = append(result.ConstructedTargets, ReferenceFlowTarget{LUIVMA: lui, LowerVMA: lower, Target: target})
					matches := target == expected
					if targetKnown && !matches && target > expected && target-expected <= uint32(flowRecipes[id].ZeroPaddingAllowance) && uint64(target) >= delta && uint64(target)-delta <= uint64(len(data)) && uint64(expected) >= delta {
						matches = true
						for _, value := range data[uint64(expected)-delta : uint64(target)-delta] {
							if value != 0 {
								matches = false
								break
							}
						}
					}
					if targetKnown && !matches {
						issues[3] = append(issues[3], fmt.Sprintf("pair_target_mismatch:0x%x", target))
					}
				}
				label := fmt.Sprintf("uses/%d/0x%x", high.RT, lui)
				result.UseQueries[fmt.Sprintf("0x%x", lui)] = label
				query, exists := graph.Queries[label]
				if !exists {
					issues[5] = append(issues[5], fmt.Sprintf("later_use_query_missing:0x%x", lui))
					continue
				}
				for _, use := range query.KnownFactSites {
					owners := make(map[string]string)
					var ownerIDs []string
					for owner := range lowerOwners[use] {
						ownerID, _ := number(owner)
						state := "unknown"
						if at, exists := byID[ownerID]; exists {
							var value string
							if json.Unmarshal(document.Entries[at].Status, &value) == nil && value != "" {
								state = value
							}
						}
						owners[owner] = state
						ownerIDs = append(ownerIDs, owner)
					}
					slices.Sort(ownerIDs)
					relation := "foreign"
					switch {
					case registered[use] != nil:
						relation = "owned"
					case benign[id][[2]uint32{lui, use}]:
						relation = "benign"
					}
					result.Readers = append(result.Readers, ReferenceFlowReader{LUIVMA: lui, UseVMA: use, Relation: relation, Owners: owners})
					if relation != "foreign" {
						continue
					}
					if len(ownerIDs) == 0 {
						issues[4] = append(issues[4], fmt.Sprintf("foreign_reader_unregistered:0x%x", use))
					}
					for _, category := range []string{"drafted", "patched", "unknown"} {
						for _, owner := range ownerIDs {
							state := owners[owner]
							if state != "drafted" && state != "patched" {
								state = "unknown"
							}
							if state == category {
								issues[4] = append(issues[4], fmt.Sprintf("foreign_reader_%s:0x%x:%s", category, use, owner))
							}
						}
					}
				}
				for _, reason := range query.IncompleteReasons {
					if reason == "work_limit" {
						issues[5] = append(issues[5], "later_use_limit")
					} else {
						issues[5] = append(issues[5], "later_use_unknown:"+reason)
					}
				}
			}
			seen := make(map[string]bool)
			for _, bucket := range issues {
				for _, issue := range bucket {
					if !seen[issue] {
						result.Diagnostics = append(result.Diagnostics, issue)
						seen[issue] = true
					}
				}
			}
			if len(result.Diagnostics) != 0 {
				result.CallerDisposition = "refuse"
			}
			for _, name := range names {
				for i := range report.Queries[name] {
					if report.Queries[name][i].ID == entry.ID {
						report.Queries[name][i].Flow = result
					}
				}
			}
		}
		report.Limits += " Optional reference flow joins declared registry sites to actual bounded low32 graph facts under asserted entries. Listed caller diagnostics are distinct from canonical patch grammar, code/whole-program closure, target backing, consumer/ABI safety and patch authorization. Unknowns and foreign readers remain refusals; recipe facts never supply graph completeness."
	}
	for _, name := range names {
		summary := ReferenceSummary{ByType: map[string]int{}}
		for i := range report.Queries[name] {
			row := &report.Queries[name][i]
			seen := make(map[string]bool)
			for _, key := range keys[row] {
				for _, other := range owners[key] {
					if scan.Queries[name].CheckCollisions && other != row.ID && !seen[other] {
						row.Collisions = append(row.Collisions, other)
						seen[other] = true
					}
				}
			}
			slices.Sort(row.Collisions)
			summary.Total++
			summary.ByType[row.RefType]++
			if row.RefType == "unknown" {
				summary.Unresolved++
			} else {
				summary.Resolved++
			}
			if row.ContentOK != nil && !*row.ContentOK {
				summary.ContentMismatches++
			}
			if row.Hybrid {
				summary.Hybrids++
			}
			if len(row.Sites) > 1 {
				summary.MultiSite++
			}
			if len(row.Collisions) != 0 {
				summary.CollisionRows++
			}
		}
		report.Summaries[name] = summary
	}
	return report, nil
}
