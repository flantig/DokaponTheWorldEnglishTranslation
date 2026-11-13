package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"slices"
)

// indexInstructions produces finite word/GP facts from a caller-validated source.
// Reverse LOAD uniqueness and exact word membership do not prove executable code.
// Source/profile identity, graph queries and registry policy belong to references.
func indexInstructions(data []byte, profile Recipes) (ReferenceReport, error) {
	report := ReferenceReport{Operation: profile.Operation, SourceSHA256: profile.SourceSHA256,
		Summaries: map[string]ReferenceSummary{}, Queries: map[string][]ReferenceRow{}}
	gpIndex, wordIndex := profile.Operation == "reference_gp_index", profile.Operation == "instruction_index"
	label := "GP"
	if wordIndex {
		label = "Instruction"
	}
	if !gpIndex && !wordIndex || profile.References == nil {
		return ReferenceReport{}, fmt.Errorf("finite index requires a validated GP or instruction profile")
	}
	scan := profile.References
	start, startErr := number(scan.FileRange.Start)
	end, endErr := number(scan.FileRange.End)
	maxWords := uint64(1 << 20)
	if wordIndex {
		maxWords = 32768
	}
	if startErr != nil || endErr != nil || start >= end || start%4 != 0 || end%4 != 0 || end > uint64(len(data)) || (end-start)/4 > maxWords {
		return ReferenceReport{}, fmt.Errorf("%s scan requires 1..%d complete aligned words within the source", label, maxWords)
	}
	mapped, err := inspect(bytes.NewReader(data), nil, &Recipes{Operation: "elf_layout", SourceSize: profile.SourceSize, SourceSHA256: profile.SourceSHA256, Evidence: profile.Evidence, AddressRanges: profile.AddressRanges})
	if err != nil {
		return ReferenceReport{}, err
	}
	var index *GPIndex
	var queryNames []string
	var queryBounds map[string][2]uint64
	if gpIndex {
		index = &GPIndex{FileRange: scan.FileRange, QueryRanges: map[string]AddressRange{}, ScannedWords: int((end - start) / 4), Instructions: []GPInstruction{}}
		report.GPIndex, report.RegisterInfo = index, mapped.RegisterInfo
		if report.RegisterInfo == nil {
			report.RegisterInfo = &ELFRegisterInfo{Error: "ELF has no MIPS register-info section"}
		}
		if report.RegisterInfo.GlobalPointer == nil {
			index.MetadataError = report.RegisterInfo.Error
		}
		queryBounds = make(map[string][2]uint64)
		for name, span := range profile.AddressRanges {
			index.QueryRanges[name] = span
			queryNames = append(queryNames, name)
			pieces := mapped.ELFMappings[name]
			queryBounds[name] = [2]uint64{pieces[0].VMA[0], pieces[len(pieces)-1].VMA[1]}
		}
		slices.Sort(queryNames)
	} else {
		report.InstructionIndex = &InstructionIndex{FileRange: scan.FileRange, ScannedWords: int((end - start) / 4), Instructions: []InstructionObservation{}}
	}

	// Forward LOAD uniqueness does not imply reverse file uniqueness: two
	// disjoint VMAs may alias the same bytes. Prove the whole scan partition.
	regions := make(map[uint64]struct {
		end, vma uint64
		header   int
	})
	var fileStarts []uint64
	for header, segment := range mapped.ELFSegments {
		if segment.Type != elf.PT_LOAD || segment.Filesz == 0 {
			continue
		}
		lo, hi := max(start, segment.Off), min(end, segment.Off+segment.Filesz)
		if lo >= hi {
			continue
		}
		vma := segment.Vaddr + lo - segment.Off
		if lo%4 != 0 || hi%4 != 0 || vma%4 != 0 {
			return ReferenceReport{}, fmt.Errorf("%s scan crosses a split or unaligned instruction mapping", label)
		}
		if _, duplicate := regions[lo]; duplicate {
			return ReferenceReport{}, fmt.Errorf("%s scan has ambiguous file-to-VMA mappings", label)
		}
		regions[lo] = struct {
			end, vma uint64
			header   int
		}{hi, vma, header}
		fileStarts = append(fileStarts, lo)
	}
	slices.Sort(fileStarts)
	cursor := start
	for _, lo := range fileStarts {
		if lo != cursor {
			return ReferenceReport{}, fmt.Errorf("%s scan requires unique complete file-backed instruction mappings", label)
		}
		cursor = regions[lo].end
	}
	if cursor != end {
		return ReferenceReport{}, fmt.Errorf("%s scan includes unmapped file bytes", label)
	}
	rowBytes := 0
	for _, lo := range fileStarts {
		region := regions[lo]
		for at := lo; at < region.end; at += 4 {
			word := binary.LittleEndian.Uint32(data[at : at+4])
			op, rs, rt := word>>26, word>>21&31, word>>16&31
			form, addressForm := instructionAddressForms[op]
			if gpIndex && (rs != 28 || !addressForm) {
				continue
			}
			vma, header := region.vma+at-lo, region.header
			bits := InstructionWord{FileOffset: at, VMA: vma, Word: word, Opcode: op, RS: rs, RT: rt}
			site := ELFMapping{VMA: [2]uint64{vma, vma + 4}, Storage: "file_backed", ProgramHeader: &header, FileRange: &[2]uint64{at, at + 4}}
			var rowData any
			if gpIndex {
				if len(index.Instructions) == 32768 {
					return ReferenceReport{}, fmt.Errorf("GP index exceeds32768 instruction rows")
				}
				kind := form.Kind
				if op == 9 && rt == 0 {
					kind = "discarded_value"
				}
				row := GPInstruction{InstructionWord: bits, SignedImmediate: int16(word & 0xffff), Kind: kind, SiteMapping: site}
				if gp := report.RegisterInfo.GlobalPointer; gp != nil {
					address := *gp + uint32(int32(row.SignedImmediate))
					row.ComputedAddress, row.MatchedQueries = &address, []string{}
					for _, name := range queryNames {
						span := queryBounds[name]
						if uint64(address) >= span[0] && uint64(address) < span[1] {
							row.MatchedQueries = append(row.MatchedQueries, name)
						}
					}
				}
				index.Instructions = append(index.Instructions, row)
				rowData = row
			} else {
				rd, sa, fn := word>>11&31, word>>6&31, word&63
				row := InstructionObservation{InstructionWord: bits, RD: rd, SiteMapping: site, Operands: InstructionOperands{Status: "known_finite_GPR_operands", GPRReads: []uint32{}, GPRMayWrite: []uint32{}, GPRMustWrite: []uint32{}, IncomingPreservation: []uint32{}, OtherBanks: []InstructionBankOperand{}, OtherEffects: []string{}}}
				effects := &row.Operands
				known := true
				condition := "unknown_register_or_coprocessor_condition"
				switch {
				case addressForm:
					if form.Kind == "constructed_address" {
						row.transfer = &instructionTransfer{kind: "offset", source: rs, destination: rt, displacement: int32(int16(word))}
					} else {
						row.memory = &instructionMemory{kind: form.Kind, bank: form.ValueBank, base: rs, value: rt, width: form.Width, displacement: int32(int16(word)), merge: form.Merge}
					}
					effects.GPRReads = append(effects.GPRReads, rs)
					role := "read"
					if form.Kind == "load" || form.Kind == "constructed_address" {
						role = "write"
					}
					switch form.ValueBank {
					case "GPR":
						if role == "write" {
							effects.GPRMayWrite = append(effects.GPRMayWrite, rt)
							effects.GPRMustWrite = append(effects.GPRMustWrite, rt)
						} else {
							effects.GPRReads = append(effects.GPRReads, rt)
						}
						if form.PreserveRT {
							effects.GPRReads = append(effects.GPRReads, rt)
							effects.IncomingPreservation = append(effects.IncomingPreservation, rt)
						}
					default:
						if form.Kind == "cache" {
							role = "operation"
						} else if form.Kind == "prefetch" {
							role = "hint"
						}
						effects.OtherBanks = append(effects.OtherBanks, InstructionBankOperand{Role: role, Bank: form.ValueBank, Index: &rt})
					}
				case op == 0x0d || op == 0x0f && rs == 0:
					if op == 0x0d {
						effects.GPRReads = append(effects.GPRReads, rs)
						if word&0xffff == 0 {
							row.transfer = &instructionTransfer{kind: "copy", source: rs, destination: rt}
						}
					}
					effects.GPRMayWrite = append(effects.GPRMayWrite, rt)
					effects.GPRMustWrite = append(effects.GPRMustWrite, rt)
				case op == 0:
					switch {
					case fn == 0 && rs == 0:
						if sa == 0 {
							row.transfer = &instructionTransfer{kind: "copy", source: rt, destination: rd}
						}
						effects.GPRReads = append(effects.GPRReads, rt)
						effects.GPRMayWrite = append(effects.GPRMayWrite, rd)
						effects.GPRMustWrite = append(effects.GPRMustWrite, rd)
					case (fn == 0x21 || fn == 0x2d || fn == 0x25) && sa == 0 && (rs == 0 || rt == 0):
						source := rs
						if source == 0 {
							source = rt
						}
						row.transfer = &instructionTransfer{kind: "copy", source: source, destination: rd}
						effects.GPRReads = append(effects.GPRReads, source)
						effects.GPRMayWrite = append(effects.GPRMayWrite, rd)
						effects.GPRMustWrite = append(effects.GPRMustWrite, rd)
					case fn == 0x21 && sa == 0:
						// ADDU has known operands; two nonzero inputs do not prove a pointer copy.
						effects.GPRReads = append(effects.GPRReads, rs, rt)
						effects.GPRMayWrite = append(effects.GPRMayWrite, rd)
						effects.GPRMustWrite = append(effects.GPRMustWrite, rd)
					case (fn == 0x0a || fn == 0x0b) && sa == 0:
						row.transfer = &instructionTransfer{kind: "conditional", source: rs, destination: rd}
						if rt == 0 {
							row.transfer.kind = "keep"
							if fn == 0x0a {
								row.transfer.kind = "copy"
							}
						}
						effects.GPRReads = append(effects.GPRReads, rs, rt)
						if rt != 0 {
							effects.GPRMayWrite = append(effects.GPRMayWrite, rd)
							effects.IncomingPreservation = append(effects.IncomingPreservation, rd)
						} else if fn == 0x0a {
							effects.GPRMayWrite = append(effects.GPRMayWrite, rd)
							effects.GPRMustWrite = append(effects.GPRMustWrite, rd)
						} else {
							effects.IncomingPreservation = append(effects.IncomingPreservation, rd)
						}
					case fn == 0x18 && sa == 0:
						effects.GPRReads = append(effects.GPRReads, rs, rt)
						effects.GPRMayWrite = append(effects.GPRMayWrite, rd)
						effects.GPRMustWrite = append(effects.GPRMustWrite, rd)
						effects.OtherEffects = []string{"HI", "LO"}
					case fn == 0x10 && rs == 0 && rt == 0 && sa == 0:
						effects.GPRMayWrite = append(effects.GPRMayWrite, rd)
						effects.GPRMustWrite = append(effects.GPRMustWrite, rd)
						effects.OtherEffects = []string{"read_HI"}
					case fn == 0x11 && rt == 0 && rd == 0 && sa == 0:
						effects.GPRReads = append(effects.GPRReads, rs)
						effects.OtherEffects = []string{"write_HI"}
					case (fn == 8 && rd == 0 || fn == 9) && rt == 0 && sa == 0:
						effects.GPRReads = append(effects.GPRReads, rs)
						row.Control = &InstructionControl{Kind: "register_jump"}
						if fn == 9 && rd != 0 {
							row.Control.LinkRegister = &rd
						}
					case fn == 12 || fn == 13:
						row.Control = &InstructionControl{Kind: "exception_or_conditional_trap"}
					default:
						known = false
					}
				case op == 1:
					switch rt {
					case 0, 1, 2, 3, 16, 17, 18, 19:
						effects.GPRReads = append(effects.GPRReads, rs)
						row.Control = &InstructionControl{Kind: "conditional_branch", Likely: rt&2 != 0}
						if rt&16 != 0 {
							link := uint32(31)
							row.Control.LinkRegister = &link
						}
						if rs == 0 {
							condition = "always_false"
							if rt&1 != 0 {
								condition = "always_true"
							}
						}
					case 8:
						effects.GPRReads = append(effects.GPRReads, rs)
						row.Control = &InstructionControl{Kind: "exception_or_conditional_trap"}
					default:
						known = false
					}
				case op == 2 || op == 3:
					row.Control = &InstructionControl{Kind: "direct_jump"}
					if op == 3 {
						link := uint32(31)
						row.Control.LinkRegister = &link
					}
				case op == 4 || op == 5 || op == 0x14 || op == 0x15:
					effects.GPRReads = append(effects.GPRReads, rs, rt)
					row.Control = &InstructionControl{Kind: "conditional_branch", Likely: op&16 != 0}
					if rs == rt {
						condition = "always_true"
						if op&1 != 0 {
							condition = "always_false"
						}
					}
				case (op == 6 || op == 7 || op == 0x16 || op == 0x17) && rt == 0:
					effects.GPRReads = append(effects.GPRReads, rs)
					row.Control = &InstructionControl{Kind: "conditional_branch", Likely: op&16 != 0}
					if rs == 0 {
						condition = "always_true"
						if op&1 != 0 {
							condition = "always_false"
						}
					}
				case (op == 0x10 || op == 0x11 || op == 0x12) && rs == 8 && rt < 4:
					row.Control = &InstructionControl{Kind: "conditional_branch", Likely: rt&2 != 0}
					effects.OtherBanks = append(effects.OtherBanks, InstructionBankOperand{Role: "condition", Bank: fmt.Sprintf("COP%d", op-0x10)})
				case op == 0x12 && (rs == 1 || rs == 5) && word&0x7ff == 0:
					role := "read"
					if rs == 1 {
						effects.GPRMayWrite = append(effects.GPRMayWrite, rt)
						effects.GPRMustWrite = append(effects.GPRMustWrite, rt)
					} else {
						role = "write"
						effects.GPRReads = append(effects.GPRReads, rt)
					}
					effects.OtherBanks = append(effects.OtherBanks, InstructionBankOperand{Role: role, Bank: "COP2_vector", Index: &rd})
				default:
					known = false
				}
				if !known {
					effects.Status = "unsupported_or_not_modelled"
					effects.GPRReads = nil
					effects.GPRMayWrite = nil
					effects.GPRMustWrite = nil
					effects.IncomingPreservation = nil
				}
				for _, registers := range []*[]uint32{&effects.GPRReads, &effects.GPRMayWrite, &effects.GPRMustWrite, &effects.IncomingPreservation} {
					slices.Sort(*registers)
					unique := (*registers)[:0]
					for _, reg := range *registers {
						if reg != 0 && (len(unique) == 0 || unique[len(unique)-1] != reg) {
							unique = append(unique, reg)
						}
					}
					*registers = unique
				}
				pc := uint32(vma)
				if c := row.Control; c != nil {
					c.Status = "known_control"
					switch c.Kind {
					case "conditional_branch":
						target := pc + 4 + uint32(int32(int16(word&0xffff))*4)
						c.Target = &target
						c.Condition = &condition
						if condition != "always_false" {
							c.PossiblePaths = append(c.PossiblePaths, InstructionPath{ConditionTaken: true, ExecuteDelay: true, NextAfterDelay: target})
						}
						if condition != "always_true" {
							c.PossiblePaths = append(c.PossiblePaths, InstructionPath{ConditionTaken: false, ExecuteDelay: !c.Likely, NextAfterDelay: pc + 8})
						}
					case "direct_jump":
						target := ((pc + 4) & 0xf0000000) | ((word & 0x3ffffff) << 2)
						c.Target = &target
						c.PossiblePaths = []InstructionPath{{ConditionTaken: true, ExecuteDelay: true, NextAfterDelay: target}}
					case "register_jump":
						c.Status = "known_indirect_control"
					case "exception_or_conditional_trap":
						c.Status = "exception_or_trap_not_normal_effect_free"
						effects.Status = "explicit_operands_only_exception_held"
					}
					if c.Kind != "exception_or_conditional_trap" {
						delay := pc + 4
						c.DelayVMA = &delay
					}
					if c.LinkRegister != nil {
						link := pc + 8
						c.LinkValue = &link
						effects.GPRMayWrite = append(effects.GPRMayWrite, *c.LinkRegister)
						effects.GPRMustWrite = append(effects.GPRMustWrite, *c.LinkRegister)
					}
				} else if known {
					next := pc + 4
					row.NextVMA = &next
				}
				report.InstructionIndex.Instructions = append(report.InstructionIndex.Instructions, row)
				rowData = row
			}
			encoded, err := json.Marshal(rowData)
			if err != nil {
				return ReferenceReport{}, err
			}
			// Reserve bounded space for final point maps or delay annotations.
			rowBytes += len(encoded) + 512
			if rowBytes > 64<<20 {
				return ReferenceReport{}, fmt.Errorf("%s index rows exceed64MiB", label)
			}
		}
	}
	if wordIndex {
		rows := report.InstructionIndex.Instructions
		byVMA := make(map[uint32]int, len(rows))
		for i, row := range rows {
			byVMA[uint32(row.VMA)] = i
		}
		for i := range rows {
			row := &rows[i]
			if row.NextVMA != nil {
				_, inside := byVMA[*row.NextVMA]
				row.NextInScan = &inside
			}
			if c := row.Control; c != nil {
				for j := range c.PossiblePaths {
					_, inside := byVMA[c.PossiblePaths[j].NextAfterDelay]
					c.PossiblePaths[j].NextInScan = inside
				}
				if c.DelayVMA != nil {
					at, present := byVMA[*c.DelayVMA]
					switch {
					case !present:
						c.DelayError = "selected_delay_missing"
					case rows[at].Operands.Status == "unsupported_or_not_modelled":
						c.DelayError = "selected_delay_unsupported"
					case rows[at].Control != nil:
						c.DelayError = "selected_delay_is_control"
					}
				}
			}
		}
		report.Limits = "Finite R5900 operand and local control facts on normal completion; every selected mapped word is retained, not proved code. GPR destination sets are not complete128-bit kills; modeled merge/conditional dependencies do not cover every preserved lane. Sequential next precedes predecessor delay context; raw alternatives remain alongside delay errors. Scope membership is exact selected VMA membership. Link is not return; indirect/exception exits and unsupported effects remain unknown. No CFG, reaching definitions, later-use/liveness, memory values, ABI, placement or patch authority."
		return report, nil
	}

	owners := make(map[uint32][]int)
	var targets []uint32
	for i, row := range index.Instructions {
		if row.ComputedAddress == nil {
			continue
		}
		target := *row.ComputedAddress
		if _, exists := owners[target]; !exists {
			targets = append(targets, target)
		}
		owners[target] = append(owners[target], i)
	}
	slices.Sort(targets)
	// Reuse the existing mapper's bounded query batches, rather than imposing
	// its per-call1024 limit on the complete instruction index.
	for first := 0; first < len(targets); first += 1024 {
		ranges := make(map[string]AddressRange)
		last := min(first+1024, len(targets))
		for _, target := range targets[first:last] {
			ranges[fmt.Sprintf("%x", target)] = AddressRange{Start: fmt.Sprintf("0x%x", target), End: fmt.Sprintf("0x%x", uint64(target)+1)}
		}
		points, err := inspect(bytes.NewReader(data), nil, &Recipes{Operation: "elf_layout", SourceSize: profile.SourceSize, SourceSHA256: profile.SourceSHA256, Evidence: profile.Evidence, AddressRanges: ranges})
		if err != nil {
			return ReferenceReport{}, err
		}
		for _, target := range targets[first:last] {
			for _, owner := range owners[target] {
				index.Instructions[owner].TargetMapping = points.ELFMappings[fmt.Sprintf("%x", target)]
			}
		}
	}
	report.Limits = "Read-only supported GP-base address forms under a fixed ELF metadata assumption, not live GP or complete GPR-use classification. Full-word file/VMA mapping does not prove code, reachability or execution. Computed point matches include discarded ADDIU arithmetic and memory/cache/prefetch effective addresses; they are not retained references, loaded pointers or memory-access extents. Numeric rt fields are opcode-dependent, not universally GPRs. Missing/invalid metadata keeps arithmetic, matches and target maps null; zero GP is valid. No CFG/valueflow, ABI, safe placement, registry changes or patch authority."
	return report, nil
}
