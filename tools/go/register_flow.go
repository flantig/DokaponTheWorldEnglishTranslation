package main

import (
	"fmt"
	"slices"
	"unicode/utf8"
)

// queryRegisterFlow builds one bounded graph from decoded facts, then searches
// before reads for definitions or after execution for uses of the same low32 GPR.
// Delay states retain their controller/outcome. A definite overwrite closes a
// value only without incoming preservation; calls never invent return edges.
// Completeness is conditional on asserted entries and the supported local model.
func queryRegisterFlow(rows []InstructionObservation, spec RegisterFlowSpec) (RegisterFlowReport, error) {
	report := RegisterFlowReport{EntryVMAs: []uint32{}, Queries: map[string]RegisterFlowResult{}}
	if len(rows) == 0 || len(rows) > 32768 || len(spec.EntryVMAs) == 0 || len(spec.EntryVMAs) > 256 || len(spec.Queries) == 0 || len(spec.Queries) > 64 {
		return report, fmt.Errorf("register flow requires 1..32768 words, 1..256 entries and 1..64 queries")
	}
	byVMA := make(map[uint32]int, len(rows))
	for i, row := range rows {
		if row.VMA > 0xffffffff || row.VMA%4 != 0 {
			return report, fmt.Errorf("register flow requires aligned 32-bit instruction sites")
		}
		if _, exists := byVMA[uint32(row.VMA)]; exists {
			return report, fmt.Errorf("register flow requires unique instruction sites")
		}
		byVMA[uint32(row.VMA)] = i
	}
	entries := make(map[uint32]bool)
	for _, text := range spec.EntryVMAs {
		vma, err := number(text)
		_, selected := byVMA[uint32(vma)]
		if err != nil || vma > 0xffffffff || !selected || entries[uint32(vma)] {
			return report, fmt.Errorf("register flow entries must be distinct selected word VMAs")
		}
		entries[uint32(vma)] = true
		report.EntryVMAs = append(report.EntryVMAs, uint32(vma))
	}
	slices.Sort(report.EntryVMAs)
	labels := make([]string, 0, len(spec.Queries))
	for label, query := range spec.Queries {
		vma, err := number(query.VMA)
		_, selected := byVMA[uint32(vma)]
		if label == "" || len(label) > 128 || !utf8.ValidString(label) || err != nil || vma > 0xffffffff || !selected || query.Register > 31 || query.MaxVisitedStates < 1 || query.MaxVisitedStates > 100000 {
			return report, fmt.Errorf("invalid register flow query %q: label, site, register or work limit", label)
		}
		if query.Kind != "reaching_defs" && query.Kind != "uses_after" {
			return report, fmt.Errorf("register flow query %q requires reaching_defs or uses_after", label)
		}
		result := RegisterFlowResult{Kind: query.Kind, Register: query.Register, VMA: uint32(vma), Context: query.Context,
			KnownFactSites: []uint32{}, IncomingEntrySites: []uint32{}, IncompleteReasons: []string{}}
		switch query.Context {
		case "any_reachable", "normal":
			if query.DelayOf != nil {
				return report, fmt.Errorf("register flow query %q only allows delay_of in delay context", label)
			}
		case "delay":
			if query.DelayOf == nil {
				return report, fmt.Errorf("register flow query %q requires delay_of", label)
			}
			controller, err := number(*query.DelayOf)
			at, selected := byVMA[uint32(controller)]
			if err != nil || controller > 0xffffffff || !selected || rows[at].Control == nil || rows[at].Control.DelayVMA == nil || *rows[at].Control.DelayVMA != result.VMA {
				return report, fmt.Errorf("register flow query %q requires its selected delay controller", label)
			}
			value := uint32(controller)
			result.DelayOf = &value
		default:
			return report, fmt.Errorf("register flow query %q requires an execution context", label)
		}
		labels = append(labels, label)
		report.Queries[label] = result
	}
	slices.Sort(labels)

	// A physical word can execute normally and in several pending transfers.
	type execution struct{ row, controller, path int }
	type node struct {
		execution
		successors, predecessors []int
		unknown                  []string
		entry                    bool
	}
	graph := make([]node, 0, len(rows))
	states := make(map[execution]int)
	for _, vma := range report.EntryVMAs {
		key := execution{row: byVMA[vma], controller: -1, path: -1}
		states[key] = len(graph)
		graph = append(graph, node{execution: key, entry: true})
	}
	graphLimited := false
	unknownFrontiers := []string{}
	for at := 0; at < len(graph); at++ {
		state := graph[at].execution
		row := rows[state.row]
		var successors []execution
		var targets []uint32
		var unknown []string
		switch {
		case state.controller >= 0:
			control := rows[state.controller].Control
			if state.path < 0 {
				unknown = append(unknown, "unresolved_indirect_exit")
			} else {
				targets = append(targets, control.PossiblePaths[state.path].NextAfterDelay)
			}
		case row.Operands.Status == "unsupported_or_not_modelled":
			unknown = append(unknown, "unsupported_instruction")
		case row.Control == nil:
			if row.NextVMA == nil {
				unknown = append(unknown, "unsupported_instruction")
			} else {
				targets = append(targets, *row.NextVMA)
			}
		case row.Control.Kind == "exception_or_conditional_trap":
			unknown = append(unknown, "unsupported_instruction")
		default:
			control := row.Control
			paths := control.PossiblePaths
			if control.Kind == "register_jump" {
				paths = []InstructionPath{{ExecuteDelay: true}}
			}
			for path, outcome := range paths {
				if !outcome.ExecuteDelay {
					targets = append(targets, outcome.NextAfterDelay)
					continue
				}
				// An annulled outcome above must not inherit an unused delay error.
				switch control.DelayError {
				case "selected_delay_missing":
					unknown = append(unknown, "missing_delay_word")
				case "selected_delay_unsupported":
					unknown = append(unknown, "unsupported_delay_word")
				case "selected_delay_is_control":
					unknown = append(unknown, "control_in_delay_slot")
				default:
					if control.DelayVMA == nil {
						unknown = append(unknown, "missing_delay_word")
						continue
					}
					delay, present := byVMA[*control.DelayVMA]
					if !present {
						unknown = append(unknown, "missing_delay_word")
						continue
					}
					if control.Kind == "register_jump" {
						path = -1
					}
					successors = append(successors, execution{row: delay, controller: state.row, path: path})
				}
			}
		}
		for _, target := range targets {
			if destination, present := byVMA[target]; present {
				successors = append(successors, execution{row: destination, controller: -1, path: -1})
			} else {
				unknown = append(unknown, "out_of_scope_direct_target")
			}
		}
		for _, key := range successors {
			next, present := states[key]
			if !present {
				if len(graph) == 100000 {
					graphLimited = true
					unknown = append(unknown, "graph_state_limit")
					continue
				}
				next = len(graph)
				states[key] = next
				graph = append(graph, node{execution: key})
			}
			if !slices.Contains(graph[at].successors, next) {
				graph[at].successors = append(graph[at].successors, next)
				graph[next].predecessors = append(graph[next].predecessors, at)
			}
		}
		graph[at].unknown = unknown
		for _, reason := range unknown {
			// A stopped unknown instruction prevents a trusted reachability claim;
			// a known external direct transfer does not imply a local continuation.
			if reason != "out_of_scope_direct_target" {
				unknownFrontiers = append(unknownFrontiers, reason)
			}
		}
	}

	batchWork := 0
	for _, label := range labels {
		query, result := spec.Queries[label], report.Queries[label]
		var roots []int
		for at, state := range graph {
			if rows[state.row].VMA != uint64(result.VMA) {
				continue
			}
			if result.Context == "normal" && state.controller >= 0 || result.Context == "delay" && (state.controller < 0 || uint32(rows[state.controller].VMA) != *result.DelayOf) {
				continue
			}
			roots = append(roots, at)
		}
		reasons := []string{}
		if graphLimited {
			reasons = append(reasons, "graph_state_limit")
		}
		if len(roots) == 0 {
			reasons = append(reasons, unknownFrontiers...)
			if len(reasons) == 0 {
				reasons = append(reasons, "query_unreachable_under_declared_entries")
			}
		} else if result.Register != 0 {
			// Unknown reachable transfers may introduce predecessors at any site.
			// Keep lower-bound facts, but never claim their absence proves closure.
			if query.Kind == "reaching_defs" {
				reasons = append(reasons, unknownFrontiers...)
			}
			var pending []int
			for _, root := range roots {
				switch query.Kind {
				case "reaching_defs":
					if graph[root].entry {
						result.IncomingEntrySites = append(result.IncomingEntrySites, result.VMA)
					}
					pending = append(pending, graph[root].predecessors...)
				case "uses_after":
					pending = append(pending, graph[root].successors...)
					reasons = append(reasons, graph[root].unknown...)
				}
			}
			visited := make(map[int]bool)
			for first := 0; first < len(pending); first++ {
				at := pending[first]
				if visited[at] {
					continue
				}
				if len(visited) == query.MaxVisitedStates {
					reasons = append(reasons, "work_limit")
					break
				}
				if batchWork == 1000000 {
					reasons = append(reasons, "batch_work_limit")
					break
				}
				visited[at] = true
				batchWork++
				state := graph[at]
				row := rows[state.row]
				effects := row.Operands
				preserves := slices.Contains(effects.IncomingPreservation, query.Register)
				kills := slices.Contains(effects.GPRMustWrite, query.Register) && !preserves
				switch query.Kind {
				case "reaching_defs":
					if slices.Contains(effects.GPRMayWrite, query.Register) {
						result.KnownFactSites = append(result.KnownFactSites, uint32(row.VMA))
					}
					if kills {
						continue
					}
					if state.entry {
						result.IncomingEntrySites = append(result.IncomingEntrySites, uint32(row.VMA))
					}
					pending = append(pending, state.predecessors...)
				case "uses_after":
					if slices.Contains(effects.GPRReads, query.Register) || preserves {
						result.KnownFactSites = append(result.KnownFactSites, uint32(row.VMA))
					}
					if kills {
						continue
					}
					reasons = append(reasons, state.unknown...)
					pending = append(pending, state.successors...)
				}
			}
		}
		for _, sites := range []*[]uint32{&result.KnownFactSites, &result.IncomingEntrySites} {
			slices.Sort(*sites)
			*sites = slices.Compact(*sites)
		}
		slices.Sort(reasons)
		result.IncompleteReasons = slices.Compact(reasons)
		result.CompleteWithinAssertedScope = len(result.IncompleteReasons) == 0
		report.Queries[label] = result
	}
	return report, nil
}
