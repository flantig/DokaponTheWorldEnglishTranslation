package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
)

// tracePointerConsumers follows one asserted low32 origin on the shared graph.
// MAY aliases join by union; exact frame addresses survive only equal inputs.
// Corrupted or escaped spill provenance stays incomplete. Linked transfers stop
// after the real delay instruction: neither a return edge nor ABI clobbers exist.
// Stack-container witnesses require converged frame facts; interrupted work
// retains legacy events but cannot publish provisional container observations.
func tracePointerConsumers(rows []InstructionObservation, graph []registerFlowNode, roots []int, query RegisterFlowQuery, origin string, remainingWork int) ([]PointerConsumerEvent, []string, int) {
	type point struct {
		node  int
		after bool
	}
	type valueState struct {
		aliases    uint32
		frameKnown uint32
		frame      [32]int32
		spills     map[int32]bool
	}
	facts := make(map[point]valueState)
	queued := make(map[point]bool)
	pending := []point{}
	events := make(map[string]PointerConsumerEvent)
	containers := make(map[point][]PointerConsumerEvent)
	reasons := []string{}
	work := 0
	if query.Register == 0 {
		return []PointerConsumerEvent{}, reasons, work
	}
	for _, root := range roots {
		key := point{node: root, after: query.SeedPhase == "after"}
		facts[key] = valueState{aliases: uint32(1) << query.Register, frameKnown: uint32(1) << 29, spills: map[int32]bool{}}
		queued[key] = true
		pending = append(pending, key)
	}
	for first := 0; first < len(pending); first++ {
		if work == query.MaxVisitedStates {
			reasons = append(reasons, "work_limit")
			break
		}
		if work == remainingWork {
			reasons = append(reasons, "batch_work_limit")
			break
		}
		work++
		key := pending[first]
		queued[key] = false
		delete(containers, key)
		state := facts[key]
		state.spills = maps.Clone(state.spills)
		node := graph[key.node]
		row := rows[node.row]
		var emitted []PointerConsumerEvent
		stop := false
		before := state.aliases
		if !key.after {
			if row.Operands.Status == "unsupported_or_not_modelled" {
				reasons = append(reasons, "unsupported_instruction")
				stop = true
			} else {
				if row.Control != nil && row.Control.Kind == "register_jump" && before&(uint32(1)<<row.RS) != 0 {
					emitted = append(emitted, PointerConsumerEvent{Kind: "pointer_jump", Register: row.RS})
					reasons = append(reasons, "unresolved_indirect_exit")
				}
				memory := row.memory
				var loadedOrigin bool
				if memory != nil {
					baseOrigin := before&(uint32(1)<<memory.base) != 0
					valueOrigin := memory.bank == "GPR" && before&(uint32(1)<<memory.value) != 0
					addressKnown := state.frameKnown&(uint32(1)<<memory.base) != 0
					address := state.frame[memory.base] + memory.displacement
					if address < -8192 || address > 8192-int32(memory.width) {
						addressKnown = false
						if state.frameKnown&(uint32(1)<<memory.base) != 0 && (len(state.spills) != 0 || valueOrigin) {
							reasons = append(reasons, "stack_offset_limit")
						}
					}
					switch memory.kind {
					case "load", "store":
						if baseOrigin {
							kind := "pointee_read"
							if memory.kind == "store" {
								kind = "pointee_write"
							}
							emitted = append(emitted, PointerConsumerEvent{Kind: kind, Register: memory.base, Width: memory.width, Displacement: memory.displacement})
						}
						if !addressKnown && len(state.spills) != 0 && (memory.kind == "store" || memory.kind == "load" && memory.bank == "GPR" && memory.width == 4 && !memory.merge) {
							reasons = append(reasons, "stack_alias_unknown")
						}
						start, end := address, address+int32(memory.width)
						if memory.merge && memory.width != 0 {
							start = address &^ int32(memory.width-1)
							end = start + int32(memory.width)
						}
						if memory.kind == "load" {
							loadedOrigin = addressKnown && memory.bank == "GPR" && memory.width == 4 && !memory.merge && address%4 == 0 && state.spills[address]
							// Unsupported reloads can move origin bits out of this
							// domain; later clearing the slot cannot close that loss.
							if !loadedOrigin && len(state.spills) != 0 {
								for slot := range state.spills {
									// A less precise address cannot erase possible origin-bit loss.
									mayOverlap := !addressKnown || start < slot+4 && slot < end
									supported := memory.bank == "GPR" && memory.width == 4 && !memory.merge && (!addressKnown || address%4 == 0)
									if mayOverlap && !supported {
										reasons = append(reasons, "unsupported_spill_reload")
									}
								}
							}
							// Losing an exact address must not erase an earlier MAY load.
							if !addressKnown && len(state.spills) != 0 && memory.bank == "GPR" && memory.width == 4 && !memory.merge {
								loadedOrigin = true
								reasons = append(reasons, "stack_alias_unknown")
							}
							if memory.merge && (baseOrigin || valueOrigin) {
								reasons = append(reasons, "unsupported_origin_transfer")
								stop = true
							}
						} else {
							for slot := range state.spills {
								if addressKnown && start < slot+4 && slot < end {
									if memory.merge || address > slot || address+int32(memory.width) < slot+4 {
										reasons = append(reasons, "stack_partial_overwrite")
									} else if !valueOrigin || memory.width == 4 && address%4 == 0 {
										delete(state.spills, slot)
									} else {
										reasons = append(reasons, "unsupported_pointer_spill_width")
									}
								}
							}
							if valueOrigin {
								switch {
								case addressKnown && memory.width == 4 && !memory.merge && address%4 == 0:
									state.spills[address] = true
								case addressKnown:
									reasons = append(reasons, "unsupported_pointer_spill_width")
								default:
									emitted = append(emitted, PointerConsumerEvent{Kind: "pointer_store_escape", Register: memory.value, Width: memory.width, Displacement: memory.displacement})
									reasons = append(reasons, "pointer_store_escape")
								}
							}
						}
					default:
						if baseOrigin || len(state.spills) != 0 {
							reasons = append(reasons, "unsupported_memory_effect")
							stop = true
						}
					}
				}
				// A known overwrite kills only that register, never another alias.
				previousFrames, previousKnown := state.frame, state.frameKnown
				for _, destination := range row.Operands.GPRMustWrite {
					if !slices.Contains(row.Operands.IncomingPreservation, destination) {
						state.aliases &^= uint32(1) << destination
						state.frameKnown &^= uint32(1) << destination
						state.frame[destination] = 0
					}
				}
				if loadedOrigin {
					state.aliases |= uint32(1) << memory.value
				}
				if transfer := row.transfer; transfer != nil && transfer.destination != 0 {
					destination, source := uint32(1)<<transfer.destination, uint32(1)<<transfer.source
					if transfer.kind != "keep" {
						if before&source != 0 {
							state.aliases |= destination
						}
						frameKnown := previousKnown&source != 0
						frame := previousFrames[transfer.source] + transfer.displacement
						if frame < -8192 || frame >= 8192 {
							frameKnown = false
						}
						if transfer.kind == "conditional" && (previousKnown&destination == 0 || previousFrames[transfer.destination] != frame) {
							frameKnown = false
						}
						state.frameKnown &^= destination
						state.frame[transfer.destination] = 0
						if frameKnown {
							state.frameKnown |= destination
							state.frame[transfer.destination] = frame
						}
					}
				} else if memory == nil && row.Control == nil && row.transfer == nil {
					for _, register := range row.Operands.GPRReads {
						if before&(uint32(1)<<register) != 0 {
							emitted = append(emitted, PointerConsumerEvent{Kind: "provenance_loss", Register: register})
							reasons = append(reasons, "unsupported_origin_transfer")
							stop = true
						}
					}
				}
				state.aliases &^= 1
				state.frameKnown &^= 1
			}
		}
		live := state.aliases != 0 || len(state.spills) != 0
		if !stop && node.controller >= 0 {
			controller := rows[node.controller]
			control := controller.Control
			actualCall := control.LinkRegister != nil && (control.Kind != "conditional_branch" || node.path >= 0 && control.PossiblePaths[node.path].ConditionTaken)
			if actualCall {
				for register := uint32(4); register <= 11; register++ {
					if state.aliases&(uint32(1)<<register) != 0 {
						emitted = append(emitted, PointerConsumerEvent{Kind: "call_argument", Register: register, Target: control.Target})
					}
					if len(state.spills) != 0 && state.frameKnown&(uint32(1)<<register) != 0 {
						reasons = append(reasons, "stack_escape_unknown")
						// The historical 64-byte window bounds spill starts, not an object.
						minimum := int32(64)
						for slot := range state.spills {
							if displacement := slot - state.frame[register]; displacement >= 0 && displacement < minimum {
								minimum = displacement
							}
						}
						if minimum < 64 {
							emitted = append(emitted, PointerConsumerEvent{Kind: "stack_container_argument", Register: register, Width: 4, Displacement: minimum, Target: control.Target})
						}
					}
				}
				if live {
					reasons = append(reasons, "call_continuation_unmodelled")
					if control.Target == nil {
						reasons = append(reasons, "unresolved_indirect_exit")
					}
				}
				stop = true
			} else if control.Kind == "register_jump" {
				if controller.RS == 31 {
					for _, register := range []uint32{2, 3} {
						if state.aliases&(uint32(1)<<register) != 0 {
							emitted = append(emitted, PointerConsumerEvent{Kind: "return_escape", Register: register})
						}
					}
				}
				if live {
					reasons = append(reasons, "unresolved_indirect_exit")
				}
				stop = true
			}
		}
		for _, event := range emitted {
			event.Origin, event.VMA = origin, uint32(row.VMA)
			if node.controller >= 0 {
				controller := uint32(rows[node.controller].VMA)
				event.DelayOf = &controller
				if rows[node.controller].Control.Kind == "conditional_branch" && node.path >= 0 {
					taken := rows[node.controller].Control.PossiblePaths[node.path].ConditionTaken
					event.Taken = &taken
				}
			}
			if event.Kind == "stack_container_argument" {
				containers[key] = append(containers[key], event)
				continue
			}
			wire, _ := json.Marshal(event)
			events[fmt.Sprintf("%08x/%s/%02d/%s", event.VMA, event.Kind, event.Register, wire)] = event
		}
		if len(state.spills) > 64 {
			reasons = append(reasons, "spill_slot_limit")
			stop = true
		}
		if stop || !live {
			continue
		}
		reasons = append(reasons, node.unknown...)
		for _, successor := range node.successors {
			next := point{node: successor}
			joined := state
			joined.spills = maps.Clone(state.spills)
			if old, exists := facts[next]; exists {
				joined.aliases |= old.aliases
				for register := uint32(0); register < 32; register++ {
					bit := uint32(1) << register
					if old.frameKnown&bit == 0 || joined.frameKnown&bit == 0 || old.frame[register] != joined.frame[register] {
						joined.frameKnown &^= bit
						joined.frame[register] = 0
					}
				}
				for slot := range old.spills {
					joined.spills[slot] = true
				}
				if joined.aliases == old.aliases && joined.frameKnown == old.frameKnown && joined.frame == old.frame && maps.Equal(joined.spills, old.spills) {
					continue
				}
			}
			if len(joined.spills) > 64 {
				reasons = append(reasons, "spill_slot_limit")
				continue
			}
			facts[next] = joined
			if !queued[next] {
				queued[next] = true
				pending = append(pending, next)
			}
		}
	}
	if !slices.Contains(reasons, "work_limit") && !slices.Contains(reasons, "batch_work_limit") && !slices.Contains(reasons, "spill_slot_limit") {
		for _, candidates := range containers {
			for _, event := range candidates {
				identity := event
				identity.Displacement, identity.Target = 0, nil
				wire, _ := json.Marshal(identity)
				key := fmt.Sprintf("%08x/%s/%02d/%s", event.VMA, event.Kind, event.Register, wire)
				if old, exists := events[key]; !exists || event.Displacement < old.Displacement {
					events[key] = event
				}
			}
		}
	}
	keys := make([]string, 0, len(events))
	for key := range events {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	ordered := make([]PointerConsumerEvent, 0, len(keys))
	for _, key := range keys {
		ordered = append(ordered, events[key])
	}
	return ordered, reasons, work
}
