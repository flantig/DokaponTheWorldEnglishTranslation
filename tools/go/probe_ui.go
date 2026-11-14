package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// readProbeUI follows only the pinned source's bounded player/widget layouts.
// Every phase uses the existing guarded read owner and pure decoders. Unsupported
// pointers/glyphs stay explicit on their widget, never a truncated trusted match.
func readProbeUI(plan ProbeUIPlan, runtime ProbeMemoryRuntime) (ProbeUIState, error) {
	var state ProbeUIState
	admission, err := admitProbeRecords(plan.Admission)
	if err != nil {
		return state, err
	}
	if admission.SourceSchema != "go-probe-records-v1" || runtime.Provenance != "owned_go" || plan.TimeoutMS < 1 || plan.TimeoutMS > 10000 || plan.MaxReads < 1 || plan.MaxReads > 32768 {
		return state, fmt.Errorf("UI acquisition requires bounded owned Go context")
	}
	if _, _, err := glyphMaps(plan.Glyphmap, true); err != nil {
		return state, err
	}
	var source struct {
		Version      int
		SHA          string `json:"source_sha256"`
		Headers      map[string][]uint32
		PlayerBase   uint32 `json:"player_base"`
		PlayerStride uint32 `json:"player_stride"`
		PlayerBytes  uint32 `json:"player_bytes"`
		QueueBase    uint32 `json:"queue_base"`
		QueueStride  uint32 `json:"queue_stride"`
		QueueCount   int    `json:"queue_count"`
		WidgetBase   uint32 `json:"widget_base"`
		WidgetStride uint32 `json:"widget_stride"`
		WidgetCount  int    `json:"widget_count"`
		MaxGlyphs    uint32 `json:"max_glyphs"`
		Begin        uint32 `json:"ee_begin"`
		End          uint32 `json:"ee_end"`
	}
	if json.Unmarshal(probeUISource, &source) != nil || source.Version != 1 || source.PlayerBytes != 508 || source.WidgetCount != 20 || source.MaxGlyphs != 512 {
		return state, fmt.Errorf("invalid built-in UI source layout")
	}
	state = ProbeUIState{AdmissionSHA256: fmt.Sprintf("%x", sha256.Sum256(plan.Admission)), Session: admission.Session, Epoch: admission.Epoch, PID: admission.PID, Headers: map[string]uint64{}, Saved: ProbeSavedState{Players: make([]ProbeSavedPlayer, 4)}, PlayerRecords: make([][]byte, 4), Widgets: []ProbeUIWidget{}, Unsupported: []string{}}
	deadline := time.Now().Add(time.Duration(plan.TimeoutMS) * time.Millisecond)
	phases := []probeUIPhase{{Kind: "header"}, {Kind: "queue"}}
	for index := 0; index < 4; index++ {
		phases = append(phases, probeUIPhase{Kind: "player", Index: index, Base: source.PlayerBase + uint32(index)*source.PlayerStride})
	}
	phases = append(phases, probeUIPhase{Kind: "widgets"})
	for phaseIndex := 0; phaseIndex < len(phases); phaseIndex++ {
		phase := phases[phaseIndex]
		reads := []ProbeMemoryRequest{}
		decoders := []ProbeMemoryDecoder{}
		specifications := []struct {
			ID      string
			Opcode  uint32
			Address uint32
		}{}
		switch phase.Kind {
		case "header":
			keys := []string{}
			for key := range source.Headers {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				field := source.Headers[key]
				specifications = append(specifications, struct {
					ID      string
					Opcode  uint32
					Address uint32
				}{key, field[0], field[1]})
			}
		case "queue":
			for index := 0; index < source.QueueCount*5; index++ {
				specifications = append(specifications, struct {
					ID      string
					Opcode  uint32
					Address uint32
				}{fmt.Sprintf("q%d", index), 2, source.QueueBase + uint32(index)*4})
			}
		case "player":
			ids := []string{}
			for offset := uint32(0); offset < 508; offset += 4 {
				id := fmt.Sprintf("p%d-%d", phase.Index, offset)
				ids = append(ids, id)
				specifications = append(specifications, struct {
					ID      string
					Opcode  uint32
					Address uint32
				}{id, 2, phase.Base + offset})
			}
			decoders = append(decoders, ProbeMemoryDecoder{ID: "player", Kind: "player", Requests: ids})
		case "widgets":
			for index := 0; index < source.WidgetCount; index++ {
				base := source.WidgetBase + uint32(index)*source.WidgetStride
				specifications = append(specifications, struct {
					ID      string
					Opcode  uint32
					Address uint32
				}{fmt.Sprintf("flags%d", index), 1, base}, struct {
					ID      string
					Opcode  uint32
					Address uint32
				}{fmt.Sprintf("kind%d", index), 1, base + 4})
			}
		case "widget":
			for _, field := range []struct {
				ID             string
				Opcode, Offset uint32
			}{{"source", 2, 0x70}, {"cursor", 2, 0xb0}, {"ready", 0, 0x48}, {"page", 0, 0x4d}, {"count", 1, 0x58}, {"glyphs", 2, 0x94}} {
				specifications = append(specifications, struct {
					ID      string
					Opcode  uint32
					Address uint32
				}{field.ID, field.Opcode, phase.Base + field.Offset})
			}
			if state.Widgets[phase.Index].Kind == 9 {
				specifications = append(specifications, struct {
					ID      string
					Opcode  uint32
					Address uint32
				}{"primitive", 2, phase.Base + 0xa0})
			}
		case "cursor":
			for index, offset := range []uint32{0, 0x16, 0x18, 0x1a, 0x1c, 4} {
				opcode := uint32(1)
				if index == 0 {
					opcode = 0
				}
				specifications = append(specifications, struct {
					ID      string
					Opcode  uint32
					Address uint32
				}{fmt.Sprintf("c%d", index), opcode, phase.Base + offset})
			}
			decoders = append(decoders, ProbeMemoryDecoder{ID: "cursor", Kind: "cursor", Requests: []string{"c0", "c1", "c2", "c3", "c4"}})
		case "nodes":
			for index := uint32(0); index < phase.Count; index++ {
				specifications = append(specifications, struct {
					ID      string
					Opcode  uint32
					Address uint32
				}{fmt.Sprintf("n%d", index), 2, phase.Base + (phase.Offset+index)*96 + 0x18})
			}
		case "labels":
			for index, node := range phase.Values {
				if node < uint64(source.Begin) || node > uint64(source.End)-0x20 {
					state.Widgets[phase.Index].Unsupported = true
					state.Unsupported = append(state.Unsupported, fmt.Sprintf("widget%d glyph pointer unsupported", state.Widgets[phase.Index].Index))
					continue
				}
				id := fmt.Sprintf("g%d", index)
				specifications = append(specifications, struct {
					ID      string
					Opcode  uint32
					Address uint32
				}{id, 2, phase.Base + (phase.Offset+uint32(index))*96 + 0x18}, struct {
					ID      string
					Opcode  uint32
					Address uint32
				}{id + "a", 3, uint32(node) + 0x10}, struct {
					ID      string
					Opcode  uint32
					Address uint32
				}{id + "b", 3, uint32(node) + 0x18})
				decoders = append(decoders, ProbeMemoryDecoder{ID: id, Kind: "char", Requests: []string{id, id + "a", id + "b"}, Glyphmap: plan.Glyphmap})
			}
		case "image-pointer":
			specifications = append(specifications, struct {
				ID      string
				Opcode  uint32
				Address uint32
			}{"primitive", 2, source.WidgetBase + uint32(state.Widgets[phase.Index].Index)*source.WidgetStride + 0xa0}, struct {
				ID      string
				Opcode  uint32
				Address uint32
			}{"texture", 2, phase.Base + 8})
		case "image-name":
			specifications = append(specifications, struct {
				ID      string
				Opcode  uint32
				Address uint32
			}{"primitive", 2, source.WidgetBase + uint32(state.Widgets[phase.Index].Index)*source.WidgetStride + 0xa0}, struct {
				ID      string
				Opcode  uint32
				Address uint32
			}{"texture", 2, uint32(phase.Values[0]) + 8})
			ids := []string{"primitive", "texture"}
			for index := uint32(0); index < 4; index++ {
				id := fmt.Sprintf("name%d", index)
				ids = append(ids, id)
				specifications = append(specifications, struct {
					ID      string
					Opcode  uint32
					Address uint32
				}{id, 3, phase.Base + 0x10 + index*8})
			}
			decoders = append(decoders, ProbeMemoryDecoder{ID: "texture", Kind: "texture", Requests: ids})
		}
		if len(specifications) == 0 {
			continue
		}
		if len(specifications) > 512 || state.Reads+len(specifications) > plan.MaxReads || !time.Now().Before(deadline) {
			return ProbeUIState{}, fmt.Errorf("UI acquisition read/deadline budget exhausted")
		}
		for _, specification := range specifications {
			opcode, address := uint8(specification.Opcode), specification.Address
			reads = append(reads, ProbeMemoryRequest{ID: specification.ID, Opcode: &opcode, Address: &address})
		}
		if len(decoders) == 0 {
			for _, read := range reads {
				decoders = append(decoders, ProbeMemoryDecoder{ID: read.ID, Kind: "scalar", Requests: []string{read.ID}})
			}
		}
		remaining := int(time.Until(deadline) / time.Millisecond)
		if remaining < 1 {
			return ProbeUIState{}, fmt.Errorf("UI acquisition deadline exhausted")
		}
		if remaining > 1000 {
			remaining = 1000
		}
		runtime.TimeoutMS = remaining
		memoryPlan := ProbeMemoryBundle{Version: 1, SourceSHA256: source.SHA, Admission: plan.Admission, BuildSHA256: plan.BuildSHA256, Requests: reads, Decoders: decoders}
		requestRaw, _ := json.Marshal(memoryPlan)
		runtimeRaw, _ := json.Marshal(runtime)
		acquired, err := readProbeMemory(requestRaw, runtimeRaw)
		if err != nil {
			return ProbeUIState{}, err
		}
		state.Reads += len(reads)
		values := map[string]uint64{}
		for _, observation := range acquired.Observations {
			values[observation.ID] = observation.Value
		}
		switch phase.Kind {
		case "header":
			state.Headers = values
			fields := []*(*uint32){&state.Saved.Story, &state.Saved.Week, &state.Saved.Day, &state.Saved.Current, &state.Saved.Area}
			for index, key := range []string{"story", "week", "day", "current", "area"} {
				value := uint32(values[key])
				*fields[index] = &value
			}
		case "queue":
			for index := 0; index < source.QueueCount; index++ {
				flags, task, actorKind := values[fmt.Sprintf("q%d", index*5)], values[fmt.Sprintf("q%d", index*5+1)], values[fmt.Sprintf("q%d", index*5+2)]
				if flags&5 == 5 && task&0xffff != 0xffff && actorKind&0xff == state.Headers["current"] && actorKind>>8&0xff == 2 {
					state.BoardAIReady = true
				}
			}
		case "player":
			state.Saved.Players[phase.Index] = *acquired.Decoded[0].Player
			for _, observation := range acquired.Observations {
				frame, err := hex.DecodeString(observation.ReplyHex)
				if err != nil || len(frame) != 9 {
					return ProbeUIState{}, fmt.Errorf("player frame length differs")
				}
				state.PlayerRecords[phase.Index] = append(state.PlayerRecords[phase.Index], frame[5:]...)
			}
		case "widgets":
			for index := 0; index < source.WidgetCount; index++ {
				flags := values[fmt.Sprintf("flags%d", index)]
				if flags&1 == 0 || flags&2 != 0 {
					continue
				}
				position := len(state.Widgets)
				state.Widgets = append(state.Widgets, ProbeUIWidget{Index: index, Flags: flags, Kind: values[fmt.Sprintf("kind%d", index)]})
				phases = append(phases, probeUIPhase{Kind: "widget", Index: position, Base: source.WidgetBase + uint32(index)*source.WidgetStride})
			}
		case "widget":
			widget := &state.Widgets[phase.Index]
			widget.Source, widget.Ready, widget.Page = values["source"], values["ready"], values["page"]
			cursor := values["cursor"]
			if cursor >= uint64(source.Begin) && cursor <= uint64(source.End)-0x50 {
				phases = append(phases, probeUIPhase{Kind: "cursor", Index: phase.Index, Base: uint32(cursor)})
			}
			count, glyphs := values["count"], values["glyphs"]
			if count > 0 && count <= uint64(source.MaxGlyphs) && glyphs >= uint64(source.Begin) && glyphs <= uint64(source.End)-count*96 {
				for offset := uint32(0); offset < uint32(count); offset += 128 {
					batch := uint32(count) - offset
					if batch > 128 {
						batch = 128
					}
					phases = append(phases, probeUIPhase{Kind: "nodes", Index: phase.Index, Base: uint32(glyphs), Offset: offset, Count: batch})
				}
			} else if count > 0 {
				widget.Unsupported = true
				state.Unsupported = append(state.Unsupported, fmt.Sprintf("widget%d glyph span unsupported", widget.Index))
			}
			primitive := values["primitive"]
			if widget.Kind == 9 {
				if primitive&3 == 0 && primitive >= uint64(source.Begin) && primitive <= uint64(source.End)-0x20 {
					phases = append(phases, probeUIPhase{Kind: "image-pointer", Index: phase.Index, Base: uint32(primitive)})
				} else {
					widget.Unsupported = true
					state.Unsupported = append(state.Unsupported, "image primitive unsupported")
				}
			}
		case "cursor":
			widget := &state.Widgets[phase.Index]
			if acquired.Decoded[0].Status != "KNOWN" {
				widget.Unsupported = true
				state.Unsupported = append(state.Unsupported, acquired.Decoded[0].Reason)
			} else {
				widget.Selection = acquired.Decoded[0].Cursor
				rows := values["c5"]
				widget.Rows = &rows
			}
		case "nodes":
			nodes := make([]uint64, phase.Count)
			for index := range nodes {
				nodes[index] = values[fmt.Sprintf("n%d", index)]
			}
			for offset := 0; offset < len(nodes); offset += 128 {
				end := offset + 128
				if end > len(nodes) {
					end = len(nodes)
				}
				phases = append(phases, probeUIPhase{Kind: "labels", Index: phase.Index, Base: phase.Base, Offset: phase.Offset + uint32(offset), Values: nodes[offset:end]})
			}
		case "labels":
			for _, decoded := range acquired.Decoded {
				if decoded.Status != "KNOWN" || decoded.Text == nil {
					state.Widgets[phase.Index].Unsupported = true
					state.Unsupported = append(state.Unsupported, decoded.Reason)
				} else {
					state.Widgets[phase.Index].Text += *decoded.Text
				}
			}
		case "image-pointer":
			texture := values["texture"]
			if texture&3 != 0 || texture < uint64(source.Begin) || texture > uint64(source.End)-0x60 {
				state.Widgets[phase.Index].Unsupported = true
				state.Unsupported = append(state.Unsupported, "image texture pointer unsupported")
			} else {
				phases = append(phases, probeUIPhase{Kind: "image-name", Index: phase.Index, Base: uint32(texture), Values: []uint64{uint64(phase.Base)}})
			}
		case "image-name":
			decoded := acquired.Decoded[0]
			if decoded.Status != "KNOWN" || decoded.Text == nil {
				state.Widgets[phase.Index].Unsupported = true
				state.Unsupported = append(state.Unsupported, decoded.Reason)
			} else {
				state.Widgets[phase.Index].ImageTexture = *decoded.Text
			}
		}
	}
	return state, nil
}
