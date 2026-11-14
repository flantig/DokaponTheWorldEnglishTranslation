package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
)

// reportProbeEvidence compares qualified saved observations, never runtime paths.
// Coverage requires the source's changed progress tuple before resumed, exact
// warm/cold fingerprints, ordered handoff, and every declared comparison.
// Tutorial normalization is limited to the armed actor's preparation transaction.
func reportProbeEvidence(raw []byte) (ProbeEvidenceReport, error) {
	var report ProbeEvidenceReport
	if len(raw) == 0 || len(raw) > 4<<20 {
		return report, fmt.Errorf("probe evidence exceeds its 4MiB input bound")
	}
	if err := checkJSON(checkedJSON{raw: raw, allObjects: true, text: true}); err != nil {
		return report, err
	}
	var bundle ProbeEvidenceBundle
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return report, err
	}
	if bundle.Version != 1 || !slices.Contains([]string{"probe-evidence-legacy-2026-11-13", "probe-evidence-go-v1"}, bundle.SourceSchema) || bundle.SourceSHA256 != "f6d9bcf48634a234da6632f42e4faea9f66d79dcaad0783b79ccce477ed4f0e8" {
		return report, fmt.Errorf("unsupported probe evidence version or source schema")
	}
	admission, err := admitProbeRecords(bundle.Admission)
	if err != nil {
		return report, fmt.Errorf("probe evidence admission: %w", err)
	}
	if (bundle.SourceSchema == "probe-evidence-go-v1") != (admission.SourceSchema == "go-probe-records-v1") {
		return report, fmt.Errorf("probe evidence producer version differs from admission")
	}
	if bundle.RunID != admission.RunID || bundle.Session != admission.Session || bundle.ISOSHA256 != admission.ISOSHA256 || bundle.Epoch == nil || *bundle.Epoch != admission.Epoch {
		return report, fmt.Errorf("probe evidence identity differs from admitted records")
	}
	storyOnly := bundle.SourceSchema == "probe-evidence-go-v1" && bundle.Cohort == "go-story-checkpoints-v1"
	checkpointOnly := bundle.SourceSchema == "probe-evidence-go-v1" && (bundle.Cohort == "go-checkpoint-only-v1" || storyOnly)
	var storyData struct {
		Recipes map[string]ProbeStoryRecipe `json:"recipes"`
	}
	if json.Unmarshal(probeScenarioData, &storyData) != nil {
		return report, fmt.Errorf("invalid story recipe facts")
	}
	var storyRecipe ProbeStoryRecipe
	if bundle.Story != nil {
		storyRecipe = storyData.Recipes[bundle.Story.Recipe]
	}
	if storyOnly && (bundle.Story == nil || storyRecipe.Required == "") || !storyOnly && bundle.Story != nil {
		return report, fmt.Errorf("unsupported explicit story evidence scope")
	}
	if storyOnly && (bundle.Story.Phase != "checkpoint" && bundle.Story.Phase != "complete" || bundle.Story.Phase == "checkpoint" && bundle.Story.TerminalEventID != 0 || bundle.Story.Phase == "complete" && bundle.Story.TerminalEventID < 1) {
		return report, fmt.Errorf("story phase/terminal membership differs")
	}
	if strings.TrimSpace(bundle.Cohort) == "" || len(bundle.Cohort) > 128 || !checkpointOnly && len(bundle.Members) < 1 || checkpointOnly && (len(bundle.Members) != 0 || len(bundle.Checks) != 0) || len(bundle.Members) > 256 || len(bundle.Checks) > 256 || len(bundle.Events) < 1 || len(bundle.Events) > 4096 {
		return report, fmt.Errorf("probe evidence requires a bounded nonempty cohort, membership and event stream")
	}
	report = ProbeEvidenceReport{Version: 1, SourceSchema: bundle.SourceSchema, BundleSHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), RunID: admission.RunID, Session: admission.Session, ISOSHA256: admission.ISOSHA256, Epoch: admission.Epoch, Cohort: bundle.Cohort, Status: "PASS", Rows: []ProbeEvidenceResult{}, Checkpoints: []ProbeCheckpointResult{}, CoveredAreas: []uint32{}, Events: bundle.Events, Limits: "Qualified saved observations only; narrative normalization does not prove controls/layout, code facts do not prove ABI, and exact RGBA does not approve artwork. Coverage requires the source progress tuple to change before resumed, not live runtime authenticity."}
	hashPattern := regexp.MustCompile(`^[0-9a-f]{64}$`)
	var events []struct {
		Event          string            `json:"event"`
		EventID        int               `json:"event_id"`
		Checkpoint     int               `json:"checkpoint"`
		Time           string            `json:"time"`
		State          *ProbeSavedState  `json:"state"`
		Expected       *ProbeSavedState  `json:"expected"`
		Slot           *int              `json:"slot"`
		Method         string            `json:"method"`
		Phase          string            `json:"phase"`
		PreviewSamples int               `json:"successful_preview_samples"`
		Mode           *uint64           `json:"mode,omitempty"`
		Prompt         *ProbeUIWidget    `json:"prompt,omitempty"`
		PromptHeaders  map[string]uint64 `json:"prompt_headers,omitempty"`
	}
	eventCheckpoint := map[int]int{}
	var previousEnd int64 = -1
	previousID, previousCheckpoint := 0, 0
	for _, saved := range bundle.Events {
		var event struct {
			Event          string            `json:"event"`
			EventID        int               `json:"event_id"`
			Checkpoint     int               `json:"checkpoint"`
			Time           string            `json:"time"`
			State          *ProbeSavedState  `json:"state"`
			Expected       *ProbeSavedState  `json:"expected"`
			Slot           *int              `json:"slot"`
			Method         string            `json:"method"`
			Phase          string            `json:"phase"`
			PreviewSamples int               `json:"successful_preview_samples"`
			Mode           *uint64           `json:"mode,omitempty"`
			Prompt         *ProbeUIWidget    `json:"prompt,omitempty"`
			PromptHeaders  map[string]uint64 `json:"prompt_headers,omitempty"`
		}
		if err := json.Unmarshal(saved.Data, &event); err != nil {
			return report, err
		}
		if saved.Offset < 0 || saved.Offset < previousEnd || event.EventID <= previousID || event.Checkpoint < previousCheckpoint || event.Event == "" {
			return report, fmt.Errorf("probe evidence events must preserve distinct IDs, checkpoint order and nonoverlapping source offsets")
		}
		if _, err := time.Parse("2006-01-02T15:04:05-0700", event.Time); err != nil {
			return report, fmt.Errorf("probe evidence event requires its source timestamp")
		}
		if event.Slot != nil && *event.Slot < 0 {
			return report, fmt.Errorf("probe evidence native slot must be nonnegative")
		}
		for _, state := range []*ProbeSavedState{event.State, event.Expected} {
			if state == nil {
				continue
			}
			if state.Story == nil || state.Week == nil || state.Day == nil || state.Current == nil || *state.Current > 3 || state.Area == nil || len(state.Players) != 4 {
				return report, fmt.Errorf("probe evidence state requires every SAVE_FIELD and four complete player fingerprints")
			}
			for _, player := range state.Players {
				if player.Control == nil || player.Square == nil || player.Money == nil || player.TutorialFlags == nil || len(player.NameWords) != 5 || !hashPattern.MatchString(player.RecordSHA256) || !hashPattern.MatchString(player.TutorialInitializedSHA256) {
					return report, fmt.Errorf("probe evidence state requires every SAVE_FIELD and four complete player fingerprints")
				}
			}
		}
		previousEnd = saved.Offset + int64(len(saved.Data))
		previousID = event.EventID
		previousCheckpoint = event.Checkpoint
		eventCheckpoint[event.EventID] = event.Checkpoint
		events = append(events, event)
	}
	// These are transaction facts, not caller-supplied PASS or coverage counters.
	checkpoints := map[int]*struct {
		Result                                                ProbeCheckpointResult
		Baseline, Prepared                                    *ProbeSavedState
		Preparing, Image, Ack, PreparedDone, Handed, Progress bool
		Method, Phase                                         string
	}{}
	var checkpointOrder []int
	for _, event := range events {
		if event.Checkpoint == 0 {
			continue
		}
		checkpoint := checkpoints[event.Checkpoint]
		if checkpoint == nil {
			checkpoint = &struct {
				Result                                                ProbeCheckpointResult
				Baseline, Prepared                                    *ProbeSavedState
				Preparing, Image, Ack, PreparedDone, Handed, Progress bool
				Method, Phase                                         string
			}{Result: ProbeCheckpointResult{Checkpoint: event.Checkpoint, Status: "UNKNOWN", Reason: "incomplete checkpoint"}}
			checkpoints[event.Checkpoint] = checkpoint
			checkpointOrder = append(checkpointOrder, event.Checkpoint)
		}
		if event.Slot != nil {
			if checkpoint.Result.Slot == nil {
				checkpoint.Result.Slot = event.Slot
			} else if *event.Slot != *checkpoint.Result.Slot {
				checkpoint.Result.Status, checkpoint.Result.Reason = "FAIL", "native slot mismatch"
			}
		}
		problem := ""
		switch event.Event {
		case "tutorial-preparation-start":
			if event.State == nil || checkpoint.Preparing || checkpoint.Baseline != nil || event.Slot == nil {
				problem = "invalid tutorial preparation order"
				break
			}
			actor := *event.State.Current
			if *event.State.Players[actor].TutorialFlags&1 != 0 {
				problem = "tutorial preparation requires the uninitialized current actor"
				break
			}
			encoded, _ := json.Marshal(event.State)
			var prepared ProbeSavedState
			_ = json.Unmarshal(encoded, &prepared)
			*prepared.Players[actor].TutorialFlags |= 1
			prepared.Players[actor].RecordSHA256 = prepared.Players[actor].TutorialInitializedSHA256
			checkpoint.Prepared, checkpoint.Preparing = &prepared, true
		case "tutorial-preparation-image", "tutorial-preparation-ack", "tutorial-preparation-complete":
			if !checkpoint.Preparing || event.Slot == nil || event.State == nil || !reflect.DeepEqual(event.State, checkpoint.Prepared) {
				problem = "tutorial preparation fingerprint mismatch"
				break
			}
			switch event.Event {
			case "tutorial-preparation-image":
				if checkpoint.Method != "warm" || checkpoint.Phase != "preparation" {
					problem = "tutorial preparation reload order mismatch"
				}
				checkpoint.Image = true
			case "tutorial-preparation-ack":
				if !checkpoint.Image {
					problem = "tutorial preparation acknowledgement precedes image"
				}
				checkpoint.Ack = true
			case "tutorial-preparation-complete":
				if !checkpoint.Ack {
					problem = "tutorial preparation completion precedes acknowledgement"
				}
				checkpoint.PreparedDone = true
			}
		case "save-complete":
			if event.State == nil || event.Slot == nil {
				problem = "save lacks complete state or native slot"
				break
			}
			if checkpoint.Preparing && !checkpoint.PreparedDone {
				break
			} // The preparation's own save is not the final baseline.
			if checkpoint.Baseline != nil {
				problem = "duplicate final save"
				break
			}
			if checkpoint.PreparedDone && !reflect.DeepEqual(event.State, checkpoint.Prepared) {
				problem = "tutorial final save fingerprint mismatch"
				break
			}
			checkpoint.Baseline = event.State
			checkpoint.Result.Area = event.State.Area
		case "reload-start":
			checkpoint.Method, checkpoint.Phase = event.Method, event.Phase
			if event.Method != "warm" && event.Method != "cold" {
				problem = "unknown reload method"
			}
			if event.Phase != "verification" && event.Phase != "preparation" {
				problem = "unknown reload phase"
			}
		case "reload-verified":
			if checkpointOnly && event.PreviewSamples != 40 {
				problem = "reload lacks all40 successful source preview samples"
				break
			}
			if checkpoint.Baseline == nil || event.State == nil || event.Slot == nil || checkpoint.Phase != "verification" || checkpoint.Method != event.Method {
				problem = "reload verification order or phase mismatch"
				break
			}
			if !reflect.DeepEqual(event.State, checkpoint.Baseline) {
				problem = "reload fingerprint mismatch"
				break
			}
			switch event.Method {
			case "warm":
				if checkpoint.Result.Warm || checkpoint.Result.Cold {
					problem = "warm verification order mismatch"
				}
				checkpoint.Result.Warm = true
			case "cold":
				if !checkpoint.Result.Warm || checkpoint.Result.Cold {
					problem = "cold verification order mismatch"
				}
				checkpoint.Result.Cold = true
			default:
				problem = "unknown reload method"
			}
		case "com-handoff-data-main":
			if !checkpoint.Result.Warm || !checkpoint.Result.Cold || event.Slot == nil || event.State == nil || !reflect.DeepEqual(event.State, checkpoint.Baseline) {
				problem = "handoff lacks matching warm/cold verification"
				break
			}
			checkpoint.Handed = true
		case "resumed":
			if !checkpoint.Handed || !checkpoint.Progress || event.Slot == nil || event.Expected == nil || !reflect.DeepEqual(event.Expected, checkpoint.Baseline) {
				problem = "advancement lacks matching handoff and changed progress"
				break
			}
			checkpoint.Result.Advanced = true
		case "story-advanced-after-reload":
			if !checkpoint.Handed || event.State == nil || checkpoint.Baseline == nil {
				problem = "progress observation precedes matching handoff"
				break
			}
			before := checkpoint.Baseline
			changed := *event.State.Story != *before.Story || *event.State.Week != *before.Week || *event.State.Day != *before.Day
			for i, player := range event.State.Players {
				changed = changed || *player.Square != *before.Players[i].Square || *player.Money != *before.Players[i].Money
			}
			if !changed {
				problem = "advancement did not change the source progress tuple"
				break
			}
			checkpoint.Progress = true
		}
		if problem != "" {
			checkpoint.Result.Status, checkpoint.Result.Reason = "FAIL", problem
		}
	}
	statusRank := map[string]int{"PASS": 0, "SKIPPED": 1, "UNKNOWN": 2, "FAIL": 3}
	for _, checkpoint := range checkpoints {
		if checkpoint.Result.Status == "UNKNOWN" && checkpoint.Result.Reason == "incomplete checkpoint" && checkpoint.Result.Warm && checkpoint.Result.Cold && checkpoint.Result.Advanced {
			checkpoint.Result.Status, checkpoint.Result.Reason = "PASS", ""
		}
	}
	members := map[string]bool{}
	checks := map[string]ProbeEvidenceCheck{}
	for _, id := range bundle.Members {
		if id == "" || len(id) > 128 || members[id] {
			return report, fmt.Errorf("probe evidence membership must contain distinct bounded IDs")
		}
		members[id] = true
	}
	previousID = 0
	comparisonOrder := []string{}
	for _, check := range bundle.Checks {
		if !members[check.ID] || checks[check.ID].ID != "" {
			return report, fmt.Errorf("probe evidence check is duplicate or outside declared membership")
		}
		if _, ok := eventCheckpoint[check.EventID]; !ok || check.EventID < previousID {
			return report, fmt.Errorf("probe comparisons must retain existing event IDs and source order")
		}
		previousID = check.EventID
		checks[check.ID] = check
		comparisonOrder = append(comparisonOrder, check.ID)
	}
	for _, id := range bundle.Members {
		if _, present := checks[id]; !present {
			comparisonOrder = append(comparisonOrder, id)
		}
	}
	narrativeControls := regexp.MustCompile(`<0x[0-9a-fA-F]{4}>|<PEN 0x[0-9a-fA-F]{4}>`)
	for _, id := range comparisonOrder {
		check, present := checks[id]
		row := ProbeEvidenceResult{ID: id, Status: "UNKNOWN", Reason: "missing required comparison"}
		if present {
			row.Kind, row.EventID = check.Kind, check.EventID
			source := ""
			switch check.Kind {
			case "fixed":
				source = "ec3ed1a8d92fbc5502851b5c0a41e2a1afeb8278a02875943165936cae500d99"
			case "narrative":
				source = "c816f9baccffd75c38a2b0fd2dec707c5e194ff50c78896e1abbe7dd8201fded"
			case "positional":
				source = "cb34703c7174a3712b3aa1d9f7875a4fc4cf17d24293c47468db9a3d5b132048"
			case "code":
				source = "69431ad09bfe6af52c384501a75051e3adc74271af01e21019c2e7339805e5fe"
				if check.SourceSHA256 == "a06d800442a077971f4be8b463f3059414659c67b1f49b2e31fee6f71e65ac20" {
					source = check.SourceSHA256
				}
			case "image":
				source = "017edb5f58ba708839fd8e623769b357e3469273f34cb404922382e545067a87"
			default:
				return report, fmt.Errorf("unsupported probe comparison kind %q", check.Kind)
			}
			if check.SourceSHA256 != source {
				return report, fmt.Errorf("probe comparison source contract differs")
			}
			switch check.Observation {
			case "SKIPPED", "UNKNOWN":
				if strings.TrimSpace(check.Reason) == "" {
					return report, fmt.Errorf("SKIPPED and UNKNOWN comparisons require their original reason")
				}
				row.Status, row.Reason = check.Observation, check.Reason
			case "observed":
				row.Status, row.Reason = "PASS", ""
				switch check.Kind {
				case "fixed":
					var field struct {
						Expected  *string         `json:"expected"`
						ActualHex *string         `json:"actual_hex"`
						Glyphmap  json.RawMessage `json:"glyphmap"`
					}
					if err := json.Unmarshal(check.Data, &field); err != nil || field.Expected == nil || len(field.Glyphmap) == 0 {
						return report, fmt.Errorf("fixed comparison requires expected text and source glyphmap")
					}
					if field.ActualHex == nil {
						row.Status, row.Reason = "UNKNOWN", "missing fixed-field observation"
						break
					}
					data, decodeErr := hex.DecodeString(*field.ActualHex)
					_, glyphs, mapErr := glyphMaps(field.Glyphmap, true)
					if decodeErr != nil || mapErr != nil || len(data) != 16 {
						row.Status, row.Reason = "UNKNOWN", "unsupported fixed-field decoding"
						break
					}
					shape, scanErr := controls(data, TextScanOptions{Decode: true, Glyphs: glyphs, FixedWords: 8})
					if scanErr != nil {
						row.Status, row.Reason = "UNKNOWN", "unsupported fixed-field decoding"
						break
					}
					var text strings.Builder
					for _, token := range shape.Tokens {
						if token.Word == 0 {
							text.WriteByte(' ')
						} else {
							text.WriteString(glyphs[token.Word])
						}
					}
					if strings.TrimRight(text.String(), sourceWhitespace) != *field.Expected {
						row.Status, row.Reason = "FAIL", "fixed-field text mismatch"
					}
				case "narrative":
					var field struct {
						Expected *string `json:"expected"`
						Actual   *string `json:"actual"`
					}
					if err := json.Unmarshal(check.Data, &field); err != nil || field.Expected == nil {
						return report, fmt.Errorf("narrative comparison requires expected text")
					}
					if field.Actual == nil {
						row.Status, row.Reason = "UNKNOWN", "missing narrative observation"
						break
					}
					values := []string{*field.Expected, *field.Actual}
					for i, value := range values {
						value = narrativeControls.ReplaceAllString(value, " ")
						value = strings.ReplaceAll(strings.ReplaceAll(value, "|", " "), "//", " ")
						var normalized strings.Builder
						for _, r := range value {
							if strings.ContainsRune(sourceWhitespace, r) {
								normalized.WriteByte(' ')
							} else {
								normalized.WriteRune(r)
							}
						}
						values[i] = strings.Join(strings.Fields(normalized.String()), " ")
					}
					if values[0] != values[1] {
						row.Status, row.Reason = "FAIL", "normalized narrative mismatch"
					}
				case "positional":
					var field struct {
						Expected *[]TextToken `json:"expected"`
						Actual   *[]TextToken `json:"actual"`
					}
					if err := checkJSON(checkedJSON{raw: check.Data, allObjects: true, text: true, requiredByDepth: map[int][]string{3: {"Kind", "Word", "Offset"}}}); err != nil {
						return report, err
					}
					if err := json.Unmarshal(check.Data, &field); err != nil || field.Expected == nil || len(*field.Expected) == 0 {
						return report, fmt.Errorf("positional comparison requires ordered source tokens")
					}
					if field.Actual == nil {
						row.Status, row.Reason = "UNKNOWN", "missing positional observation"
						break
					}
					if !reflect.DeepEqual(*field.Expected, *field.Actual) {
						row.Status, row.Reason = "FAIL", "positional token or scaffold mismatch"
					}
				case "code":
					if check.SourceSHA256 == "a06d800442a077971f4be8b463f3059414659c67b1f49b2e31fee6f71e65ac20" {
						var observed ProbeCapacityObservation
						var table ProbeObservationTable
						if json.Unmarshal(check.Data, &observed) != nil || json.Unmarshal(probeObservationData, &table) != nil || observed.Contract != "current-configured-capacity-v1" || bundle.SourceSchema != "probe-evidence-go-v1" {
							return report, fmt.Errorf("unsupported current configured-capacity contract")
						}
						definition := table.Rows[id]
						facts := definition.Capacity
						if facts == nil || definition.Kind != "code" || definition.SourceISOSHA256 != bundle.ISOSHA256 || observed.RuntimeAllocation != nil || observed.RuntimeUsed != nil {
							return report, fmt.Errorf("configured capacity source differs or claims unmeasured runtime state")
						}
						row.RuntimeAllocation, row.RuntimeUsed = "UNKNOWN", "UNKNOWN"
						if len(observed.Actual) == 0 || observed.Artifact == nil {
							row.Status, row.Reason = "UNKNOWN", "missing acquired code or inspected artifact"
							break
						}
						var shifts []string
						for site := range facts.Stream.WindowSRLWords {
							shifts = append(shifts, site)
						}
						slices.Sort(shifts)
						sites := append(append(slices.Clone(facts.Stream.LoaderVMAs), facts.Stream.WindowLUIVMAs...), shifts...)
						if len(sites) != 13 || len(observed.Actual) != len(sites) {
							return report, fmt.Errorf("configured capacity requires all13 ordered code sites")
						}
						var words []uint32
						for index, actual := range observed.Actual {
							request, requestErr := hex.DecodeString(actual.RequestHex)
							reply, replyErr := hex.DecodeString(actual.ReplyHex)
							address, addressErr := number(sites[index])
							if requestErr != nil || replyErr != nil || addressErr != nil || actual.ID != fmt.Sprintf("capacity%d", index) || len(request) != 9 || len(reply) != 9 || binary.LittleEndian.Uint32(request) != 9 || request[4] != 2 || uint64(binary.LittleEndian.Uint32(request[5:])) != address || binary.LittleEndian.Uint32(reply) != 9 || reply[4] != 0 || uint64(binary.LittleEndian.Uint32(reply[5:])) != actual.Value {
								return report, fmt.Errorf("configured capacity site/order/wire observation differs")
							}
							words = append(words, uint32(actual.Value))
						}
						sectors := words[2] & 0xffff
						loader := uint64(words[0]&0xffff)<<16 | uint64(words[1]&0xffff)
						if words[0]>>16 != 0x3c05 || words[1]>>16 != 0x34a5 || words[2]>>16 != 0x240e || words[2] != words[3] || sectors == 0 || sectors > 0x7fff || loader != uint64(sectors)*2048 {
							row.Status, row.Reason = "UNKNOWN", "unsupported acquired loader configuration"
							break
						}
						configured, windowsMatch := loader, true
						for index, word := range words[4:] {
							var window uint64
							if index < 2 {
								if word>>16 != 0x3c09 || word&0xffff == 0 {
									row.Status, row.Reason = "UNKNOWN", "unsupported acquired translation LUI"
									break
								}
								window = uint64(word&0xffff) << 16
							} else {
								expected, err := number(facts.Stream.WindowSRLWords[sites[index+4]])
								if err != nil || word>>21 != 0 || word&0x3f != 2 || word>>16&31 == 0 || word>>11&31 == 0 || uint64(word)&0xfffff83f != expected&0xfffff83f {
									row.Status, row.Reason = "UNKNOWN", "unsupported acquired translation shift"
									break
								}
								window = uint64(1) << ((word >> 6) & 31)
							}
							windowsMatch = windowsMatch && window == facts.WindowBytes
							configured = min(configured, window)
						}
						if row.Status != "PASS" {
							break
						}
						row.ConfiguredBytes, row.Artifact = &configured, observed.Artifact
						artifact := observed.Artifact
						if artifact.Source.SHA256 != bundle.ISOSHA256 || artifact.Source.Size < 1 || artifact.Offset < 0 || artifact.Bytes < 0 || artifact.Offset > artifact.Source.Size-artifact.Bytes || artifact.Used < 0 || artifact.Used > artifact.Bytes || artifact.Cursor != (artifact.Used+15)&^15 || artifact.Cursor > artifact.Bytes {
							return report, fmt.Errorf("inspected artifact source/extent/cursor is inconsistent")
						}
						if loader != facts.LoaderBytes || !windowsMatch || configured != min(facts.LoaderBytes, facts.WindowBytes) || uint64(artifact.Cursor) > configured || artifact.Offset != facts.ArtifactOffset || artifact.Bytes != facts.ArtifactBytes || artifact.SHA256 != facts.ArtifactSHA256 || artifact.Used != facts.ArtifactUsed || artifact.Cursor != facts.ArtifactCursor {
							row.Status, row.Reason = "FAIL", "configured code or serialized artifact mismatch"
						}
						break
					}
					var field struct {
						Site           *uint32   `json:"site"`
						Old            []uint32  `json:"old"`
						New            []uint32  `json:"new"`
						Actual         *[]uint32 `json:"actual"`
						Units          string    `json:"units"`
						CapacitySource string    `json:"capacity_source_sha256"`
						Capacity       *uint64   `json:"capacity_bytes"`
						ActualCapacity *uint64   `json:"actual_capacity_bytes"`
						Used           *uint64   `json:"used_bytes"`
					}
					if err := json.Unmarshal(check.Data, &field); err != nil || field.Site == nil || *field.Site%4 != 0 || len(field.Old) == 0 || len(field.New) != len(field.Old) || field.Units != "bytes" || field.Capacity == nil || *field.Capacity == 0 || field.CapacitySource != "9124263d85493454d9022c201aa24280e300eb04bbfd75199618c0b677dfa03f" {
						return report, fmt.Errorf("code comparison requires guarded words and explicit byte capacity")
					}
					if field.Actual == nil || field.ActualCapacity == nil || field.Used == nil {
						row.Status, row.Reason = "UNKNOWN", "missing code or capacity observation"
						break
					}
					if !slices.Equal(field.New, *field.Actual) || *field.Capacity != *field.ActualCapacity || *field.Used > *field.ActualCapacity {
						row.Status, row.Reason = "FAIL", "code word or byte capacity mismatch"
					}
				case "image":
					var field struct {
						Width        int     `json:"width"`
						Height       int     `json:"height"`
						ActualWidth  int     `json:"actual_width"`
						ActualHeight int     `json:"actual_height"`
						Format       string  `json:"format"`
						ExpectedHex  string  `json:"expected_rgba_hex"`
						ActualHex    *string `json:"actual_rgba_hex"`
						CLUT         string  `json:"clut_sha256"`
						ActualCLUT   string  `json:"actual_clut_sha256"`
						ISO          string  `json:"iso_sha256"`
					}
					if err := json.Unmarshal(check.Data, &field); err != nil || field.Width < 1 || field.Height < 1 || field.Width > 4096 || field.Height > 4096 || field.Format != "RGBA8" || !hashPattern.MatchString(field.CLUT) {
						return report, fmt.Errorf("image comparison requires bounded RGBA8 geometry and exact CLUT")
					}
					expected, decodeErr := hex.DecodeString(field.ExpectedHex)
					if decodeErr != nil || len(expected) != field.Width*field.Height*4 {
						return report, fmt.Errorf("image expected bytes differ from RGBA geometry")
					}
					if field.ActualHex == nil {
						row.Status, row.Reason = "UNKNOWN", "missing image observation"
						break
					}
					actual, decodeErr := hex.DecodeString(*field.ActualHex)
					if decodeErr != nil {
						return report, fmt.Errorf("image observation must be complete hexadecimal RGBA")
					}
					if field.ISO != bundle.ISOSHA256 || field.ActualWidth != field.Width || field.ActualHeight != field.Height || field.ActualCLUT != field.CLUT || !bytes.Equal(expected, actual) {
						row.Status, row.Reason = "FAIL", "image geometry, source, CLUT or exact RGBA mismatch"
					}
				}
			default:
				return report, fmt.Errorf("probe comparison observation must be observed, SKIPPED or UNKNOWN")
			}
		}
		report.Rows = append(report.Rows, row)
		if row.Status != "PASS" {
			for _, checkpoint := range checkpoints {
				if statusRank[row.Status] > statusRank[checkpoint.Result.Status] {
					checkpoint.Result.Status, checkpoint.Result.Reason = row.Status, "comparison cohort incomplete"
				}
			}
		}
		if statusRank[row.Status] > statusRank[report.Status] {
			report.Status = row.Status
		}
	}
	// Strict acquisition linkage is an extra data phase; legacy outcomes stay exact.
	seenCaptures := map[string]bool{}
	capturedEvents := map[int]ProbeCaptureReceipt{}
	var precedingCapture *ProbeCaptureReceipt
	lastCaptureEvent := 0
	var captureRecords ProbeRecordBundle
	_ = json.Unmarshal(bundle.Admission, &captureRecords)
	var captureOwned ProbeProcessRecord
	for _, record := range captureRecords.Records {
		if record.Role == "owned" {
			_ = json.Unmarshal(record.Data, &captureOwned)
		}
	}
	for _, capture := range bundle.Captures {
		receipt := capture.Receipt
		transitionOperation := ""
		captureAdmission := admission
		captureAdmissionRaw := bundle.Admission
		if len(capture.Admission) > 0 {
			if !checkpointOnly {
				return report, fmt.Errorf("per-capture admission requires the Go checkpoint cohort")
			}
			qualified, err := admitProbeRecords(capture.Admission)
			if err != nil {
				return report, err
			}
			var currentRecords ProbeRecordBundle
			_ = json.Unmarshal(capture.Admission, &currentRecords)
			if qualified.SourceSchema != "go-probe-records-v1" || qualified.RunID != admission.RunID || qualified.Session != admission.Session || qualified.ISOSHA256 != admission.ISOSHA256 || qualified.Epoch > admission.Epoch || currentRecords.GoOwner == nil || captureRecords.GoOwner == nil || currentRecords.GoOwner.Profile.Root != captureRecords.GoOwner.Profile.Root || currentRecords.GoOwner.Profile.Program != captureRecords.GoOwner.Profile.Program || !reflect.DeepEqual(currentRecords.GoOwner.Profile.Inputs, captureRecords.GoOwner.Profile.Inputs) || !reflect.DeepEqual(currentRecords.GoOwner.Profile.ProgramArgs, captureRecords.GoOwner.Profile.ProgramArgs) || receipt.BuildSHA256 != currentRecords.GoOwner.Profile.Program.SHA256 {
				return report, fmt.Errorf("capture admission crosses Go owner lineage")
			}
			transitionOperation = currentRecords.GoOwner.Step.Request.Operation
			if storyOnly && (!reflect.DeepEqual(currentRecords.GoOwner.Profile.Scenario, captureRecords.GoOwner.Profile.Scenario) || !reflect.DeepEqual(currentRecords.GoOwner.Profile.Seed, captureRecords.GoOwner.Profile.Seed) || currentRecords.GoOwner.Profile.Scenario == nil || currentRecords.GoOwner.Profile.Scenario.Recipe != bundle.Story.Recipe) {
				return report, fmt.Errorf("story capture crosses recipe/cadence contract")
			}
			captureAdmission, captureAdmissionRaw = qualified, capture.Admission
			for _, record := range currentRecords.Records {
				if record.Role == "owned" {
					_ = json.Unmarshal(record.Data, &captureOwned)
				}
			}
		} else if checkpointOnly {
			return report, fmt.Errorf("checkpoint capture lacks its actual epoch admission")
		}
		if checkpointOnly {
			for _, event := range events {
				if event.EventID != receipt.EventID {
					continue
				}
				wanted := ""
				switch event.Event {
				case "save-complete":
					wanted = "initial"
					if storyOnly {
						wanted = "newgame"
						if event.Checkpoint > 1 {
							wanted = "restore"
						}
					}
					for _, earlier := range events {
						if earlier.EventID >= event.EventID {
							break
						}
						if earlier.Checkpoint != event.Checkpoint {
							continue
						}
						if earlier.Event == "tutorial-preparation-start" && !storyOnly {
							wanted = "newgame"
						}
						if earlier.Event == "tutorial-preparation-complete" {
							wanted = "prepare-load"
						}
					}
				case "continue-preview", "reload-verified":
					wanted = event.Method + "-load"
				case "tutorial-preparation-image":
					wanted = "warm-load"
				case "com-handoff-data-main", "story-advanced-after-reload":
					wanted = "load"
				case "story-target-reached":
					if storyOnly {
						wanted = "restore"
					}
				}
				if wanted == "" || transitionOperation != wanted {
					return report, fmt.Errorf("checkpoint capture lacks its completed source owner operation")
				}
			}
		}
		if seenCaptures[receipt.CaptureID] || receipt.CaptureID == "" || receipt.EventID < lastCaptureEvent {
			return report, fmt.Errorf("capture receipts require distinct IDs and source order")
		}
		seenCaptures[receipt.CaptureID], lastCaptureEvent = true, receipt.EventID
		if receipt.Version != 1 || receipt.SourceSHA256 != "5439db31097c19d3b92969d5403c2c19dc3518cea4ed4c075df1a3830b8ef56f" || receipt.PadSourceSHA256 != "1c1dab832d28026ad960eeb9d08e19c5ab40e00f9c30517aadc906921c555a36" || receipt.RunID != captureAdmission.RunID || receipt.Session != captureAdmission.Session || receipt.Epoch != captureAdmission.Epoch || receipt.PID != captureOwned.PID || receipt.Starttime != captureOwned.Starttime || receipt.ISOSHA256 != captureAdmission.ISOSHA256 || eventCheckpoint[receipt.EventID] != receipt.Checkpoint || checkpoints[receipt.Checkpoint] == nil {
			return report, fmt.Errorf("capture receipt differs from admitted identity or source event")
		}
		if checkpointOnly && precedingCapture != nil {
			if receipt.Epoch < precedingCapture.Epoch || receipt.Epoch > precedingCapture.Epoch+1 || receipt.Epoch == precedingCapture.Epoch && (receipt.PID != precedingCapture.PID || receipt.Starttime != precedingCapture.Starttime) || receipt.Epoch == precedingCapture.Epoch+1 && receipt.PID == precedingCapture.PID {
				return report, fmt.Errorf("checkpoint capture epoch/process transition differs")
			}
			if receipt.Epoch == precedingCapture.Epoch+1 && transitionOperation != "cold-load" {
				return report, fmt.Errorf("new capture epoch lacks completed cold ownership")
			}
		}
		precedingCapture = &receipt
		logBytes, err := hex.DecodeString(receipt.LogHex)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(logBytes)) != receipt.LogSHA256 || receipt.LogOffset < 0 {
			return report, fmt.Errorf("capture source log bytes or hash differ")
		}
		var logged, selected any
		if err := json.Unmarshal(logBytes, &logged); err != nil {
			return report, err
		}
		for index, event := range events {
			if event.EventID == receipt.EventID {
				_ = json.Unmarshal(bundle.Events[index].Data, &selected)
				if bundle.Events[index].Offset != receipt.LogOffset {
					return report, fmt.Errorf("capture source log offset differs")
				}
			}
		}
		if !reflect.DeepEqual(logged, selected) {
			return report, fmt.Errorf("capture log does not contain its selected source event")
		}
		encoded, _ := json.Marshal(receipt)
		link := ProbeCaptureLink{CaptureID: receipt.CaptureID, EventID: receipt.EventID, Checkpoint: receipt.Checkpoint, Status: "UNKNOWN", Reason: receipt.Reason, ReceiptSHA256: fmt.Sprintf("%x", sha256.Sum256(encoded)), Provenance: receipt.Provenance}
		switch receipt.Status {
		case "CAPTURED":
			if receipt.MemoryBefore == nil || receipt.MemoryAfter == nil || receipt.GuideCommand != "tap GUIDE 0.05" || receipt.Representation != "original-png" {
				return report, fmt.Errorf("complete capture lacks original image or typed observations")
			}
			ack, err := hex.DecodeString(receipt.GuideAckHex)
			if err != nil || strings.TrimSpace(string(ack)) != "ok" {
				return report, fmt.Errorf("complete capture lacks screenshot acknowledgement")
			}
			before, after := receipt.MemoryBefore, receipt.MemoryAfter
			if before.Session != receipt.Session || before.Epoch != receipt.Epoch || before.BuildSHA256 != receipt.BuildSHA256 || before.ISOSHA256 != receipt.ISOSHA256 || after.ISOSHA256 != before.ISOSHA256 || after.Session != before.Session || after.Epoch != before.Epoch || after.BuildSHA256 != before.BuildSHA256 || after.SessionEvidenceSHA256 != before.SessionEvidenceSHA256 || before.Provenance != receipt.Provenance || after.Provenance != receipt.Provenance || !reflect.DeepEqual(before.Decoded, after.Decoded) {
				return report, fmt.Errorf("capture typed observations cross session, build or sequential UI")
			}
			for _, memory := range []*ProbeMemoryReport{before, after} {
				if memory.Version != 1 || memory.SourceSHA256 != receipt.SourceSHA256 || memory.SessionEvidenceSHA256 != fmt.Sprintf("%x", sha256.Sum256(captureAdmissionRaw)) || (memory.Provenance == "live" || memory.Provenance == "owned_go") && !memory.ProcessGuarded {
					return report, fmt.Errorf("capture typed observations differ from admitted evidence or process guards")
				}
				knownTags, knownUI := false, false
				for _, decoded := range memory.Decoded {
					if decoded.Status != "KNOWN" {
						continue
					}
					switch decoded.Kind {
					case "frame_tags":
						knownTags = len(decoded.FrameTags) == 3
					case "player":
						knownUI = knownUI || decoded.Player != nil
					case "cursor":
						knownUI = knownUI || decoded.Cursor != nil
					case "fixed", "texture", "char":
						knownUI = knownUI || decoded.Text != nil
					}
				}
				if !knownTags || !knownUI || len(memory.Observations) == 0 {
					return report, fmt.Errorf("capture requires positive source frame tags and decoded UI")
				}
			}
			imageBytes, err := hex.DecodeString(capture.ImageHex)
			if err != nil || int64(len(imageBytes)) != receipt.ImageBytes || fmt.Sprintf("%x", sha256.Sum256(imageBytes)) != receipt.ImageSHA256 || receipt.ImagePath != receipt.CaptureID+".png" {
				return report, fmt.Errorf("capture original image bytes or path differ")
			}
			raster, _, err := decodePNG(imageBytes, 1<<20)
			if err != nil || raster.Bounds().Dx() != receipt.Width || raster.Bounds().Dy() != receipt.Height {
				return report, fmt.Errorf("capture original PNG geometry differs")
			}
			link.Status, link.Reason, link.ImagePath, link.ImageSHA256 = "ACCEPTED", "", receipt.ImagePath, receipt.ImageSHA256
			capturedEvents[receipt.EventID] = receipt
		case "UNKNOWN", "REFUSED":
			if strings.TrimSpace(receipt.Reason) == "" {
				return report, fmt.Errorf("unavailable capture requires its source reason")
			}
		default:
			return report, fmt.Errorf("unsupported capture receipt outcome")
		}
		report.Captures = append(report.Captures, link)
		if link.Status != "ACCEPTED" {
			checkpoint := checkpoints[receipt.Checkpoint]
			if checkpoint.Result.Status != "FAIL" {
				checkpoint.Result.Status, checkpoint.Result.Reason = "UNKNOWN", "capture evidence unavailable"
			}
			if report.Status != "FAIL" {
				report.Status = "UNKNOWN"
			}
		}
	}
	if checkpointOnly {
		if !storyOnly && len(checkpointOrder) != 1 {
			return report, fmt.Errorf("checkpoint-only scope requires one actual checkpoint")
		}
		for _, number := range checkpointOrder {
			var warm, cold *ProbeCaptureReceipt
			required := map[string]bool{"save-complete": false, "continue-preview/warm": false, "continue-preview/cold": false, "reload-verified/warm": false, "reload-verified/cold": false, "com-handoff-data-main": false, "story-advanced-after-reload": false}
			for _, event := range events {
				if event.Checkpoint != number {
					continue
				}
				if event.Event == "tutorial-preparation-start" {
					required["tutorial-preparation-image"] = false
				}
			}
			for _, event := range events {
				if event.Checkpoint != number {
					continue
				}
				key := event.Event
				if event.Event == "continue-preview" || event.Event == "reload-verified" {
					key += "/" + event.Method
				}
				if _, ok := required[key]; ok {
					receipt, exists := capturedEvents[event.EventID]
					required[key] = exists
					if exists && key == "reload-verified/warm" {
						saved := receipt
						warm = &saved
					}
					if exists && key == "reload-verified/cold" {
						saved := receipt
						cold = &saved
					}
				}
			}
			complete := true
			for _, present := range required {
				complete = complete && present
			}
			if warm != nil && cold != nil && (cold.Epoch != warm.Epoch+1 || cold.PID == warm.PID || cold.BuildSHA256 != warm.BuildSHA256) {
				return report, fmt.Errorf("checkpoint cold capture does not follow verified warm owner")
			}
			if !complete {
				for _, checkpoint := range checkpoints {
					if checkpoint.Result.Checkpoint != number {
						continue
					}
					if checkpoint.Result.Status != "FAIL" {
						checkpoint.Result.Status, checkpoint.Result.Reason = "UNKNOWN", "required checkpoint capture missing"
					}
				}
			}
		}
	}
	for _, id := range checkpointOrder {
		checkpoint := checkpoints[id]
		if checkpoint.Result.Status == "PASS" && checkpoint.Result.Area != nil && !slices.Contains(report.CoveredAreas, *checkpoint.Result.Area) {
			report.CoveredAreas = append(report.CoveredAreas, *checkpoint.Result.Area)
		}
		report.Checkpoints = append(report.Checkpoints, checkpoint.Result)
		status := checkpoint.Result.Status
		if statusRank[status] > statusRank[report.Status] {
			report.Status = status
		}
	}
	if len(report.Checkpoints) == 0 && report.Status == "PASS" {
		report.Status = "UNKNOWN"
	}
	slices.Sort(report.CoveredAreas)
	if storyOnly && bundle.Story.TerminalEventID > 0 {
		created, overwritten, terminal := false, false, false
		slots := map[int]bool{}
		for _, event := range events {
			checkpoint := checkpoints[event.Checkpoint]
			if checkpoint == nil || checkpoint.Result.Status != "PASS" {
				continue
			}
			if event.Slot != nil {
				slots[*event.Slot] = true
			}
			_, hasYesNo := event.PromptHeaders["yesno"]
			_, hasMessage := event.PromptHeaders["message_widget"]
			if event.Prompt != nil && hasYesNo && hasMessage && !event.Prompt.Unsupported && event.Prompt.Flags&3 == 1 && event.PromptHeaders["mode"] == 0x2e0 && event.PromptHeaders["mc_dialog"] != 0 && event.PromptHeaders["message_widget"] == uint64(event.Prompt.Index) {
				created = created || event.Event == "card-data-created" && strings.HasPrefix(event.Prompt.Text, "Newdatawascreated") && event.Prompt.Ready == 1
				overwritten = overwritten || event.Event == "overwrite-confirmed" && strings.HasPrefix(event.Prompt.Text, "OverwriteFile") && event.PromptHeaders["yesno"] == 0
			}
			if event.EventID == bundle.Story.TerminalEventID && event.Event == "story-target-reached" && event.State != nil {
				_, captured := capturedEvents[event.EventID]
				cleared := *event.State.Story == 49 && event.Mode != nil && *event.Mode == 0x280 && bundle.Story.PostClearMS >= 60000
				for _, player := range event.State.Players {
					cleared = cleared && *player.Control == 0
				}
				terminal = captured && (*event.State.Story >= 50 || cleared) && event.EventID == events[len(events)-1].EventID
			}
		}
		witness := storyRecipe.Required == "card-data-created" && created || storyRecipe.Required == "overwrite-confirmed" && overwritten || storyRecipe.Required == "both-slots" && slots[0] && slots[1]
		if !terminal || !witness || len(report.Checkpoints) == 0 {
			if report.Status != "FAIL" {
				report.Status = "UNKNOWN"
			}
			report.CoveredAreas = []uint32{}
		}
	}
	if storyOnly {
		if bundle.Story.PostClearMS < 0 || bundle.Story.PostClearMS > 86400000 {
			return report, fmt.Errorf("postclear observation exceeds bounded source scope")
		}
		wanted := storyRecipe.StartFile
		for index, checkpoint := range report.Checkpoints {
			if checkpoint.Checkpoint != index+1 || checkpoint.Slot == nil || *checkpoint.Slot != wanted {
				return report, fmt.Errorf("story checkpoint/file sequence differs")
			}
			if checkpoint.Status == "PASS" && storyRecipe.Alternate {
				wanted = 1 - wanted
			}
		}
	}
	if resume := bundle.Resume; resume != nil {
		if resume.Seed == nil || resume.Slot == nil || resume.Actor == nil || resume.OriginalControl == nil || *resume.OriginalControl < 1 || *resume.OriginalControl > 3 || resume.Expected == nil || resume.ISOSHA256 != report.ISOSHA256 || len(resume.AcceptedCheckpoints) == 0 || len(resume.ScheduledIntervals) == 0 || len(resume.ScheduledIntervals) >= 4096 || !filepath.IsAbs(resume.SourceFrameRoot) || filepath.Clean(resume.SourceFrameRoot) != resume.SourceFrameRoot {
			return report, fmt.Errorf("resume requires bounded complete source receipt facts")
		}
		var run struct {
			RunID     string `json:"run_id"`
			ISO       string `json:"iso_sha256"`
			End       string `json:"end_reason"`
			Fail      *bool  `json:"fail"`
			Cleanup   *bool  `json:"cleanup_complete"`
			Stopped   *bool  `json:"owned_emulator_stopped"`
			Card      string `json:"private_card_final_sha256"`
			Completed []int  `json:"completed_checkpoints"`
			Profile   struct {
				Datapath string `json:"datapath"`
			} `json:"private_profile"`
			Config struct {
				Scenario  string  `json:"scenario"`
				Seed      *uint64 `json:"seed"`
				Intervals []int   `json:"interval_seconds"`
				Session   string  `json:"session"`
			} `json:"checkpoint_config"`
		}
		var sequence struct {
			Status string `json:"status"`
			ISO    string `json:"iso_sha256"`
			Runs   []struct {
				Run    string          `json:"run"`
				Result json.RawMessage `json:"result"`
			} `json:"runs"`
		}
		if json.Unmarshal(resume.Run, &run) != nil || json.Unmarshal(resume.Sequence, &sequence) != nil || run.Fail == nil || !*run.Fail || run.Cleanup == nil || !*run.Cleanup || run.Stopped == nil || !*run.Stopped || run.ISO != report.ISOSHA256 || run.RunID != report.RunID || run.End != "autoplay_failure" || run.Config.Seed == nil || *run.Config.Seed != *resume.Seed || run.Config.Scenario != "first-create" || run.Config.Session != report.Session || !reflect.DeepEqual(run.Config.Intervals, []int{3600, 10800}) || run.Profile.Datapath != filepath.Join(resume.SourceFrameRoot, "profile") || sequence.Status != "failed" || sequence.ISO != report.ISOSHA256 || len(sequence.Runs) == 0 || sequence.Runs[0].Run != resume.SourceFrameRoot || !hashPattern.MatchString(run.Card) || resume.Artifacts["card"].SHA256 != run.Card {
			return report, fmt.Errorf("resume prior run, cleanup, card, seed or sequence linkage differs")
		}
		var sourceRun, sequenceResult any
		runDecoder := json.NewDecoder(bytes.NewReader(resume.Run))
		runDecoder.UseNumber()
		resultDecoder := json.NewDecoder(bytes.NewReader(sequence.Runs[0].Result))
		resultDecoder.UseNumber()
		if runDecoder.Decode(&sourceRun) != nil || resultDecoder.Decode(&sequenceResult) != nil || !reflect.DeepEqual(sourceRun, sequenceResult) {
			return report, fmt.Errorf("resume sequence does not contain the complete prior run")
		}
		var admitted ProbeRecordBundle
		_ = json.Unmarshal(bundle.Admission, &admitted)
		if admitted.RunRoot != resume.SourceFrameRoot {
			return report, fmt.Errorf("resume admitted run root differs")
		}
		prefix := []int{}
		for _, checkpoint := range report.Checkpoints {
			if checkpoint.Status == "PASS" {
				prefix = append(prefix, checkpoint.Checkpoint)
			} else if checkpoint.Checkpoint != resume.FailedCheckpoint || checkpoint.Status == "FAIL" {
				return report, fmt.Errorf("resume accepted prefix contains inconsistent checkpoint evidence")
			}
		}
		if !reflect.DeepEqual(prefix, resume.AcceptedCheckpoints) || !reflect.DeepEqual(prefix, run.Completed) || resume.FailedCheckpoint != prefix[len(prefix)-1]+1 || !reflect.DeepEqual(resume.Coverage, report.CoveredAreas) {
			return report, fmt.Errorf("resume accepted prefix or coverage differs from derived events")
		}
		for _, row := range report.Rows {
			if row.Status != "PASS" {
				return report, fmt.Errorf("resume comparison evidence is incomplete or mismatched")
			}
		}
		var saved, cold, control, failure int = -1, -1, -1, -1
		created := false
		schedule := []int{}
		for index, event := range events {
			var detail struct {
				Screenshot string `json:"screenshot"`
				Interval   *int   `json:"interval_seconds"`
			}
			_ = json.Unmarshal(bundle.Events[index].Data, &detail)
			switch event.EventID {
			case resume.SaveEvent:
				saved = index
			case resume.ColdLoadEvent:
				cold = index
			case resume.ControlEvent:
				control = index
			case resume.FailureEvent:
				failure = index
			}
			if event.Event == "resumed" && event.Checkpoint == resume.FailedCheckpoint {
				return report, fmt.Errorf("resume failed checkpoint was already resumed")
			}
			if event.Event == "card-data-created" && slices.Contains(prefix, event.Checkpoint) {
				created = true
			}
			if event.Event == "checkpoint-scheduled" {
				if detail.Interval == nil {
					return report, fmt.Errorf("resume scheduled event has no interval")
				}
				schedule = append(schedule, *detail.Interval)
			}
			if slices.Contains(prefix, event.Checkpoint) && (event.Event == "save-complete" || event.Event == "reload-verified") {
				shot := resume.Screenshots[detail.Screenshot]
				if detail.Screenshot == "" || filepath.IsAbs(detail.Screenshot) || filepath.Clean(detail.Screenshot) != detail.Screenshot || strings.HasPrefix(detail.Screenshot, "..") || shot.Path != filepath.Join(filepath.Dir(resume.Artifacts["events"].Path), detail.Screenshot) || shot.Size < 1 || !hashPattern.MatchString(shot.SHA256) {
					return report, fmt.Errorf("resume accepted checkpoint screenshot evidence missing")
				}
			}
		}
		if !created || saved < 0 || cold < 0 || control < 0 || failure < 0 || !(control < saved && saved < cold && cold < failure) {
			return report, fmt.Errorf("resume first-create or failed-prefix event order differs")
		}
		savedEvent, coldEvent, controlEvent, failureEvent := events[saved], events[cold], events[control], events[failure]
		if savedEvent.Event != "save-complete" || coldEvent.Event != "load-board" || controlEvent.Event != "takeover-write-ack" || failureEvent.Event != "failure" || savedEvent.Checkpoint != resume.FailedCheckpoint || coldEvent.Checkpoint != resume.FailedCheckpoint || failureEvent.Checkpoint != resume.FailedCheckpoint || savedEvent.Slot == nil || *savedEvent.Slot != *resume.Slot || !reflect.DeepEqual(savedEvent.State, resume.Expected) || !reflect.DeepEqual(coldEvent.State, resume.Expected) {
			return report, fmt.Errorf("resume saved payload, native slot or failed prefix differs")
		}
		var takeover struct {
			Response [][]*int `json:"response"`
			Player   *uint32  `json:"player"`
			Original *uint32  `json:"original_control"`
		}
		var failed struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(bundle.Events[control].Data, &takeover)
		_ = json.Unmarshal(bundle.Events[failure].Data, &failed)
		if takeover.Player == nil || *takeover.Player != *resume.Actor || takeover.Original == nil || *takeover.Original != *resume.OriginalControl || len(takeover.Response) != 1 || len(takeover.Response[0]) != 2 || takeover.Response[0][0] == nil || *takeover.Response[0][0] != 0 || takeover.Response[0][1] != nil || failed.Error != "RuntimeError: missing checkpoint screenshot: load-board" || resume.Expected.Current == nil || *resume.Expected.Current != *resume.Actor || len(resume.Expected.Players) != 4 {
			return report, fmt.Errorf("resume saved control or failure provenance differs")
		}
		for index, player := range resume.Expected.Players {
			if player.Control == nil || (*player.Control == 0) != (uint32(index) == *resume.Actor) {
				return report, fmt.Errorf("resume saved actor/control ownership differs")
			}
		}
		intervals, err := probeCheckpointIntervals(*resume.Seed, len(schedule)+1)
		if err != nil || !reflect.DeepEqual(schedule, resume.ScheduledIntervals) || !reflect.DeepEqual(schedule, intervals[:len(schedule)]) {
			return report, fmt.Errorf("resume seeded schedule differs from full source draw prefix")
		}
		next := intervals[len(schedule)]
		report.ResumeNextInterval = &next
		report.ResumeStatus = "QUALIFIED_SAVED_FACTS"
	}
	return report, nil
}
