package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// runProbeLifecycle owns one bounded direct-child session. Immutable pending
// receipts are directory-synced before effects; incomplete effects never replay.
// This slice uses an owned event sink, not an emulator/uinput handover or a soak.
func runProbeLifecycle(raw []byte) (ProbeLifecycleReport, error) {
	var report ProbeLifecycleReport
	if len(raw) == 0 || len(raw) > 1<<20 {
		return report, fmt.Errorf("lifecycle profile exceeds1MiB")
	}
	if err := checkJSON(checkedJSON{raw: raw, allObjects: true, text: true, nonNull: true}); err != nil {
		return report, err
	}
	var profile ProbeLifecycleProfile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return report, err
	}
	if profile.Version != 1 || profile.SourceFormat != "go-owned-lifecycle-v1" || len(profile.Requests) < 1 || len(profile.Requests) > 32 || len(profile.Session) < 1 || len(profile.Session) > 128 || strings.TrimSpace(profile.Session) != profile.Session || len(profile.ProgramArgs) > 16 {
		return report, fmt.Errorf("unsupported lifecycle version or bounded session/request contract")
	}
	if profile.Requests[len(profile.Requests)-1].Operation != "stop" {
		return report, fmt.Errorf("bounded lifecycle slice must end with an explicit stop request")
	}
	if profile.ReadyTimeoutMS == 0 {
		profile.ReadyTimeoutMS = 10000
	}
	if profile.StopTimeoutMS == 0 {
		profile.StopTimeoutMS = 10000
	}
	if profile.QuietMS == 0 {
		profile.QuietMS = 15000
	}
	if profile.ReadyTimeoutMS < 1 || profile.ReadyTimeoutMS > 10000 || profile.StopTimeoutMS < 1 || profile.StopTimeoutMS > 10000 || profile.QuietMS < 1 || profile.QuietMS > 15000 {
		return report, fmt.Errorf("lifecycle deadlines exceed bounded first-slice limits")
	}
	if len(profile.Inputs) != 4 {
		return report, fmt.Errorf("lifecycle requires iso/settings/bios/card input roles")
	}
	if policy := profile.Policy; policy != nil && (policy.PollMS < 1 || policy.PollMS > 1000 || policy.WarnRepeats < 1 || policy.TerminalRepeats < policy.WarnRepeats || policy.TerminalRepeats > 4096 || policy.MaxPolls < 1 || policy.MaxPolls > 4096 || policy.MaxRecoveries < 0 || policy.MaxRecoveries > 16 || policy.MaxDistinctSkips < 1 || policy.MaxDistinctSkips > 32) {
		return report, fmt.Errorf("invalid explicit bounded Go lifecycle policy")
	}
	for _, role := range []string{"iso", "settings", "bios", "card"} {
		if profile.Inputs[role].Path == "" {
			return report, fmt.Errorf("missing lifecycle input role %s", role)
		}
	}
	rootInfo, err := os.Lstat(profile.Root)
	resolved, resolveErr := filepath.EvalSymlinks(profile.Root)
	if err != nil || resolveErr != nil || !filepath.IsAbs(profile.Root) || resolved != profile.Root || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0700 {
		return report, fmt.Errorf("lifecycle requires an explicit private0700 canonical root")
	}
	owner, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) {
		return report, fmt.Errorf("lifecycle root is not owned")
	}
	lock, err := os.OpenFile(filepath.Join(profile.Root, "lifecycle.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return report, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return report, fmt.Errorf("lifecycle root already has a controller")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	receiptDir := filepath.Join(profile.Root, "receipts")
	if err := os.Mkdir(receiptDir, 0700); err != nil && !os.IsExist(err) {
		return report, err
	}
	receiptInfo, err := os.Lstat(receiptDir)
	if err != nil || !receiptInfo.IsDir() || receiptInfo.Mode().Perm() != 0700 {
		return report, fmt.Errorf("lifecycle receipts require a private directory")
	}
	var table struct {
		Version int
		Actions map[string]struct {
			From    []string
			Effects []string
			To      string
		}
		WarmCommand       string               `json:"warm_command"`
		WarmSettleMS      int                  `json:"warm_settle_ms"`
		WarmWidths        []uint64             `json:"warm_widths"`
		PauseCommand      string               `json:"pause_command"`
		PauseSettleMS     int                  `json:"pause_settle_ms"`
		StatusPolls       int                  `json:"status_polls"`
		StatusPollMS      int                  `json:"status_poll_ms"`
		WatchSourceSHA256 string               `json:"watch_source_sha256"`
		WatchReads        []ProbeMemoryRequest `json:"watch_reads"`
		ProgressOrder     []string             `json:"progress_order"`
	}
	if err := json.Unmarshal(probeLifecycleActions, &table); err != nil {
		return report, err
	}
	var scenarioData struct {
		Rows map[string]struct {
			FileIndex    int    `json:"file_index"`
			DisplayFile  int    `json:"display_file"`
			CardSlot     int    `json:"hardware_card_slot"`
			DataCursor   uint64 `json:"data_cursor"`
			DataAttempts int    `json:"data_attempts"`
			SaveTab      uint64 `json:"save_tab"`
			SaveAttempts int    `json:"save_attempts"`
			CardAttempts int    `json:"card_attempts"`
			PollMS       int    `json:"poll_ms"`
			IdlePollMS   int    `json:"idle_poll_ms"`
			SettleMS     int    `json:"settle_ms"`
		}
		MoveSource  uint64 `json:"move_source"`
		ControlBase uint32 `json:"control_base"`
		Stride      uint32 `json:"player_stride"`
		DataText    string `json:"data_text"`
		Prompts     []string
		Recipes     map[string]ProbeStoryRecipe `json:"recipes"`
		NewGame     struct {
			TitleTarget   uint64 `json:"title_target"`
			NarrationMode uint64 `json:"narration_mode"`
			YesNoMode     uint64 `json:"yesno_mode"`
			IntroMode     uint64 `json:"intro_mode"`
			ImageMode     uint64 `json:"image_mode"`
			ImageTexture  string `json:"image_texture"`
			MaxFrontEndMS int    `json:"max_front_end_ms"`
		} `json:"newgame"`
		Reload struct {
			BootMode          uint64 `json:"boot_mode"`
			MovieMode         uint64 `json:"movie_mode"`
			ContinueTarget    uint64 `json:"continue_target"`
			TitlePrefix       string `json:"title_prefix"`
			TitleAttempts     int    `json:"title_attempts"`
			PreviewSamples    int    `json:"preview_samples"`
			PreviewPollMS     int    `json:"preview_poll_ms"`
			TitleTimeoutMS    int    `json:"title_timeout_ms"`
			AdvanceTimeoutMS  int    `json:"advance_timeout_ms"`
			BootMessageSource uint64 `json:"boot_message_source"`
		} `json:"reload"`
	}
	if json.Unmarshal(probeScenarioData, &scenarioData) != nil {
		return report, fmt.Errorf("invalid built-in scenario facts")
	}
	var observationData struct {
		Rows map[string]struct {
			Kind                      string `json:"kind"`
			RecipeID                  string `json:"recipe_id"`
			RecipeSHA256              string `json:"recipe_sha256"`
			SpanBytes                 int    `json:"span_bytes"`
			Cells                     int    `json:"cells"`
			CellWords                 int    `json:"cell_words"`
			SourceSpanSHA256          string `json:"source_span_sha256"`
			ComparisonSourceSHA256    string `json:"comparison_source_sha256"`
			GlyphmapSHA256            string `json:"glyphmap_sha256"`
			HistoricalStaticISOSHA256 string `json:"historical_static_iso_sha256"`
			SourceISOSHA256           string `json:"source_iso_sha256"`
			Limits                    string `json:"limits"`
		} `json:"rows"`
	}
	if json.Unmarshal(probeObservationData, &observationData) != nil {
		return report, fmt.Errorf("invalid built-in observation facts")
	}
	if profile.Storage != nil {
		row, ok := observationData.Rows[profile.Storage.ID]
		if !ok || profile.Storage.Glyphmap.SHA256 != row.GlyphmapSHA256 {
			return report, fmt.Errorf("unsupported source-bound storage observation")
		}
		switch row.Kind {
		case "fixed":
			if profile.Storage.Recipe == nil || profile.Storage.Recipe.SHA256 != row.RecipeSHA256 {
				return report, fmt.Errorf("unsupported source-bound storage observation")
			}
		case "narrative", "positional":
			if profile.Storage.Recipe != nil || row.SpanBytes < 2 || row.SpanBytes > 4096 || row.SpanBytes%2 != 0 {
				return report, fmt.Errorf("stored stream requires its qualified source extent, not an authoring recipe")
			}
			if row.Kind == "positional" && (row.Cells < 1 || row.Cells > 2047 || row.CellWords < 1 || row.CellWords > 2047 || row.SpanBytes != 2*(row.Cells*row.CellWords+1)) {
				return report, fmt.Errorf("stored cell layout differs from its qualified extent")
			}
		default:
			return report, fmt.Errorf("unsupported source-bound storage observation")
		}
		if profile.Inputs["iso"].SHA256 != row.SourceISOSHA256 {
			return report, fmt.Errorf("storage address is unqualified for this ISO input")
		}
	}
	if profile.Scenario != nil {
		if _, ok := scenarioData.Rows[profile.Scenario.ID]; !ok || profile.Scenario.TimeoutMS < 1 || profile.Scenario.TimeoutMS > 180000 || profile.Scenario.MaxUIReads < 1 || profile.Scenario.MaxUIReads > 32768 {
			return report, fmt.Errorf("unsupported bounded scenario")
		}
		if profile.Scenario.Recipe != "" {
			if _, ok := scenarioData.Recipes[profile.Scenario.Recipe]; !ok || profile.Seed == nil || profile.Scenario.WaitTimeoutMS < 1 || profile.Scenario.WaitTimeoutMS > 86400000 || profile.Resume != nil {
				return report, fmt.Errorf("unsupported bounded story recipe or resume")
			}
		} else if profile.Scenario.Calibration || profile.Scenario.WaitTimeoutMS != 0 {
			return report, fmt.Errorf("story calibration/wait policy requires its explicit recipe")
		}
	}
	report = ProbeLifecycleReport{Version: 1, SourceFormat: profile.SourceFormat, Session: profile.Session, Status: "COMPLETED", Steps: []ProbeLifecycleStep{}, SourceSHA256: map[string]string{}, PadLayoutSHA256: fmt.Sprintf("%x", sha256.Sum256(probePadLayout)), Limits: "Offline Go-owned direct-child/event-sink lifecycle and qualified saved-source resume. No native emulator/device/SDL/BIOS/card acceptance, legacy fixed-file IPC compatibility, Continue/restored-state proof, gameplay coverage or full.05 credit. Resource/soak agreement and native qualification remain pending."}
	facts := profile
	facts.Requests = nil
	factsBytes, _ := json.Marshal(facts)
	factsSHA := fmt.Sprintf("%x", sha256.Sum256(factsBytes))
	roleOrder := []string{"iso", "settings", "bios", "card", "program"}
	sourceInputs := map[string]RegistryInput{}
	for role, input := range profile.Inputs {
		sourceInputs[role] = input
	}
	sourceInputs["program"] = profile.Program
	var scenarioGlyphs json.RawMessage
	var storageGlyphs json.RawMessage
	var storageExpected string
	var storageAddress uint32
	var storageExpectedTokens []TextToken
	storageBytes := 16
	if profile.Storage != nil {
		loaded := map[string][]byte{}
		inputs := map[string]RegistryInput{"storage-glyphmap": profile.Storage.Glyphmap, "storage-registry": profile.Storage.Registry}
		if profile.Storage.Recipe != nil {
			inputs["storage-recipe"] = *profile.Storage.Recipe
		}
		for role, input := range inputs {
			sourceInputs[role] = input
			roleOrder = append(roleOrder, role)
			loaded[role], err = readInput(input.Path, 64<<20)
			if err != nil || int64(len(loaded[role])) != input.Size || fmt.Sprintf("%x", sha256.Sum256(loaded[role])) != input.SHA256 || checkJSON(checkedJSON{raw: loaded[role], allObjects: true, text: true}) != nil {
				return report, fmt.Errorf("storage source input differs: %s", role)
			}
		}
		storageGlyphs = loaded["storage-glyphmap"]
		encodingGlyphs, _, err := glyphMaps(storageGlyphs, true)
		if err != nil {
			return report, err
		}
		var registry Registry
		var recipe Recipes
		row := observationData.Rows[profile.Storage.ID]
		address, parseErr := strconv.ParseUint(strings.TrimPrefix(row.RecipeID, "0x"), 16, 32)
		if json.Unmarshal(loaded["storage-registry"], &registry) != nil || parseErr != nil {
			return report, fmt.Errorf("storage registry/recipe contract differs")
		}
		if row.Kind == "fixed" {
			if json.Unmarshal(loaded["storage-recipe"], &recipe) != nil || recipe.Operation != "fixed_field" {
				return report, fmt.Errorf("storage registry/recipe contract differs")
			}
			entry, exists := recipe.Entries[row.RecipeID]
			oldBytes, decodeErr := hex.DecodeString(entry.ExpectedHex)
			if !exists || decodeErr != nil || len(oldBytes) != 16 {
				return report, fmt.Errorf("storage recipe does not declare the complete16-byte field")
			}
		} else {
			storageBytes = row.SpanBytes
		}
		matches := 0
		for _, entry := range registry.Entries {
			if entry.ID == row.RecipeID {
				storageExpected = entry.EN
				matches++
			}
		}
		if matches != 1 || storageExpected == "" {
			return report, fmt.Errorf("storage requires one canonical registry wording row")
		}
		if row.Kind == "positional" {
			labels := strings.Split(storageExpected, "|")
			if len(labels) != row.Cells {
				return report, fmt.Errorf("registry cell count differs from source grid")
			}
			for _, label := range labels {
				encoded, err := encode(label, nil, encodingGlyphs, TextEncodeOptions{})
				if err != nil || len(encoded) > row.CellWords*2 {
					return report, fmt.Errorf("registry label exceeds source cell capacity")
				}
				for index := 0; index < row.CellWords; index++ {
					token := TextToken{Kind: "space", Offset: len(storageExpectedTokens) * 2}
					if index*2 < len(encoded) {
						token.Word = binary.LittleEndian.Uint16(encoded[index*2:])
					}
					if token.Word >= 0x800 {
						return report, fmt.Errorf("registry grid labels must contain only plain glyph words")
					}
					if token.Word != 0 {
						token.Kind = "glyph"
					}
					storageExpectedTokens = append(storageExpectedTokens, token)
				}
			}
			storageExpectedTokens = append(storageExpectedTokens, TextToken{Kind: "end", Word: 0xf800, Offset: row.SpanBytes - 2})
		}
		storageAddress = uint32(address)
	}
	if profile.Scenario != nil {
		sourceInputs["scenario-glyphmap"] = profile.Scenario.Glyphmap
		roleOrder = append(roleOrder, "scenario-glyphmap")
		scenarioGlyphs, err = readInput(profile.Scenario.Glyphmap.Path, 8<<20)
		if err != nil || int64(len(scenarioGlyphs)) != profile.Scenario.Glyphmap.Size || fmt.Sprintf("%x", sha256.Sum256(scenarioGlyphs)) != profile.Scenario.Glyphmap.SHA256 {
			return report, fmt.Errorf("scenario glyph input differs")
		}
		if _, _, err := glyphMaps(scenarioGlyphs, true); err != nil {
			return report, err
		}
	}
	var resumeFacts *ProbeResumeFacts
	var resumeEvidence ProbeEvidenceBundle
	if profile.Resume != nil {
		if profile.Seed == nil || profile.Requests[0].Operation != "resume" {
			return report, fmt.Errorf("saved resume requires its explicit seed and first resume request")
		}
		resumeRoot, rootErr := filepath.EvalSymlinks(profile.Resume.Root)
		if rootErr != nil || !filepath.IsAbs(resumeRoot) || resumeRoot != profile.Resume.Root || resumeRoot == profile.Root {
			return report, fmt.Errorf("resume requires a distinct canonical source root")
		}
		for role, input := range map[string]RegistryInput{"resume-receipt": profile.Resume.Receipt, "resume-evidence": profile.Resume.Evidence} {
			resolved, err := filepath.EvalSymlinks(input.Path)
			rel, relErr := filepath.Rel(resumeRoot, input.Path)
			local, _ := filepath.Rel(profile.Root, input.Path)
			info, statErr := os.Lstat(input.Path)
			if err != nil || relErr != nil || resolved != input.Path || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || local != ".." && !strings.HasPrefix(local, ".."+string(filepath.Separator)) || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0222 != 0 || input.Size < 1 || input.Size > 8<<20 || info.Size() != input.Size {
				return report, fmt.Errorf("resume metadata must be readonly regular files inside its source root")
			}
			sourceInputs[role] = input
			roleOrder = append(roleOrder, role)
		}
		rawReceipt, err := readInput(profile.Resume.Receipt.Path, 8<<20)
		if err == nil && (int64(len(rawReceipt)) != profile.Resume.Receipt.Size || fmt.Sprintf("%x", sha256.Sum256(rawReceipt)) != profile.Resume.Receipt.SHA256) {
			return report, fmt.Errorf("loaded resume receipt hash differs")
		}
		if err != nil || checkJSON(checkedJSON{raw: rawReceipt, allObjects: true, text: true}) != nil {
			return report, fmt.Errorf("resume receipt is malformed")
		}
		resumeFacts = &ProbeResumeFacts{}
		if json.Unmarshal(rawReceipt, resumeFacts) != nil || resumeFacts.Seed == nil || *resumeFacts.Seed != *profile.Seed {
			return report, fmt.Errorf("resume receipt seed differs")
		}
		rawEvidence, err := readInput(profile.Resume.Evidence.Path, 8<<20)
		if err == nil && (int64(len(rawEvidence)) != profile.Resume.Evidence.Size || fmt.Sprintf("%x", sha256.Sum256(rawEvidence)) != profile.Resume.Evidence.SHA256) {
			return report, fmt.Errorf("loaded resume evidence hash differs")
		}
		if err != nil || checkJSON(checkedJSON{raw: rawEvidence, allObjects: true, text: true}) != nil || json.Unmarshal(rawEvidence, &resumeEvidence) != nil {
			return report, fmt.Errorf("resume evidence is malformed")
		}
		loaded := map[string][]byte{}
		for _, role := range []string{"run", "sequence", "events", "card"} {
			input, ok := resumeFacts.Artifacts[role]
			resolved, err := filepath.EvalSymlinks(input.Path)
			rel, relErr := filepath.Rel(resumeRoot, input.Path)
			local, _ := filepath.Rel(profile.Root, input.Path)
			info, statErr := os.Lstat(input.Path)
			if !ok || err != nil || relErr != nil || resolved != input.Path || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || local != ".." && !strings.HasPrefix(local, ".."+string(filepath.Separator)) || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0222 != 0 || info.Size() < 1 || info.Size() > 64<<20 || input.Size != 0 && input.Size != info.Size() {
				return report, fmt.Errorf("resume artifact %s is outside its readonly source contract", role)
			}
			input.Size = info.Size()
			resumeFacts.Artifacts[role] = input
			sourceInputs["resume-"+role] = input
			roleOrder = append(roleOrder, "resume-"+role)
			if role != "card" {
				loaded[role], err = readInput(input.Path, 8<<20)
				if err != nil {
					return report, err
				}
				if int64(len(loaded[role])) != input.Size || fmt.Sprintf("%x", sha256.Sum256(loaded[role])) != input.SHA256 {
					return report, fmt.Errorf("loaded resume artifact hash differs: %s", role)
				}
			}
		}
		resumeFacts.Run, resumeFacts.Sequence = loaded["run"], loaded["sequence"]
		resumeFacts.Screenshots = map[string]RegistryInput{}
		resumeEvidence.Events = nil
		offset := int64(0)
		lines := bytes.SplitAfter(loaded["events"], []byte{'\n'})
		for _, line := range lines {
			if len(line) == 0 {
				continue
			}
			if line[len(line)-1] != '\n' {
				return report, fmt.Errorf("resume event stream has a partial final record")
			}
			data := bytes.TrimSuffix(line, []byte{'\n'})
			if len(data) == 0 {
				return report, fmt.Errorf("resume event stream has an empty record")
			}
			resumeEvidence.Events = append(resumeEvidence.Events, ProbeEvidenceEvent{Offset: offset, Data: bytes.Clone(data)})
			offset += int64(len(line))
			var event struct {
				Event      string `json:"event"`
				Checkpoint int    `json:"checkpoint"`
				Screenshot string `json:"screenshot"`
			}
			if json.Unmarshal(data, &event) != nil {
				return report, fmt.Errorf("resume event stream malformed")
			}
			if slices.Contains(resumeFacts.AcceptedCheckpoints, event.Checkpoint) && (event.Event == "save-complete" || event.Event == "reload-verified") {
				if event.Screenshot == "" || filepath.IsAbs(event.Screenshot) || filepath.Clean(event.Screenshot) != event.Screenshot || strings.HasPrefix(event.Screenshot, "..") {
					return report, fmt.Errorf("resume screenshot path is invalid")
				}
				path := filepath.Join(filepath.Dir(resumeFacts.Artifacts["events"].Path), event.Screenshot)
				resolved, err := filepath.EvalSymlinks(path)
				rel, relErr := filepath.Rel(resumeRoot, path)
				info, statErr := os.Lstat(path)
				if err != nil || relErr != nil || resolved != path || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0222 != 0 || info.Size() < 1 || info.Size() > 16<<20 {
					return report, fmt.Errorf("resume screenshot is missing or mutable")
				}
				contents, err := readInput(path, 16<<20)
				if err != nil {
					return report, err
				}
				input := RegistryInput{Path: path, Size: int64(len(contents)), SHA256: fmt.Sprintf("%x", sha256.Sum256(contents))}
				resumeFacts.Screenshots[event.Screenshot] = input
				sourceInputs["resume-shot-"+event.Screenshot] = input
			}
		}
		for role := range sourceInputs {
			if strings.HasPrefix(role, "resume-shot-") {
				roleOrder = append(roleOrder, role)
			}
		}
		sort.Strings(roleOrder)
		if resumeFacts.ISOSHA256 != profile.Inputs["iso"].SHA256 || resumeFacts.Artifacts["card"].Path != profile.Inputs["card"].Path || resumeFacts.Artifacts["card"].SHA256 != profile.Inputs["card"].SHA256 {
			return report, fmt.Errorf("resume ISO or copied source card differs")
		}
		resumeEvidence.Resume = resumeFacts
	}
	profileDir := filepath.Join(profile.Root, "profile")
	dataRoot := filepath.Join(profileDir, "PCSX2")
	cardPath := filepath.Join(dataRoot, "memcards", "probe-slot1.ps2")
	phase, epoch, lastNonce := "new", 0, uint64(0)
	var owned *ProbeProcessRecord
	var child *exec.Cmd
	var readyDeadline time.Time
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	padReady, padDone := make(chan error, 1), make(chan error, 1)
	padStarted := false
	skipReasons := map[string]bool{}
	recoveryAttempts := 0
	readFailure, ambiguousFailure := false, false
	lastSafeCardSHA := ""
	resumeVerified, gameplayStarted := false, false
	scheduledIntervals := []int{}
	var lastOwnedStep ProbeLifecycleStep
	var scenarioAdmission json.RawMessage
	var scenarioRuntime ProbeMemoryRuntime
	var scenarioSaved *ProbeSavedState
	var scenarioEvent json.RawMessage
	scenarioEvents := []ProbeEvidenceEvent{}
	scenarioCaptures := []ProbeCaptureObservation{}
	var scenarioLog []byte
	var scenarioLogInfo os.FileInfo
	loadMethod := ""
	warmVerified, coldVerified, restored := false, false, false
	previewSamples := 0
	lastFrontMode := uint64(0)
	yesNoBoxes := 0
	var preparedState *ProbeSavedState
	var frontEndDeadline time.Time
	yesNoPending := false
	yesNoTarget := uint64(0)
	preparationAcknowledged := false
	var scenarioUI ProbeUIState
	scenarioActor, originalControl := -1, uint32(0)
	fileSelected, saveCompleted := false, false
	var scenarioDeadline time.Time
	checkpointNumber, acceptedCheckpoint := 0, 0
	checkpointFileIndex := 1
	pendingPromptKind := ""
	var pendingPrompt *ProbeUIWidget
	var pendingPromptHeaders map[string]uint64
	seenPromptWitness := map[string]bool{}
	scenarioFileIndex := 1
	if profile.Scenario != nil {
		scenarioFileIndex = scenarioData.Rows[profile.Scenario.ID].FileIndex
		if profile.Scenario.Recipe != "" {
			scenarioFileIndex = scenarioData.Recipes[profile.Scenario.Recipe].StartFile
		}
	}
	var checkpointDue, postClearSince time.Time
	noncePattern := regexp.MustCompile(`^([1-9][0-9]*)-(initial|newgame|prepare-scenario|prepare-load|resave|warm|warm-load|cold|cold-load|load|stop|pause|unpause|watch|recover|resume|scenario|restore|finish|observe-storage)$`)
	for _, request := range profile.Requests {
		step := ProbeLifecycleStep{Request: request, Status: "REFUSED", Epoch: epoch, Owned: owned, Effects: []string{}, RecoveryAttempts: recoveryAttempts}
		// Current source bytes and role identities precede effects, not supplied claims.
		sourceOK := true
		for _, role := range roleOrder {
			input := sourceInputs[role]
			info, statErr := os.Lstat(input.Path)
			canonical, canonicalErr := filepath.EvalSymlinks(input.Path)
			if statErr != nil || canonicalErr != nil || !filepath.IsAbs(input.Path) || canonical != input.Path || !info.Mode().IsRegular() || input.Size < 1 || input.Size > 8<<30 || info.Size() != input.Size || len(input.SHA256) != 64 || role != "program" && info.Mode().Perm()&0222 != 0 {
				step.Reason = "lifecycle input role identity differs: " + role
				sourceOK = false
				break
			}
			if role == "card" {
				stat, ok := info.Sys().(*syscall.Stat_t)
				if !ok || stat.Nlink != 1 {
					step.Reason = "source card is not exclusive"
					sourceOK = false
					break
				}
			}
			file, openErr := os.Open(input.Path)
			if openErr != nil {
				step.Reason = "lifecycle input unavailable: " + role
				sourceOK = false
				break
			}
			hasher := sha256.New()
			count, hashErr := io.Copy(hasher, io.LimitReader(file, input.Size+1))
			after, afterErr := file.Stat()
			_ = file.Close()
			if hashErr != nil || afterErr != nil || count != input.Size || !os.SameFile(info, after) || info.Size() != after.Size() || info.ModTime() != after.ModTime() || fmt.Sprintf("%x", hasher.Sum(nil)) != input.SHA256 {
				step.Reason = "lifecycle input hash differs: " + role
				sourceOK = false
				break
			}
			report.SourceSHA256[role] = input.SHA256
		}
		if !sourceOK {
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		if resumeFacts != nil && !resumeVerified {
			data, _ := json.Marshal(resumeEvidence)
			qualified, err := reportProbeEvidence(data)
			if err != nil || qualified.ResumeStatus != "QUALIFIED_SAVED_FACTS" || qualified.ISOSHA256 != profile.Inputs["iso"].SHA256 || qualified.Session == profile.Session {
				return report, fmt.Errorf("saved resume qualification failed: %w", err)
			}
			epoch = qualified.Epoch + 1
			step.Epoch = epoch
			resumeVerified = true
			scheduledIntervals = slices.Clone(resumeFacts.ScheduledIntervals)
			gameplayStarted = true
			step.ResumeEvidenceSHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
		}
		if request.Session != profile.Session {
			step.Reason = "lifecycle request session differs"
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		if request.Phase != "requested" {
			step.Reason = "lifecycle request phase is not requested"
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		parts := noncePattern.FindStringSubmatch(request.Nonce)
		if len(parts) != 3 || parts[2] != request.Operation {
			step.Reason = "invalid lifecycle operation/nonce"
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		ordinal, parseErr := strconv.ParseUint(parts[1], 10, 64)
		if parseErr != nil {
			step.Reason = "invalid lifecycle nonce sequence"
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		completePath := filepath.Join(receiptDir, request.Nonce+".complete.json")
		if old, err := readInput(completePath, 1<<20); err == nil {
			var saved ProbeLifecycleStep
			if json.Unmarshal(old, &saved) != nil || saved.Status != "COMPLETED" || saved.ProfileSHA256 != factsSHA || !reflect.DeepEqual(saved.Request, request) {
				step.Reason = "conflicting completed lifecycle nonce"
				report.Status = "INCOMPLETE"
			} else {
				step = saved
				step.Replayed = true
			}
			report.Steps = append(report.Steps, step)
			continue
		} else if !os.IsNotExist(err) {
			step.Reason = "lifecycle completion receipt unreadable"
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		existing, err := os.ReadDir(receiptDir)
		if err != nil {
			return report, err
		}
		if len(existing) > 512 {
			return report, fmt.Errorf("lifecycle receipt budget exceeded")
		}
		pending := false
		for _, entry := range existing {
			if strings.HasPrefix(entry.Name(), request.Nonce+"-") && strings.HasSuffix(entry.Name(), ".pending.json") {
				pending = true
			}
		}
		if pending {
			step.Status, step.Reason = "UNKNOWN", "durable pending effect prevents replay"
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		if ordinal <= lastNonce {
			step.Reason = "replayed or reordered lifecycle nonce"
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		action, ok := table.Actions[request.Operation]
		if !ok || !slices.Contains(action.From, phase) {
			step.Reason = "lifecycle operation not valid in current state"
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		if request.Operation == "stop" && phase == "unknown" && (owned == nil || child == nil) {
			step.Reason = "safe stop requires an established owned child"
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		if request.Operation == "watch" && profile.Policy == nil {
			step.Reason = "watch requires explicit bounded Go policy"
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		if slices.Contains([]string{"scenario", "newgame", "prepare-scenario"}, request.Operation) && profile.Scenario == nil {
			return report, fmt.Errorf("scenario request requires its pinned source recipe")
		}
		if request.Operation == "observe-storage" && profile.Storage == nil {
			return report, fmt.Errorf("storage request requires its pinned source recipe")
		}
		if slices.Contains([]string{"load", "prepare-load", "resave", "warm-load", "cold-load", "restore", "finish"}, request.Operation) && (profile.Scenario == nil || scenarioSaved == nil) {
			step.Reason = "checkpoint action lacks the source Save context"
			report.Status = "INCOMPLETE"
			report.Steps = append(report.Steps, step)
			continue
		}
		if request.Operation == "resume" {
			if !resumeVerified {
				return report, fmt.Errorf("resume requires qualified bound saved artifacts")
			}
			if _, err := os.Lstat(profileDir); !os.IsNotExist(err) {
				return report, fmt.Errorf("resume destination is not a fresh profile")
			}
		}
		if request.Operation == "recover" {
			if profile.Policy == nil || recoveryAttempts >= profile.Policy.MaxRecoveries {
				step.Reason = "explicit Go recovery budget exhausted"
			} else if !readFailure || ambiguousFailure || lastSafeCardSHA == "" || child != nil || owned != nil {
				step.Reason = "recovery requires proved disposal after a read-only failure"
			} else {
				data, err := readInput(cardPath, 64<<20)
				if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != lastSafeCardSHA {
					step.Reason = "recovery retained card differs from stable postflush bytes"
				}
			}
			if step.Reason != "" {
				report.Status = "INCOMPLETE"
				report.Steps = append(report.Steps, step)
				continue
			}
			recoveryAttempts++
			step.RecoveryAttempts, step.CardAfter = recoveryAttempts, lastSafeCardSHA
		}
		step.Status = "UNKNOWN"
		step.ProfileSHA256 = factsSHA
		lastNonce = ordinal
		requestBytes, _ := json.Marshal(request)
		requestSHA := fmt.Sprintf("%x", sha256.Sum256(requestBytes))
	actions:
		for index, repeats := 0, 0; index < len(action.Effects); {
			effect := action.Effects[index]
			repeatEffect := false
			pendingRow := ProbeLifecycleEffect{Version: 1, Session: profile.Session, Nonce: request.Nonce, RequestSHA256: requestSHA, Action: effect, Phase: "pending"}
			pendingData, _ := json.Marshal(pendingRow)
			effectBase := fmt.Sprintf("%s-%02d-%s", request.Nonce, index, effect)
			if repeats > 0 {
				effectBase += fmt.Sprintf("-repeat%d", repeats)
			}
			if err := writeNewFile(filepath.Join(receiptDir, effectBase+".pending.json"), bytes.NewReader(pendingData), int64(len(pendingData)), fmt.Sprintf("%x", sha256.Sum256(pendingData)), 0600); err != nil {
				step.Reason = "pending effect publication failed"
				break
			}
			directory, err := os.Open(receiptDir)
			if err == nil {
				err = directory.Sync()
				_ = directory.Close()
			}
			if err != nil {
				step.Reason = "pending directory durability failed"
				break
			}
			// Prompt observations share the same serialized journal publisher. The
			// admitted planned effect remains card-save, including across repeats.
			plannedEffect := effect
			if pendingPromptKind != "" {
				effect = "emit-card-witness"
			}
			switch effect {
			case "acquire-board", "qualify-load", "qualify-handoff", "qualify-newgame", "qualify-resave", "qualify-terminal", "observe-storage":
				if owned == nil || lastOwnedStep.Status != "COMPLETED" {
					step.Reason = "scenario requires completed current ownership"
					break actions
				}
				if effect == "qualify-load" {
					loadMethod = lastOwnedStep.Request.Operation
					loadMethod = strings.TrimSuffix(loadMethod, "-load")
					if scenarioSaved == nil || loadMethod != "warm" && loadMethod != "cold" || loadMethod == "cold" && !warmVerified {
						step.Reason = "load lacks the completed source warm/cold transition"
						break actions
					}
					if request.Operation == "prepare-load" && (preparedState == nil || loadMethod != "warm") {
						step.Reason = "preparation Load lacks exact initialized-state contract"
						break actions
					}
					if request.Operation != "prepare-load" && (scenarioSaved.Players[scenarioActor].TutorialFlags == nil || *scenarioSaved.Players[scenarioActor].TutorialFlags&1 == 0) {
						step.Reason = "ordinary paired reload does not admit uninitialized tutorial actors"
						break actions
					}
				}
				if effect == "qualify-handoff" && (!warmVerified || !coldVerified || scenarioSaved == nil) {
					step.Reason = "handoff lacks independently verified warm/cold pair"
					break actions
				}
				if effect == "qualify-resave" && (!preparationAcknowledged || preparedState == nil) {
					step.Reason = "final resave lacks completed preparation"
					break actions
				}
				observed, err := observeProbeProcess(ProbeMemoryRuntime{}, owned.PID, owned, profile.Program.SHA256)
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				card, err := readInput(cardPath, 64<<20)
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				view := ProbeProfileRecord{Datapath: profileDir, DataRoot: dataRoot, SourceSettings: profile.Inputs["settings"].Path, SourceSettingsSHA256: profile.Inputs["settings"].SHA256, SourceCard: profile.Inputs["card"].Path, SourceCardSHA256: profile.Inputs["card"].SHA256, Card: cardPath, CardInitialSHA256: profile.Inputs["card"].SHA256, BIOS: filepath.Join(dataRoot, "bios", filepath.Base(profile.Inputs["bios"].Path))}
				viewRaw, _ := json.Marshal(view)
				ownedRaw, _ := json.Marshal(owned)
				bundle := ProbeRecordBundle{Version: 1, SourceSchema: "go-probe-records-v1", SourceSHA256: "5439db31097c19d3b92969d5403c2c19dc3518cea4ed4c075df1a3830b8ef56f", ProjectRoot: profile.Root, WorkingDirectory: profile.Root, RunRoot: profile.Root, Context: "owned_go", Records: []ProbeRecord{{Role: "profile", Data: viewRaw}, {Role: "owned", Data: ownedRaw}}, AfterProcess: &observed, GoOwner: &ProbeGoOwner{Profile: profile, Step: lastOwnedStep, CardSHA256: fmt.Sprintf("%x", sha256.Sum256(card))}}
				scenarioAdmission, _ = json.Marshal(bundle)
				admitted, err := admitProbeRecords(scenarioAdmission)
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				path := filepath.Join(profile.Root, "go-records-"+request.Nonce+".json")
				digest := fmt.Sprintf("%x", sha256.Sum256(scenarioAdmission))
				if err := writeNewFile(path, bytes.NewReader(scenarioAdmission), int64(len(scenarioAdmission)), digest, 0600); err != nil {
					step.Reason = err.Error()
					break actions
				}
				scenarioRuntime = ProbeMemoryRuntime{Provenance: "owned_go", Root: profile.Root, TimeoutMS: 1000, Evidence: &RegistryInput{Path: path, Size: int64(len(scenarioAdmission)), SHA256: digest}}
				if effect == "observe-storage" {
					row := observationData.Rows[profile.Storage.ID]
					plan := ProbeMemoryBundle{Version: 1, SourceSHA256: bundle.SourceSHA256, Admission: scenarioAdmission, BuildSHA256: profile.Program.SHA256}
					var readIDs []string
					for offset := 0; offset < storageBytes; {
						opcode, address := uint8(3), storageAddress+uint32(offset)
						for 1<<opcode > storageBytes-offset {
							opcode--
						}
						id := fmt.Sprintf("field%d", len(readIDs))
						readIDs = append(readIDs, id)
						plan.Requests = append(plan.Requests, ProbeMemoryRequest{ID: id, Opcode: &opcode, Address: &address})
						offset += 1 << opcode
					}
					decoderKind := row.Kind
					if row.Kind == "narrative" || row.Kind == "positional" {
						decoderKind = "stream"
					}
					plan.Decoders = []ProbeMemoryDecoder{{ID: profile.Storage.ID, Kind: decoderKind, Requests: readIDs, Glyphmap: storageGlyphs}}
					planRaw, _ := json.Marshal(plan)
					runtimeRaw, _ := json.Marshal(scenarioRuntime)
					memory, err := readProbeMemory(planRaw, runtimeRaw)
					if err != nil && (row.Kind == "fixed" || len(memory.Observations) != len(plan.Requests)) {
						step.Reason = err.Error()
						break actions
					}
					step.Memory = &memory
					memoryRaw, _ := json.Marshal(memory)
					memoryPath := filepath.Join(profile.Root, "storage-"+request.Nonce+".memory.json")
					memorySHA := fmt.Sprintf("%x", sha256.Sum256(memoryRaw))
					if err := writeNewFile(memoryPath, bytes.NewReader(memoryRaw), int64(len(memoryRaw)), memorySHA, 0600); err != nil {
						step.Reason = err.Error()
						break actions
					}
					if err != nil {
						step.Reason = err.Error()
						break actions
					}
					var actual []byte
					for index, observation := range memory.Observations {
						var word [8]byte
						binary.LittleEndian.PutUint64(word[:], observation.Value)
						actual = append(actual, word[:1<<*plan.Requests[index].Opcode]...)
					}
					// This event is a storage acquisition, not a displayed-UI or checkpoint witness.
					eventRaw, _ := json.Marshal(map[string]any{"event": "storage-observed", "event_id": 1, "checkpoint": 0, "time": time.Now().Format("2006-01-02T15:04:05-0700"), "registry_id": profile.Storage.ID, "memory": RegistryInput{Path: memoryPath, Size: int64(len(memoryRaw)), SHA256: memorySHA}, "registry": profile.Storage.Registry, "recipe": profile.Storage.Recipe, "source_iso_sha256": row.SourceISOSHA256, "historical_static_iso_sha256": row.HistoricalStaticISOSHA256, "limits": row.Limits})
					checkData := map[string]any{"expected": storageExpected, "actual_hex": hex.EncodeToString(actual), "glyphmap": storageGlyphs}
					switch row.Kind {
					case "narrative":
						checkData = map[string]any{"expected": storageExpected, "actual": *memory.Decoded[0].Text}
					case "positional":
						tokens := memory.Decoded[0].Tokens
						if len(tokens) != row.Cells*row.CellWords+1 {
							step.Reason = "acquired grid token count differs from source layout"
							break actions
						}
						for index, token := range tokens {
							if token.Offset != index*2 || len(token.Payload) != 0 {
								step.Reason = "acquired grid token offsets/payload differ from source layout"
								break actions
							}
							if index == len(tokens)-1 {
								if token.Kind != "end" || token.Word != 0xf800 {
									step.Reason = "acquired grid lacks its stored END guard"
									break actions
								}
							} else if token.Word >= 0x800 || token.Kind != "glyph" && token.Kind != "space" {
								step.Reason = "acquired grid contains a non-cell control word"
								break actions
							}
						}
						checkData = map[string]any{"expected": storageExpectedTokens, "actual": tokens}
					}
					checkRaw, _ := json.Marshal(checkData)
					evidence := ProbeEvidenceBundle{Version: 1, SourceSchema: "probe-evidence-go-v1", SourceSHA256: "f6d9bcf48634a234da6632f42e4faea9f66d79dcaad0783b79ccce477ed4f0e8", Admission: scenarioAdmission, RunID: admitted.RunID, Session: admitted.Session, ISOSHA256: admitted.ISOSHA256, Epoch: &admitted.Epoch, Cohort: "go-storage-observation-v1", Members: []string{profile.Storage.ID}, Events: []ProbeEvidenceEvent{{Offset: 0, Data: eventRaw}}, Checks: []ProbeEvidenceCheck{{ID: profile.Storage.ID, Kind: row.Kind, SourceSHA256: row.ComparisonSourceSHA256, EventID: 1, Observation: "observed", Data: checkRaw}}}
					evidenceRaw, _ := json.Marshal(evidence)
					evidencePath := filepath.Join(profile.Root, "storage-"+request.Nonce+".evidence.json")
					evidenceSHA := fmt.Sprintf("%x", sha256.Sum256(evidenceRaw))
					if err := writeNewFile(evidencePath, bytes.NewReader(evidenceRaw), int64(len(evidenceRaw)), evidenceSHA, 0600); err != nil {
						step.Reason = err.Error()
						break actions
					}
					comparison, err := reportProbeEvidence(evidenceRaw)
					if err != nil {
						step.Reason = err.Error()
						break actions
					}
					step.Checkpoint = &comparison
					step.Evidence = &RegistryInput{Path: evidencePath, Size: int64(len(evidenceRaw)), SHA256: evidenceSHA}
					break
				}
				scenarioDeadline = time.Now().Add(time.Duration(profile.Scenario.TimeoutMS) * time.Millisecond)
				if effect == "qualify-terminal" {
					scenarioDeadline = time.Now().Add(time.Duration(profile.Scenario.WaitTimeoutMS) * time.Millisecond)
				}
				if effect == "qualify-newgame" {
					timeout := profile.Scenario.FrontEndTimeoutMS
					if timeout == 0 {
						timeout = scenarioData.NewGame.MaxFrontEndMS
					}
					if timeout < 1 || timeout > scenarioData.NewGame.MaxFrontEndMS {
						step.Reason = "front-end timeout outside declared source bound"
						break actions
					}
					scenarioDeadline = time.Now().Add(time.Duration(timeout) * time.Millisecond)
					frontEndDeadline = scenarioDeadline
					lastFrontMode = 0
					yesNoBoxes = 0
					yesNoPending = false
				}
				scenarioUI, err = readProbeUI(ProbeUIPlan{Admission: scenarioAdmission, BuildSHA256: profile.Program.SHA256, Glyphmap: scenarioGlyphs, TimeoutMS: 10000, MaxReads: profile.Scenario.MaxUIReads}, scenarioRuntime)
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				if effect != "acquire-board" {
					fileSelected = false
					if effect == "qualify-resave" {
						saveCompleted = false
					}
					previewSamples = 0
					step.UI = &scenarioUI
					break
				}
				if profile.Scenario.Recipe != "" {
					if !gameplayStarted {
						if scenarioUI.Headers["story"] < 1 || scenarioUI.Headers["story"] > 49 {
							step.Reason = "checkpoint outside source gameplay interval"
							break actions
						}
						intervals, err := probeCheckpointIntervals(*profile.Seed, 1, profile.Scenario.Calibration)
						if err != nil {
							step.Reason = err.Error()
							break actions
						}
						scheduledIntervals = intervals
						gameplayStarted = true
						checkpointDue = time.Now().Add(time.Duration(intervals[0]) * time.Second)
					}
					if time.Until(checkpointDue) > time.Duration(profile.Scenario.WaitTimeoutMS)*time.Millisecond {
						step.Reason = "recipe due exceeds explicit wait budget"
						break actions
					}
					for time.Now().Before(checkpointDue) {
						time.Sleep(min(time.Second, time.Until(checkpointDue)))
						scenarioUI, err = readProbeUI(ProbeUIPlan{Admission: scenarioAdmission, BuildSHA256: profile.Program.SHA256, Glyphmap: scenarioGlyphs, TimeoutMS: 10000, MaxReads: profile.Scenario.MaxUIReads}, scenarioRuntime)
						if err != nil {
							step.Reason = err.Error()
							break actions
						}
					}
					step.ScheduledIntervals = slices.Clone(scheduledIntervals)
				}
				scenarioActor = int(scenarioUI.Headers["current"])
				move := false
				for _, widget := range scenarioUI.Widgets {
					move = move || !widget.Unsupported && widget.Source == scenarioData.MoveSource && widget.Text == "Move" && widget.Ready == 0 && widget.Flags&3 == 1
				}
				if scenarioActor < 0 || scenarioActor >= 4 || scenarioUI.Headers["mode"] != 0x1b0 || scenarioUI.Headers["board_options"] != 5 || scenarioUI.Headers["board_handle"] != 1 || scenarioUI.Headers["board_cursor"] != 0 || !move || !scenarioUI.BoardAIReady {
					step.Reason = "source board/Move/task context is not eligible"
					break actions
				}
				for _, player := range scenarioUI.Saved.Players {
					if player.Control == nil || *player.Control < 1 || *player.Control > 3 {
						step.Reason = "source board has unowned human or invalid control"
						break actions
					}
				}
				originalControl = *scenarioUI.Saved.Players[scenarioActor].Control
				if profile.Seed != nil && !gameplayStarted {
					intervals, err := probeCheckpointIntervals(*profile.Seed, 1, profile.Scenario.Calibration)
					if err != nil {
						step.Reason = err.Error()
						break actions
					}
					scheduledIntervals = intervals
					gameplayStarted = true
					checkpointDue = time.Now().Add(time.Duration(intervals[0]) * time.Second)
					step.ScheduledIntervals = slices.Clone(intervals)
				}
				checkpointNumber++
				checkpointFileIndex = scenarioFileIndex
				// Waiting for a scheduled, eligible turn is separate from the
				// acquired UI transaction's bounded takeover/Save budget.
				scenarioDeadline = time.Now().Add(time.Duration(profile.Scenario.TimeoutMS) * time.Millisecond)
				warmVerified, coldVerified, restored = false, false, false
				preparedState = nil
				preparationAcknowledged = false
				scenarioSaved = nil
				fileSelected, saveCompleted = false, false
				step.UI = &scenarioUI
			case "takeover-control", "restore-control", "boot-handoff":
				if owned == nil || scenarioActor < 0 || scenarioActor >= 4 || len(scenarioAdmission) == 0 {
					step.Reason = "named control transaction has no qualified owner"
					break actions
				}
				fresh, err := readProbeUI(ProbeUIPlan{Admission: scenarioAdmission, BuildSHA256: profile.Program.SHA256, Glyphmap: scenarioGlyphs, TimeoutMS: 10000, MaxReads: profile.Scenario.MaxUIReads}, scenarioRuntime)
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				if effect == "restore-control" {
					dataMain := false
					for _, widget := range fresh.Widgets {
						dataMain = dataMain || !widget.Unsupported && widget.Text == scenarioData.DataText
					}
					if !warmVerified || !coldVerified || scenarioSaved == nil || !dataMain || fresh.Headers["mode"] != 0x2e0 || fresh.Headers["data_context"] != 0 || fresh.Headers["data_focus"] != 0 || fresh.Headers["mc_dialog"] != 0 || !reflect.DeepEqual(fresh.Saved, *scenarioSaved) {
						step.Reason = "restore lacks matching pair and Data MAIN owner"
						break actions
					}
					scenarioUI = fresh
				}
				if effect == "boot-handoff" {
					humans := 0
					sharedSquares := true
					for _, player := range fresh.Saved.Players {
						if *player.Control == 0 {
							humans++
						}
						sharedSquares = sharedSquares && *player.Square == *fresh.Saved.Players[0].Square
					}
					if fresh.Headers["mode"] != scenarioData.NewGame.IntroMode || humans != 1 || !sharedSquares || *fresh.Saved.Players[scenarioActor].Control != 0 || fresh.Headers["story"] > 1 || fresh.Headers["week"] != 0 {
						step.Reason = "fresh intro handoff owner changed"
						break actions
					}
					scenarioUI = fresh
				}
				for _, key := range []string{"mode", "story", "week", "day", "current", "area", "board_handle", "board_options", "board_cursor"} {
					if fresh.Headers[key] != scenarioUI.Headers[key] {
						step.Reason = "source board owner changed before takeover"
						break actions
					}
				}
				if !reflect.DeepEqual(fresh.Saved, scenarioUI.Saved) || !reflect.DeepEqual(fresh.Widgets, scenarioUI.Widgets) {
					step.Reason = "source widget/player owner changed before takeover"
					break actions
				}
				if _, err := observeProbeProcess(ProbeMemoryRuntime{}, owned.PID, owned, profile.Program.SHA256); err != nil {
					step.Reason = err.Error()
					break actions
				}
				connection, err := net.DialTimeout("unix", filepath.Join(profile.Root, "peer.sock"), time.Second)
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				_ = connection.SetDeadline(time.Now().Add(time.Second))
				peer, err := connection.(*net.UnixConn).File()
				if err != nil {
					_ = connection.Close()
					step.Reason = err.Error()
					break actions
				}
				credentials, credentialErr := syscall.GetsockoptUcred(int(peer.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
				_ = peer.Close()
				if credentialErr != nil || int(credentials.Pid) != owned.PID || credentials.Uid != uint32(os.Getuid()) {
					_ = connection.Close()
					step.Reason = "named control transaction peer differs"
					break actions
				}
				status, err := exchangeProbeFrame(connection, []byte{5, 0, 0, 0, 15}, 9)
				wantedStatus := uint32(1)
				writeControl := byte(0)
				if effect == "restore-control" {
					wantedStatus = 0
					writeControl = byte(originalControl)
				}
				if effect == "boot-handoff" {
					wantedStatus = 0
					writeControl = 1
				}
				if err != nil || binary.LittleEndian.Uint32(status[5:]) != wantedStatus {
					_ = connection.Close()
					step.Reason = "takeover requires actual paused status"
					break actions
				}
				address := scenarioData.ControlBase + uint32(scenarioActor)*scenarioData.Stride
				packet := []byte{10, 0, 0, 0, 4, 0, 0, 0, 0, 0}
				binary.LittleEndian.PutUint32(packet[5:], address)
				packet[9] = writeControl
				_, err = exchangeProbeFrame(connection, packet, 5)
				if err != nil {
					_ = connection.Close()
					step.Reason = "named takeover acknowledgement unknown: " + err.Error()
					break actions
				}
				readback := []byte{9, 0, 0, 0, 0, 0, 0, 0, 0}
				binary.LittleEndian.PutUint32(readback[5:], address)
				value, err := exchangeProbeFrame(connection, readback, 6)
				_ = connection.Close()
				if err != nil || value[5] != writeControl {
					step.Reason = "named takeover readback differs"
					break actions
				}
				if effect == "boot-handoff" {
					if _, err := observeProbeProcess(ProbeMemoryRuntime{}, owned.PID, owned, profile.Program.SHA256); err != nil {
						step.Reason = err.Error()
						break actions
					}
					break
				}
				fresh, err = readProbeUI(ProbeUIPlan{Admission: scenarioAdmission, BuildSHA256: profile.Program.SHA256, Glyphmap: scenarioGlyphs, TimeoutMS: 10000, MaxReads: profile.Scenario.MaxUIReads}, scenarioRuntime)
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				for player := range fresh.PlayerRecords {
					expected := bytes.Clone(scenarioUI.PlayerRecords[player])
					if player == scenarioActor {
						expected[241] = writeControl
					}
					if !bytes.Equal(expected, fresh.PlayerRecords[player]) {
						step.Reason = "source owner changed during takeover"
						break actions
					}
				}
				if !reflect.DeepEqual(fresh.Headers, scenarioUI.Headers) || !reflect.DeepEqual(fresh.Widgets, scenarioUI.Widgets) {
					step.Reason = "source context changed during takeover"
					break actions
				}
				step.UI = &fresh
				if effect == "restore-control" {
					restored = true
				}
			case "verify-human", "select-data", "select-save", "card-save", "select-continue", "select-newgame", "front-end", "wait-board", "card-preview", "card-load", "card-prepare-load", "card-load-prepared", "ack-preparation-image", "wait-advance", "wait-terminal":
				if repeats == 0 && (effect == "front-end" || effect == "wait-board") {
					scenarioDeadline = frontEndDeadline
				}
				if repeats == 0 && (effect == "select-continue" || effect == "wait-advance") {
					timeout := scenarioData.Reload.TitleTimeoutMS
					if effect == "wait-advance" {
						timeout = scenarioData.Reload.AdvanceTimeoutMS
					}
					limit := time.Now().Add(time.Duration(timeout) * time.Millisecond)
					if limit.Before(scenarioDeadline) {
						scenarioDeadline = limit
					}
				}
				if !time.Now().Before(scenarioDeadline) {
					step.Reason = "source scenario deadline expired"
					break actions
				}
				ui, err := readProbeUI(ProbeUIPlan{Admission: scenarioAdmission, BuildSHA256: profile.Program.SHA256, Glyphmap: scenarioGlyphs, TimeoutMS: 10000, MaxReads: profile.Scenario.MaxUIReads}, scenarioRuntime)
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				step.UI = &ui
				loading := effect == "wait-terminal" || effect == "select-continue" || effect == "select-newgame" || effect == "front-end" || effect == "wait-board" || effect == "card-preview" || effect == "preview-dwell" || effect == "card-load" || effect == "card-prepare-load" || effect == "card-load-prepared" || effect == "ack-preparation-image"
				if !loading && effect != "wait-advance" && (ui.Headers["current"] != uint64(scenarioActor) || *ui.Saved.Players[scenarioActor].Control != 0) {
					step.Reason = "source human actor changed"
					break actions
				}
				for player, record := range ui.Saved.Players {
					if loading || effect == "wait-advance" {
						break
					}
					if player != scenarioActor && (record.Control == nil || *record.Control != *scenarioUI.Saved.Players[player].Control) {
						step.Reason = "source other controller changed"
						break actions
					}
				}
				row := scenarioData.Rows[profile.Scenario.ID]
				row.FileIndex, row.DisplayFile = scenarioFileIndex, scenarioFileIndex+1
				command := ""
				selectingFile := false
				switch effect {
				case "wait-terminal":
					if profile.Scenario.Recipe == "" || acceptedCheckpoint < 1 {
						step.Reason = "terminal requires accepted recipe checkpoint"
						break actions
					}
					postClear := ui.Headers["story"] == 49 && ui.Headers["mode"] == 0x280
					for _, player := range ui.Saved.Players {
						postClear = postClear && player.Control != nil && *player.Control == 0
					}
					if postClear {
						if postClearSince.IsZero() {
							postClearSince = time.Now()
						}
					} else {
						postClearSince = time.Time{}
					}
					if ui.Headers["story"] >= 50 || !postClearSince.IsZero() && time.Since(postClearSince) >= 60*time.Second {
						break
					}
					time.Sleep(time.Second)
					repeatEffect = true
				case "front-end":
					mode := ui.Headers["mode"]
					if mode != lastFrontMode {
						if mode == scenarioData.NewGame.YesNoMode {
							yesNoBoxes++
						}
						lastFrontMode = mode
					}
					if yesNoPending {
						yesNoPending = false
						if mode != scenarioData.NewGame.YesNoMode || ui.Headers["yesno"] != yesNoTarget {
							repeatEffect = true
							break
						}
					}
					if mode == scenarioData.NewGame.IntroMode {
						humans := []int{}
						sharedSquares := true
						for index, player := range ui.Saved.Players {
							if *player.Control == 0 {
								humans = append(humans, index)
							}
							sharedSquares = sharedSquares && *player.Square == *ui.Saved.Players[0].Square
						}
						if len(humans) == 1 && sharedSquares && ui.Headers["story"] <= 1 && ui.Headers["week"] == 0 {
							scenarioActor = humans[0]
							scenarioUI = ui
							break
						}
						time.Sleep(time.Second)
						repeatEffect = true
						break
					}
					if mode == scenarioData.NewGame.YesNoMode {
						yesNoTarget = 0
						if profile.Scenario.NoTutorial && yesNoBoxes == 2 {
							yesNoTarget = 1
						}
						if ui.Headers["yesno"] != yesNoTarget {
							command = "UP"
							if yesNoTarget == 1 {
								command = "DOWN"
							}
							yesNoPending = true
						} else {
							command = "CIRCLE"
						}
					} else {
						command = "CIRCLE"
					}
					repeatEffect = true
				case "ack-preparation-image":
					image := false
					for _, widget := range ui.Widgets {
						image = image || !widget.Unsupported && widget.Index == 0 && widget.Kind == 9 && widget.Ready == 1 && widget.Flags&3 == 1 && widget.ImageTexture == scenarioData.NewGame.ImageTexture
					}
					if preparationAcknowledged || preparedState == nil || !image || ui.Headers["mode"] != scenarioData.NewGame.ImageMode || ui.Headers["current"] != uint64(scenarioActor) || *ui.Saved.Players[scenarioActor].Control != 0 || !reflect.DeepEqual(ui.Saved, *preparedState) || step.Capture == nil || step.Capture.Status != "CAPTURED" {
						step.Reason = "preparation image/initialized state changed before acknowledgement"
						break actions
					}
					command = "CIRCLE"
				case "wait-board":
					eligible := ui.Headers["mode"] == 0x1b0 && ui.Headers["current"] < 4 && ui.Headers["board_options"] == 5 && ui.Headers["board_handle"] == 1 && ui.Headers["board_cursor"] == 0 && ui.BoardAIReady
					move := false
					for _, widget := range ui.Widgets {
						move = move || !widget.Unsupported && widget.Source == scenarioData.MoveSource && widget.Text == "Move" && widget.Ready == 0 && widget.Flags&3 == 1
					}
					for _, player := range ui.Saved.Players {
						eligible = eligible && *player.Control >= 1 && *player.Control <= 3
					}
					if eligible && move {
						break
					}
					time.Sleep(250 * time.Millisecond)
					repeatEffect = true
				case "select-continue", "select-newgame":
					if repeats >= scenarioData.Reload.TitleAttempts {
						step.Reason = "source Continue selector timed out"
						break actions
					}
					var menu *ProbeUIWidget
					for index := range ui.Widgets {
						widget := &ui.Widgets[index]
						if !widget.Unsupported && strings.HasPrefix(widget.Text, scenarioData.Reload.TitlePrefix) && widget.Selection != nil {
							menu = widget
						}
					}
					bootMessage := false
					for _, widget := range ui.Widgets {
						bootMessage = bootMessage || ui.Headers["mode"] == scenarioData.Reload.MovieMode && widget.Index == 0 && widget.Source == scenarioData.Reload.BootMessageSource
					}
					startup := bootMessage || (ui.Headers["mode"] == scenarioData.Reload.BootMode || ui.Headers["mode"] == scenarioData.Reload.MovieMode) && ui.Headers["save_kind"] == 0 && ui.Headers["mc_dialog"] == 1
					target := scenarioData.Reload.ContinueTarget
					if effect == "select-newgame" {
						target = scenarioData.NewGame.TitleTarget
					}
					if menu != nil && ui.Headers["mode"] == scenarioData.Reload.BootMode && !startup {
						if *menu.Selection == target {
							command = "CIRCLE"
						} else if *menu.Selection > target {
							command = "UP"
						} else {
							command = "DOWN"
						}
					} else if startup {
						messageIndex := ui.Headers["message_widget"]
						if bootMessage {
							messageIndex = 0
						}
						for _, widget := range ui.Widgets {
							if uint64(widget.Index) == messageIndex {
								if widget.Unsupported || widget.Text != "" && !strings.HasPrefix(widget.Text, "Checkingthememorycard") && !strings.HasPrefix(widget.Text, "Thereisnodataonthememorycard(PS2).") {
									step.Reason = "unrecognized startup card prompt"
									break actions
								}
								if widget.Ready == 1 && widget.Text != "" {
									command = "CIRCLE"
								}
							}
						}
					} else if ui.Headers["mode"] == scenarioData.Reload.BootMode {
						command = "CROSS,START"
					} else if ui.Headers["mode"] == scenarioData.Reload.MovieMode {
						command = "START"
					}
					if ui.Headers["mode"] == scenarioData.Reload.BootMode && ui.Headers["mc_dialog"] == 0 && ui.Headers["file_widget"] != 0 && menu == nil {
						break
					}
					if effect == "select-newgame" && (ui.Headers["mode"] == scenarioData.NewGame.NarrationMode || ui.Headers["mode"] == scenarioData.NewGame.YesNoMode || ui.Headers["mode"] == scenarioData.NewGame.IntroMode) {
						break
					}
					repeatEffect = true
					if command == "" {
						time.Sleep(250 * time.Millisecond)
					}
				case "wait-advance":
					if !restored || scenarioSaved == nil {
						step.Reason = "advancement lacks guarded COM restoration"
						break actions
					}
					before := scenarioSaved
					changed := *ui.Saved.Story != *before.Story || *ui.Saved.Week != *before.Week || *ui.Saved.Day != *before.Day
					for player, record := range ui.Saved.Players {
						changed = changed || *record.Square != *before.Players[player].Square || *record.Money != *before.Players[player].Money
					}
					if !changed {
						time.Sleep(250 * time.Millisecond)
						repeatEffect = true
					}
				case "verify-human":
					retainedMove := false
					for _, before := range scenarioUI.Widgets {
						if before.Unsupported || before.Source != scenarioData.MoveSource || before.Text != "Move" || before.Ready != 0 || before.Flags&3 != 1 {
							continue
						}
						for _, after := range ui.Widgets {
							if !after.Unsupported && after.Index == before.Index && after.Source == before.Source && after.Text == before.Text && after.Ready == before.Ready && after.Flags&3 == 1 {
								retainedMove = true
							}
						}
					}
					if !retainedMove {
						step.Reason = "source Move owner changed after resume"
						break actions
					}
					for _, key := range []string{"mode", "story", "week", "day", "current", "area", "board_handle", "board_options", "board_cursor"} {
						if ui.Headers[key] != scenarioUI.Headers[key] {
							step.Reason = "source owner changed after unpause"
							break actions
						}
					}
				case "select-data":
					dataMain := false
					for _, widget := range ui.Widgets {
						dataMain = dataMain || !widget.Unsupported && widget.Text == scenarioData.DataText
					}
					if ui.Headers["mode"] == 0x2e0 && ui.Headers["data_context"] == 0 && ui.Headers["data_focus"] == 0 && ui.Headers["mc_dialog"] == 0 && dataMain {
						break
					}
					if repeats >= row.DataAttempts || ui.Headers["mode"] != 0x1b0 {
						step.Reason = "source Data selection failed"
						break actions
					}
					if ui.Headers["board_cursor"] == row.DataCursor {
						command = "CIRCLE"
					} else {
						command = "DOWN"
					}
					repeatEffect = true
				case "select-save":
					if ui.Headers["save_kind"] == 1 && ui.Headers["mc_dialog"] == 0 && ui.Headers["file_widget"] != 0 {
						break
					}
					var tabs *ProbeUIWidget
					for index := range ui.Widgets {
						if !ui.Widgets[index].Unsupported && ui.Widgets[index].Text == scenarioData.DataText {
							tabs = &ui.Widgets[index]
						}
					}
					if repeats >= row.SaveAttempts+1 || tabs == nil || tabs.Selection == nil || ui.Headers["mode"] != 0x2e0 {
						step.Reason = "source Save tab unavailable"
						break actions
					}
					if *tabs.Selection == row.SaveTab {
						command = "CIRCLE"
					} else {
						command = "DOWN"
						repeatEffect = true
					}
					// The acknowledged Save-tab Circle enters card(), which can
					// begin with creation I/O/dialogs before any file menu exists.
				case "card-save", "card-preview", "card-load", "card-prepare-load", "card-load-prepared":
					if (effect == "card-prepare-load" || effect == "card-load-prepared") && ui.Headers["mode"] == scenarioData.NewGame.ImageMode {
						image := false
						ready := false
						for _, widget := range ui.Widgets {
							ready = ready || widget.Index == 0 && widget.Kind == 9 && widget.Ready == 1
							image = image || !widget.Unsupported && widget.Index == 0 && widget.Kind == 9 && widget.Ready == 1 && widget.Flags&3 == 1 && widget.ImageTexture == scenarioData.NewGame.ImageTexture
						}
						if !ready {
							time.Sleep(250 * time.Millisecond)
							repeatEffect = true
							break
						}
						if preparedState == nil || !image || !reflect.DeepEqual(ui.Saved, *preparedState) || ui.Headers["current"] != uint64(scenarioActor) || *ui.Saved.Players[scenarioActor].Control != 0 {
							step.Reason = "unrecognized preparation image or additional saved-state mutation"
							break actions
						}
						if effect == "card-prepare-load" && !preparationAcknowledged {
							break
						}
						time.Sleep(250 * time.Millisecond)
						repeatEffect = true
						break
					}
					if (effect == "card-load" || effect == "card-load-prepared") && ui.Headers["mode"] == 0x1b0 && ui.Headers["story"] > 0 {
						expected := scenarioSaved
						if effect == "card-load-prepared" {
							expected = preparedState
						}
						if previewSamples != 40 || expected == nil || effect == "card-load-prepared" && !preparationAcknowledged || !reflect.DeepEqual(ui.Saved, *expected) {
							step.Reason = "loaded source fingerprint or complete preview dwell differs"
							break actions
						}
						if effect == "card-load-prepared" {
							break
						}
						if loadMethod == "warm" {
							warmVerified = true
						} else if loadMethod == "cold" && warmVerified {
							coldVerified = true
						} else {
							step.Reason = "invalid paired reload order"
							break actions
						}
						break
					}
					wantedMode := uint64(0x2e0)
					if effect != "card-save" {
						wantedMode = 0x260
					}
					if repeats >= row.CardAttempts || ui.Headers["mode"] != wantedMode {
						step.Reason = "source card UI unavailable or timed out"
						break actions
					}
					if ui.Headers["mc_dialog"] != 0 {
						var prompt *ProbeUIWidget
						for index := range ui.Widgets {
							if uint64(ui.Widgets[index].Index) == ui.Headers["message_widget"] && !ui.Widgets[index].Unsupported {
								prompt = &ui.Widgets[index]
							}
						}
						known := false
						if prompt != nil {
							for _, prefix := range scenarioData.Prompts {
								known = known || strings.HasPrefix(prompt.Text, prefix)
							}
						}
						if !known {
							step.Reason = "unrecognized source card prompt"
							break actions
						}
						if profile.Scenario.Recipe != "" {
							kind := ""
							if effect == "card-save" && strings.HasPrefix(prompt.Text, "OverwriteFile") && ui.Headers["yesno"] == 0 {
								kind = "overwrite-confirmed"
							}
							if effect == "card-save" && strings.HasPrefix(prompt.Text, "Newdatawascreated") && prompt.Ready == 1 {
								kind = "card-data-created"
							}
							if kind != "" && !seenPromptWitness[fmt.Sprintf("%d:%s", checkpointNumber, kind)] {
								pendingPromptKind = kind
								observed := *prompt
								pendingPrompt = &observed
								pendingPromptHeaders = map[string]uint64{"mode": ui.Headers["mode"], "mc_dialog": ui.Headers["mc_dialog"], "yesno": ui.Headers["yesno"], "message_widget": ui.Headers["message_widget"]}
								repeatEffect = true
								break
							}
						}
						busy := strings.HasPrefix(prompt.Text, "Saving.") || strings.HasPrefix(prompt.Text, "Creatingnewdata") || strings.HasPrefix(prompt.Text, "Loading.")
						question := strings.HasPrefix(prompt.Text, "Createnewdata") || strings.HasPrefix(prompt.Text, "OverwriteFile") || strings.HasPrefix(prompt.Text, "Savetoanewfile") || strings.HasPrefix(prompt.Text, "LoadFile")
						if busy && prompt.Ready != 1 {
							time.Sleep(time.Duration(row.PollMS) * time.Millisecond)
						} else if question && ui.Headers["yesno"] != 0 {
							command = "UP"
						} else if question || prompt.Ready == 1 {
							if strings.HasPrefix(prompt.Text, "Savecomplete.") {
								saveCompleted = true
							}
							command = "CIRCLE"
						} else {
							time.Sleep(time.Duration(row.IdlePollMS) * time.Millisecond)
						}
						repeatEffect = true
					} else {
						var menu *ProbeUIWidget
						for index := range ui.Widgets {
							if uint64(ui.Widgets[index].Index) == ui.Headers["file_widget"] && !ui.Widgets[index].Unsupported {
								menu = &ui.Widgets[index]
							}
						}
						if menu == nil || menu.Selection == nil {
							step.Reason = "source file menu unavailable"
							break actions
						}
						if fileSelected {
							if effect != "card-save" || !saveCompleted {
								step.Reason = "source file selection returned without Save completion"
								break actions
							}
							saved := ui.Saved
							scenarioSaved = &saved
							break
						}
						if effect == "card-preview" && *menu.Selection == uint64(row.FileIndex) {
							break
						}
						if *menu.Selection != uint64(row.FileIndex) {
							if *menu.Selection > uint64(row.FileIndex) {
								command = "UP"
							} else {
								command = "DOWN"
							}
						} else {
							command = "CIRCLE"
							selectingFile = true
						}
						repeatEffect = true
					}
				}
				if command != "" {
					for _, button := range strings.Split(command, ",") {
						if _, err := observeProbeProcess(ProbeMemoryRuntime{}, owned.PID, owned, profile.Program.SHA256); err != nil {
							step.Reason = err.Error()
							break actions
						}
						connection, err := net.DialTimeout("unix", filepath.Join(profile.Root, "pad.sock"), time.Second)
						if err != nil {
							step.Reason = err.Error()
							break actions
						}
						_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
						_, err = io.Copy(connection, strings.NewReader("tap "+button+" 0.1"))
						if err == nil {
							err = connection.(*net.UnixConn).CloseWrite()
						}
						ack, ackErr := io.ReadAll(io.LimitReader(connection, 257))
						_ = connection.Close()
						if err != nil || ackErr != nil || string(ack) != "ok\n" {
							step.Reason = "source input acknowledgement unknown"
							break actions
						}
						if selectingFile {
							fileSelected = true
						}
						if effect == "ack-preparation-image" {
							preparationAcknowledged = true
						}
						settle := row.SettleMS
						if button == "UP" || button == "DOWN" || button == "CROSS" {
							settle = 300
						}
						if effect == "front-end" {
							settle = 1200
							if ui.Headers["mode"] == scenarioData.NewGame.YesNoMode {
								settle = 1500
								if button == "UP" || button == "DOWN" {
									settle = 600
								}
							}
						}
						time.Sleep(time.Duration(settle) * time.Millisecond)
					}
				}
			case "preview-dwell":
				if scenarioSaved == nil || fileSelected {
					step.Reason = "preview dwell lacks unconfirmed File2"
					break actions
				}
				for previewSamples < scenarioData.Reload.PreviewSamples {
					time.Sleep(time.Duration(scenarioData.Reload.PreviewPollMS) * time.Millisecond)
					if !time.Now().Before(scenarioDeadline) {
						step.Reason = "preview dwell deadline exhausted"
						break actions
					}
					plan := ProbeMemoryBundle{Version: 1, SourceSHA256: "5439db31097c19d3b92969d5403c2c19dc3518cea4ed4c075df1a3830b8ef56f", Admission: scenarioAdmission, BuildSHA256: profile.Program.SHA256}
					for index, field := range []struct {
						Opcode  uint8
						Address uint32
					}{{1, 0x56581c}, {2, 0x570108}} {
						opcode, address := field.Opcode, field.Address
						id := fmt.Sprintf("preview%d", index)
						plan.Requests = append(plan.Requests, ProbeMemoryRequest{ID: id, Opcode: &opcode, Address: &address})
						plan.Decoders = append(plan.Decoders, ProbeMemoryDecoder{ID: id, Kind: "scalar", Requests: []string{id}})
					}
					planRaw, _ := json.Marshal(plan)
					runtimeRaw, _ := json.Marshal(scenarioRuntime)
					observed, err := readProbeMemory(planRaw, runtimeRaw)
					if err != nil || len(observed.Observations) != 2 || observed.Observations[0].Value != 0x260 || observed.Observations[1].Value != 0 {
						step.Reason = "preview dwell changed or read failed"
						break actions
					}
					previewSamples++
				}
				step.PreviewSamples = previewSamples
			case "capture-save", "capture-preparation-save", "capture-preparation-image", "emit-preparation-start", "emit-preparation-ack", "emit-preparation-complete", "capture-preview", "capture-reload", "capture-handoff", "capture-advance", "emit-resumed", "emit-reload-start", "capture-terminal", "emit-card-witness":
				if effect == "emit-preparation-start" {
					if step.UI == nil || scenarioActor < 0 || *step.UI.Saved.Players[scenarioActor].TutorialFlags&1 != 0 {
						step.Reason = "preparation requires source uninitialized owned actor"
						break actions
					}
					saved := step.UI.Saved
					scenarioSaved = &saved
					encoded, _ := json.Marshal(saved)
					var initialized ProbeSavedState
					_ = json.Unmarshal(encoded, &initialized)
					*initialized.Players[scenarioActor].TutorialFlags |= 1
					initialized.Players[scenarioActor].RecordSHA256 = initialized.Players[scenarioActor].TutorialInitializedSHA256
					preparedState = &initialized
					preparationAcknowledged = false
				}
				isPrompt := effect == "emit-card-witness"
				if !isPrompt && (effect != "emit-preparation-start" && !saveCompleted || scenarioSaved == nil) || scenarioActor < 0 || originalControl == 0 {
					step.Reason = "capture requires source-confirmed nondefault save"
					break actions
				}
				row := scenarioData.Rows[profile.Scenario.ID]
				row.FileIndex, row.DisplayFile = checkpointFileIndex, checkpointFileIndex+1
				eventKind := map[string]string{"capture-save": "save-complete", "capture-preparation-save": "save-complete", "emit-preparation-start": "tutorial-preparation-start", "capture-preparation-image": "tutorial-preparation-image", "emit-preparation-ack": "tutorial-preparation-ack", "emit-preparation-complete": "tutorial-preparation-complete", "capture-preview": "continue-preview", "capture-reload": "reload-verified", "capture-handoff": "com-handoff-data-main", "capture-advance": "story-advanced-after-reload", "emit-resumed": "resumed", "emit-reload-start": "reload-start"}[effect]
				if effect != "capture-save" && step.UI == nil {
					step.Reason = "checkpoint event lacks current acquired UI"
					break actions
				}
				if effect == "capture-terminal" {
					eventKind = "story-target-reached"
				}
				if isPrompt {
					eventKind = pendingPromptKind
				}
				event := map[string]any{"event": eventKind, "event_id": len(scenarioEvents) + 1, "checkpoint": checkpointNumber, "time": time.Now().UTC().Format("2006-01-02T15:04:05-0700"), "state": scenarioSaved, "slot": row.FileIndex, "display_file": row.DisplayFile, "hardware_card_slot": row.CardSlot, "actor": scenarioActor, "original_control": originalControl, "epoch": epoch}
				if effect == "capture-terminal" {
					event["mode"] = step.UI.Headers["mode"]
				}
				if isPrompt {
					event["prompt"] = pendingPrompt
					event["prompt_headers"] = pendingPromptHeaders
				}
				if effect != "capture-save" {
					event["state"] = step.UI.Saved
				}
				if effect == "capture-preview" || effect == "capture-reload" {
					event["method"] = loadMethod
					event["phase"] = "verification"
					if request.Operation == "prepare-load" {
						event["phase"] = "preparation"
					}
				}
				if effect == "emit-reload-start" {
					event["method"] = strings.TrimSuffix(request.Operation, "-load")
					event["phase"] = "verification"
					if preparedState != nil && !preparationAcknowledged {
						event["phase"] = "preparation"
					}
				}
				if effect == "capture-reload" {
					event["successful_preview_samples"] = previewSamples
				}
				if effect == "emit-resumed" {
					if !restored {
						step.Reason = "resumed lacks guarded restoration"
						break actions
					}
					event["expected"] = scenarioSaved
				}
				scenarioEvent, _ = json.Marshal(event)
				log := append(bytes.Clone(scenarioEvent), '\n')
				logOffset := len(scenarioLog)
				logPath := filepath.Join(profile.Root, "events.jsonl")
				if len(scenarioLog) == 0 {
					if err := writeNewFile(logPath, bytes.NewReader(log), int64(len(log)), fmt.Sprintf("%x", sha256.Sum256(log)), 0600); err != nil {
						step.Reason = err.Error()
						break actions
					}
					var err error
					scenarioLogInfo, err = os.Lstat(logPath)
					if err != nil {
						step.Reason = "new event journal identity unavailable"
						break actions
					}
				} else {
					prior, err := readInput(logPath, 4<<20)
					info, statErr := os.Lstat(logPath)
					if err != nil || statErr != nil || !os.SameFile(info, scenarioLogInfo) || !bytes.Equal(prior, scenarioLog) || info.Mode().Perm() != 0600 {
						step.Reason = "owned event prefix or identity changed"
						break actions
					}
					stat, ok := info.Sys().(*syscall.Stat_t)
					if !ok || stat.Nlink != 1 || len(prior)+len(log) > 4<<20 {
						step.Reason = "owned event journal exceeds exclusive bounded contract"
						break actions
					}
					file, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0600)
					if err != nil {
						step.Reason = err.Error()
						break actions
					}
					opened, statErr := file.Stat()
					if statErr != nil || !os.SameFile(info, opened) || opened.Size() != int64(len(prior)) {
						_ = file.Close()
						step.Reason = "event journal changed before append"
						break actions
					}
					_, err = io.Copy(file, bytes.NewReader(log))
					if err == nil {
						err = file.Sync()
					}
					closeErr := file.Close()
					if err != nil || closeErr != nil {
						step.Reason = "event append is partial or durability unknown"
						break actions
					}
				}
				scenarioLog = append(scenarioLog, log...)
				readback, err := readInput(logPath, 4<<20)
				if err != nil || !bytes.Equal(readback, scenarioLog) {
					step.Reason = "event append readback differs"
					break actions
				}
				scenarioEvents = append(scenarioEvents, ProbeEvidenceEvent{Offset: int64(logOffset), Data: log})
				if isPrompt {
					seenPromptWitness[fmt.Sprintf("%d:%s", checkpointNumber, pendingPromptKind)] = true
					pendingPromptKind = ""
					repeatEffect = true
					break
				}
				if effect == "emit-preparation-complete" {
					if !preparationAcknowledged || preparedState == nil || !reflect.DeepEqual(step.UI.Saved, *preparedState) {
						step.Reason = "preparation completed with changed saved state"
						break actions
					}
					saved := step.UI.Saved
					scenarioSaved = &saved
				}
				if effect == "emit-reload-start" || effect == "emit-preparation-start" || effect == "emit-preparation-ack" || effect == "emit-preparation-complete" {
					break
				}
				if effect == "emit-resumed" {
					if profile.Seed != nil && profile.Scenario.Recipe == "" {
						intervals, err := probeCheckpointIntervals(*profile.Seed, len(scheduledIntervals)+1)
						if err != nil {
							step.Reason = err.Error()
							break actions
						}
						scheduledIntervals = intervals
						step.ScheduledIntervals = slices.Clone(intervals)
					}
					clear(skipReasons)
					break
				}
				captureRoot := filepath.Join(profile.Root, "captures")
				if err := os.Mkdir(captureRoot, 0700); err != nil && !(len(scenarioCaptures) > 0 && os.IsExist(err)) {
					step.Reason = err.Error()
					break actions
				}
				memory := ProbeMemoryBundle{Version: 1, SourceSHA256: "5439db31097c19d3b92969d5403c2c19dc3518cea4ed4c075df1a3830b8ef56f", Admission: scenarioAdmission, BuildSHA256: profile.Program.SHA256}
				for index, field := range []struct {
					Opcode  uint8
					Address uint32
				}{{1, 0x56581c}, {1, 0x56b598}, {0, 0x56b18c}} {
					opcode, address := field.Opcode, field.Address
					memory.Requests = append(memory.Requests, ProbeMemoryRequest{ID: fmt.Sprintf("tag%d", index), Opcode: &opcode, Address: &address})
				}
				memory.Decoders = append(memory.Decoders, ProbeMemoryDecoder{ID: "source-tags", Kind: "frame_tags", Requests: []string{"tag0", "tag1", "tag2"}})
				playerIDs := []string{}
				for offset := uint32(0); offset < 508; offset += 4 {
					opcode, address := uint8(2), uint32(0x56bed0)+uint32(scenarioActor)*508+offset
					id := fmt.Sprintf("player-%d", offset)
					playerIDs = append(playerIDs, id)
					memory.Requests = append(memory.Requests, ProbeMemoryRequest{ID: id, Opcode: &opcode, Address: &address})
				}
				memory.Decoders = append(memory.Decoders, ProbeMemoryDecoder{ID: "source-player", Kind: "player", Requests: playerIDs})
				memoryRaw, _ := json.Marshal(memory)
				captureID := "save-" + request.Nonce
				if effect != "capture-save" && effect != "capture-preparation-save" {
					captureID = effect + "-" + request.Nonce
				}
				captureProfile := ProbeCaptureProfile{Version: 1, SourceSHA256: memory.SourceSHA256, PadSourceSHA256: "1c1dab832d28026ad960eeb9d08e19c5ab40e00f9c30517aadc906921c555a36", Memory: memoryRaw, CaptureID: captureID, EventID: len(scenarioEvents), Checkpoint: checkpointNumber, LogOffset: int64(logOffset), LogBytes: len(log), LogSHA256: fmt.Sprintf("%x", sha256.Sum256(log)), MaxSnapshotFiles: 16, MaxImageBytes: 16 << 20, MaxPixels: 1 << 20, MaxRetainedFiles: 32, MaxRetainedBytes: 256 << 20, LockTimeoutMS: 1000, CaptureTimeoutMS: 3000}
				captureRuntime := ProbeCaptureRuntime{Memory: scenarioRuntime, Snapshots: filepath.Join(dataRoot, "snaps"), Output: captureRoot, BackendPID: os.Getpid()}
				captureRaw, _ := json.Marshal(captureProfile)
				runtimeRaw, _ := json.Marshal(captureRuntime)
				receipt, err := captureProbeEvidence(captureRaw, runtimeRaw)
				step.Capture = &receipt
				if err != nil || receipt.Status != "CAPTURED" {
					step.Reason = "save original-PNG capture is unknown: " + receipt.Reason
					if err != nil {
						step.Reason += ": " + err.Error()
					}
					break actions
				}
				image, err := readInput(filepath.Join(captureRoot, receipt.ImagePath), 16<<20)
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				scenarioCaptures = append(scenarioCaptures, ProbeCaptureObservation{Receipt: receipt, ImageHex: hex.EncodeToString(image), Admission: bytes.Clone(scenarioAdmission)})
			case "report-save", "report-pair", "report-checkpoint", "report-story":
				if step.Capture == nil || step.Capture.Status != "CAPTURED" || len(scenarioEvent) == 0 {
					step.Reason = "save report requires its captured event"
					break actions
				}
				image, err := readInput(filepath.Join(profile.Root, "captures", step.Capture.ImagePath), 16<<20)
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				currentEpoch := epoch
				bundle := ProbeEvidenceBundle{Version: 1, SourceSchema: "probe-evidence-go-v1", SourceSHA256: "f6d9bcf48634a234da6632f42e4faea9f66d79dcaad0783b79ccce477ed4f0e8", Admission: scenarioAdmission, RunID: profile.Session, Session: profile.Session, ISOSHA256: profile.Inputs["iso"].SHA256, Epoch: &currentEpoch, Cohort: profile.Scenario.ID, Members: []string{"paired-checkpoint"}, Events: []ProbeEvidenceEvent{{Offset: 0, Data: append(bytes.Clone(scenarioEvent), '\n')}}, Captures: []ProbeCaptureObservation{{Receipt: *step.Capture, ImageHex: hex.EncodeToString(image)}}}
				if effect != "report-save" || profile.Scenario.Recipe != "" {
					bundle.Cohort = "go-checkpoint-only-v1"
					bundle.Members = nil
					bundle.Events = scenarioEvents
					bundle.Captures = scenarioCaptures
					if profile.Scenario.Recipe != "" {
						bundle.Cohort = "go-story-checkpoints-v1"
						bundle.Story = &ProbeStoryFacts{Recipe: profile.Scenario.Recipe, Phase: "checkpoint"}
						if effect == "report-story" {
							bundle.Story.Phase = "complete"
							bundle.Story.TerminalEventID = len(scenarioEvents)
							if !postClearSince.IsZero() {
								bundle.Story.PostClearMS = time.Since(postClearSince).Milliseconds()
							}
						}
					}
				}
				bundleRaw, _ := json.Marshal(bundle)
				if effect != "report-save" {
					path := filepath.Join(profile.Root, request.Nonce+"-evidence.json")
					hash := fmt.Sprintf("%x", sha256.Sum256(bundleRaw))
					if err := writeNewFile(path, bytes.NewReader(bundleRaw), int64(len(bundleRaw)), hash, 0400); err != nil {
						step.Reason = err.Error()
						break actions
					}
					step.Evidence = &RegistryInput{Path: path, Size: int64(len(bundleRaw)), SHA256: hash}
				}
				result, err := reportProbeEvidence(bundleRaw)
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				step.Checkpoint = &result
				if effect == "report-save" && (result.Status != "UNKNOWN" || len(result.Checkpoints) != checkpointNumber || result.Checkpoints[len(result.Checkpoints)-1].Warm || result.Checkpoints[len(result.Checkpoints)-1].Cold || result.Checkpoints[len(result.Checkpoints)-1].Advanced || profile.Scenario.Recipe == "" && len(result.CoveredAreas) != 0) {
					step.Reason = "save-only evidence cannot accept a paired checkpoint"
					break actions
				}
				if (effect == "report-checkpoint" || effect == "report-story") && (result.Status != "PASS" || len(result.Checkpoints) != checkpointNumber || !result.Checkpoints[len(result.Checkpoints)-1].Warm || !result.Checkpoints[len(result.Checkpoints)-1].Cold || !result.Checkpoints[len(result.Checkpoints)-1].Advanced) {
					step.Reason = "actual checkpoint evidence is incomplete or inconsistent"
					break actions
				}
				if effect == "report-checkpoint" && profile.Scenario.Recipe != "" {
					acceptedCheckpoint = checkpointNumber
					intervals, err := probeCheckpointIntervals(*profile.Seed, len(scheduledIntervals)+1, profile.Scenario.Calibration)
					if err != nil {
						step.Reason = err.Error()
						break actions
					}
					scheduledIntervals = intervals
					step.ScheduledIntervals = slices.Clone(intervals)
					checkpointDue = time.Now().Add(time.Duration(intervals[len(intervals)-1]) * time.Second)
					if scenarioData.Recipes[profile.Scenario.Recipe].Alternate {
						scenarioFileIndex = 1 - scenarioFileIndex
					}
				}
				resultRaw, _ := json.Marshal(result)
				resultName := "save-report.json"
				if effect != "report-save" || profile.Scenario.Recipe != "" {
					resultName = request.Nonce + "-report.json"
				}
				if err := writeNewFile(filepath.Join(profile.Root, resultName), bytes.NewReader(resultRaw), int64(len(resultRaw)), fmt.Sprintf("%x", sha256.Sum256(resultRaw)), 0600); err != nil {
					step.Reason = err.Error()
					break actions
				}
			case "prepare":
				settings, err := readInput(profile.Inputs["settings"].Path, 1<<20)
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				required := map[string]string{"Folders.Bios": "bios", "Folders.Snapshots": "snaps", "Folders.Savestates": "sstates", "Folders.MemoryCards": "memcards", "Folders.Logs": "logs", "Folders.Cheats": "cheats", "Folders.Patches": "patches", "Folders.UserResources": "resources", "Folders.Cache": "cache", "Folders.Textures": "textures", "Folders.InputProfiles": "inputprofiles", "Folders.Videos": "videos", "Folders.DebuggerLayouts": "debuggerlayouts", "Folders.DebuggerSettings": "debuggersettings", "Filenames.BIOS": filepath.Base(profile.Inputs["bios"].Path), "MemoryCards.Slot1_Enable": "true", "MemoryCards.Slot1_Filename": "probe-slot1.ps2", "MemoryCards.Slot2_Enable": "false", "Hotkeys.ResetVM": "SDL-0/RightStick", "Hotkeys.TogglePause": "SDL-0/LeftStick"}
				values := map[string]string{}
				section := ""
				for _, line := range strings.Split(string(settings), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
						continue
					}
					if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
						section = line[1 : len(line)-1]
						continue
					}
					key, value, found := strings.Cut(line, "=")
					name := section + "." + strings.TrimSpace(key)
					if !found || values[name] != "" {
						step.Reason = "settings template is not normalized"
						break actions
					}
					values[name] = strings.TrimSpace(value)
				}
				for key, value := range required {
					if values[key] != value {
						step.Reason = "private settings contract differs: " + key
						break actions
					}
				}
				for key, value := range values {
					if key != "Hotkeys.ResetVM" && key != "Hotkeys.TogglePause" && (strings.Contains(value, "SDL-0/RightStick") || strings.Contains(value, "SDL-0/LeftStick")) {
						step.Reason = "private control hotkey overlaps game input"
						break actions
					}
				}
				if err := os.Mkdir(profileDir, 0700); err != nil {
					step.Reason = "private profile already exists or cannot be created"
					break actions
				}
				for _, name := range []string{"inis", "bios", "memcards", "snaps", "logs", "sstates", "cache", "cheats", "patches", "resources", "textures", "inputprofiles", "videos", "debuggerlayouts", "debuggersettings"} {
					if err := os.MkdirAll(filepath.Join(dataRoot, name), 0700); err != nil {
						step.Reason = err.Error()
						break actions
					}
				}
				for _, copyRole := range []string{"settings", "bios", "card"} {
					input := profile.Inputs[copyRole]
					target := cardPath
					if copyRole == "settings" {
						target = filepath.Join(dataRoot, "inis", "PCSX2.ini")
					}
					if copyRole == "bios" {
						target = filepath.Join(dataRoot, "bios", filepath.Base(input.Path))
					}
					source, err := os.Open(input.Path)
					if err != nil {
						step.Reason = err.Error()
						break actions
					}
					err = writeNewFile(target, source, input.Size, input.SHA256, 0600)
					_ = source.Close()
					if err != nil {
						step.Reason = err.Error()
						break actions
					}
				}
			case "pad":
				go serveProbePad(ctx, ProbePadSpec{Root: profile.Root, Backend: "event-sink"}, padReady, padDone)
				if err := <-padReady; err != nil {
					_ = <-padDone
					step.Reason = "pad service failed: " + err.Error()
					break actions
				}
				padStarted = true
			case "launch":
				if child != nil {
					step.Reason = "a child is already owned"
					break actions
				}
				if request.Operation == "cold" || request.Operation == "cold-load" || request.Operation == "recover" {
					epoch++
				}
				args := append(slices.Clone(profile.ProgramArgs), "-datapath", profileDir, "-batch", profile.Inputs["iso"].Path)
				child = exec.Command(profile.Program.Path, args...)
				child.Env = append(os.Environ(), "DOKAPON_PROBE_SESSION_ROOT="+profile.Root)
				log, err := os.OpenFile(filepath.Join(profile.Root, fmt.Sprintf("child-epoch-%d.log", epoch)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if err != nil {
					child = nil
					step.Reason = err.Error()
					break actions
				}
				child.Stdout, child.Stderr = log, log
				if err := child.Start(); err != nil {
					_ = log.Close()
					child = nil
					step.Reason = "child launch failed: " + err.Error()
					break actions
				}
				_ = log.Close()
				readyDeadline = time.Now().Add(time.Duration(profile.ReadyTimeoutMS) * time.Millisecond)
				// exec startup can briefly expose an empty /proc cmdline. Wait for
				// the exact identity, never adopt a partial or mismatched command.
				var observed ProbeProcessRecord
				for {
					observed, err = observeProbeProcess(ProbeMemoryRuntime{Provenance: "owned_child", Root: profile.Root}, child.Process.Pid, nil, profile.Program.SHA256)
					if err == nil && reflect.DeepEqual(observed.Cmdline, child.Args) || !time.Now().Before(readyDeadline) {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if err != nil || !reflect.DeepEqual(observed.Cmdline, child.Args) {
					step.Reason = "launched child identity differs"
					if err != nil {
						step.Reason += ": " + err.Error()
					} else {
						step.Reason += fmt.Sprintf(": observed command %q does not match launched argv %q", observed.Cmdline, child.Args)
					}
					break actions
				}
				observed.Session, observed.Profile, observed.ISO, observed.ISOSHA256 = profile.Session, profileDir, profile.Inputs["iso"].Path, profile.Inputs["iso"].SHA256
				currentEpoch := epoch
				observed.Epoch = &currentEpoch
				owned = &observed
				step.Owned = owned
				step.Epoch = epoch
			case "verify", "verify-warm", "quiescent", "status-running", "status-paused", "watch-progress":
				if owned == nil {
					step.Reason = "no owned child for observation"
					break actions
				}
				deadline := time.Now().Add(time.Duration(profile.ReadyTimeoutMS) * time.Millisecond)
				if effect == "verify" {
					deadline = readyDeadline
				}
				quietSince := time.Now()
				lastCard := ""
				if effect == "quiescent" {
					// Explicit Go profile timing, not source60s/1s quiescence parity.
					deadline = time.Now().Add(time.Duration(profile.QuietMS+profile.ReadyTimeoutMS) * time.Millisecond)
				}
				statusOnly := effect == "status-running" || effect == "status-paused"
				watch := effect == "watch-progress"
				pollLimit := int(^uint(0) >> 1)
				if statusOnly {
					pollLimit = table.StatusPolls
					if index == 0 || action.Effects[index-1] != "toggle-pause" {
						pollLimit = 1
					}
					deadline = time.Now().Add(time.Duration(table.StatusPolls*table.StatusPollMS+profile.ReadyTimeoutMS) * time.Millisecond)
				}
				if watch {
					pollLimit = profile.Policy.MaxPolls
					deadline = time.Now().Add(time.Duration(profile.Policy.PollMS*pollLimit+profile.ReadyTimeoutMS) * time.Millisecond)
				}
				var previousProgress []uint64
				verified := false
				for polls := 0; polls < pollLimit && time.Now().Before(deadline); polls++ {
					if _, err := observeProbeProcess(ProbeMemoryRuntime{Provenance: "owned_child", Root: profile.Root}, owned.PID, owned, profile.Program.SHA256); err != nil {
						step.Reason = err.Error()
						break actions
					}
					connection, err := net.DialTimeout("unix", filepath.Join(profile.Root, "peer.sock"), 100*time.Millisecond)
					if err != nil {
						time.Sleep(10 * time.Millisecond)
						continue
					}
					_ = connection.SetDeadline(time.Now().Add(100 * time.Millisecond))
					peerFile, peerErr := connection.(*net.UnixConn).File()
					if peerErr != nil {
						_ = connection.Close()
						step.Reason = "PINE peer identity unavailable"
						break actions
					}
					credentials, credentialErr := syscall.GetsockoptUcred(int(peerFile.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
					_ = peerFile.Close()
					if credentialErr != nil || int(credentials.Pid) != owned.PID || credentials.Uid != uint32(os.Getuid()) {
						_ = connection.Close()
						step.Reason = "PINE peer is not the owned child"
						break actions
					}
					status, err := exchangeProbeFrame(connection, []byte{5, 0, 0, 0, 15}, 9)
					readSet := table.WatchReads[:1]
					if watch {
						readSet = table.WatchReads
					}
					if statusOnly {
						readSet = nil
					}
					readMap := map[string]ProbeMemoryRequest{}
					payloads := map[string][]byte{}
					values := map[string]uint64{}
					memory := ProbeMemoryReport{Version: 1, SourceSHA256: table.WatchSourceSHA256, BuildSHA256: profile.Program.SHA256, Session: profile.Session, Epoch: epoch, ISOSHA256: profile.Inputs["iso"].SHA256, Provenance: "go-owned-lifecycle-v1", ProcessGuarded: true, Observations: []ProbeMemoryObservation{}, Decoded: []ProbeMemoryDecoded{}, Limits: "Actual owned Go-child finite reads; not legacy admission or gameplay/coverage acceptance."}
					decoders := []ProbeMemoryDecoder{}
					for _, read := range readSet {
						if err != nil {
							break
						}
						requestData := []byte{9, 0, 0, 0, *read.Opcode, 0, 0, 0, 0}
						binary.LittleEndian.PutUint32(requestData[5:], *read.Address)
						var reply []byte
						reply, err = exchangeProbeFrame(connection, requestData, 5+1<<*read.Opcode)
						if err != nil {
							break
						}
						var padded [8]byte
						copy(padded[:], reply[5:])
						value := binary.LittleEndian.Uint64(padded[:])
						readMap[read.ID], payloads[read.ID], values[read.ID] = read, reply[5:], value
						memory.Observations = append(memory.Observations, ProbeMemoryObservation{ID: read.ID, RequestHex: fmt.Sprintf("%x", requestData), ReplyHex: fmt.Sprintf("%x", reply), Value: value})
						decoders = append(decoders, ProbeMemoryDecoder{ID: read.ID, Kind: "scalar", Requests: []string{read.ID}})
					}
					_ = connection.Close()
					if err != nil {
						if watch || statusOnly {
							step.Reason = "owned observation failed: " + err.Error()
							break actions
						}
						time.Sleep(10 * time.Millisecond)
						continue
					}
					vmStatus := binary.LittleEndian.Uint32(status[5:])
					if statusOnly {
						wanted := uint32(0)
						if effect == "status-paused" {
							wanted = 1
						}
						if index == 0 || action.Effects[index-1] != "toggle-pause" {
							value := vmStatus
							step.VMStatusBefore = &value
						} else {
							value := vmStatus
							step.VMStatusAfter = &value
						}
						if vmStatus == wanted {
							verified = true
							break
						}
						if index == 0 || action.Effects[index-1] != "toggle-pause" || vmStatus != 1-wanted {
							step.Reason = "unexpected VM status during guarded toggle"
							break actions
						}
						time.Sleep(time.Duration(table.StatusPollMS) * time.Millisecond)
						continue
					}
					if vmStatus != 0 {
						step.Reason = "owned VM is not running"
						break actions
					}
					if watch {
						memory.Decoded, err = decodeProbeMemory(readMap, payloads, values, decoders)
						if err != nil {
							step.Reason = err.Error()
							break actions
						}
						step.Memory = &memory
						step.Samples++
						if !gameplayStarted && profile.Seed != nil && values["story"] >= 1 && values["story"] <= 49 {
							calibration := profile.Scenario != nil && profile.Scenario.Calibration
							intervals, err := probeCheckpointIntervals(*profile.Seed, len(scheduledIntervals)+1, calibration)
							if err != nil || !slices.Equal(intervals[:len(scheduledIntervals)], scheduledIntervals) {
								step.Reason = "checkpoint schedule prefix differs"
								break actions
							}
							scheduledIntervals = intervals
							gameplayStarted = true
							if profile.Scenario != nil && profile.Scenario.Recipe != "" {
								checkpointDue = time.Now().Add(time.Duration(intervals[len(intervals)-1]) * time.Second)
							}
						}
						step.ScheduledIntervals = slices.Clone(scheduledIntervals)
						progress := []uint64{}
						for _, id := range table.ProgressOrder {
							value := values[id]
							if id == "week" {
								value++
							}
							progress = append(progress, value)
						}
						if previousProgress != nil && reflect.DeepEqual(previousProgress, progress) {
							step.Repeated++
						} else {
							step.Repeated = 0
						}
						previousProgress = progress
						if step.Repeated >= profile.Policy.WarnRepeats {
							step.Warning = true
						}
						skip := ""
						switch {
						case values["current"] > 3:
							skip = "invalid current player"
						case values["mode"] != 0x1b0:
							skip = "event or combat instead of board menu"
						case values["board_options"] != 5:
							skip = "unsupported board menu"
						case values["board_handle"] != 1 || values["board_cursor"] != 0:
							skip = "board Move selection inactive"
						}
						if skip != "" && !skipReasons[skip] {
							if len(skipReasons) >= profile.Policy.MaxDistinctSkips {
								step.Reason = "explicit Go skip budget exhausted"
								break actions
							}
							skipReasons[skip] = true
							step.Skips = append(step.Skips, skip)
						}
						if step.Repeated >= profile.Policy.TerminalRepeats {
							step.WatchOutcome = "STALLED"
							step.Reason = "progress stalled"
							break actions
						}
						if polls+1 == pollLimit {
							step.WatchOutcome = "OBSERVED"
							verified = true
							break
						}
						time.Sleep(time.Duration(profile.Policy.PollMS) * time.Millisecond)
						continue
					}
					width := values["mode"]
					if effect == "quiescent" {
						wantedWidth := uint64(0x2e0)
						if request.Operation == "cold-load" {
							wantedWidth = 0x1b0
						}
						if width != wantedWidth {
							step.Reason = "warm reset requires the saved-card UI"
							break actions
						}
						if scenarioSaved != nil {
							ui, err := readProbeUI(ProbeUIPlan{Admission: scenarioAdmission, BuildSHA256: profile.Program.SHA256, Glyphmap: scenarioGlyphs, TimeoutMS: 10000, MaxReads: profile.Scenario.MaxUIReads}, scenarioRuntime)
							if err != nil || ui.Headers["mc_dialog"] != 0 || !reflect.DeepEqual(ui.Saved, *scenarioSaved) {
								step.Reason = "source held card-quiescence owner changed"
								break actions
							}
							if request.Operation == "cold-load" {
								if ui.Headers["current"] != uint64(scenarioActor) || *ui.Saved.Players[scenarioActor].Control != 0 {
									step.Reason = "cold quiescence lost human turn"
									break actions
								}
							} else {
								matched := false
								for _, widget := range ui.Widgets {
									if uint64(widget.Index) == ui.Headers["file_widget"] && widget.Selection != nil && *widget.Selection == uint64(checkpointFileIndex) && !widget.Unsupported {
										matched = true
									}
								}
								if ui.Headers["save_kind"] != 1 || !matched {
									step.Reason = "warm quiescence lost File2 owner"
									if profile.Scenario.Recipe != "" {
										step.Reason = "warm quiescence lost declared game-file owner"
									}
									break actions
								}
							}
							step.UI = &ui
						}
						data, err := readInput(cardPath, 64<<20)
						if err != nil {
							step.Reason = err.Error()
							break actions
						}
						digest := fmt.Sprintf("%x", sha256.Sum256(data))
						if digest != lastCard {
							lastCard = digest
							quietSince = time.Now()
						}
						if time.Since(quietSince) >= time.Duration(profile.QuietMS)*time.Millisecond {
							step.CardBefore = digest
							value := width
							step.WidthBefore = &value
							verified = true
							break
						}
					} else if slices.Contains(table.WarmWidths, width) {
						value := width
						step.WidthAfter = &value
						verified = true
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if !verified {
					step.Reason = "owned boot/quiescence observation timed out"
					break actions
				}
			case "reset", "toggle-pause":
				if owned == nil {
					step.Reason = "warm reset has no owned child"
					break actions
				}
				if _, err := observeProbeProcess(ProbeMemoryRuntime{Provenance: "owned_child", Root: profile.Root}, owned.PID, owned, profile.Program.SHA256); err != nil {
					step.Reason = err.Error()
					break actions
				}
				connection, err := net.DialTimeout("unix", filepath.Join(profile.Root, "pad.sock"), time.Second)
				if err != nil {
					step.Reason = "owned pad unavailable"
					break actions
				}
				_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
				command, settle := table.WarmCommand, table.WarmSettleMS
				if effect == "toggle-pause" {
					command, settle = table.PauseCommand, table.PauseSettleMS
				}
				_, sendErr := io.Copy(connection, strings.NewReader(command))
				_ = connection.(*net.UnixConn).CloseWrite()
				ack, ackErr := io.ReadAll(io.LimitReader(connection, 257))
				_ = connection.Close()
				if sendErr != nil || ackErr != nil || strings.TrimSpace(string(ack)) != "ok" {
					step.Reason = "warm reset effect is ambiguous"
					break actions
				}
				time.Sleep(time.Duration(settle) * time.Millisecond)
			case "terminate":
				if owned == nil || child == nil {
					step.Reason = "no current owned child to stop"
					break actions
				}
				observed, err := observeProbeProcess(ProbeMemoryRuntime{Provenance: "owned_child", Root: profile.Root}, owned.PID, owned, profile.Program.SHA256)
				if err != nil {
					// Reaping a known direct child proves disposal without signaling
					// a stale/replaced PID. A live mismatching process is never killed.
					var status syscall.WaitStatus
					pid, waitErr := syscall.Wait4(child.Process.Pid, &status, syscall.WNOHANG, nil)
					if waitErr == nil && pid == owned.PID && child.Process.Pid == owned.PID {
						step.ExitedBeforeStop = true
						_ = child.Process.Release()
						child, owned = nil, nil
						break
					}
					step.Reason = err.Error()
					break actions
				}
				if observed.Profile != "" && observed.Profile != profileDir {
					step.Reason = "owned profile changed"
					break actions
				}
				data, err := readInput(cardPath, 64<<20)
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				step.CardBefore = fmt.Sprintf("%x", sha256.Sum256(data))
				if err := child.Process.Signal(syscall.SIGTERM); err != nil {
					step.Reason = "owned graceful stop failed: " + err.Error()
					break actions
				}
				stopped := false
				deadline := time.Now().Add(time.Duration(profile.StopTimeoutMS) * time.Millisecond)
				for time.Now().Before(deadline) {
					var status syscall.WaitStatus
					pid, err := syscall.Wait4(owned.PID, &status, syscall.WNOHANG, nil)
					if err != nil {
						step.Reason = "owned wait failed: " + err.Error()
						break actions
					}
					if pid == owned.PID {
						stopped = true
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if !stopped {
					step.Reason = "owned graceful stop timed out; no replacement"
					break actions
				}
				_ = child.Process.Release()
				child = nil
				owned = nil
			case "flush":
				if child != nil {
					step.Reason = "card flush requires confirmed process exit"
					break actions
				}
				file, err := os.Open(cardPath)
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				err = file.Sync()
				_ = file.Close()
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				data, err := readInput(cardPath, 64<<20)
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				post := fmt.Sprintf("%x", sha256.Sum256(data))
				time.Sleep(250 * time.Millisecond)
				stable, err := readInput(cardPath, 64<<20)
				if err != nil || fmt.Sprintf("%x", sha256.Sum256(stable)) != post {
					step.Reason = "private card still changing after exit"
					break actions
				}
				step.CardAfter = post
				lastSafeCardSHA = post
			case "backup":
				data, err := readInput(cardPath, 64<<20)
				if err != nil {
					step.Reason = err.Error()
					break actions
				}
				if err := writeNewFile(filepath.Join(receiptDir, request.Nonce+".flushed-card"), bytes.NewReader(data), int64(len(data)), step.CardAfter, 0600); err != nil {
					step.Reason = err.Error()
					break actions
				}
			default:
				step.Reason = "unsupported lifecycle action"
				break actions
			}
			effect = plannedEffect
			if !repeatEffect {
				step.Effects = append(step.Effects, effect)
			}
			pendingRow.Phase = "complete"
			detail, _ := json.Marshal(step)
			pendingRow.Details = detail
			completeData, _ := json.Marshal(pendingRow)
			if err := writeNewFile(filepath.Join(receiptDir, effectBase+".complete.json"), bytes.NewReader(completeData), int64(len(completeData)), fmt.Sprintf("%x", sha256.Sum256(completeData)), 0600); err != nil {
				step.Reason = "effect completion publication failed"
				break
			}
			directory, err = os.Open(receiptDir)
			if err == nil {
				err = directory.Sync()
				_ = directory.Close()
			}
			if err != nil {
				step.Reason = "effect completion durability failed"
				break
			}
			if repeatEffect {
				repeats++
			} else {
				index++
				repeats = 0
			}
		}
		if step.Reason == "" && len(step.Effects) == len(action.Effects) {
			step.Status = "COMPLETED"
			if request.Operation == "recover" {
				readFailure = false
			}
			phase = action.To
			step.Epoch = epoch
			completeData, _ := json.Marshal(step)
			if err := writeNewFile(completePath, bytes.NewReader(completeData), int64(len(completeData)), fmt.Sprintf("%x", sha256.Sum256(completeData)), 0600); err != nil {
				step.Status, step.Reason = "UNKNOWN", "operation completion publication failed"
			} else {
				directory, err := os.Open(receiptDir)
				if err == nil {
					err = directory.Sync()
					_ = directory.Close()
				}
				if err != nil {
					step.Status, step.Reason = "UNKNOWN", "operation completion durability failed"
				}
			}
		} else {
			phase = "unknown"
			if request.Operation == "watch" {
				readFailure = true
			} else if request.Operation != "stop" {
				ambiguousFailure = true
			}
		}
		if step.Status != "COMPLETED" {
			report.Status = "INCOMPLETE"
		}
		if step.Status == "COMPLETED" && step.Owned != nil {
			lastOwnedStep = step
		}
		report.Steps = append(report.Steps, step)
	}
	cancel()
	if padStarted {
		if err := <-padDone; err != nil {
			report.Status = "INCOMPLETE"
		}
	}
	if child != nil {
		report.Status = "INCOMPLETE"
	}
	return report, nil
}
