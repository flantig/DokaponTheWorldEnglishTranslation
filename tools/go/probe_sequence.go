package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
)

// runProbeSequence only succeeds across three fresh immutable lifecycle profiles.
// Pending sequence roots never replay. Carry is copied only after actual source
// completion, stopped ownership and the controller's stable postflush hash.
func runProbeSequence(raw []byte) (ProbeSequenceReport, error) {
	report := ProbeSequenceReport{Version: 1, SourceFormat: "go-probe-sequence-v1", Status: "INCOMPLETE", Runs: []ProbeSequenceRun{}, Limits: "Controlled/offline sequence evidence only. No native stories, device parity, comparison-family coverage, resource/soak agreement or handover acceptance."}
	if len(raw) == 0 || len(raw) > 4<<20 {
		return report, fmt.Errorf("sequence input exceeds4MiB")
	}
	if err := checkJSON(checkedJSON{raw: raw, allObjects: true, text: true, nonNull: true}); err != nil {
		return report, err
	}
	var spec ProbeSequenceSpec
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&spec); err != nil {
		return report, err
	}
	if spec.Version != 1 || spec.SourceFormat != report.SourceFormat || len(spec.Profiles) != 3 || spec.Seed > ^uint64(0)-2 {
		return report, fmt.Errorf("sequence requires exactly three bounded source recipes")
	}
	root, err := os.Lstat(spec.Root)
	resolved, resolveErr := filepath.EvalSymlinks(spec.Root)
	if err != nil || resolveErr != nil || resolved != spec.Root || !filepath.IsAbs(spec.Root) || !root.IsDir() || root.Mode().Perm() != 0700 {
		return report, fmt.Errorf("sequence requires canonical private0700 root")
	}
	stat, ok := root.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return report, fmt.Errorf("sequence root is not owned")
	}
	var recipeData struct {
		SequenceOrder []string `json:"sequence_order"`
	}
	if json.Unmarshal(probeScenarioData, &recipeData) != nil || len(recipeData.SequenceOrder) != 3 {
		return report, fmt.Errorf("invalid built-in sequence order")
	}
	recipes := recipeData.SequenceOrder
	sessions := map[string]bool{}
	roots := map[string]bool{}
	for index, profile := range spec.Profiles {
		if profile.Scenario == nil || profile.Scenario.Recipe != recipes[index] || profile.SourceFormat != "go-owned-lifecycle-v1" || profile.Version != 1 || profile.Resume != nil || profile.Seed == nil || *profile.Seed != spec.Seed+uint64(index) || profile.Session == "" || sessions[profile.Session] || roots[profile.Root] || len(profile.Inputs) != 4 || len(profile.Requests) < 1 || len(profile.Requests) > 32 || profile.Requests[0].Operation != "initial" || profile.Requests[len(profile.Requests)-1].Operation != "stop" {
			return report, fmt.Errorf("sequence recipe/profile/session/request boundary differs")
		}
		if profile.Program != spec.Profiles[0].Program || profile.Inputs["iso"] != spec.Profiles[0].Inputs["iso"] || profile.Inputs["settings"] != spec.Profiles[0].Inputs["settings"] || profile.Inputs["bios"] != spec.Profiles[0].Inputs["bios"] {
			return report, fmt.Errorf("sequence source/build/input lineage differs")
		}
		if index > 0 && profile.Inputs["card"] != (RegistryInput{}) {
			return report, fmt.Errorf("later sequence card must be an unclaimed carry placeholder")
		}
		info, err := os.Lstat(profile.Root)
		canonical, canonicalErr := filepath.EvalSymlinks(profile.Root)
		if err != nil || canonicalErr != nil || canonical != profile.Root || !strings.HasPrefix(profile.Root, spec.Root+string(os.PathSeparator)) || !info.IsDir() || info.Mode().Perm() != 0700 {
			return report, fmt.Errorf("sequence run root is not a fresh private descendant")
		}
		files, err := os.ReadDir(profile.Root)
		if err != nil || len(files) != 0 {
			return report, fmt.Errorf("sequence run root already has evidence or pending effects")
		}
		sessions[profile.Session], roots[profile.Root] = true, true
	}
	lock, err := os.OpenFile(filepath.Join(spec.Root, "sequence.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return report, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return report, fmt.Errorf("sequence already has an owner")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if err := writeNewFile(filepath.Join(spec.Root, "sequence.pending.json"), bytes.NewReader(raw), int64(len(raw)), fmt.Sprintf("%x", sha256.Sum256(raw)), 0400); err != nil {
		return report, fmt.Errorf("pending sequence prevents replay: %w", err)
	}
	directory, err := os.Open(spec.Root)
	if err != nil {
		return report, err
	}
	err = directory.Sync()
	_ = directory.Close()
	if err != nil {
		return report, err
	}
	carry := spec.Profiles[0].Inputs["card"]
	for index, declared := range spec.Profiles {
		profile := declared
		profile.Inputs = map[string]RegistryInput{}
		for role, input := range declared.Inputs {
			profile.Inputs[role] = input
		}
		profile.Inputs["card"] = carry
		profileRaw, _ := json.Marshal(profile)
		profilePath := filepath.Join(spec.Root, fmt.Sprintf("run-%d-profile.json", index+1))
		profileSHA := fmt.Sprintf("%x", sha256.Sum256(profileRaw))
		if err := writeNewFile(profilePath, bytes.NewReader(profileRaw), int64(len(profileRaw)), profileSHA, 0400); err != nil {
			return report, err
		}
		directory, err := os.Open(spec.Root)
		if err != nil {
			return report, err
		}
		err = directory.Sync()
		_ = directory.Close()
		if err != nil {
			return report, err
		}
		result, runErr := runProbeLifecycle(profileRaw)
		row := ProbeSequenceRun{Recipe: recipes[index], Profile: RegistryInput{Path: profilePath, Size: int64(len(profileRaw)), SHA256: profileSHA}, InitialCardSHA256: carry.SHA256, Lifecycle: result}
		report.Runs = append(report.Runs, row)
		if runErr != nil || result.Status != "COMPLETED" || len(result.Steps) != len(profile.Requests) {
			report.Reason = "source lifecycle failed or incomplete"
			return report, nil
		}
		var story *ProbeLifecycleStep
		for position := range result.Steps {
			step := &result.Steps[position]
			if step.Status != "COMPLETED" {
				report.Reason = "sequence has a refused/unknown effect"
				return report, nil
			}
			if step.Request.Operation == "finish" {
				story = step
			}
		}
		stop := result.Steps[len(result.Steps)-1]
		if story == nil || story.Evidence == nil || story.Checkpoint == nil || story.Checkpoint.Status != "PASS" || stop.Request.Operation != "stop" || stop.CardAfter == "" || stop.Owned == nil {
			report.Reason = "sequence lacks actual terminal/checkpoint/stopped-card evidence"
			return report, nil
		}
		if _, err := observeProbeProcess(ProbeMemoryRuntime{}, stop.Owned.PID, stop.Owned, profile.Program.SHA256); err == nil {
			report.Reason = "owned process remains after stop"
			return report, nil
		}
		evidenceRaw, err := readInput(story.Evidence.Path, 4<<20)
		if err != nil || int64(len(evidenceRaw)) != story.Evidence.Size || fmt.Sprintf("%x", sha256.Sum256(evidenceRaw)) != story.Evidence.SHA256 {
			report.Reason = "final story evidence hash differs"
			return report, nil
		}
		var storyBundle ProbeEvidenceBundle
		if json.Unmarshal(evidenceRaw, &storyBundle) != nil || storyBundle.Story == nil || storyBundle.Story.Phase != "complete" || storyBundle.Story.TerminalEventID < 1 || storyBundle.Story.Recipe != recipes[index] {
			report.Reason = "sequence lacks final source story scope"
			return report, nil
		}
		qualified, err := reportProbeEvidence(evidenceRaw)
		if err != nil || qualified.Status != "PASS" || !reflect.DeepEqual(qualified, *story.Checkpoint) {
			report.Reason = "final source report does not independently qualify"
			return report, nil
		}
		cardPath := filepath.Join(profile.Root, "profile", "PCSX2", "memcards", "probe-slot1.ps2")
		info, err := os.Lstat(cardPath)
		if err != nil || !info.Mode().IsRegular() {
			report.Reason = "postflush card unavailable"
			return report, nil
		}
		cardStat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || cardStat.Nlink != 1 {
			report.Reason = "postflush card is aliased"
			return report, nil
		}
		card, err := readInput(cardPath, 64<<20)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(card)) != stop.CardAfter {
			report.Reason = "actual postflush card hash differs"
			return report, nil
		}
		carryPath := filepath.Join(spec.Root, fmt.Sprintf("carry-%d.ps2", index+1))
		if err := writeNewFile(carryPath, bytes.NewReader(card), int64(len(card)), stop.CardAfter, 0400); err != nil {
			return report, err
		}
		directory, err = os.Open(spec.Root)
		if err != nil {
			return report, err
		}
		err = directory.Sync()
		_ = directory.Close()
		if err != nil {
			return report, err
		}
		carry = RegistryInput{Path: carryPath, Size: int64(len(card)), SHA256: stop.CardAfter}
		promoted := carry
		report.Runs[index].Carry = &promoted
		evidence := *story.Evidence
		report.Runs[index].Evidence = &evidence
	}
	report.Status = "PASS"
	return report, nil
}
