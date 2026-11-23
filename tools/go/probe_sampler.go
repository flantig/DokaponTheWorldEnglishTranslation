package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// waitProbeFrame preserves the caller's original monotonic wait barrier while
// servicing the same cooperative tick. Acquisition work can extend a wait, never
// shorten it; absent/unadmitted sampling retains the historical sleep behavior.
func waitProbeFrame(profile ProbeLifecycleProfile, journal *ProbeEventJournal, state *ProbeFrameRun, duration time.Duration) error {
	if state == nil || !state.Ready || state.Finalizing {
		time.Sleep(duration)
		return nil
	}
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		if err := sampleProbeFrame(profile, journal, state, time.Now()); err != nil {
			return err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		wait := remaining
		due := time.Until(state.NextWake)
		if due <= 0 {
			continue
		}
		wait = min(wait, due)
		time.Sleep(wait)
	}
	return sampleProbeFrame(profile, journal, state, time.Now())
}

// sampleProbeFrame is one cooperative tick, shared by lifecycle wait sites.
// It never waits for a schedule or restarts a process. Successful acquisition is
// health even when filtered; retained state advances only in publishProbeFrame.
// Finalization reuses the same capture-gap policy without acquiring or publishing.
func sampleProbeFrame(profile ProbeLifecycleProfile, journal *ProbeEventJournal, state *ProbeFrameRun, now time.Time) error {
	if profile.Frames == nil || state == nil || state.Started.IsZero() && !state.Finalizing {
		return nil
	}
	var failure error
	attempted := false
	for {
		if state.Summary.Failure != "" {
			failure = fmt.Errorf("frame sampler already failed: %s", state.Summary.Failure)
			break
		}
		if !state.Finalizing && now.Sub(state.Started) >= time.Duration(state.Policy.MaxRunSeconds)*time.Second {
			failure = fmt.Errorf("frame sampler run-time budget exhausted")
			break
		}
		if state.Finalizing && state.Summary.EpochCaptures == 0 {
			failure = fmt.Errorf("frame sampler lacks a successful capture in the final epoch")
			break
		}
		if state.Ready || state.Finalizing {
			anchor := state.EpochStarted
			if state.LastSample.After(anchor) {
				anchor = state.LastSample
			}
			gap := now.Sub(anchor).Seconds()
			if state.Finalizing {
				// The stopped-epoch observation is saved with its completed stop.
				// Replay must check that fact, not the wall clock of a later run.
				if state.Summary.FinalCaptureGapSeconds == nil && !state.Started.IsZero() {
					state.Summary.FinalCaptureGapSeconds = &gap
				}
				if state.Summary.FinalCaptureGapSeconds == nil || *state.Summary.FinalCaptureGapSeconds < 0 {
					failure = fmt.Errorf("frame sampler final capture gap is unavailable")
					break
				}
				gap = *state.Summary.FinalCaptureGapSeconds
			}
			if gap > 120 {
				failure = fmt.Errorf("frame sampler successful capture gap exceeded120s")
				break
			}
		}
		if state.Finalizing {
			break
		}
		storageDue := !now.Before(state.NextStorage)
		healthDue := !now.Before(state.NextHealth)
		captureDue := state.Ready && !state.OrdinaryCaptureInhibited && !now.Before(state.NextAttempt)
		if !storageDue && !healthDue && !captureDue {
			break
		}
		if state.Budget == nil || journal == nil || journal.Budget != state.Budget {
			failure = fmt.Errorf("frame sampler lacks its admitted accounting/journal owner")
			break
		}
		if err := accountProbeArtifacts(state.Budget, probeArtifactReserve, nil); err != nil {
			failure = err
			break
		}
		if storageDue {
			paths := []string{profile.Root, state.Runtime.Snapshots, filepath.Dir(state.CardPath)}
			minimum, err := observeProbeStorage(state.Budget, paths)
			if err != nil || minimum < 2<<30 {
				failure = fmt.Errorf("frame sampler storage unavailable or below2GiB reserve: %v", err)
				break
			}
			state.NextStorage = time.Now().Add(10 * time.Second)
		}
		if healthDue {
			event, _ := json.Marshal(map[string]any{"event": "go-frame-health", "event_id": len(journal.Events) + 1, "time": time.Now().UTC().Format("2006-01-02T15:04:05-0700"), "elapsed_s": now.Sub(state.Started).Seconds(), "frames": state.Summary})
			if _, err := publishProbeEvent(profile.Root, journal, event); err != nil {
				failure = err
				break
			}
			state.Summary.HealthEvents++
			state.NextHealth = time.Now().Add(10 * time.Second)
		}
		if !captureDue {
			break
		}
		if state.Summary.SelectedCommits+state.Summary.CheckpointCommits >= state.Policy.MaxRetainedFrames {
			failure = fmt.Errorf("frame sampler retained-frame budget exhausted")
			break
		}
		captureID := fmt.Sprintf("frame-e%d-a%d", state.Summary.Epoch, state.Summary.Attempts+1)
		claim := ProbeArtifactClaim{ID: "native:" + captureID, Path: state.Runtime.Snapshots, Class: probeArtifactNative, MaxFinalBytes: 16 << 20}
		if err := accountProbeArtifacts(state.Budget, probeArtifactReserve, []ProbeArtifactClaim{claim}); err != nil {
			failure = err
			break
		}
		state.NativeSlot = &claim
		event, _ := json.Marshal(map[string]any{"event": probeOrdinaryFrameEventKind, "event_id": len(journal.Events) + 1, "checkpoint": 0, "capture_id": captureID, "time": time.Now().UTC().Format("2006-01-02T15:04:05-0700")})
		published, err := publishProbeEvent(profile.Root, journal, event)
		if err != nil {
			failure = err
			break
		}
		memory := ProbeMemoryBundle{Version: 1, SourceSHA256: "5439db31097c19d3b92969d5403c2c19dc3518cea4ed4c075df1a3830b8ef56f", Admission: state.Admission, BuildSHA256: profile.Program.SHA256}
		for index, field := range []struct {
			Opcode  uint8
			Address uint32
		}{{1, 0x56581c}, {1, 0x56b598}, {0, 0x56b18c}} {
			opcode, address := field.Opcode, field.Address
			memory.Requests = append(memory.Requests, ProbeMemoryRequest{ID: fmt.Sprintf("tag%d", index), Opcode: &opcode, Address: &address})
		}
		memory.Decoders = []ProbeMemoryDecoder{{ID: "source-tags", Kind: "frame_tags", Requests: []string{"tag0", "tag1", "tag2"}}}
		memoryRaw, _ := json.Marshal(memory)
		plan := ProbeCaptureProfile{Version: 1, SourceSHA256: memory.SourceSHA256, PadSourceSHA256: "1c1dab832d28026ad960eeb9d08e19c5ab40e00f9c30517aadc906921c555a36", Memory: memoryRaw, CaptureID: captureID, EventID: len(journal.Events), Checkpoint: 0, LogOffset: published.Offset, LogBytes: len(published.Data), LogSHA256: fmt.Sprintf("%x", sha256.Sum256(published.Data)), MaxSnapshotFiles: 256, MaxImageBytes: 16 << 20, MaxPixels: 1 << 20, MaxRetainedFiles: 2, MaxRetainedBytes: 20 << 20, LockTimeoutMS: 10000, CaptureTimeoutMS: 10000}
		if profile.PadBackend == "private-x11" {
			plan.TriggerBackend = "private-x11"
			plan.PadSourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(probePadLayout))
		}
		planRaw, _ := json.Marshal(plan)
		runtimeRaw, _ := json.Marshal(state.Runtime)
		state.Summary.Attempts++
		attempted = true
		var sample ProbeFrameSample
		receipt, captureErr := captureProbeEvidence(planRaw, runtimeRaw, &sample, state.Budget)
		completed := time.Now()
		if !receipt.ManagedPineAt.IsZero() {
			state.LastPine = receipt.ManagedPineAt
			elapsed := state.LastPine.Sub(state.Started).Seconds()
			state.Summary.LastPineSeconds = &elapsed
		} else if receipt.ManagedPineAttempted {
			state.Summary.PineErrors++
		}
		if captureErr != nil || receipt.Status != "SAMPLED" {
			state.Summary.CaptureErrors++
			if receipt.ManagedFailure != probeCaptureObservation {
				failure = fmt.Errorf("frame sampler capture %s: %s: %v", receipt.ManagedFailure, receipt.Reason, captureErr)
				break
			}
			// Only a fully verified observation may adopt its preserved native PNG.
			if receipt.Snapshot == "" || receipt.ImageSHA256 == "" {
				failure = fmt.Errorf("frame sampler observation has no verified native input")
				break
			}
			path := filepath.Join(state.Runtime.Snapshots, receipt.Snapshot)
			info, statErr := os.Lstat(path)
			if statErr != nil {
				failure = statErr
				break
			}
			claim.Path, claim.ExpectedInfo, claim.ExpectedSHA256 = path, info, receipt.ImageSHA256
			if err := accountProbeArtifacts(state.Budget, probeArtifactCommit, []ProbeArtifactClaim{claim}); err != nil {
				failure = err
				break
			}
			state.NativeSlot = nil
			break
		}
		state.LastSample = completed
		state.Summary.SampleSuccesses++
		state.Summary.EpochCaptures++
		elapsed := completed.Sub(state.Started).Seconds()
		state.Summary.LastSampleSeconds = &elapsed
		claim.ExpectedInfo = state.Budget.SnapshotRoots[state.Runtime.Snapshots]
		if err := accountProbeArtifacts(state.Budget, probeArtifactRelease, []ProbeArtifactClaim{claim}); err != nil {
			failure = err
			break
		}
		state.NativeSlot = nil
		mean := float64(999)
		if len(state.Previous) != 0 {
			_, mean, err = compareProbeFrames(sample.Sample, state.Previous)
			if err != nil {
				failure = err
				break
			}
		}
		state.Summary.LastMean = &mean
		if mean >= 1 {
			state.LastVisual = completed
			visual := completed.Sub(state.Started).Seconds()
			state.Summary.LastVisualSeconds = &visual
		}
		if mean < 2 {
			break
		}
		if err := publishProbeFrame(profile, journal, state, sample, receipt, completed); err != nil {
			failure = err
		}
		break
	}
	if attempted {
		state.NextAttempt = time.Now().Add(4 * time.Second)
	}
	state.NextWake = state.Started.Add(time.Duration(state.Policy.MaxRunSeconds) * time.Second)
	wakes := []time.Time{state.NextHealth, state.NextStorage}
	if !state.OrdinaryCaptureInhibited {
		wakes = append(wakes, state.NextAttempt)
	}
	for _, due := range wakes {
		if !due.IsZero() && due.Before(state.NextWake) {
			state.NextWake = due
		}
	}
	if failure != nil {
		state.Summary.Status = "UNKNOWN"
		if state.Summary.Failure == "" {
			state.Summary.Failure = failure.Error()
		}
	}
	return failure
}
