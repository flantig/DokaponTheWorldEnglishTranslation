package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"
)

// publishProbeFrame owns JPEG/CSV/journal commit ordering. Its sample is already
// normalized by the capture owner; this transaction never selects or reacquires.
// Before JPEG acknowledgment, the shared writer may clean only its own failed
// inode. Durable partial JPEG/CSV facts survive later failures. Selection state advances
// only after the journal acknowledgment, and a partial transaction cannot retry.
// Go JPEG output is explicitly unqualified against the historical Pillow codec.
func publishProbeFrame(profile ProbeLifecycleProfile, journal *ProbeEventJournal, state *ProbeFrameRun, sample ProbeFrameSample, receipt ProbeCaptureReceipt, completed time.Time) error {
	if state == nil || state.Budget == nil || journal == nil || journal.Budget != state.Budget || state.Finalizing || journal.Finalizing || state.Summary.PendingJPEG != "" || state.Summary.PendingCSV {
		return fmt.Errorf("frame publication requires its active serialized budget/journal and no partial transaction")
	}
	if state.Started.IsZero() || completed.Before(state.Started) || state.Policy.MaxRunSeconds == 0 || completed.Sub(state.Started).Seconds() > float64(state.Policy.MaxRunSeconds) || state.Policy.MaxRetainedFrames == 0 || state.Summary.SelectedCommits >= state.Policy.MaxRetainedFrames || state.Summary.CheckpointCommits >= state.Policy.MaxRetainedFrames-state.Summary.SelectedCommits {
		return fmt.Errorf("frame publication exceeds its run/retained-frame resource bound")
	}
	if receipt.Checkpoint < 0 || receipt.EventID < 1 || receipt.Session != profile.Session || receipt.Epoch != state.Summary.Epoch || !regexp.MustCompile(probeCaptureIDPattern).MatchString(receipt.CaptureID) || receipt.Checkpoint == 0 && receipt.Status != "SAMPLED" || receipt.Checkpoint > 0 && receipt.Status != "CAPTURED" {
		return fmt.Errorf("frame publication capture identity/status differs")
	}
	if receipt.EventID > len(journal.Events) {
		return fmt.Errorf("frame publication source parent is not in the acknowledged journal")
	}
	parent := journal.Events[receipt.EventID-1]
	logBytes, logErr := hex.DecodeString(receipt.LogHex)
	if parent.Offset < 0 || len(parent.Data) > len(journal.Bytes) || parent.Offset > int64(len(journal.Bytes)-len(parent.Data)) || receipt.LogOffset != parent.Offset || logErr != nil || hex.EncodeToString(logBytes) != receipt.LogHex || !bytes.Equal(logBytes, parent.Data) || fmt.Sprintf("%x", sha256.Sum256(parent.Data)) != receipt.LogSHA256 || !bytes.Equal(journal.Bytes[parent.Offset:parent.Offset+int64(len(parent.Data))], parent.Data) {
		return fmt.Errorf("frame publication source parent slice/hash differs")
	}
	var source struct {
		Event      string `json:"event"`
		EventID    int    `json:"event_id"`
		Checkpoint *int   `json:"checkpoint"`
	}
	if err := checkJSON(checkedJSON{raw: parent.Data, allObjects: true, text: true}); err != nil {
		return err
	}
	if err := json.Unmarshal(parent.Data, &source); err != nil || source.EventID != receipt.EventID || source.Checkpoint == nil || *source.Checkpoint != receipt.Checkpoint || source.Event == "" {
		return fmt.Errorf("frame publication source parent identity differs")
	}
	if receipt.Checkpoint == 0 {
		var ordinary struct {
			ProbeCaptureEvent
			Session string `json:"session"`
			Epoch   *int   `json:"epoch"`
		}
		if err := json.Unmarshal(parent.Data, &ordinary); err != nil || source.Event != probeOrdinaryFrameEventKind || ordinary.CaptureID != receipt.CaptureID || ordinary.Session != "" && ordinary.Session != receipt.Session || ordinary.Epoch != nil && *ordinary.Epoch != receipt.Epoch {
			return fmt.Errorf("frame publication ordinary source kind/capture ID differs")
		}
		if _, err := time.Parse("2006-01-02T15:04:05-0700", ordinary.Time); err != nil {
			return fmt.Errorf("frame publication ordinary source time differs")
		}
	} else if source.Event == probeOrdinaryFrameEventKind {
		return fmt.Errorf("frame publication checkpoint source kind/capture ID differs")
	}
	if sample.Normalized == nil || sample.Normalized.Rect != image.Rect(0, 0, 640, 480) || sample.Normalized.Stride < 640*4 || len(sample.Normalized.Pix) < 640*4 || sample.Normalized.Stride > (len(sample.Normalized.Pix)-640*4)/479 || len(sample.Sample) != 64*48*3 || sample.Facts.Status != "AVAILABLE" || sample.Facts.ComparisonRGBSHA256 != fmt.Sprintf("%x", sha256.Sum256(sample.Sample)) {
		return fmt.Errorf("frame publication requires its normalized640x480 image and64x48 comparison facts")
	}
	for y := 0; y < 480; y++ {
		for x := 0; x < 640; x++ {
			if sample.Normalized.Pix[y*sample.Normalized.Stride+x*4+3] != 255 {
				return fmt.Errorf("frame publication requires opaque normalized pixels")
			}
		}
	}
	rootInfo, err := os.Lstat(profile.Root)
	resolved, resolveErr := filepath.EvalSymlinks(profile.Root)
	rootPin := state.Budget.Roots[profile.Root]
	if err != nil || resolveErr != nil || !filepath.IsAbs(profile.Root) || resolved != profile.Root || rootPin == nil || !os.SameFile(rootPin, rootInfo) || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0700 {
		return fmt.Errorf("frame publication root authority differs")
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || rootStat.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("frame publication root owner differs")
	}
	rootDirectory, err := os.Open(profile.Root)
	if err != nil {
		return err
	}
	defer rootDirectory.Close()
	openedRoot, statErr := rootDirectory.Stat()
	if statErr != nil || !os.SameFile(rootPin, openedRoot) {
		return fmt.Errorf("frame publication opened root identity differs")
	}
	cardRelative, cardPathErr := filepath.Rel(profile.Root, state.CardPath)
	if cardPathErr != nil || !filepath.IsLocal(cardRelative) || cardRelative == "." || !filepath.IsAbs(state.CardPath) || filepath.Clean(state.CardPath) != state.CardPath {
		return fmt.Errorf("frame publication requires its exact owned card path")
	}
	// The source checks free storage before every retained JPEG, including checkpoints.
	minimumFree, err := observeProbeStorage(state.Budget, []string{profile.Root, state.Runtime.Snapshots, filepath.Dir(state.CardPath)})
	if err != nil {
		return err
	}
	if minimumFree < 2<<30 {
		return fmt.Errorf("frame publication storage below2GiB reserve")
	}
	checkpoint := receipt.Checkpoint > 0
	quality, kind := 82, "go-frame-retained"
	relative := fmt.Sprintf("f%04d.jpg", state.Summary.SelectedCommits+1)
	if checkpoint {
		quality, kind = 75, "go-checkpoint-jpeg"
		relative = filepath.Join("checkpoint-frames", receipt.CaptureID+".jpg")
		directory := filepath.Join(profile.Root, "checkpoint-frames")
		createErr := syscall.Mkdirat(int(rootDirectory.Fd()), "checkpoint-frames", 0700)
		info, statErr := os.Lstat(directory)
		canonical, canonicalErr := filepath.EvalSymlinks(directory)
		if createErr != nil && !os.IsExist(createErr) || statErr != nil || canonicalErr != nil || canonical != directory || !info.IsDir() || info.Mode().Perm() != 0700 {
			return fmt.Errorf("checkpoint JPEG directory is not private and canonical")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		pin := state.Budget.Roots[directory]
		if !ok || stat.Uid != uint32(os.Getuid()) || pin != nil && !os.SameFile(pin, info) {
			return fmt.Errorf("checkpoint JPEG directory authority differs")
		}
		state.Budget.Roots[directory] = info
		if createErr == nil {
			if err := rootDirectory.Sync(); err != nil {
				return fmt.Errorf("checkpoint JPEG directory durability unknown")
			}
		}
	}
	var encoded bytes.Buffer
	if err := jpeg.Encode(&encoded, sample.Normalized, &jpeg.Options{Quality: quality}); err != nil {
		return err
	}
	jpegBytes := encoded.Bytes()
	jpegSHA := fmt.Sprintf("%x", sha256.Sum256(jpegBytes))
	jpegPath := filepath.Join(profile.Root, relative)
	jpegClaim := ProbeArtifactClaim{ID: "frame-jpeg:" + relative, Path: jpegPath, MaxFinalBytes: uint64(len(jpegBytes)), Class: probeArtifactNormal}
	if err := accountProbeArtifacts(state.Budget, probeArtifactReserve, []ProbeArtifactClaim{jpegClaim}); err != nil {
		return fmt.Errorf("frame JPEG reservation: %w", err)
	}
	directory, err := os.Open(filepath.Dir(jpegPath))
	if err != nil {
		return err
	}
	defer directory.Close()
	openedParent, statErr := directory.Stat()
	parentPin := state.Budget.Roots[filepath.Dir(jpegPath)]
	if statErr != nil || parentPin == nil || !os.SameFile(parentPin, openedParent) {
		return fmt.Errorf("frame JPEG opened parent identity differs")
	}
	jpegInfo, err := writeNewFile(jpegPath, directory, bytes.NewReader(jpegBytes), int64(len(jpegBytes)), jpegSHA, 0600)
	if err != nil {
		return fmt.Errorf("frame JPEG %s write failed; reservation retained: %w", relative, err)
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil || closeErr != nil {
		return fmt.Errorf("frame JPEG directory durability unknown")
	}
	state.Summary.PendingJPEG, state.Summary.PendingJPEGSHA256 = relative, jpegSHA
	jpegClaim.ExpectedInfo, jpegClaim.ExpectedSHA256 = jpegInfo, jpegSHA
	if err := accountProbeArtifacts(state.Budget, probeArtifactCommit, []ProbeArtifactClaim{jpegClaim}); err != nil {
		return fmt.Errorf("frame JPEG commit: %w", err)
	}
	elapsed := completed.Sub(state.Started).Seconds()
	var mode, story, week uint64
	if !checkpoint {
		if receipt.MemoryBefore == nil {
			return fmt.Errorf("frame CSV requires source tag observations")
		}
		seen := map[string]bool{}
		for _, observation := range receipt.MemoryBefore.Observations {
			switch observation.ID {
			case "tag0", "tag1", "tag2":
				if seen[observation.ID] || observation.Value > 0xffffffff {
					return fmt.Errorf("frame CSV source tags are duplicated or outside32bits")
				}
				seen[observation.ID] = true
				switch observation.ID {
				case "tag0":
					mode = observation.Value
				case "tag1":
					story = observation.Value
				case "tag2":
					week = observation.Value + 1
				}
			}
		}
		if len(seen) != 3 {
			return fmt.Errorf("frame CSV requires all three source tag observations")
		}
		csvPath := filepath.Join(profile.Root, "frames.csv")
		row := []byte(relative + "," + strconv.FormatFloat(elapsed, 'f', 2, 64) + fmt.Sprintf(",0x%x,%d,%d\n", mode, story, week))
		if state.Policy.MaxJournalBytes == 0 || state.Policy.MaxJournalBytes >= 1<<63 || !bytes.HasPrefix(state.CSV, []byte("frame,t,mode,story,week\n")) || uint64(len(state.CSV)) > state.Policy.MaxJournalBytes || uint64(len(row)) > state.Policy.MaxJournalBytes-uint64(len(state.CSV)) {
			return fmt.Errorf("frame CSV prefix or byte bound differs")
		}
		next := append(bytes.Clone(state.CSV), row...)
		csvClaim := ProbeArtifactClaim{ID: "frames-csv", Path: csvPath, MaxFinalBytes: uint64(len(next)), Class: probeArtifactNormal, ExpectedInfo: state.CSVInfo}
		if err := accountProbeArtifacts(state.Budget, probeArtifactReserve, []ProbeArtifactClaim{csvClaim}); err != nil {
			return fmt.Errorf("frame CSV reservation: %w", err)
		}
		prior, readErr := readInput(csvPath, int64(state.Policy.MaxJournalBytes))
		info, statErr := os.Lstat(csvPath)
		if readErr != nil || statErr != nil || state.CSVInfo == nil || !os.SameFile(state.CSVInfo, info) || !bytes.Equal(prior, state.CSV) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return fmt.Errorf("frame CSV owned prefix or identity changed")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
			return fmt.Errorf("frame CSV is not its exclusive owned file")
		}
		file, err := os.OpenFile(csvPath, os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		opened, statErr := file.Stat()
		if statErr != nil || !os.SameFile(info, opened) || opened.Size() != int64(len(prior)) {
			file.Close()
			return fmt.Errorf("frame CSV changed before append")
		}
		_, err = io.Copy(file, bytes.NewReader(row))
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			return fmt.Errorf("frame CSV append is partial or durability unknown")
		}
		readback, readErr := readInput(csvPath, int64(state.Policy.MaxJournalBytes))
		current, statErr := os.Lstat(csvPath)
		if readErr != nil || statErr != nil || !os.SameFile(info, current) || !bytes.Equal(readback, next) {
			return fmt.Errorf("frame CSV append readback differs")
		}
		state.CSV, state.CSVInfo = next, current
		state.Summary.PendingCSV = true
		csvClaim.ExpectedInfo = current
		csvClaim.ExpectedSHA256 = fmt.Sprintf("%x", sha256.Sum256(next))
		if err := accountProbeArtifacts(state.Budget, probeArtifactCommit, []ProbeArtifactClaim{csvClaim}); err != nil {
			return fmt.Errorf("frame CSV commit: %w", err)
		}
	}
	event := map[string]any{"event": kind, "event_id": len(journal.Events) + 1, "parent_event_id": receipt.EventID, "capture_id": receipt.CaptureID, "checkpoint": receipt.Checkpoint, "epoch": receipt.Epoch, "session": receipt.Session, "time": completed.UTC().Format(time.RFC3339Nano), "t": elapsed, "jpeg": relative, "jpeg_sha256": jpegSHA, "jpeg_quality": quality, "codec_qualification": "go-image-jpeg-unqualified", "comparison": sample.Facts}
	if !checkpoint {
		event["mode"], event["story"], event["week"] = mode, story, week
	}
	eventBytes, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := publishProbeEvent(profile.Root, journal, eventBytes); err != nil {
		return fmt.Errorf("frame journal acknowledgment: %w", err)
	}
	state.Summary.CodecQualification = "go-image-jpeg-unqualified"
	state.Summary.PendingJPEG, state.Summary.PendingJPEGSHA256, state.Summary.PendingCSV = "", "", false
	if checkpoint {
		state.Summary.CheckpointCommits++
		return nil
	}
	state.Previous = bytes.Clone(sample.Sample)
	state.LastSelected = time.Now()
	state.Summary.SelectedCommits++
	state.Summary.PreviousComparisonHash = sample.Facts.ComparisonRGBSHA256
	committedElapsed := state.LastSelected.Sub(state.Started).Seconds()
	state.Summary.LastSelectedSeconds = &committedElapsed
	state.Summary.LastJPEG, state.Summary.LastJPEGSHA256 = relative, jpegSHA
	return nil
}
