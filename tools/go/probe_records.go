package main

import (
	"bytes"
	"crypto/sha256"
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

// admitProbeRecords checks an immutable, source-versioned legacy record bundle.
// Syntax/membership checks precede source-ordered boot checks. The outer caller's
// acknowledged request is idempotent; the same nonce reaching boot is a replay.
// Observations are saved evidence, never permission to open paths or control a VM.
func admitProbeRecords(raw []byte) (ProbeRecordReport, error) {
	var report ProbeRecordReport
	if len(raw) == 0 || len(raw) > 1<<20 {
		return report, fmt.Errorf("probe record bundle exceeds its 1MiB input bound")
	}
	if err := checkJSON(checkedJSON{raw: raw, allObjects: true, text: true}); err != nil {
		return report, err
	}
	var bundle ProbeRecordBundle
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return report, err
	}
	if bundle.Version == 1 && bundle.SourceSchema == "go-probe-records-v1" && bundle.SourceSHA256 == "5439db31097c19d3b92969d5403c2c19dc3518cea4ed4c075df1a3830b8ef56f" {
		if bundle.GoOwner == nil || bundle.Context != "owned_go" || bundle.AfterProcess == nil || len(bundle.Records) != 2 || len(bundle.Files) != 0 {
			return report, fmt.Errorf("Go probe records require their lifecycle owner and two identity records")
		}
		owner := bundle.GoOwner
		profile := owner.Profile
		step := owner.Step
		parts := regexp.MustCompile(`^([1-9][0-9]*)-([a-z-]+)$`).FindStringSubmatch(step.Request.Nonce)
		linked := false
		for _, request := range profile.Requests {
			if reflect.DeepEqual(request, step.Request) {
				linked = true
				break
			}
		}
		var contract struct {
			Actions map[string]struct{ Effects []string }
		}
		_ = json.Unmarshal(probeLifecycleActions, &contract)
		completed, known := contract.Actions[step.Request.Operation]
		if len(parts) != 3 || parts[2] != step.Request.Operation || !linked || !known || !slices.Equal(completed.Effects, step.Effects) {
			return report, fmt.Errorf("Go completed request nonce/operation/linkage differs")
		}
		var owned ProbeProcessRecord
		var view ProbeProfileRecord
		roles := map[string]bool{}
		for _, record := range bundle.Records {
			if roles[record.Role] {
				return report, fmt.Errorf("duplicate Go probe identity role")
			}
			roles[record.Role] = true
			switch record.Role {
			case "owned":
				if json.Unmarshal(record.Data, &owned) != nil {
					return report, fmt.Errorf("malformed Go owned record")
				}
			case "profile":
				if json.Unmarshal(record.Data, &view) != nil {
					return report, fmt.Errorf("malformed Go profile record")
				}
			default:
				return report, fmt.Errorf("unsupported Go probe identity role")
			}
		}
		facts := profile
		facts.Requests = nil
		factsBytes, _ := json.Marshal(facts)
		dataRoot := filepath.Join(profile.Root, "profile", "PCSX2")
		if profile.Version != 1 || profile.SourceFormat != "go-owned-lifecycle-v1" || !filepath.IsAbs(profile.Root) || filepath.Clean(profile.Root) != profile.Root || bundle.RunRoot != profile.Root || profile.Session == "" || step.Status != "COMPLETED" || step.Owned == nil || step.ProfileSHA256 != fmt.Sprintf("%x", sha256.Sum256(factsBytes)) || step.Request.Session != profile.Session || step.Request.Phase != "requested" || owned.Epoch == nil || *owned.Epoch != step.Epoch || owned.PID < 1 || owned.Starttime == 0 || !reflect.DeepEqual(*step.Owned, owned) || owned.Session != profile.Session || owned.Profile != filepath.Join(profile.Root, "profile") || owned.ISO != profile.Inputs["iso"].Path || owned.ISOSHA256 != profile.Inputs["iso"].SHA256 || len(owner.CardSHA256) != 64 {
			return report, fmt.Errorf("Go lifecycle owner/epoch/profile identity differs")
		}
		expectedArgs := append(slices.Clone(profile.ProgramArgs), "-datapath", owned.Profile, "-batch", owned.ISO)
		expectedArgs = append([]string{profile.Program.Path}, expectedArgs...)
		if !reflect.DeepEqual(owned.Cmdline, expectedArgs) || bundle.AfterProcess.PID != owned.PID || bundle.AfterProcess.Starttime != owned.Starttime || !reflect.DeepEqual(bundle.AfterProcess.Cmdline, owned.Cmdline) || bundle.AfterProcess.State == "" || bundle.AfterProcess.State == "Z" || bundle.AfterProcess.State == "X" || view.Datapath != owned.Profile || view.DataRoot != dataRoot || view.Card != filepath.Join(dataRoot, "memcards", "probe-slot1.ps2") || view.CardInitialSHA256 != profile.Inputs["card"].SHA256 || view.SourceCard != profile.Inputs["card"].Path || view.SourceCardSHA256 != profile.Inputs["card"].SHA256 || view.SourceSettings != profile.Inputs["settings"].Path || view.SourceSettingsSHA256 != profile.Inputs["settings"].SHA256 || view.BIOS != filepath.Join(dataRoot, "bios", filepath.Base(profile.Inputs["bios"].Path)) {
			return report, fmt.Errorf("Go probe argv/profile snapshot differs")
		}
		return ProbeRecordReport{Version: 1, SourceSchema: bundle.SourceSchema, BundleSHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), Status: "ADMITTED", Context: bundle.Context, RunID: profile.Session, Session: profile.Session, ISOSHA256: owned.ISOSHA256, Epoch: *owned.Epoch, PID: owned.PID, Starttime: owned.Starttime, Nonce: step.Request.Nonce, CardSHA256: owner.CardSHA256, RecordOrder: []string{"profile", "owned"}, RecordSHA256: map[string]string{}, Limits: "Go-produced saved lifecycle facts, not legacy emission or live ownership. Acquisition independently checks actual kernel/process/peer and immutable evidence."}, nil
	}
	if bundle.Version != 1 || bundle.SourceSchema != "text-probe-legacy-2026-11-13" || bundle.SourceSHA256 != "5439db31097c19d3b92969d5403c2c19dc3518cea4ed4c075df1a3830b8ef56f" {
		return report, fmt.Errorf("unsupported probe record import version or source schema")
	}
	if bundle.GoOwner != nil {
		return report, fmt.Errorf("legacy probe records must not contain Go ownership")
	}
	if !slices.Contains([]string{"initial", "boot_checkpoint", "outer_requested"}, bundle.Context) {
		return report, fmt.Errorf("probe record context must be initial, boot_checkpoint or outer_requested")
	}
	if len(bundle.Records) < 4 || len(bundle.Records) > 8 || len(bundle.Files) != 5 {
		return report, fmt.Errorf("probe bundle requires 4..8 records and five file observations")
	}

	var run ProbeRunRecord
	var profile ProbeProfileRecord
	var config ProbeConfigRecord
	var owned, previousOwned ProbeProcessRecord
	var request, ack, previousAck ProbeHandshakeRecord
	records := make(map[string]bool)
	report.RecordSHA256 = make(map[string]string)
	// Legacy records may carry additional diagnostics. Their complete bytes remain
	// pinned in the report; only these identity keys have admission semantics.
	identityKeys := []string{"status", "iso", "iso_sha256", "run_id", "started_at", "runner_pid", "private_profile", "datapath", "data_root", "source_settings", "source_settings_sha256", "source_card", "source_card_sha256", "card", "card_initial_sha256", "bios", "session", "profile", "pid", "starttime", "state", "cmdline", "epoch", "nonce", "phase", "operation", "error", "owned", "card_sha256_before", "card_sha256_after"}
	for _, record := range bundle.Records {
		if records[record.Role] {
			return report, fmt.Errorf("duplicate probe record role %q", record.Role)
		}
		if len(bytes.TrimSpace(record.Data)) == 0 || bytes.TrimSpace(record.Data)[0] != '{' {
			return report, fmt.Errorf("probe record %q requires an object", record.Role)
		}
		if err := checkJSON(checkedJSON{raw: record.Data, allObjects: true, text: true,
			aliasesByDepth: map[int][]string{1: identityKeys, 2: identityKeys}}); err != nil {
			return report, err
		}
		var destination any
		switch record.Role {
		case "run":
			destination = &run
		case "profile":
			destination = &profile
		case "config":
			destination = &config
		case "owned":
			destination = &owned
		case "previous_owned":
			destination = &previousOwned
		case "request":
			destination = &request
		case "ack":
			destination = &ack
		case "previous_ack":
			destination = &previousAck
		default:
			return report, fmt.Errorf("unknown probe record role %q", record.Role)
		}
		if err := json.Unmarshal(record.Data, destination); err != nil {
			return report, fmt.Errorf("invalid %s record: %w", record.Role, err)
		}
		records[record.Role] = true
		report.RecordOrder = append(report.RecordOrder, record.Role)
		report.RecordSHA256[record.Role] = fmt.Sprintf("%x", sha256.Sum256(record.Data))
	}
	required := []string{"run", "profile", "config", "owned"}
	if bundle.Context != "initial" {
		required = append(required, "previous_owned", "request", "ack")
	}
	for _, role := range required {
		if !records[role] {
			return report, fmt.Errorf("missing probe record %q", role)
		}
	}
	if bundle.Context == "initial" && len(records) != 4 {
		return report, fmt.Errorf("initial probe bundle cannot contain restart records")
	}
	files := make(map[string]ProbeFileObservation)
	for _, file := range bundle.Files {
		if !slices.Contains([]string{"iso", "card", "source_card", "settings", "bios"}, file.Role) {
			return report, fmt.Errorf("unknown probe file role %q", file.Role)
		}
		if _, exists := files[file.Role]; exists {
			return report, fmt.Errorf("duplicate probe file role %q", file.Role)
		}
		files[file.Role] = file
	}

	// These lexical paths represent Python's saved resolved paths. Never consult
	// the host filesystem to manufacture missing ownership evidence.
	for _, path := range []string{bundle.ProjectRoot, bundle.WorkingDirectory, bundle.RunRoot} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
			return report, fmt.Errorf("probe roots require canonical absolute paths")
		}
	}
	generated := filepath.Join(bundle.ProjectRoot, "generated")
	profilePath := filepath.Join(bundle.RunRoot, "profile")
	dataRoot := filepath.Join(profilePath, "PCSX2")
	if !strings.HasPrefix(bundle.RunRoot, generated+string(filepath.Separator)) || config.Profile != profilePath || profile.Datapath != profilePath || profile.DataRoot != dataRoot {
		return report, fmt.Errorf("checkpoint session/profile is outside its private run")
	}
	card := files["card"]
	if profile.Card != filepath.Join(dataRoot, "memcards", "probe-slot1.ps2") || card.Path != profile.Card || card.Resolved != profile.Card || card.Kind != "regular" || card.Symlink == nil || *card.Symlink || card.Nlink != 1 {
		return report, fmt.Errorf("checkpoint card is not an exclusive private file")
	}
	iso := files["iso"]
	if !filepath.IsAbs(config.ISO) || filepath.Clean(config.ISO) != config.ISO || iso.Path != config.ISO || iso.Resolved != config.ISO || iso.Kind != "regular" || iso.Writable == nil || *iso.Writable || iso.SHA256 != config.ISOSHA256 {
		return report, fmt.Errorf("checkpoint ISO is not the unchanged frozen candidate")
	}
	isoSuffix, err := filepath.Rel(bundle.ProjectRoot, config.ISO)
	if err != nil || isoSuffix == "." || isoSuffix == ".." || strings.HasPrefix(isoSuffix, ".."+string(filepath.Separator)) {
		return report, fmt.Errorf("checkpoint ISO is outside project root")
	}
	isoSuffix = filepath.ToSlash(isoSuffix)
	resolvedRunISO := run.ISO
	if !filepath.IsAbs(resolvedRunISO) {
		resolvedRunISO = filepath.Join(bundle.WorkingDirectory, resolvedRunISO)
	}
	if filepath.Clean(resolvedRunISO) != config.ISO || run.ISOSHA256 != config.ISOSHA256 || run.RunID != filepath.Base(bundle.RunRoot) || run.RunnerPID < 1 || run.PrivateProfile == nil || *run.PrivateProfile != profile || !slices.Contains([]string{"running", "cleaning_up", "ended"}, run.Status) {
		return report, fmt.Errorf("run metadata conflicts with its profile, ISO or run identity")
	}
	if _, err := time.Parse(time.RFC3339Nano, run.StartedAt); err != nil {
		if _, legacyErr := time.Parse("2006-01-02T15:04:05-0700", run.StartedAt); legacyErr != nil {
			return report, fmt.Errorf("run metadata requires its original start timestamp")
		}
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(config.Session) {
		return report, fmt.Errorf("invalid checkpoint session identity")
	}
	resolvedFiles := make(map[string]string)
	for _, file := range bundle.Files {
		pin, err := hex.DecodeString(file.SHA256)
		if err != nil || len(pin) != sha256.Size || hex.EncodeToString(pin) != file.SHA256 || file.Kind != "regular" || file.Nlink < 1 || file.Symlink == nil || file.Writable == nil || !filepath.IsAbs(file.Path) || !filepath.IsAbs(file.Resolved) || filepath.Clean(file.Path) != file.Path || filepath.Clean(file.Resolved) != file.Resolved {
			return report, fmt.Errorf("invalid saved file observation %q", file.Role)
		}
		if prior := resolvedFiles[file.Resolved]; prior != "" {
			return report, fmt.Errorf("probe file roles %q and %q alias", prior, file.Role)
		}
		resolvedFiles[file.Resolved] = file.Role
	}
	if files["settings"].Path != profile.SourceSettings || files["settings"].SHA256 != profile.SourceSettingsSHA256 || files["source_card"].Path != profile.SourceCard || files["source_card"].SHA256 != profile.SourceCardSHA256 || profile.CardInitialSHA256 != profile.SourceCardSHA256 || files["bios"].Path != profile.BIOS || filepath.Dir(profile.BIOS) != filepath.Join(dataRoot, "bios") {
		return report, fmt.Errorf("profile receipt conflicts with its saved source identities")
	}
	if owned.Session != config.Session || owned.ISO != config.ISO || owned.ISOSHA256 != config.ISOSHA256 || owned.Profile != profilePath || owned.Epoch == nil || *owned.Epoch < 0 {
		return report, fmt.Errorf("owned epoch conflicts with checkpoint session/profile/ISO")
	}

	status := "recorded-initial-epoch"
	if bundle.Context == "initial" {
		if *owned.Epoch != 0 || card.SHA256 != profile.CardInitialSHA256 || bundle.BeforeProcess != nil {
			return report, fmt.Errorf("initial epoch conflicts with copied card or process history")
		}
	} else {
		if request.Session != config.Session || request.Operation != "cold-restart" || request.Phase != "requested" || !regexp.MustCompile(`^[1-9][0-9]*-cold$`).MatchString(request.Nonce) {
			return report, fmt.Errorf("invalid cold restart session/operation/nonce")
		}
		// Decimal strings avoid imposing a machine-int or contiguous counter rule.
		requested := strings.TrimSuffix(request.Nonce, "-cold")
		if records["previous_ack"] {
			if previousAck.Session != config.Session || previousAck.Operation != request.Operation || previousAck.Phase != "ready" || previousAck.Error != "" || !regexp.MustCompile(`^[1-9][0-9]*-cold$`).MatchString(previousAck.Nonce) {
				return report, fmt.Errorf("invalid previous acknowledgement")
			}
			prior := strings.TrimSuffix(previousAck.Nonce, "-cold")
			if bundle.Context == "boot_checkpoint" && (len(requested) < len(prior) || len(requested) == len(prior) && requested <= prior) {
				return report, fmt.Errorf("replayed cold restart nonce")
			}
		}
		if previousOwned.Session != config.Session || previousOwned.ISO != config.ISO || previousOwned.ISOSHA256 != config.ISOSHA256 || previousOwned.Profile != profilePath || previousOwned.Epoch == nil || *previousOwned.Epoch < 0 || previousOwned.PID < 1 || previousOwned.Starttime == 0 {
			return report, fmt.Errorf("previous owned epoch conflicts with checkpoint identity")
		}
		if bundle.Context == "boot_checkpoint" && records["previous_ack"] {
			if previousAck.Epoch == nil || *previousAck.Epoch != *previousOwned.Epoch || previousAck.Owned == nil || !reflect.DeepEqual(*previousAck.Owned, previousOwned) {
				return report, fmt.Errorf("previous acknowledgement conflicts with previous owned epoch")
			}
			for _, pin := range []string{previousAck.CardBefore, previousAck.CardAfter} {
				decoded, err := hex.DecodeString(pin)
				if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != pin {
					return report, fmt.Errorf("previous acknowledgement requires card hash evidence")
				}
			}
		}
		if bundle.Context == "boot_checkpoint" {
			before := bundle.BeforeProcess
			if before == nil || before.PID != previousOwned.PID || before.Starttime != previousOwned.Starttime || before.State == "Z" || before.State == "" || before.PID < 1 || before.Starttime == 0 || !slices.Contains(before.Cmdline, "-batch") || len(before.Cmdline) == 0 {
				return report, fmt.Errorf("cold restart lost its exact live owned process")
			}
			last := strings.TrimRight(before.Cmdline[len(before.Cmdline)-1], "/")
			if last != isoSuffix && !strings.HasSuffix(last, "/"+isoSuffix) {
				return report, fmt.Errorf("cold restart lost its exact live owned process")
			}
			position := slices.Index(before.Cmdline, "-datapath")
			if position < 0 || position+1 == len(before.Cmdline) || before.Cmdline[position+1] != profilePath {
				return report, fmt.Errorf("owned process no longer uses the private profile")
			}
		}
		if ack.Error != "" {
			return report, fmt.Errorf("cold restart acknowledgement contains an error: %s", ack.Error)
		}
		if ack.Nonce != request.Nonce || ack.Session != request.Session || ack.Operation != request.Operation || ack.Phase != "ready" || ack.Owned == nil {
			return report, fmt.Errorf("cold restart acknowledgement is incomplete or conflicts with request")
		}
		if ack.Epoch == nil || *ack.Epoch != *owned.Epoch || *owned.Epoch != *previousOwned.Epoch+1 || !reflect.DeepEqual(*ack.Owned, owned) {
			return report, fmt.Errorf("cold restart acknowledgement conflicts with new epoch")
		}
		if bundle.Context == "outer_requested" && records["previous_ack"] && !reflect.DeepEqual(previousAck, ack) {
			return report, fmt.Errorf("outer acknowledgement conflicts with completed request")
		}
		if owned.PID == previousOwned.PID && owned.Starttime == previousOwned.Starttime {
			return report, fmt.Errorf("cold restart retained the old emulator identity")
		}
		for _, pin := range []string{ack.CardBefore, ack.CardAfter} {
			decoded, err := hex.DecodeString(pin)
			if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != pin {
				return report, fmt.Errorf("cold restart acknowledgement requires card hash evidence")
			}
		}
		if card.SHA256 != ack.CardAfter {
			return report, fmt.Errorf("cold restart acknowledgement conflicts with post-flush card")
		}
		status = "recorded-cold-ready"
		if bundle.Context == "outer_requested" {
			status = "already-acknowledged"
		}
	}
	after := bundle.AfterProcess
	if after == nil || after.PID != owned.PID || after.Starttime != owned.Starttime || after.State != owned.State || after.PID < 1 || after.Starttime == 0 || after.State == "" || after.State == "Z" || !slices.Contains(after.Cmdline, "-batch") || len(after.Cmdline) == 0 {
		return report, fmt.Errorf("recorded new process does not match owned epoch")
	}
	last := strings.TrimRight(after.Cmdline[len(after.Cmdline)-1], "/")
	if last != isoSuffix && !strings.HasSuffix(last, "/"+isoSuffix) {
		return report, fmt.Errorf("recorded new process does not match owned epoch")
	}
	position := slices.Index(after.Cmdline, "-datapath")
	if position < 0 || position+1 == len(after.Cmdline) || after.Cmdline[position+1] != profilePath || !slices.Equal(after.Cmdline, owned.Cmdline) {
		return report, fmt.Errorf("recorded new process does not use the private profile")
	}
	report.Version, report.SourceSchema = bundle.Version, bundle.SourceSchema
	report.BundleSHA256 = fmt.Sprintf("%x", sha256.Sum256(raw))
	report.Status, report.Context = status, bundle.Context
	report.RunID, report.Session, report.ISOSHA256 = run.RunID, config.Session, config.ISOSHA256
	report.Epoch, report.PID, report.Starttime = *owned.Epoch, owned.PID, owned.Starttime
	report.Nonce, report.PreviousNonce, report.CardSHA256 = request.Nonce, previousAck.Nonce, card.SHA256
	report.Limits = "Offline legacy-record linkage only; saved observations are not live ownership, runtime authorization, native acceptance or permission to open any claimed path."
	return report, nil
}
