package main

import (
	"encoding/json"
	"os"
	"time"
)

// Two bounded process cmdlines can expand under JSON escaping. Stop records do
// not contain image/UI payloads; this ceiling is reserved per finalizer output.
const probeFinalizerArtifactBytes uint64 = 16 << 20

// ProbeFramePolicy is an explicit cooperative-run budget, not owner acceptance
// or a kernel quota. No finite capture-count default substitutes for a full run.
type ProbeFramePolicy struct {
	MaxRunSeconds         uint64 `json:"max_run_seconds"`
	MaxRetainedFrames     uint64 `json:"max_retained_frames"`
	MaxManagedFiles       uint64 `json:"max_managed_files"`
	MaxManagedBytes       uint64 `json:"max_managed_bytes"`
	MaxJournalBytes       uint64 `json:"max_journal_bytes"`
	RetainFirstRawWitness bool   `json:"retain_first_raw_witness,omitempty"`
}

// ProbeFrameSummary distinguishes successful sampling from retained publication.
// Codec qualification remains explicit even when the nominal source settings match.
type ProbeFrameSummary struct {
	Status                 string           `json:"status"`
	CodecQualification     string           `json:"codec_qualification"`
	Policy                 ProbeFramePolicy `json:"policy"`
	Epoch                  int              `json:"epoch"`
	Attempts               uint64           `json:"attempts"`
	SampleSuccesses        uint64           `json:"sample_successes"`
	EpochCaptures          uint64           `json:"epoch_captures"`
	SelectedCommits        uint64           `json:"selected_commits"`
	CheckpointCommits      uint64           `json:"checkpoint_commits"`
	PineErrors             uint64           `json:"pine_errors"`
	CaptureErrors          uint64           `json:"capture_errors"`
	LastPineSeconds        *float64         `json:"last_pine_seconds,omitempty"`
	LastSampleSeconds      *float64         `json:"last_sample_seconds,omitempty"`
	FinalCaptureGapSeconds *float64         `json:"final_capture_gap_seconds,omitempty"`
	LastVisualSeconds      *float64         `json:"last_visual_seconds,omitempty"`
	LastSelectedSeconds    *float64         `json:"last_selected_seconds,omitempty"`
	LastMean               *float64         `json:"last_mean,omitempty"`
	PreviousComparisonHash string           `json:"previous_comparison_hash,omitempty"`
	LastJPEG               string           `json:"last_jpeg,omitempty"`
	LastJPEGSHA256         string           `json:"last_jpeg_sha256,omitempty"`
	PendingJPEG            string           `json:"pending_jpeg,omitempty"`
	PendingJPEGSHA256      string           `json:"pending_jpeg_sha256,omitempty"`
	PendingCSV             bool             `json:"pending_csv,omitempty"`
	HealthEvents           uint64           `json:"health_events"`
	Failure                string           `json:"failure,omitempty"`
	Limits                 string           `json:"limits"`
}

// ProbeFrameRun belongs to one serialized lifecycle. A cold owned-ready epoch
// resets only epoch/sample baselines; run time and retained ordinals continue.
type ProbeFrameRun struct {
	Policy    ProbeFramePolicy
	Budget    *ProbeArtifactBudget
	Runtime   ProbeCaptureRuntime
	Admission json.RawMessage
	CardPath  string
	Ready     bool
	// Owned pause/toggle inhibits ordinary F8 only, not epoch health or deadlines.
	OrdinaryCaptureInhibited bool
	Finalizing               bool
	Started                  time.Time
	EpochStarted             time.Time
	NextAttempt              time.Time
	NextHealth               time.Time
	NextStorage              time.Time
	NextWake                 time.Time
	LastPine                 time.Time
	LastSample               time.Time
	LastVisual               time.Time
	LastSelected             time.Time
	Previous                 []byte
	CSV                      []byte
	CSVInfo                  os.FileInfo
	Summary                  ProbeFrameSummary
	NativeSlot               *ProbeArtifactClaim
	FinalizerClaims          []ProbeArtifactClaim
}
