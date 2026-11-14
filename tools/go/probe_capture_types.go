package main

import "encoding/json"

// ProbeCaptureProfile pins one source event and finite acquisition budgets.
// Caps are enforced policy, not a claim of owner-agreed native retention limits.
type ProbeCaptureProfile struct {
	Version          int             `json:"version"`
	SourceSHA256     string          `json:"source_sha256"`
	PadSourceSHA256  string          `json:"pad_source_sha256"`
	Memory           json.RawMessage `json:"memory"`
	CaptureID        string          `json:"capture_id"`
	EventID          int             `json:"event_id"`
	Checkpoint       int             `json:"checkpoint"`
	LogOffset        int64           `json:"log_offset"`
	LogBytes         int             `json:"log_bytes"`
	LogSHA256        string          `json:"log_sha256"`
	MaxSnapshotFiles int             `json:"max_snapshot_files"`
	MaxImageBytes    int64           `json:"max_image_bytes"`
	MaxPixels        uint64          `json:"max_pixels"`
	MaxRetainedFiles int             `json:"max_retained_files"`
	MaxRetainedBytes int64           `json:"max_retained_bytes"`
	LockTimeoutMS    int             `json:"lock_timeout_ms"`
	CaptureTimeoutMS int             `json:"capture_timeout_ms"`
}

type ProbeCaptureRuntime struct {
	Memory     ProbeMemoryRuntime `json:"memory"`
	Snapshots  string             `json:"snapshots"`
	Output     string             `json:"output"`
	BackendPID int                `json:"backend_pid"`
}

// The original PNG and its source log/typed observations are separate evidence.
// No normalized Pillow/JPEG image is produced or implied by this receipt.
type ProbeCaptureReceipt struct {
	Version           int                `json:"version"`
	SourceSHA256      string             `json:"source_sha256"`
	PadSourceSHA256   string             `json:"pad_source_sha256"`
	CaptureID         string             `json:"capture_id"`
	EventID           int                `json:"event_id"`
	Checkpoint        int                `json:"checkpoint"`
	RunID             string             `json:"run_id"`
	Session           string             `json:"session"`
	Epoch             int                `json:"epoch"`
	PID               int                `json:"pid"`
	Starttime         uint64             `json:"starttime"`
	ISOSHA256         string             `json:"iso_sha256"`
	BuildSHA256       string             `json:"build_sha256"`
	Provenance        string             `json:"provenance"`
	Status            string             `json:"status"`
	Reason            string             `json:"reason,omitempty"`
	StartedAt         string             `json:"started_at"`
	FinishedAt        string             `json:"finished_at"`
	LockBudgetMS      int                `json:"lock_budget_ms"`
	CaptureBudgetMS   int                `json:"capture_budget_ms"`
	GuideCommand      string             `json:"guide_command,omitempty"`
	GuideAckHex       string             `json:"guide_ack_hex,omitempty"`
	Snapshot          string             `json:"snapshot,omitempty"`
	SnapshotPreserved bool               `json:"snapshot_preserved"`
	ImagePath         string             `json:"image_path,omitempty"`
	ImageSHA256       string             `json:"image_sha256,omitempty"`
	ImageBytes        int64              `json:"image_bytes,omitempty"`
	Width             int                `json:"width,omitempty"`
	Height            int                `json:"height,omitempty"`
	LogOffset         int64              `json:"log_offset"`
	LogSHA256         string             `json:"log_sha256"`
	LogHex            string             `json:"log_hex"`
	MemoryBefore      *ProbeMemoryReport `json:"memory_before,omitempty"`
	MemoryAfter       *ProbeMemoryReport `json:"memory_after,omitempty"`
	Representation    string             `json:"representation"`
	Derivatives       string             `json:"derivatives"`
	PolicyStatus      string             `json:"policy_status"`
}

type ProbeCaptureObservation struct {
	Receipt  ProbeCaptureReceipt `json:"receipt"`
	ImageHex string              `json:"image_hex,omitempty"`
}

type ProbeCaptureLink struct {
	CaptureID     string `json:"capture_id"`
	EventID       int    `json:"event_id"`
	Checkpoint    int    `json:"checkpoint"`
	Status        string `json:"status"`
	Reason        string `json:"reason,omitempty"`
	ReceiptSHA256 string `json:"receipt_sha256"`
	Provenance    string `json:"provenance"`
	ImagePath     string `json:"image_path,omitempty"`
	ImageSHA256   string `json:"image_sha256,omitempty"`
}
