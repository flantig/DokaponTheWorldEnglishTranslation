package main

import (
	_ "embed"
	"encoding/json"
)

//go:embed profiles/probe/lifecycle-actions.json
var probeLifecycleActions []byte

//go:embed profiles/probe/pad-layout.json
var probePadLayout []byte

// ProbeLifecycleProfile declares one pinned program and owned input roles.
// The initial slice is a bounded direct-child transaction, not production handover.
type ProbeLifecycleProfile struct {
	Version        int                      `json:"version"`
	SourceFormat   string                   `json:"source_format"`
	Root           string                   `json:"root"`
	Session        string                   `json:"session"`
	Program        RegistryInput            `json:"program"`
	ProgramArgs    []string                 `json:"program_args"`
	Inputs         map[string]RegistryInput `json:"inputs"`
	Requests       []ProbeLifecycleRequest  `json:"requests"`
	ReadyTimeoutMS int                      `json:"ready_timeout_ms"`
	StopTimeoutMS  int                      `json:"stop_timeout_ms"`
	QuietMS        int                      `json:"quiet_ms"`
	Policy         *ProbeLifecyclePolicy    `json:"go_policy,omitempty"`
	Seed           *uint64                  `json:"checkpoint_seed,omitempty"`
	Resume         *ProbeLifecycleResume    `json:"resume,omitempty"`
	Scenario       *ProbeScenarioSpec       `json:"scenario,omitempty"`
}

type ProbeLifecycleResume struct {
	Root     string        `json:"root"`
	Receipt  RegistryInput `json:"receipt"`
	Evidence RegistryInput `json:"evidence"`
}

// ProbeLifecyclePolicy is explicit bounded Go policy, not an owner agreement
// or an attributed historical automatic-restart/default retention policy.
type ProbeLifecyclePolicy struct {
	PollMS           int `json:"poll_ms"`
	WarnRepeats      int `json:"warn_repeats"`
	TerminalRepeats  int `json:"terminal_repeats"`
	MaxPolls         int `json:"max_polls"`
	MaxRecoveries    int `json:"max_recoveries"`
	MaxDistinctSkips int `json:"max_distinct_skips"`
}

type ProbeLifecycleRequest struct {
	Session   string `json:"session"`
	Operation string `json:"operation"`
	Phase     string `json:"phase"`
	Nonce     string `json:"nonce"`
}

type ProbeLifecycleStep struct {
	ProfileSHA256        string                `json:"profile_sha256"`
	Request              ProbeLifecycleRequest `json:"request"`
	Status               string                `json:"status"`
	Reason               string                `json:"reason,omitempty"`
	Replayed             bool                  `json:"replayed,omitempty"`
	Epoch                int                   `json:"epoch"`
	Owned                *ProbeProcessRecord   `json:"owned,omitempty"`
	CardBefore           string                `json:"card_sha256_before,omitempty"`
	CardAfter            string                `json:"card_sha256_after,omitempty"`
	WidthBefore          *uint64               `json:"window_width_before,omitempty"`
	WidthAfter           *uint64               `json:"window_width_after,omitempty"`
	Effects              []string              `json:"effects"`
	VMStatusBefore       *uint32               `json:"vm_status_before,omitempty"`
	VMStatusAfter        *uint32               `json:"vm_status_after,omitempty"`
	Memory               *ProbeMemoryReport    `json:"memory,omitempty"`
	Samples              int                   `json:"samples,omitempty"`
	Repeated             int                   `json:"repeated,omitempty"`
	Warning              bool                  `json:"warning,omitempty"`
	Skips                []string              `json:"reported_skips,omitempty"`
	WatchOutcome         string                `json:"watch_outcome,omitempty"`
	RecoveryAttempts     int                   `json:"recovery_attempts,omitempty"`
	ExitedBeforeStop     bool                  `json:"exited_before_stop,omitempty"`
	ScheduledIntervals   []int                 `json:"scheduled_intervals,omitempty"`
	ResumeEvidenceSHA256 string                `json:"resume_evidence_sha256,omitempty"`
	UI                   *ProbeUIState         `json:"ui,omitempty"`
	Capture              *ProbeCaptureReceipt  `json:"capture,omitempty"`
	Checkpoint           *ProbeEvidenceReport  `json:"checkpoint,omitempty"`
}

type ProbeLifecycleReport struct {
	Version         int                  `json:"version"`
	SourceFormat    string               `json:"source_format"`
	Session         string               `json:"session"`
	Status          string               `json:"status"`
	Steps           []ProbeLifecycleStep `json:"steps"`
	SourceSHA256    map[string]string    `json:"source_sha256"`
	PadLayoutSHA256 string               `json:"pad_layout_sha256"`
	Limits          string               `json:"limits"`
}

type ProbeLifecycleEffect struct {
	Version       int             `json:"version"`
	Session       string          `json:"session"`
	Nonce         string          `json:"nonce"`
	RequestSHA256 string          `json:"request_sha256"`
	Action        string          `json:"action"`
	Phase         string          `json:"phase"`
	Details       json.RawMessage `json:"details,omitempty"`
}

type ProbePadSpec struct {
	Root    string
	Backend string
}
