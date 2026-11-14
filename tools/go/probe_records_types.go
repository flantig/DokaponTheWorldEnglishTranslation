package main

import "encoding/json"

// ProbeRecordBundle versions this offline import, not the legacy emitted JSON.
// Claimed paths and process observations are data and are never opened or adopted.
type ProbeRecordBundle struct {
	Version          int                    `json:"version"`
	SourceSchema     string                 `json:"source_schema"`
	SourceSHA256     string                 `json:"source_sha256"`
	ProjectRoot      string                 `json:"project_root"`
	WorkingDirectory string                 `json:"working_directory"`
	RunRoot          string                 `json:"run_root"`
	Context          string                 `json:"context"`
	Records          []ProbeRecord          `json:"records"`
	Files            []ProbeFileObservation `json:"files"`
	BeforeProcess    *ProbeProcessRecord    `json:"before_process,omitempty"`
	AfterProcess     *ProbeProcessRecord    `json:"after_process"`
	GoOwner          *ProbeGoOwner          `json:"go_owner,omitempty"`
}

// ProbeGoOwner versions Go-produced lifecycle facts separately from legacy JSON.
// Admission remains pure; live acquisition must independently revalidate them.
type ProbeGoOwner struct {
	Profile    ProbeLifecycleProfile `json:"profile"`
	Step       ProbeLifecycleStep    `json:"step"`
	CardSHA256 string                `json:"card_sha256"`
}

type ProbeRecord struct {
	Role string          `json:"role"`
	Data json.RawMessage `json:"data"`
}

// File observations attest saved facts only. A valid bundle grants no live IO.
type ProbeFileObservation struct {
	Role     string `json:"role"`
	Path     string `json:"path"`
	Resolved string `json:"resolved_path"`
	SHA256   string `json:"sha256"`
	Kind     string `json:"kind"`
	Nlink    uint64 `json:"nlink"`
	Symlink  *bool  `json:"symlink"`
	Writable *bool  `json:"writable"`
}

type ProbeProfileRecord struct {
	Datapath             string `json:"datapath"`
	DataRoot             string `json:"data_root"`
	SourceSettings       string `json:"source_settings"`
	SourceSettingsSHA256 string `json:"source_settings_sha256"`
	SourceCard           string `json:"source_card"`
	SourceCardSHA256     string `json:"source_card_sha256"`
	Card                 string `json:"card"`
	CardInitialSHA256    string `json:"card_initial_sha256"`
	BIOS                 string `json:"bios"`
}

type ProbeRunRecord struct {
	Status         string              `json:"status"`
	ISO            string              `json:"iso"`
	ISOSHA256      string              `json:"iso_sha256"`
	RunID          string              `json:"run_id"`
	StartedAt      string              `json:"started_at"`
	RunnerPID      int                 `json:"runner_pid"`
	PrivateProfile *ProbeProfileRecord `json:"private_profile"`
}

type ProbeConfigRecord struct {
	Session   string `json:"session"`
	ISO       string `json:"iso"`
	ISOSHA256 string `json:"iso_sha256"`
	Profile   string `json:"profile"`
}

// This is the common saved process shape used by owned epochs and ready acks.
type ProbeProcessRecord struct {
	PID       int      `json:"pid"`
	Starttime uint64   `json:"starttime"`
	State     string   `json:"state"`
	Cmdline   []string `json:"cmdline"`
	Session   string   `json:"session,omitempty"`
	ISO       string   `json:"iso,omitempty"`
	ISOSHA256 string   `json:"iso_sha256,omitempty"`
	Profile   string   `json:"profile,omitempty"`
	Epoch     *int     `json:"epoch,omitempty"`
}

type ProbeHandshakeRecord struct {
	Nonce      string              `json:"nonce"`
	Phase      string              `json:"phase"`
	Session    string              `json:"session"`
	Operation  string              `json:"operation"`
	Error      string              `json:"error,omitempty"`
	Epoch      *int                `json:"epoch,omitempty"`
	Owned      *ProbeProcessRecord `json:"owned,omitempty"`
	CardBefore string              `json:"card_sha256_before,omitempty"`
	CardAfter  string              `json:"card_sha256_after,omitempty"`
}

type ProbeRecordReport struct {
	Version       int               `json:"version"`
	SourceSchema  string            `json:"source_schema"`
	BundleSHA256  string            `json:"bundle_sha256"`
	Status        string            `json:"status"`
	Context       string            `json:"context"`
	RunID         string            `json:"run_id"`
	Session       string            `json:"session"`
	ISOSHA256     string            `json:"iso_sha256"`
	Epoch         int               `json:"epoch"`
	PID           int               `json:"pid"`
	Starttime     uint64            `json:"starttime"`
	Nonce         string            `json:"nonce,omitempty"`
	PreviousNonce string            `json:"previous_nonce,omitempty"`
	CardSHA256    string            `json:"card_sha256"`
	RecordOrder   []string          `json:"record_order"`
	RecordSHA256  map[string]string `json:"record_sha256"`
	LiveOwnership bool              `json:"live_ownership"`
	Limits        string            `json:"limits"`
}
