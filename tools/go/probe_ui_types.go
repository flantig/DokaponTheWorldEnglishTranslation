package main

import (
	_ "embed"
	"encoding/json"
)

//go:embed profiles/probe/ui-source.json
var probeUISource []byte

// ProbeUIPlan bounds the fixed source UI walk. It is not a general pointer graph.
type ProbeUIPlan struct {
	Admission   json.RawMessage `json:"admission"`
	BuildSHA256 string          `json:"build_sha256"`
	Glyphmap    json.RawMessage `json:"glyphmap"`
	TimeoutMS   int             `json:"timeout_ms"`
	MaxReads    int             `json:"max_reads"`
}

type ProbeUIWidget struct {
	Index                            int `json:"index"`
	Flags, Kind, Source, Ready, Page uint64
	Text                             string  `json:"text,omitempty"`
	Selection                        *uint64 `json:"selection,omitempty"`
	Rows                             *uint64 `json:"rows,omitempty"`
	ImageTexture                     string  `json:"image_texture,omitempty"`
	Unsupported                      bool    `json:"unsupported,omitempty"`
}

type ProbeUIState struct {
	AdmissionSHA256 string            `json:"admission_sha256"`
	Session         string            `json:"session"`
	Epoch           int               `json:"epoch"`
	PID             int               `json:"pid"`
	Headers         map[string]uint64 `json:"headers"`
	Saved           ProbeSavedState   `json:"saved"`
	PlayerRecords   [][]byte          `json:"player_records"`
	Widgets         []ProbeUIWidget   `json:"widgets"`
	BoardAIReady    bool              `json:"board_ai_ready"`
	Reads           int               `json:"reads"`
	Unsupported     []string          `json:"unsupported"`
}

// probeUIPhase is one source-specific work item, never caller-supplied code.
type probeUIPhase struct {
	Kind        string
	Index       int
	Base, Count uint32
	Offset      uint32
	Values      []uint64
}
