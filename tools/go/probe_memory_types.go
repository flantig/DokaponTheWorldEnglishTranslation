package main

import "encoding/json"

// ProbeMemoryBundle is a finite source-specific acquisition/decoder plan.
// Saved replies are wire packets, not caller-provided decoded values.
type ProbeMemoryBundle struct {
	Version           int                  `json:"version"`
	SourceSHA256      string               `json:"source_sha256"`
	Admission         json.RawMessage      `json:"admission"`
	BuildSHA256       string               `json:"build_sha256"`
	Requests          []ProbeMemoryRequest `json:"requests"`
	Replies           []string             `json:"replies,omitempty"`
	Decoders          []ProbeMemoryDecoder `json:"decoders"`
	WordGuards        map[string]uint32    `json:"word_guards,omitempty"`
	DiagnosticVersion string               `json:"diagnostic_version,omitempty"`
}

type ProbeMemoryRequest struct {
	ID      string  `json:"id"`
	Opcode  *uint8  `json:"opcode"`
	Address *uint32 `json:"address"`
}

type ProbeMemoryDecoder struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	Requests []string        `json:"requests"`
	Glyphmap json.RawMessage `json:"glyphmap,omitempty"`
}

// Runtime roots are explicit CLI inputs; no path claimed by an admission bundle
// is followed. Synthetic peers are confined to an owned private root, never live.
type ProbeMemoryRuntime struct {
	Provenance string `json:"provenance"`
	Root       string `json:"root"`
	TimeoutMS  int    `json:"timeout_ms"`
}

type ProbeMemoryObservation struct {
	ID         string `json:"id"`
	RequestHex string `json:"request_hex"`
	ReplyHex   string `json:"reply_hex"`
	Value      uint64 `json:"value"`
}

type ProbeMemoryDecoded struct {
	ID        string            `json:"id"`
	Kind      string            `json:"kind"`
	Status    string            `json:"status"`
	Reason    string            `json:"reason,omitempty"`
	Value     *uint64           `json:"value,omitempty"`
	Text      *string           `json:"text,omitempty"`
	Player    *ProbeSavedPlayer `json:"player,omitempty"`
	Cursor    *uint64           `json:"cursor,omitempty"`
	FrameTags []uint64          `json:"frame_tags,omitempty"`
}

type ProbeMemoryReport struct {
	Version               int                      `json:"version"`
	BundleSHA256          string                   `json:"bundle_sha256"`
	SourceSHA256          string                   `json:"source_sha256"`
	BuildSHA256           string                   `json:"build_sha256"`
	Session               string                   `json:"session"`
	Epoch                 int                      `json:"epoch"`
	ISOSHA256             string                   `json:"iso_sha256"`
	Provenance            string                   `json:"provenance"`
	ProcessGuarded        bool                     `json:"process_guarded"`
	SessionEvidenceSHA256 string                   `json:"session_evidence_sha256"`
	Observations          []ProbeMemoryObservation `json:"observations"`
	Decoded               []ProbeMemoryDecoded     `json:"decoded"`
	DiagnosticVersion     string                   `json:"diagnostic_version,omitempty"`
	Limits                string                   `json:"limits"`
}
