package main

import _ "embed"

//go:embed profiles/probe/scenarios.json
var probeScenarioData []byte

// ProbeScenarioSpec selects source-owned facts, never arbitrary RAM writes or predicates.
type ProbeScenarioSpec struct {
	ID                string        `json:"id"`
	Glyphmap          RegistryInput `json:"glyphmap"`
	TimeoutMS         int           `json:"timeout_ms"`
	MaxUIReads        int           `json:"max_ui_reads"`
	NoTutorial        bool          `json:"no_tutorial,omitempty"`
	FrontEndTimeoutMS int           `json:"front_end_timeout_ms,omitempty"`
}
