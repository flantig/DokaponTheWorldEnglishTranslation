package main

import _ "embed"

//go:embed profiles/probe/scenarios.json
var probeScenarioData []byte

// ProbeStoryRecipe is shared source data for execution, final reporting and carry.
type ProbeStoryRecipe struct {
	StartFile int    `json:"start_file"`
	Alternate bool   `json:"alternate"`
	Required  string `json:"required"`
}

// ProbeScenarioSpec selects source-owned facts, never arbitrary RAM writes or predicates.
type ProbeScenarioSpec struct {
	ID                string        `json:"id"`
	Glyphmap          RegistryInput `json:"glyphmap"`
	TimeoutMS         int           `json:"timeout_ms"`
	MaxUIReads        int           `json:"max_ui_reads"`
	NoTutorial        bool          `json:"no_tutorial,omitempty"`
	FrontEndTimeoutMS int           `json:"front_end_timeout_ms,omitempty"`
	Recipe            string        `json:"recipe,omitempty"`
	Calibration       bool          `json:"calibration,omitempty"`
	WaitTimeoutMS     int           `json:"wait_timeout_ms,omitempty"`
}
