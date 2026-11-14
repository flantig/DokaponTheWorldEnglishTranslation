package main

// ProbeSequenceSpec fixes three fresh single-profile runs. Later card roles are
// empty placeholders, filled only from a verified successful postflush carry.
type ProbeSequenceSpec struct {
	Version      int                     `json:"version"`
	SourceFormat string                  `json:"source_format"`
	Root         string                  `json:"root"`
	Seed         uint64                  `json:"seed"`
	Profiles     []ProbeLifecycleProfile `json:"profiles"`
}

type ProbeSequenceRun struct {
	Recipe            string               `json:"recipe"`
	Profile           RegistryInput        `json:"profile"`
	InitialCardSHA256 string               `json:"initial_card_sha256"`
	Lifecycle         ProbeLifecycleReport `json:"lifecycle"`
	Evidence          *RegistryInput       `json:"evidence,omitempty"`
	Carry             *RegistryInput       `json:"carry,omitempty"`
}

type ProbeSequenceReport struct {
	Version      int                `json:"version"`
	SourceFormat string             `json:"source_format"`
	Status       string             `json:"status"`
	Reason       string             `json:"reason,omitempty"`
	Runs         []ProbeSequenceRun `json:"runs"`
	Limits       string             `json:"limits"`
}
