package main

import "encoding/json"

// ProbeEvidenceBundle binds saved JSONL observations to admitted run records.
// Membership is explicit; an absent comparison remains UNKNOWN, never an empty pass.
type ProbeEvidenceBundle struct {
	Version      int                       `json:"version"`
	SourceSchema string                    `json:"source_schema"`
	SourceSHA256 string                    `json:"source_sha256"`
	Admission    json.RawMessage           `json:"admission"`
	RunID        string                    `json:"run_id"`
	Session      string                    `json:"session"`
	ISOSHA256    string                    `json:"iso_sha256"`
	Epoch        *int                      `json:"epoch"`
	Cohort       string                    `json:"cohort"`
	Members      []string                  `json:"members"`
	Events       []ProbeEvidenceEvent      `json:"events"`
	Checks       []ProbeEvidenceCheck      `json:"checks"`
	Captures     []ProbeCaptureObservation `json:"captures,omitempty"`
	Resume       *ProbeResumeFacts         `json:"resume,omitempty"`
	Story        *ProbeStoryFacts          `json:"story,omitempty"`
}

// ProbeStoryFacts selects one source recipe's final saved-evidence gate.
// Actual process disposal/card promotion remains the sequence owner's I/O duty.
type ProbeStoryFacts struct {
	Recipe          string `json:"recipe"`
	Phase           string `json:"phase"`
	TerminalEventID int    `json:"terminal_event_id"`
	PostClearMS     int64  `json:"postclear_ms"`
}

// ProbeResumeFacts is the source resume receipt plus loaded saved artifacts.
// Pure comparisons do not attest paths: the controller rehashes files first.
type ProbeResumeFacts struct {
	ISOSHA256           string                   `json:"iso_sha256"`
	Seed                *uint64                  `json:"seed"`
	Artifacts           map[string]RegistryInput `json:"artifacts"`
	SourceFrameRoot     string                   `json:"source_frame_root"`
	AcceptedCheckpoints []int                    `json:"accepted_checkpoints"`
	FailedCheckpoint    int                      `json:"failed_checkpoint"`
	SaveEvent           int                      `json:"save_event"`
	ColdLoadEvent       int                      `json:"cold_load_event"`
	ControlEvent        int                      `json:"control_event"`
	FailureEvent        int                      `json:"failure_event"`
	Slot                *int                     `json:"slot"`
	Actor               *uint32                  `json:"actor"`
	OriginalControl     *uint32                  `json:"original_control"`
	Expected            *ProbeSavedState         `json:"expected"`
	Coverage            []uint32                 `json:"coverage"`
	ScheduledIntervals  []int                    `json:"scheduled_intervals"`
	Run                 json.RawMessage          `json:"loaded_run,omitempty"`
	Sequence            json.RawMessage          `json:"loaded_sequence,omitempty"`
	Screenshots         map[string]RegistryInput `json:"loaded_screenshots,omitempty"`
}

type ProbeEvidenceEvent struct {
	Offset int64           `json:"offset"`
	Data   json.RawMessage `json:"data"`
}

type ProbeEvidenceCheck struct {
	ID           string          `json:"id"`
	Kind         string          `json:"kind"`
	SourceSHA256 string          `json:"source_sha256"`
	EventID      int             `json:"event_id"`
	Observation  string          `json:"observation"`
	Reason       string          `json:"reason,omitempty"`
	Data         json.RawMessage `json:"data,omitempty"`
}

// These are exactly SAVE_FIELDS and the complete player fingerprint shape.
type ProbeSavedState struct {
	Story   *uint32            `json:"story"`
	Week    *uint32            `json:"week"`
	Day     *uint32            `json:"day"`
	Current *uint32            `json:"current"`
	Area    *uint32            `json:"area"`
	Players []ProbeSavedPlayer `json:"players"`
}

type ProbeSavedPlayer struct {
	Control                   *uint32  `json:"control"`
	Square                    *uint32  `json:"square"`
	Money                     *uint32  `json:"money"`
	NameWords                 []uint32 `json:"name_words"`
	RecordSHA256              string   `json:"record_sha256"`
	TutorialFlags             *uint32  `json:"tutorial_flags"`
	TutorialInitializedSHA256 string   `json:"tutorial_initialized_sha256"`
}

type ProbeEvidenceResult struct {
	ID      string `json:"id"`
	Kind    string `json:"kind,omitempty"`
	EventID int    `json:"event_id,omitempty"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
}

type ProbeCheckpointResult struct {
	Checkpoint int     `json:"checkpoint"`
	Slot       *int    `json:"slot,omitempty"`
	Area       *uint32 `json:"area,omitempty"`
	Warm       bool    `json:"warm"`
	Cold       bool    `json:"cold"`
	Advanced   bool    `json:"advanced"`
	Status     string  `json:"status"`
	Reason     string  `json:"reason,omitempty"`
}

type ProbeEvidenceReport struct {
	Version            int                     `json:"version"`
	SourceSchema       string                  `json:"source_schema"`
	BundleSHA256       string                  `json:"bundle_sha256"`
	RunID              string                  `json:"run_id"`
	Session            string                  `json:"session"`
	ISOSHA256          string                  `json:"iso_sha256"`
	Epoch              int                     `json:"epoch"`
	Cohort             string                  `json:"cohort"`
	Status             string                  `json:"status"`
	Rows               []ProbeEvidenceResult   `json:"rows"`
	Checkpoints        []ProbeCheckpointResult `json:"checkpoints"`
	CoveredAreas       []uint32                `json:"covered_areas"`
	Events             []ProbeEvidenceEvent    `json:"events"`
	Captures           []ProbeCaptureLink      `json:"captures,omitempty"`
	LiveOwnership      bool                    `json:"live_ownership"`
	Limits             string                  `json:"limits"`
	ResumeStatus       string                  `json:"resume_status,omitempty"`
	ResumeNextInterval *int                    `json:"resume_next_interval,omitempty"`
}
