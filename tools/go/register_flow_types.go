package main

// RegisterFlowSpec asserts normal entries into the selected instruction range.
// Entries are analysis assumptions, not evidence of whole-program closure.
type RegisterFlowSpec struct {
	EntryVMAs []string                     `json:"entry_vmas"`
	Queries   map[string]RegisterFlowQuery `json:"queries"`
}

type RegisterFlowQuery struct {
	Kind             string  `json:"kind"`
	Register         uint32  `json:"register"`
	VMA              string  `json:"vma"`
	Context          string  `json:"context"`
	DelayOf          *string `json:"delay_of,omitempty"`
	MaxVisitedStates int     `json:"max_visited_states"`
}

type RegisterFlowReport struct {
	EntryVMAs               []uint32                      `json:"entry_vmas"`
	WholeProgramScopeProven bool                          `json:"whole_program_scope_proven"`
	Queries                 map[string]RegisterFlowResult `json:"queries"`
}

type RegisterFlowResult struct {
	Kind                        string   `json:"kind"`
	Register                    uint32   `json:"register"`
	VMA                         uint32   `json:"vma"`
	Context                     string   `json:"context"`
	DelayOf                     *uint32  `json:"delay_of"`
	KnownFactSites              []uint32 `json:"known_fact_sites"`
	IncomingEntrySites          []uint32 `json:"incoming_entry_sites"`
	CompleteWithinAssertedScope bool     `json:"complete_within_asserted_scope"`
	IncompleteReasons           []string `json:"incomplete_reasons"`
}
