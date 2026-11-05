package main

// ReferenceFlowSpec declares bounded entry assumptions and per-ID caller policy.
// These requests cannot supply graph facts or authorize a patch.
type ReferenceFlowSpec struct {
	EntryVMAs        []string                       `json:"entry_vmas"`
	MaxVisitedStates int                            `json:"max_visited_states"`
	Entries          map[string]ReferenceFlowRecipe `json:"entries"`
}

type ReferenceFlowRecipe struct {
	BenignReaderPairs    []ReferenceBenignUse `json:"benign_reader_pairs,omitempty"`
	ZeroPaddingAllowance int                  `json:"zero_padding_allowance,omitempty"`
}

type ReferenceBenignUse struct {
	LUIVMA   string `json:"lui_vma"`
	UseVMA   string `json:"use_vma"`
	Evidence string `json:"evidence"`
}

// ReferenceFlowRow joins declared sites to the authoritative register-flow group.
// Eligible means only that this read-only row meets the declared finite policy.
type ReferenceFlowRow struct {
	CallerDisposition   string                `json:"caller_disposition"`
	Diagnostics         []string              `json:"diagnostics"`
	DefinitionQueries   map[string]string     `json:"definition_queries"`
	UseQueries          map[string]string     `json:"use_queries"`
	ConstructedTargets  []ReferenceFlowTarget `json:"constructed_targets"`
	Readers             []ReferenceFlowReader `json:"readers"`
	CanonicalPairErrors map[string]string     `json:"canonical_pair_errors"`
}

type ReferenceFlowTarget struct {
	LUIVMA   uint32 `json:"lui_vma"`
	LowerVMA uint32 `json:"lower_vma"`
	Target   uint32 `json:"target"`
}

type ReferenceFlowReader struct {
	LUIVMA   uint32            `json:"lui_vma"`
	UseVMA   uint32            `json:"use_vma"`
	Relation string            `json:"relation"`
	Owners   map[string]string `json:"owners"`
}
