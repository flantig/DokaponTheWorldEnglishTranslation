package main

import "encoding/json"

type RegistryEntry struct {
	JP         json.RawMessage `json:"jp,omitempty"`
	PatchRef   string          `json:"patch_ref,omitempty"`
	ID         string          `json:"id"`
	EN         string          `json:"en"`
	LandingVMA string          `json:"landing_vma,omitempty"`
	RefType    string          `json:"ref_type,omitempty"`
	RefSites   []ReferenceSite `json:"ref_sites,omitempty"`
}

type Registry struct {
	Entries []RegistryEntry `json:"entries"`
}

// RegistryImportSpec selects draft admission, not source-control or patch readiness.
// Resource names refer to the enclosing table's pinned RegistryInputs.
// CSV provenance is a shared label capped at 512 UTF-8 bytes before row projection.
type RegistryImportSpec struct {
	Policy       string   `json:"policy"`
	Batches      []string `json:"batches"`
	Glyphmap     string   `json:"glyphmap"`
	DiscoveredBy string   `json:"discovered_by,omitempty"`
	MarkerOrders string   `json:"marker_orders,omitempty"`
}

// RegistryMarkerOrder pins reviewed draft wording and a complete lexical mapping.
// English marker j takes the ONE-BASED Japanese occurrence ENSourcesJP[j].
// Equal kind/code values do not establish identity of opaque parameter payloads.
type RegistryMarkerOrder struct {
	JPSHA256    string `json:"jp_sha256"`
	ENSHA256    string `json:"en_sha256"`
	ENSourcesJP []int  `json:"en_sources_jp"`
}

// RegistryCorrection is reviewed intent, not a canonical registry row.
// NoteSuffix owns its separator and annotation; an already-applied row never appends it.
type RegistryCorrection struct {
	ID         string `json:"id"`
	OldEN      string `json:"old_en"`
	NewEN      string `json:"new_en"`
	NoteSuffix string `json:"note_suffix"`
}

// GlossaryProposal supplies only the five fields owned when adding a glossary row.
// Matching existing JP/EN retains all existing metadata instead of refreshing it.
type GlossaryProposal struct {
	JP         string `json:"jp"`
	EN         string `json:"en"`
	Provenance string `json:"provenance"`
	Source     string `json:"source"`
	UsageNote  string `json:"usage_note"`
}

// RegistryHumanEntry names the six authored fields; JP is resolved from source
// records or an explicit override, never accepted as a seventh authored field.
type RegistryHumanEntry struct {
	EN        string `json:"en"`
	Chapter   string `json:"chapter"`
	Character string `json:"character"`
	Event     string `json:"event"`
	Tier      string `json:"tier"`
	Note      string `json:"note"`
	JP        string `json:"-"`
}

// RegistryHumanBatch is source intent, not permission to change locked wording.
// The registry owner applies drift and status policy after source resolution.
type RegistryHumanBatch struct {
	Entries        map[uint64]RegistryHumanEntry
	OverwriteDrift bool
	DiscoveredBy   string
}

// RegistryCount keeps JSON null distinct from an empty or missing-field label.
// Display is escaped for Markdown; Value retains the original grouping value.
type RegistryCount struct {
	Value   *string `json:"value"`
	Count   int     `json:"count"`
	Display string  `json:"display"`
}

// RegistryOptions carries document inputs and publication choices, not patch facts.
type RegistryOptions struct {
	RegistryPath string
	ProfilePath  string
	GlyphmapPath string
	Output       string
	Apply        bool
}
