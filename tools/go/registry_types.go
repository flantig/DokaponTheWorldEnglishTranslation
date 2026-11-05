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
	GlyphmapPath string
	Output       string
	Apply        bool
}
