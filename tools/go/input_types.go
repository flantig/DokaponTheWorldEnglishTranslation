package main

// RegistryInput pins a read-only artifact; paths resolve relative to its recipe/profile.
type RegistryInput struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// checkedJSON scopes key and Unicode validation without interpreting opaque data.
// Registry ownership is selective; complete profiles and glyphmaps own all objects.
// fieldsByDepth closes typed object keys; aliasesByDepth rejects aliases only
// of owned names, keeping other metadata keys opaque. Policies use object depth.
type checkedJSON struct {
	raw                                []byte
	updates, text, records, allObjects bool
	nonNull                            bool             // Authored numeric nulls must not silently become zero.
	nonNullByDepth                     map[int][]string // Reject null only for these owned fields.
	requiredByDepth                    map[int][]string // Require explicit owned fields, including zero-valued token coordinates.
	fieldsByDepth                      map[int][]string
	aliasesByDepth                     map[int][]string
}
