package main

// SnapshotOptions routes one opaque-artifact lifecycle without patch prerequisites.
type SnapshotOptions struct {
	Operation, Directory, Tag, Commit, Note string
	Source, Output                          string
	Apply                                   bool
}

// SnapshotReceipt is published after the verified payload. Revision provenance is
// caller supplied; it does not attest to a clean checkout or restore any registry.
type SnapshotReceipt struct {
	SchemaVersion    int    `json:"schema_version"`
	Tag              string `json:"tag"`
	CreatedUTC       string `json:"created_utc"`
	SHA256           string `json:"sha256"`
	Size             int64  `json:"size"`
	RepositoryCommit string `json:"repository_commit"`
	CommitProvenance string `json:"commit_provenance"`
	SourcePath       string `json:"source_path"`
	Note             string `json:"note,omitempty"`
}
