package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// snapshotArtifacts manages immutable tagged payloads and receipt-last publication.
// Listing does not hash payloads; restore verifies bytes and creates a NEW output.
// Failed creates may reserve an incomplete tag for inspection; no directory is deleted.
// This detects observed source changes, not an atomic snapshot of a live filesystem.
func snapshotArtifacts(options SnapshotOptions, stdout io.Writer) error {
	if options.Directory == "" {
		return fmt.Errorf("snapshot directory is required")
	}
	validTag, _ := regexp.MatchString(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`, options.Tag)
	switch options.Operation {
	case "create":
		commit, err := hex.DecodeString(options.Commit)
		if !validTag || options.Source == "" || options.Output != "" {
			return fmt.Errorf("snapshot create requires source and safe tag; output is forbidden")
		}
		if err != nil || len(commit) != 20 && len(commit) != 32 {
			return fmt.Errorf("snapshot create requires a full revision")
		}
		if !utf8.ValidString(options.Note) || len(options.Note) > 4096 {
			return fmt.Errorf("snapshot note requires bounded UTF8")
		}
	case "list":
		if options.Tag != "" || options.Source != "" || options.Output != "" || options.Apply || options.Commit != "" || options.Note != "" {
			return fmt.Errorf("snapshot list takes only a directory")
		}
	case "restore":
		if !validTag || options.Source != "" || options.Commit != "" || options.Note != "" || options.Apply != (options.Output != "") {
			return fmt.Errorf("snapshot restore requires a tag; apply requires a new output and dry run takes none")
		}
	default:
		return fmt.Errorf("unknown snapshot operation %q", options.Operation)
	}
	store, err := os.Lstat(options.Directory)
	if err != nil && (!os.IsNotExist(err) || options.Operation != "create") {
		return err
	}
	if err == nil && !store.IsDir() {
		return fmt.Errorf("snapshot store must be a directory, not a symlink")
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	var receipt SnapshotReceipt
	sourcePath := options.Source
	tagPath := filepath.Join(options.Directory, options.Tag)
	if options.Operation == "create" {
		if _, err := os.Lstat(tagPath); err == nil || !os.IsNotExist(err) {
			return fmt.Errorf("snapshot tag is already reserved or unavailable: %s", options.Tag)
		}
		sourcePath, err = filepath.Abs(sourcePath)
		if err != nil {
			return err
		}
		receipt = SnapshotReceipt{SchemaVersion: 1, Tag: options.Tag, CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano), RepositoryCommit: strings.ToLower(options.Commit), CommitProvenance: "caller supplied; not verified", SourcePath: sourcePath, Note: options.Note}
	} else {
		tags := []string{options.Tag}
		if options.Operation == "list" {
			entries, err := os.ReadDir(options.Directory)
			if err != nil {
				return err
			}
			tags = nil
			for _, entry := range entries {
				tags = append(tags, entry.Name())
			}
		}
		rows := make([]map[string]any, 0, len(tags))
		for _, tag := range tags {
			path := filepath.Join(options.Directory, tag)
			row := map[string]any{"tag": tag, "digest_verified": false}
			problem := ""
			valid, _ := regexp.MatchString(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`, tag)
			info, statErr := os.Lstat(path)
			if !valid || statErr != nil || !info.IsDir() {
				problem = "unsafe or missing tag directory"
			} else if info, err := os.Lstat(filepath.Join(path, "receipt.json")); os.IsNotExist(err) {
				problem = "incomplete: receipt missing"
			} else if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
				problem = "invalid receipt file"
			} else {
				body, readErr := readInput(filepath.Join(path, "receipt.json"), 64<<10)
				decoder := json.NewDecoder(bytes.NewReader(body))
				decoder.DisallowUnknownFields()
				var entry SnapshotReceipt
				decodeErr := decoder.Decode(&entry)
				var extra any
				digest, digestErr := hex.DecodeString(entry.SHA256)
				commit, commitErr := hex.DecodeString(entry.RepositoryCommit)
				created, timeErr := time.Parse(time.RFC3339Nano, entry.CreatedUTC)
				_, zone := created.Zone()
				switch {
				case readErr != nil || decodeErr != nil || decoder.Decode(&extra) != io.EOF:
					problem = "invalid receipt JSON"
				case entry.SchemaVersion != 1 || entry.Tag != tag || entry.Size < 0 || entry.Size == 1<<63-1:
					problem = "invalid receipt version, tag or size"
				case digestErr != nil || len(digest) != sha256.Size || entry.SHA256 != strings.ToLower(entry.SHA256):
					problem = "invalid receipt digest"
				case commitErr != nil || len(commit) != 20 && len(commit) != 32:
					problem = "invalid receipt revision"
				case timeErr != nil || zone != 0:
					problem = "invalid receipt UTC timestamp"
				case entry.CommitProvenance != "caller supplied; not verified" || !filepath.IsAbs(entry.SourcePath) || !utf8.ValidString(entry.Note) || len(entry.Note) > 4096:
					problem = "invalid receipt provenance"
				}
				if problem == "" {
					row["receipt"] = entry
					receipt = entry
					payload, err := os.Lstat(filepath.Join(path, "artifact.bin"))
					switch {
					case os.IsNotExist(err):
						problem = "payload missing"
					case err != nil || !payload.Mode().IsRegular():
						problem = "unsafe payload file"
					case payload.Size() != entry.Size:
						problem = "payload size mismatch"
					}
				}
			}
			if options.Operation == "restore" && problem != "" {
				return fmt.Errorf("snapshot %s: %s", tag, problem)
			}
			if problem == "" {
				problem = "present-unverified"
			}
			row["status"] = problem
			rows = append(rows, row)
		}
		if options.Operation == "list" {
			return encoder.Encode(map[string]any{"operation": "snapshot_list", "snapshots": rows})
		}
		sourcePath = filepath.Join(tagPath, "artifact.bin")
	}
	identity, err := os.Lstat(sourcePath)
	if err != nil {
		return err
	}
	if !identity.Mode().IsRegular() || identity.Size() == 1<<63-1 {
		return fmt.Errorf("snapshot source must be a regular file, not a symlink")
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	before, err := source.Stat()
	if err != nil || !os.SameFile(identity, before) {
		return fmt.Errorf("snapshot source identity changed")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(source, before.Size()+1))
	if err != nil {
		return err
	}
	after, err := source.Stat()
	current, pathErr := os.Lstat(sourcePath)
	if err != nil || pathErr != nil || !os.SameFile(before, current) || n != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return fmt.Errorf("snapshot source changed during hashing")
	}
	digest := fmt.Sprintf("%x", hash.Sum(nil))
	if options.Operation == "restore" && (digest != receipt.SHA256 || n != receipt.Size) {
		return fmt.Errorf("snapshot payload digest or size mismatch")
	}
	receipt.SHA256, receipt.Size = digest, n
	if options.Apply {
		if _, err := source.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if options.Operation == "create" {
			if err := os.MkdirAll(options.Directory, 0o700); err != nil {
				return err
			}
			if info, err := os.Lstat(options.Directory); err != nil || !info.IsDir() {
				return fmt.Errorf("snapshot store identity changed")
			}
			if err := os.Mkdir(tagPath, 0o700); err != nil {
				return err
			}
		}
		output := options.Output
		if options.Operation == "create" {
			output = filepath.Join(tagPath, "artifact.bin")
		}
		if err := writeNewFile(output, source, n, digest, 0o600); err != nil {
			return err
		}
		if options.Operation == "create" {
			body, err := json.MarshalIndent(receipt, "", "  ")
			if err != nil {
				return err
			}
			body = append(body, '\n')
			if err := writeNewFile(filepath.Join(tagPath, "receipt.json"), bytes.NewReader(body), int64(len(body)), fmt.Sprintf("%x", sha256.Sum256(body)), 0o600); err != nil {
				return err
			}
			for _, path := range []string{tagPath, options.Directory} {
				directory, err := os.Open(path)
				if err != nil {
					return err
				}
				syncErr := directory.Sync()
				closeErr := directory.Close()
				if syncErr != nil {
					return syncErr
				}
				if closeErr != nil {
					return closeErr
				}
			}
		}
	}
	return encoder.Encode(map[string]any{"operation": "snapshot_" + options.Operation, "applied": options.Apply, "digest_verified": true, "receipt": receipt})
}
