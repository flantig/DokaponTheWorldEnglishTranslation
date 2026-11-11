package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"
)

const isoSector = 2048

type fileSpan struct {
	offset int64
	size   int64
}

// isoFileExtent resolves one file through the source image's ISO9660 directories.
// The master uses both-endian extent fields; malformed or ambiguous names refuse.
func isoFileExtent(image io.ReaderAt, imageSize int64, path string) (fileSpan, error) {
	parts := strings.Split(path, "/")
	if len(parts) < 1 || len(parts) > 8 {
		return fileSpan{}, fmt.Errorf("invalid ISO path %q", path)
	}
	pvd := make([]byte, isoSector)
	if _, err := image.ReadAt(pvd, 16*isoSector); err != nil {
		return fileSpan{}, err
	}
	if !bytes.Equal(pvd[:7], []byte{1, 'C', 'D', '0', '0', '1', 1}) || binary.LittleEndian.Uint16(pvd[128:]) != isoSector || binary.BigEndian.Uint16(pvd[130:]) != isoSector || pvd[156] < 34 {
		return fileSpan{}, fmt.Errorf("invalid ISO9660 primary volume")
	}
	root := pvd[156 : 156+int(pvd[156])]
	unsupportedRoot := root[1] != 0 || root[25]&2 == 0 || root[26] != 0 || root[27] != 0 || binary.LittleEndian.Uint16(root[28:]) != 1 || binary.BigEndian.Uint16(root[30:]) != 1
	invalidRootExtent := binary.LittleEndian.Uint32(root[2:]) != binary.BigEndian.Uint32(root[6:]) || binary.LittleEndian.Uint32(root[10:]) != binary.BigEndian.Uint32(root[14:])
	if unsupportedRoot || invalidRootExtent {
		return fileSpan{}, fmt.Errorf("invalid ISO9660 root record")
	}
	current := fileSpan{int64(binary.LittleEndian.Uint32(root[2:])) * isoSector, int64(binary.LittleEndian.Uint32(root[10:]))}
	if current.offset < 0 || current.size <= 0 || current.size > imageSize-current.offset {
		return fileSpan{}, fmt.Errorf("invalid ISO root extent")
	}
	for depth, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "\\;\x00") || current.size > 16<<20 {
			return fileSpan{}, fmt.Errorf("invalid ISO path component %q", part)
		}
		var found fileSpan
		matches := 0
		for sector := int64(0); sector < current.size; sector += isoSector {
			block := make([]byte, min(int64(isoSector), current.size-sector))
			if _, err := image.ReadAt(block, current.offset+sector); err != nil {
				return fileSpan{}, err
			}
			for at := 0; at < len(block) && block[at] != 0; {
				n := int(block[at])
				if n < 34 || n > len(block)-at {
					return fileSpan{}, fmt.Errorf("invalid ISO directory record")
				}
				rec := block[at : at+n]
				at += n
				nameLen := int(rec[32])
				if nameLen < 1 || 33+nameLen > len(rec) {
					return fileSpan{}, fmt.Errorf("invalid ISO name length")
				}
				name := strings.TrimSuffix(string(rec[33:33+nameLen]), ";1")
				if !strings.EqualFold(name, part) {
					continue
				}
				lba, size := binary.LittleEndian.Uint32(rec[2:]), binary.LittleEndian.Uint32(rec[10:])
				unsupportedLayout := rec[1] != 0 || rec[26] != 0 || rec[27] != 0 || binary.LittleEndian.Uint16(rec[28:]) != 1 || binary.BigEndian.Uint16(rec[30:]) != 1 || rec[25]&128 != 0
				invalidExtent := lba != binary.BigEndian.Uint32(rec[6:]) || size != binary.BigEndian.Uint32(rec[14:]) || int64(lba)*isoSector > imageSize || int64(size) > imageSize-int64(lba)*isoSector
				wrongType := (rec[25]&2 != 0) != (depth < len(parts)-1)
				if unsupportedLayout || invalidExtent || wrongType {
					return fileSpan{}, fmt.Errorf("invalid ISO extent or file type for %s", path)
				}
				found = fileSpan{int64(lba) * isoSector, int64(size)}
				matches++
			}
		}
		if matches != 1 {
			return fileSpan{}, fmt.Errorf("ISO path %q has %d matches at %q", path, matches, part)
		}
		current = found
	}
	return current, nil
}

// cmbIndex resolves exact member names within a pinned fixed-size CMB archive.
// It also retains index order, independently of physical payload order. Duplicate
// or overlapping records reject the whole index before any member is trusted.
func cmbIndex(image io.ReaderAt, archive fileSpan, expectedIndexSHA string) (map[string]fileSpan, []string, error) {
	header := make([]byte, 8)
	if _, err := image.ReadAt(header, archive.offset); err != nil {
		return nil, nil, err
	}
	base, count := uint64(binary.LittleEndian.Uint32(header)), uint64(binary.LittleEndian.Uint32(header[4:]))
	if count == 0 || count > 100000 || base != 8+88*count || base > uint64(archive.size) {
		return nil, nil, fmt.Errorf("invalid CMB header")
	}
	index := make([]byte, base)
	if _, err := image.ReadAt(index, archive.offset); err != nil {
		return nil, nil, err
	}
	if fmt.Sprintf("%x", sha256.Sum256(index)) != expectedIndexSHA {
		return nil, nil, fmt.Errorf("CMB index hash mismatch")
	}
	members := make(map[string]fileSpan, count)
	order := make([]string, 0, count)
	seen := make(map[string]bool, count)
	intervals := make([]fileSpan, 0, count)
	for i := uint64(0); i < count; i++ {
		record := index[8+88*i : 8+88*(i+1)]
		end := bytes.IndexByte(record[:80], 0)
		if end <= 0 {
			return nil, nil, fmt.Errorf("invalid CMB member name")
		}
		name := string(record[:end])
		key := strings.ToLower(name)
		if seen[key] || strings.ContainsAny(name, "/\x00") {
			return nil, nil, fmt.Errorf("duplicate or invalid CMB member %q", name)
		}
		seen[key] = true
		rel, size := uint64(binary.LittleEndian.Uint32(record[80:])), uint64(binary.LittleEndian.Uint32(record[84:]))
		if size == 0 || rel > uint64(archive.size)-base || size > uint64(archive.size)-base-rel {
			return nil, nil, fmt.Errorf("CMB member %q exceeds archive", name)
		}
		span := fileSpan{archive.offset + int64(base+rel), int64(size)}
		members[name] = span
		order = append(order, name)
		intervals = append(intervals, span)
	}
	sort.Slice(intervals, func(i, j int) bool { return intervals[i].offset < intervals[j].offset })
	for i := 1; i < len(intervals); i++ {
		if intervals[i].offset < intervals[i-1].offset+intervals[i-1].size {
			return nil, nil, fmt.Errorf("overlapping CMB members")
		}
	}
	return members, order, nil
}

// planBundle turns pinned ISO files or indexed CMB members into guarded edits.
// Source/image and bundle hashes are independently checked by verifySource and here.
func planBundle(recipe Recipes, source io.ReaderAt) ([]Edit, error) {
	if recipe.Sentinel != nil || recipe.RegistryInputs != nil || recipe.RegistryImport != nil || recipe.RegistryColumns != nil || recipe.AddressRanges != nil || recipe.WordingField != "" || source == nil || recipe.SourceSize <= 0 || recipe.BundlePath == "" || recipe.Evidence == "" || len(recipe.Entries)+len(recipe.Values)+len(recipe.WordBlocks) != 0 || recipe.Stream != nil || recipe.Layout != nil || recipe.Growth != nil || recipe.References != nil || recipe.RegistryUpdates != nil || recipe.RegistryPatchRef != "" || recipe.ScopeSHA256 != "" || recipe.GlyphmapSHA256 != "" || recipe.ISOELFOffset != "" || recipe.ELFVMADelta != "" || recipe.Placement != "" || recipe.PointerState != "" || recipe.SourceContext || recipe.Updated != "" || recipe.BaseRecipe != "" || recipe.BaseSHA256 != "" {
		return nil, fmt.Errorf("incomplete or mixed named-bundle recipe")
	}
	switch recipe.Operation {
	case "cmb_member_replace":
		if len(recipe.Archives) == 0 || len(recipe.Files) != 0 {
			return nil, fmt.Errorf("CMB replacement requires only indexed archives")
		}
	case "iso_file_replace":
		if len(recipe.Files) == 0 || len(recipe.Archives) != 0 || recipe.OutputSHA256 == "" {
			return nil, fmt.Errorf("ISO file replacement requires named files and output hash")
		}
	default:
		return nil, fmt.Errorf("unsupported named-bundle operation")
	}
	pins := []string{recipe.SourceSHA256, recipe.BundleSHA256, recipe.TargetReferenceSHA256}
	if recipe.OutputSHA256 != "" {
		pins = append(pins, recipe.OutputSHA256)
	}
	for _, pin := range pins {
		value, err := hex.DecodeString(pin)
		if err != nil || len(value) != sha256.Size {
			return nil, fmt.Errorf("invalid CMB SHA-256 pin")
		}
	}
	bundleInfo, err := os.Stat(recipe.BundlePath)
	if err != nil {
		return nil, err
	}
	if !bundleInfo.Mode().IsRegular() || bundleInfo.Size() <= 0 || bundleInfo.Size() > 128<<20 {
		return nil, fmt.Errorf("invalid CMB bundle size/type")
	}
	bundleBytes, err := os.ReadFile(recipe.BundlePath)
	if err != nil {
		return nil, err
	}
	if fmt.Sprintf("%x", sha256.Sum256(bundleBytes)) != recipe.BundleSHA256 {
		return nil, fmt.Errorf("CMB bundle hash mismatch")
	}
	bundle, err := zip.NewReader(bytes.NewReader(bundleBytes), int64(len(bundleBytes)))
	if err != nil {
		return nil, err
	}
	files := make(map[string]*zip.File, len(bundle.File))
	for _, file := range bundle.File {
		if file.FileInfo().IsDir() || files[file.Name] != nil || file.Flags&1 != 0 {
			return nil, fmt.Errorf("invalid or duplicate CMB bundle entry %q", file.Name)
		}
		files[file.Name] = file
	}
	type bundleReplacement struct {
		key    string
		span   fileSpan
		member BundleMember
	}
	var replacements []bundleReplacement
	for _, path := range slices.Sorted(maps.Keys(recipe.Files)) {
		file := recipe.Files[path]
		extent, err := isoFileExtent(source, recipe.SourceSize, path)
		if err != nil {
			return nil, err
		}
		if extent.offset != file.SourceISOOffset || extent.size != file.Size {
			return nil, fmt.Errorf("ISO file extent mismatch: %s", path)
		}
		replacements = append(replacements, bundleReplacement{path, extent, file.BundleMember})
	}
	for _, archivePath := range slices.Sorted(maps.Keys(recipe.Archives)) {
		archive := recipe.Archives[archivePath]
		extent, err := isoFileExtent(source, recipe.SourceSize, archivePath)
		if err != nil {
			return nil, err
		}
		if extent.offset != archive.SourceISOOffset || extent.size != archive.Size || len(archive.Members) == 0 {
			return nil, fmt.Errorf("CMB archive extent or members mismatch: %s", archivePath)
		}
		members, _, err := cmbIndex(source, extent, archive.IndexSHA256)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", archivePath, err)
		}
		for _, name := range slices.Sorted(maps.Keys(archive.Members)) {
			member := archive.Members[name]
			span, ok := members[name]
			key := archivePath + "/" + strings.ReplaceAll(name, "\\", "/")
			if !ok {
				return nil, fmt.Errorf("CMB member missing: %s", key)
			}
			replacements = append(replacements, bundleReplacement{key, span, member})
		}
	}
	var edits []Edit
	for _, replacement := range replacements {
		key, span, member := replacement.key, replacement.span, replacement.member
		file := files[member.BundleKey]
		if member.Size <= 0 || span.size != member.Size || member.BundleKey != key || file == nil || file.UncompressedSize64 != uint64(member.Size) || member.Size > 64<<20 {
			return nil, fmt.Errorf("named file/member or bundle scope mismatch: %s", key)
		}
		old := make([]byte, member.Size)
		if _, err := source.ReadAt(old, span.offset); err != nil {
			return nil, err
		}
		if fmt.Sprintf("%x", sha256.Sum256(old)) != member.SourceSHA256 {
			return nil, fmt.Errorf("bundle source hash mismatch: %s", key)
		}
		reader, err := file.Open()
		if err != nil {
			return nil, err
		}
		newBytes, readErr := io.ReadAll(io.LimitReader(reader, member.Size+1))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || int64(len(newBytes)) != member.Size || fmt.Sprintf("%x", sha256.Sum256(newBytes)) != member.TargetSHA256 {
			return nil, fmt.Errorf("bundle target mismatch: %s", key)
		}
		delete(files, member.BundleKey)
		edits = append(edits, Edit{ID: key, Offset: span.offset, Old: old, New: newBytes, Operation: recipe.Operation})
	}
	if len(files) != 0 {
		return nil, fmt.Errorf("unreferenced CMB bundle entries")
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].Offset < edits[j].Offset })
	return edits, validateEdits(edits, recipe.SourceSize)
}
