package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"unicode/utf8"
)

// manifestTextures streams a pinned extracted CMB into an ordered asset index.
// All entries survive decode failures. Publication is one exclusive ZIP, so a
// failed join or source recheck cannot leave a partially published collection.
func manifestTextures(sourcePath, profilePath, output string, profile TextureProfile, profileData []byte, apply bool, stdout io.Writer) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	before, err := source.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() != profile.SourceSize {
		return fmt.Errorf("manifest source size/type mismatch")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.NewSectionReader(source, 0, profile.SourceSize))
	if err != nil || n != profile.SourceSize || fmt.Sprintf("%x", hash.Sum(nil)) != profile.SourceSHA256 {
		return fmt.Errorf("manifest source identity mismatch")
	}
	members, order, err := cmbIndex(source, fileSpan{0, profile.SourceSize}, profile.IndexSHA256)
	if err != nil {
		return err
	}
	annotations := make(map[string]string)
	for _, id := range slices.Sorted(maps.Keys(profile.Specifications)) {
		spec := profile.Specifications[id]
		_, present := members[spec.Entry]
		key := spec.Entry + "\x00" + spec.Texture
		if strings.TrimSpace(id) == "" || len(id) > 256 || !present || strings.ContainsRune(spec.Entry+spec.Texture, 0) || len(spec.Texture) > 1024 || spec.Archive != "" && spec.Archive != profile.Archive || annotations[key] != "" {
			return fmt.Errorf("invalid or repeated manifest specification %q", id)
		}
		annotations[key] = id
	}
	manifest := TextureManifest{Archive: profile.Archive, SourceSHA256: profile.SourceSHA256, SourceSize: profile.SourceSize, IndexSHA256: profile.IndexSHA256,
		ProfileSHA256: fmt.Sprintf("%x", sha256.Sum256(profileData)), PNGConversion: "Pillow12.3", Entries: []TextureManifestEntry{},
		Limits: "All pinned CMB index entries, in index order. Decoding uses calibrated shared codecs; source failures and work bounds remain explicit. Discovery is advisory, not OCR or screen/visual/patch approval. Detector scores are unavailable for the reference's below-8px and cropped-mask error domains. Preview links are relative to this ZIP; unjoined asset_id is empty, raw PNG native_ordinal is -1. Archive is a declared source label."}
	var bundle bytes.Buffer
	archive := zip.NewWriter(&bundle)
	matched := make(map[string]bool)
	requestedPixels := uint64(0)
	rasterRows := 0
	for ordinal, name := range order {
		if !utf8.ValidString(name) {
			return fmt.Errorf("manifest entry names require UTF-8")
		}
		span := members[name]
		entry := TextureManifestEntry{Ordinal: ordinal, Name: name, SourceRange: [2]int64{span.offset, span.offset + span.size}, SourceSize: span.size, Rasters: []TextureManifestRaster{}}
		hash.Reset()
		n, err := io.Copy(hash, io.NewSectionReader(source, span.offset, span.size))
		if err != nil || n != span.size {
			return fmt.Errorf("manifest entry %d could not be read", ordinal)
		}
		entry.SourceSHA256 = fmt.Sprintf("%x", hash.Sum(nil))
		if span.size > 64<<20 {
			entry.Status, entry.Diagnostic = "unavailable", "entry exceeds 64MiB decode bound"
			manifest.Entries = append(manifest.Entries, entry)
			continue
		}
		data := make([]byte, span.size)
		if _, err := source.ReadAt(data, span.offset); err != nil {
			return err
		}
		isPNG := bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n"))
		var natives []NativeTexture
		var nativeIndex *TextureIndex
		switch {
		case isPNG:
			entry.Status, natives = "raw-png", []NativeTexture{{}}
		case len(data) >= 4 && bytes.Equal(data[:4], []byte{0x16, 0, 0, 0}):
			index, err := indexTextures(data)
			if err != nil {
				entry.Status, entry.Diagnostic = "invalid-txd", err.Error()
			} else {
				entry.Status, natives = "indexed", index.Textures
				nativeIndex = &index
				if len(natives) == 0 {
					entry.Status = "empty-txd"
				}
			}
		default:
			entry.Status = "not-texture-archive"
		}
		rasterRows += len(natives)
		if rasterRows > 100000 {
			return fmt.Errorf("manifest exceeds 100000 raster rows")
		}
		for nativeOrdinal, native := range natives {
			row := TextureManifestRaster{TextureSpecificationRow: TextureSpecificationRow{NativeOrdinal: nativeOrdinal, Specification: TextureSpecification{Texture: native.Name}, Header: native.Header, DecodedStatus: "unavailable"}}
			if isPNG {
				row.NativeOrdinal = -1
			}
			key := name + "\x00" + native.Name
			if id := annotations[key]; id != "" {
				if matched[id] {
					return fmt.Errorf("manifest specification %q matches multiple native textures", id)
				}
				matched[id], row.ID, row.Specification = true, id, profile.Specifications[id]
			}
			var raster *image.NRGBA
			if isPNG {
				var charged uint64
				raster, charged, err = decodePNG(data, (1<<28)-requestedPixels)
				requestedPixels += charged
				switch err {
				case nil:
					row.DecodedFormat = "PNG"
				case errPNGPixelBudget:
					row.Diagnostic = "manifest decoded pixel work budget exhausted"
				case errPNGChunkBounds:
					return err
				default:
					row.Diagnostic = err.Error()
				}
			} else {
				var area uint64
				if native.Header != nil {
					area = uint64(native.Header.Width) * uint64(native.Header.Height)
				}
				withinBudget := area == 0 || area > 1<<20 || requestedPixels+area <= 1<<28
				if area > 0 && area <= 1<<20 && withinBudget {
					requestedPixels += area
				}
				if !withinBudget {
					row.Diagnostic = "manifest decoded pixel work budget exhausted"
				} else {
					policy := ""
					if native.Header != nil && native.Header.Depth == 32 {
						policy = "rgba"
					}
					_, raster, err = texture(data, native.Name, nil, nil, policy, nativeIndex)
					if err != nil {
						row.Diagnostic = err.Error()
					} else {
						switch native.Header.Depth {
						case 4:
							row.DecodedFormat = "PSMT4"
						case 8:
							row.DecodedFormat = "PSMT8"
						case 32:
							row.DecodedFormat = "PSMCT32"
						}
					}
				}
			}
			row.Discovery = inspectRaster(raster, name, native.Name)
			if raster != nil {
				row.DecodedStatus, row.DecodedGeometry = "decoded", &[2]int{raster.Rect.Dx(), raster.Rect.Dy()}
				digest := fmt.Sprintf("%x", sha256.Sum256(raster.Pix))
				row.RGBASHA256 = &digest
				var preview bytes.Buffer
				if isPNG {
					preview.Write(data)
				} else if err := png.Encode(&preview, raster); err != nil {
					return err
				}
				row.Preview = fmt.Sprintf("previews/%06d_%04d.png", ordinal, nativeOrdinal)
				row.PreviewSHA256 = fmt.Sprintf("%x", sha256.Sum256(preview.Bytes()))
				file, err := archive.CreateHeader(&zip.FileHeader{Name: row.Preview, Method: zip.Store})
				if err != nil {
					return err
				}
				if _, err := file.Write(preview.Bytes()); err != nil {
					return err
				}
				if bundle.Len() > 128<<20 {
					return fmt.Errorf("manifest preview bundle exceeds 128MiB")
				}
			}
			entry.Rasters = append(entry.Rasters, row)
		}
		manifest.Entries = append(manifest.Entries, entry)
	}
	if len(matched) != len(profile.Specifications) {
		return fmt.Errorf("manifest specifications did not all join exact native assets")
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	file, err := archive.CreateHeader(&zip.FileHeader{Name: "manifest.json", Method: zip.Store})
	if err != nil {
		return err
	}
	if _, err := file.Write(append(manifestData, '\n')); err != nil {
		return err
	}
	if err := archive.Close(); err != nil {
		return err
	}
	if bundle.Len() > 128<<20 {
		return fmt.Errorf("manifest bundle exceeds 128MiB")
	}
	hash.Reset()
	n, err = io.Copy(hash, io.NewSectionReader(source, 0, profile.SourceSize))
	after, statErr := source.Stat()
	current, pathErr := os.Stat(sourcePath)
	if err != nil || statErr != nil || pathErr != nil || n != profile.SourceSize || fmt.Sprintf("%x", hash.Sum(nil)) != profile.SourceSHA256 || after.Size() != before.Size() || after.ModTime() != before.ModTime() || !os.SameFile(before, current) {
		return fmt.Errorf("manifest source changed during traversal")
	}
	if err := source.Close(); err != nil {
		return err
	}
	currentProfile, err := readInput(profilePath, 1<<20)
	if err != nil || !bytes.Equal(currentProfile, profileData) {
		return fmt.Errorf("manifest profile changed during traversal")
	}
	bundleDigest := fmt.Sprintf("%x", sha256.Sum256(bundle.Bytes()))
	if apply {
		if err := writeNewFile(output, bytes.NewReader(bundle.Bytes()), int64(bundle.Len()), bundleDigest, 0600); err != nil {
			return err
		}
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(map[string]any{"operation": "texture_authoring", "mode": "manifest", "applied": apply, "manifest": manifest, "bundle_sha256": bundleDigest, "bundle_size": bundle.Len()})
}
