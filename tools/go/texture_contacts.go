package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	_ "embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"io/fs"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

//go:embed profiles/previews/inventory-layout.json
var textureContactLayout []byte

// contactSheets joins pinned manifest bundles before grouping or sorting assets.
// Non-UI duplicates are removed before sorting, per group. Final page links can
// be overwritten by later groups; CSV then propagates the first linked pixel hash.
// Empty source hashes deliberately do not deduplicate. Publication is one new ZIP.
func contactSheets(sourcePath, profilePath, output string, profile TextureProfile, profileData []byte, apply bool, stdout io.Writer) error {
	var layout struct {
		EntrySuffix              int       `json:"entry_suffix"`
		TextureSuffix            int       `json:"texture_suffix"`
		Groups                   [4]string `json:"groups"`
		Columns, Rows            int
		Cell, Thumbnail, Padding [2]int
		Background               [3]uint8
		ThumbnailBackground      [3]uint8    `json:"thumbnail_background"`
		Positions                [2][2]int   `json:"label_positions"`
		Colors                   [2][3]uint8 `json:"label_colors"`
		FontSize                 int         `json:"font_size"`
		FontLayout               string      `json:"font_layout"`
		PixelArtThreshold        int         `json:"pixel_art_threshold"`
	}
	if err := json.Unmarshal(textureContactLayout, &layout); err != nil {
		return err
	}
	if layout.Columns < 1 || layout.Columns > 64 || layout.Rows < 1 || layout.Rows > 64 || layout.Cell[0] < 1 || layout.Cell[0] > 4096 || layout.Cell[1] < 1 || layout.Cell[1] > 4096 || layout.Columns*layout.Cell[0] > 4096 || layout.Rows*layout.Cell[1] > 4096 || layout.Columns*layout.Rows*layout.Cell[0]*layout.Cell[1] > 1<<20 || layout.Thumbnail[0] < 1 || layout.Thumbnail[1] < 1 || layout.Padding[0] < 0 || layout.Padding[1] < 0 || layout.Padding[0]+layout.Thumbnail[0] > layout.Cell[0] || layout.Padding[1]+layout.Thumbnail[1] > layout.Cell[1] || layout.EntrySuffix < 0 || layout.EntrySuffix > 4096 || layout.TextureSuffix < 0 || layout.TextureSuffix > 1024 {
		return fmt.Errorf("invalid contact layout or page bounds")
	}
	groupNamesSeen := make(map[string]bool)
	for _, name := range layout.Groups {
		if name == "." || !fs.ValidPath(name) || strings.ContainsAny(name, "/\\") || groupNamesSeen[name] {
			return fmt.Errorf("invalid contact group name")
		}
		groupNamesSeen[name] = true
	}
	for _, position := range layout.Positions {
		if position[0] < 0 || position[0] >= layout.Cell[0] || position[1] < 0 || position[1] >= layout.Cell[1] {
			return fmt.Errorf("invalid contact label anchor")
		}
	}

	inputs := append([]RegistryInput{{Path: sourcePath, Size: profile.SourceSize, SHA256: profile.SourceSHA256}}, profile.Contacts.Sources...)
	inputs = append(inputs, profile.Contacts.Font)
	paths := make([]string, len(inputs))
	contents := make([][]byte, len(inputs))
	totalInput := int64(0)
	for i, input := range inputs {
		limit := int64(128 << 20)
		if i == len(inputs)-1 {
			limit = 4 << 20
		}
		if input.Path == "" || input.Size < 1 || input.Size > limit {
			return fmt.Errorf("invalid contacts input bounds")
		}
		path := input.Path
		if i != 0 && !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(profilePath), path)
		}
		data, err := readInput(path, limit)
		if err != nil {
			return err
		}
		if int64(len(data)) != input.Size || fmt.Sprintf("%x", sha256.Sum256(data)) != input.SHA256 {
			return fmt.Errorf("contacts input identity mismatch: %s", path)
		}
		totalInput += int64(len(data))
		if totalInput > 256<<20 {
			return fmt.Errorf("contacts inputs exceed 256MiB")
		}
		paths[i], contents[i] = path, data
	}
	font := contents[len(contents)-1]
	baseline, err := textMasks(font, layout.FontSize, layout.FontLayout, []TextRequest{{Text: "A"}})
	if err != nil {
		return err
	}
	lineStep := baseline[0].Bearing.Y + baseline[0].Coverage.Rect.Dy() + 4
	rows := []TextureContactRow{}
	type measuredPreview struct {
		Encoded                        []byte
		EncodedSHA, PixelSHA, PixelKey string
		Size                           [2]int
		Thumbnail                      *image.NRGBA
	}
	previews := make(map[string]measuredPreview)
	geometries := make(map[string][2]int)
	pixelKeys := make(map[string]string)
	sourceManifests := []TextureManifest{}
	requestedPixels, expandedBytes := uint64(0), uint64(0)
	for sourceOrdinal, data := range contents[:len(contents)-1] {
		archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return err
		}
		if len(archive.File) > 100001 {
			return fmt.Errorf("contacts source exceeds member count")
		}
		files := make(map[string]*zip.File)
		for _, member := range archive.File {
			if !utf8.ValidString(member.Name) || !fs.ValidPath(member.Name) || member.Name == "." || strings.ContainsAny(member.Name, "\\\x00") || !member.Mode().IsRegular() || files[member.Name] != nil || member.UncompressedSize64 > 64<<20 {
				return fmt.Errorf("invalid or repeated contacts ZIP member")
			}
			expandedBytes += member.UncompressedSize64
			if expandedBytes > 256<<20 {
				return fmt.Errorf("contacts expanded sources exceed 256MiB")
			}
			files[member.Name] = member
		}
		manifestFile := files["manifest.json"]
		if manifestFile == nil || manifestFile.UncompressedSize64 > 32<<20 {
			return fmt.Errorf("contacts requires bounded manifest.json")
		}
		reader, err := manifestFile.Open()
		if err != nil {
			return err
		}
		raw, readErr := io.ReadAll(io.LimitReader(reader, (32<<20)+1))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || len(raw) > 32<<20 {
			return fmt.Errorf("contacts manifest read failed")
		}
		sourceFields := map[int][]string{
			1: {"archive", "source_sha256", "source_size", "index_sha256", "profile_sha256", "raw_png_rgba_conversion", "entries", "limits"},
			3: {"ordinal", "name", "source_file_range", "source_sha256", "source_size", "status", "diagnostic", "rasters"},
			5: {"asset_id", "native_ordinal", "specification", "header", "decoded_status", "decoded_geometry", "decoded_format", "rgba_sha256", "diagnostic", "discovery", "preview", "preview_sha256"},
			6: {"texture", "archive", "entry", "kind", "description", "jp_text", "proposed_en", "difficulty", "screen_hint", "notes", "width", "height", "depth", "raster_format", "version", "tier", "status", "score", "flag_reasons", "diagnostic"},
			7: {"glyph_clusters", "cluster_fraction", "glyph_tiles", "dominant_color_fraction", "opaque_fraction", "text_line_rows"},
		}
		if err := checkJSON(checkedJSON{raw: raw, allObjects: true, text: true, aliasesByDepth: sourceFields, fieldsByDepth: sourceFields}); err != nil {
			return err
		}
		var manifest TextureManifest
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&manifest); err != nil {
			return err
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			return fmt.Errorf("contacts manifest requires one object")
		}
		if strings.TrimSpace(manifest.Archive) == "" || len(manifest.Archive) > 256 || strings.ContainsRune(manifest.Archive, 0) || len(manifest.Entries) > 100000 {
			return fmt.Errorf("invalid contacts manifest label/count")
		}
		sourceManifests = append(sourceManifests, manifest)
		entryOrdinals := make(map[int]bool)
		for _, entry := range manifest.Entries {
			entryOrdinal := entry.Ordinal
			if entryOrdinal < 0 || entryOrdinal >= 100000 || entryOrdinals[entryOrdinal] || len(entry.Name) > 4096 || strings.ContainsRune(entry.Name, 0) {
				return fmt.Errorf("invalid contacts entry ordinal/name")
			}
			entryOrdinals[entryOrdinal] = true
			count := max(1, len(entry.Rasters))
			for nativeOrdinal := 0; nativeOrdinal < count; nativeOrdinal++ {
				key := fmt.Sprintf("sources/%03d/%06d/%04d", sourceOrdinal, entryOrdinal, nativeOrdinal)
				row := TextureContactRow{Key: key, Archive: manifest.Archive, Entry: entry.Name, EntryOrdinal: entryOrdinal, EntryStatus: entry.Status, EntryDiagnostic: entry.Diagnostic}
				if len(entry.Rasters) > 0 {
					raster := entry.Rasters[nativeOrdinal]
					row.Raster = &raster
					if len(raster.Specification.Texture) > 1024 || strings.ContainsRune(raster.Specification.Texture, 0) {
						return fmt.Errorf("invalid contacts texture label")
					}
					if raster.DecodedStatus == "decoded" {
						member := files[raster.Preview]
						if member == nil || raster.Preview == "manifest.json" || raster.PreviewSHA256 == "" {
							return fmt.Errorf("decoded contact row requires pinned preview")
						}
						previewPath := fmt.Sprintf("sources/%03d/", sourceOrdinal) + raster.Preview
						measured, present := previews[previewPath]
						if !present {
							reader, err := member.Open()
							if err != nil {
								return err
							}
							encoded, readErr := io.ReadAll(io.LimitReader(reader, (64<<20)+1))
							closeErr := reader.Close()
							if readErr != nil || closeErr != nil || len(encoded) > 64<<20 {
								return fmt.Errorf("contacts preview read failed")
							}
							measured.Encoded, measured.EncodedSHA = encoded, fmt.Sprintf("%x", sha256.Sum256(encoded))
							if measured.EncodedSHA != raster.PreviewSHA256 {
								return fmt.Errorf("contacts preview identity mismatch")
							}
							decoded, charged, err := decodePNG(encoded, (1<<28)-requestedPixels)
							requestedPixels += charged
							if err != nil {
								return fmt.Errorf("contacts preview %s: %w", key, err)
							}
							measured.Size = [2]int{decoded.Rect.Dx(), decoded.Rect.Dy()}
							measured.PixelSHA, measured.PixelKey = fmt.Sprintf("%x", sha256.Sum256(decoded.Pix)), fmt.Sprintf("%x", sha1.Sum(decoded.Pix))[:12]
							previews[previewPath] = measured
						}
						if measured.EncodedSHA != raster.PreviewSHA256 {
							return fmt.Errorf("contacts preview identity mismatch")
						}
						if raster.DecodedGeometry == nil || *raster.DecodedGeometry != measured.Size {
							return fmt.Errorf("contacts preview geometry mismatch")
						}
						// Hash presence controls row dedup even when another row shares this member.
						if raster.RGBASHA256 != nil && *raster.RGBASHA256 != "" {
							if measured.PixelSHA != *raster.RGBASHA256 {
								return fmt.Errorf("contacts preview pixel identity mismatch")
							}
							pixelKeys[key] = measured.PixelKey
						}
						raster.Preview = previewPath
						geometries[key] = measured.Size

					} else if raster.Preview != "" {
						return fmt.Errorf("unavailable contact row cannot carry a preview")
					}
					if raster.Header != nil {
						geometries[key] = [2]int{int(raster.Header.Width), int(raster.Header.Height)}
					}
					if raster.DecodedStatus != "decoded" && raster.DecodedStatus != "unavailable" {
						return fmt.Errorf("unknown contacts decoded status")
					}
					if raster.Discovery.Tier != "ui" && raster.Discovery.Tier != "icons" && raster.Discovery.Tier != "model" {
						return fmt.Errorf("unknown contacts tier")
					}
					switch raster.Discovery.Status {
					case "measured", "unavailable", "not_evaluated":
					default:
						return fmt.Errorf("unknown contacts discovery status")
					}
					if (raster.Discovery.Status == "measured") != (raster.Discovery.Score != nil) {
						return fmt.Errorf("inconsistent contacts discovery status")
					}
					if raster.Discovery.Score != nil {
						score := raster.Discovery.Score
						if score.GlyphClusters < 0 || score.GlyphClusters > 1<<20 || score.TextLineRows < 0 || score.TextLineRows > 4096 || score.GlyphTiles < 0 || score.GlyphTiles > 1<<20 || score.ClusterFraction < 0 || score.ClusterFraction > 1 || score.DominantColorFraction < 0 || score.DominantColorFraction > 1 || score.OpaqueFraction < 0 || score.OpaqueFraction > 1 {
							return fmt.Errorf("invalid contacts discovery score")
						}
					}
				}
				rows = append(rows, row)
				if len(rows) > 100000 {
					return fmt.Errorf("contacts exceeds 100000 rows")
				}
			}
		}
	}
	const (
		uiGroup = iota
		iconGroup
		flaggedModelGroup
		eventGroup
	)
	groups := make([][]int, 4)
	for i, row := range rows {
		raster := row.Raster
		if raster == nil || raster.Preview == "" || raster.Discovery.Status == "not_evaluated" {
			continue
		}
		switch raster.Discovery.Tier {
		case "ui":
			groups[uiGroup] = append(groups[uiGroup], i)
		case "icons":
			groups[iconGroup] = append(groups[iconGroup], i)
		case "model":
			score := raster.Discovery.Score
			detectedText := score != nil && score.TextLineRows >= 1
			if detectedText || slices.Contains(raster.Discovery.FlagReasons, "name-hint") {
				groups[flaggedModelGroup] = append(groups[flaggedModelGroup], i)
			}
			path := strings.ToLower(row.Entry)
			if row.Archive == "EVENT" && (strings.HasPrefix(path, `event\bg`) || strings.HasPrefix(path, `event\race\rm`)) {
				groups[eventGroup] = append(groups[eventGroup], i)
			}
		default:
			return fmt.Errorf("unknown contacts tier")
		}
	}
	groupNames := layout.Groups
	payloadBytes := 0
	for _, data := range previews {
		payloadBytes += len(data.Encoded)
	}
	if payloadBytes > 128<<20 {
		return fmt.Errorf("contacts previews exceed 128MiB")
	}
	pagePixels := uint64(0)
	thumbnailPixels := 0
	pageLinks := make(map[string]string)
	payloads := make(map[string][]byte)
	pageReports := []map[string]any{}
	for group, items := range groups {
		seen := make(map[string]bool)
		ordered := make(map[string]int)
		sortKeys := []string{}
		for _, index := range items {
			row := rows[index]
			pixelKey := pixelKeys[row.Key]
			if group != uiGroup && pixelKey != "" && seen[pixelKey] {
				continue
			}
			seen[pixelKey] = true
			sortKey := fmt.Sprintf("%s\x00%06d\x00%06d", row.Archive, row.EntryOrdinal, index)
			sortKeys = append(sortKeys, sortKey)
			ordered[sortKey] = index
		}
		sort.Strings(sortKeys)
		perPage := layout.Columns * layout.Rows
		for start := 0; start < len(sortKeys); start += perPage {
			name := fmt.Sprintf("sheets/%s_%03d.png", groupNames[group], start/perPage+1)
			width, height := layout.Columns*layout.Cell[0], layout.Rows*layout.Cell[1]
			pagePixels += uint64(width) * uint64(height)
			if pagePixels > 1<<28 {
				return fmt.Errorf("contacts page work exceeds 256M pixels")
			}
			canvas := image.NewNRGBA(image.Rect(0, 0, width, height))
			for i := 0; i < len(canvas.Pix); i += 4 {
				copy(canvas.Pix[i:i+3], layout.Background[:])
				canvas.Pix[i+3] = 255
			}
			var labels []TextRequest
			var positions []image.Point
			var labelColors [][3]uint8
			type placement struct {
				Origin               image.Point
				Thumbnail            *image.NRGBA
				LabelStart, LabelEnd int
			}
			var placements []placement
			for position, key := range sortKeys[start:min(start+perPage, len(sortKeys))] {
				row := rows[ordered[key]]
				raster := row.Raster
				measured := previews[raster.Preview]
				if measured.Thumbnail == nil {
					pixels, charged, err := decodePNG(measured.Encoded, (1<<28)-requestedPixels)
					requestedPixels += charged
					if err != nil {
						return err
					}
					filter := "thumbnail-lanczos"
					if min(pixels.Rect.Dx(), pixels.Rect.Dy()) <= layout.PixelArtThreshold {
						filter = "thumbnail-nearest"
					}
					thumb, err := resizeRaster(pixels, layout.Thumbnail[0], layout.Thumbnail[1], filter, nil)
					if err != nil {
						return err
					}
					measured.Thumbnail = thumb.(*image.NRGBA)
					thumbnailPixels += measured.Thumbnail.Rect.Dx() * measured.Thumbnail.Rect.Dy()
					if thumbnailPixels > 1<<24 {
						return fmt.Errorf("contacts thumbnail cache exceeds 16M pixels")
					}
					previews[raster.Preview] = measured
				}
				thumbnail := measured.Thumbnail
				x, y := position%layout.Columns*layout.Cell[0], position/layout.Columns*layout.Cell[1]
				_, tail, ok := strings.Cut(row.Entry, "\\")
				if !ok {
					tail = row.Entry
				}
				entryTail := []rune(tail)
				entryTail = entryTail[max(0, len(entryTail)-layout.EntrySuffix):]
				textureTail := []rune(raster.Specification.Texture)
				textureTail = textureTail[max(0, len(textureTail)-layout.TextureSuffix):]
				dimensions := geometries[row.Key]
				labelStart := len(labels)
				// The original error tuple supplies a display sentinel, not a measurement.
				glyphClusters := -1
				if score := raster.Discovery.Score; score != nil {
					glyphClusters = score.GlyphClusters
				}
				formatted := []string{row.Archive + ":" + string(entryTail), fmt.Sprintf("%s %dx%d #%d s%d", string(textureTail), dimensions[0], dimensions[1], row.EntryOrdinal, glyphClusters)}
				for logical, label := range formatted {
					offset := layout.Positions[logical]
					for line, text := range strings.Split(label, "\n") {
						labels = append(labels, TextRequest{Text: text})
						positions = append(positions, image.Pt(x+offset[0], y+offset[1]+line*lineStep))
						labelColors = append(labelColors, layout.Colors[logical])
					}
				}
				placements = append(placements, placement{image.Pt(x, y), thumbnail, labelStart, len(labels)})
				pageLinks[raster.Preview] = name
			}
			var masks []TextMask
			for start := 0; start < len(labels); start += 4096 {
				batch, err := textMasks(font, layout.FontSize, layout.FontLayout, labels[start:min(start+4096, len(labels))])
				if err != nil {
					return err
				}
				masks = append(masks, batch...)
			}
			// Earlier ink may spill into a later thumbnail; preserve the original item order.
			for _, item := range placements {
				for ty := 0; ty < item.Thumbnail.Rect.Dy(); ty++ {
					for tx := 0; tx < item.Thumbnail.Rect.Dx(); tx++ {
						bg := color.NRGBA{layout.ThumbnailBackground[0], layout.ThumbnailBackground[1], layout.ThumbnailBackground[2], 255}
						canvas.SetNRGBA(item.Origin.X+layout.Padding[0]+tx, item.Origin.Y+layout.Padding[1]+ty, pixelOver(bg, item.Thumbnail.NRGBAAt(tx, ty)))
					}
				}
				for i := item.LabelStart; i < item.LabelEnd; i++ {
					mask := masks[i]
					at := positions[i].Add(mask.Bearing)
					ink := labelColors[i]
					for y := 0; y < mask.Coverage.Rect.Dy(); y++ {
						for x := 0; x < mask.Coverage.Rect.Dx(); x++ {
							target := at.Add(image.Pt(x, y))
							if target.In(canvas.Rect) {
								canvas.SetNRGBA(target.X, target.Y, pixelOver(canvas.NRGBAAt(target.X, target.Y), color.NRGBA{ink[0], ink[1], ink[2], mask.Coverage.GrayAt(x, y).Y}))
							}
						}
					}
				}
			}
			var encoded bytes.Buffer
			if err := png.Encode(&encoded, canvas); err != nil {
				return err
			}
			payloadBytes += encoded.Len()
			if payloadBytes > 128<<20 {
				return fmt.Errorf("contacts pages/previews exceed 128MiB")
			}
			payloads[name] = encoded.Bytes()
			pageReports = append(pageReports, map[string]any{"path": name, "size": [2]int{width, height}, "rgba_sha256": fmt.Sprintf("%x", sha256.Sum256(canvas.Pix)), "png_sha256": fmt.Sprintf("%x", sha256.Sum256(encoded.Bytes()))})
		}
	}
	// Link propagation is separate from group deduplication and keeps source order.
	firstLinked := make(map[string]string)
	for _, row := range rows {
		if row.Raster != nil && pixelKeys[row.Key] != "" && pageLinks[row.Raster.Preview] != "" {
			if _, present := firstLinked[pixelKeys[row.Key]]; !present {
				firstLinked[pixelKeys[row.Key]] = pageLinks[row.Raster.Preview]
			}
		}
	}
	var inventory bytes.Buffer
	csvWriter := csv.NewWriter(&inventory)
	if err := csvWriter.Write([]string{"archive", "idx", "entry", "texture", "w", "h", "depth", "status", "png", "tier", "flagged", "flag_reason", "glyph_clusters", "text_lines", "sheet"}); err != nil {
		return err
	}
	for i := range rows {
		row := &rows[i]
		raster := row.Raster
		values := []string{row.Archive, strconv.Itoa(row.EntryOrdinal), row.Entry, "", "0", "0", "0", row.EntryStatus, "", "", "0", "", "", "", ""}
		if raster != nil {
			row.Sheet = pageLinks[raster.Preview]
			if row.Sheet == "" && raster.Preview != "" && pixelKeys[row.Key] != "" && firstLinked[pixelKeys[row.Key]] != "" {
				row.Sheet = firstLinked[pixelKeys[row.Key]] + " (dup pixels)"
			}
			dimensions := geometries[row.Key]
			depth := uint32(0)
			if raster.Header != nil {
				depth = raster.Header.Depth
			}
			values[3], values[4], values[5], values[6], values[7], values[8], values[9] = raster.Specification.Texture, strconv.Itoa(dimensions[0]), strconv.Itoa(dimensions[1]), strconv.FormatUint(uint64(depth), 10), raster.DecodedStatus, raster.Preview, raster.Discovery.Tier
			if len(raster.Discovery.FlagReasons) > 0 {
				values[10] = "1"
			}
			values[11] = strings.Join(raster.Discovery.FlagReasons, "+")
			if score := raster.Discovery.Score; score != nil {
				values[12], values[13] = strconv.Itoa(score.GlyphClusters), strconv.Itoa(score.TextLineRows)
			} else if raster.Preview != "" && raster.Discovery.Status == "unavailable" {
				values[12], values[13] = "-1", "0"
			}
			values[14] = row.Sheet
		}
		if err := csvWriter.Write(values); err != nil {
			return err
		}
	}
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		return err
	}
	report := map[string]any{"operation": "texture_authoring", "mode": "contacts", "profile_sha256": fmt.Sprintf("%x", sha256.Sum256(profileData)), "layout_sha256": fmt.Sprintf("%x", sha256.Sum256(textureContactLayout)), "font": profile.Contacts.Font, "sources": sourceManifests, "rows": rows, "pages": pageReports, "limits": "Pinned extracted manifest collection only. Source order precedes per-group pixel dedup, then stable archive/index sort. Legacy12hexSHA1 pixel dedup ignores dimensions; absent/empty pixel hashes never dedup. Labels clip to whole page; no OCR, source edits, native blend, artwork, visual or patch approval.256MiB inputs/expanded ZIPs;100000rows;256Mpixel decode/page work;1Mpage pixels;16Mpx thumbnail cache;128MiB outputZIP."}
	reportData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if len(reportData) > 32<<20 {
		return fmt.Errorf("contacts report exceeds 32MiB")
	}
	payloads["manifest.json"], payloads["inventory.csv"] = append(reportData, '\n'), inventory.Bytes()
	for name, data := range previews {
		payloads[name] = data.Encoded
	}
	names := make([]string, 0, len(payloads))
	totalOutput := 0
	for name, data := range payloads {
		names = append(names, name)
		totalOutput += len(data)
		if totalOutput > 128<<20 {
			return fmt.Errorf("contacts payloads exceed 128MiB")
		}
	}
	sort.Strings(names)
	var bundle bytes.Buffer
	archive := zip.NewWriter(&bundle)
	for _, name := range names {
		file, err := archive.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			return err
		}
		if _, err := file.Write(payloads[name]); err != nil {
			return err
		}
	}
	if err := archive.Close(); err != nil {
		return err
	}
	if bundle.Len() > 128<<20 {
		return fmt.Errorf("contacts bundle exceeds 128MiB")
	}
	for i, path := range paths {
		current, err := readInput(path, int64(len(contents[i])))
		if err != nil || !bytes.Equal(current, contents[i]) {
			return fmt.Errorf("contacts input changed before publication: %s", path)
		}
	}
	current, err := readInput(profilePath, 1<<20)
	if err != nil || !bytes.Equal(current, profileData) {
		return fmt.Errorf("contacts profile changed before publication")
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(bundle.Bytes()))
	if apply {
		if err := writeNewFile(output, bytes.NewReader(bundle.Bytes()), int64(bundle.Len()), digest, 0600); err != nil {
			return err
		}
	}
	report["applied"] = apply
	report["bundle_sha256"], report["bundle_size"] = digest, bundle.Len()
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
