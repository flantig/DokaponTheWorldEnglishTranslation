package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
)

//go:embed profiles/previews/pair-layouts.json
var texturePairLayouts []byte

// authorTexture dispatches pinned TXD authoring, discovery or PNG comparisons.
// It never opens an ISO writer; publication is exclusive and preserves source files.
// Specification joins preserve declared annotations; metadata and decoded geometry
// stay distinct, and an unavailable measurement never gains a fallback value.
func authorTexture(sourcePath, profilePath, output string, apply bool, stdout io.Writer) error {
	if apply != (output != "") {
		return fmt.Errorf("texture apply requires a new output path; preview takes no output")
	}
	profileData, err := readInput(profilePath, 1<<20)
	if err != nil || !utf8.Valid(profileData) {
		return fmt.Errorf("texture profile must be readable UTF-8: %v", err)
	}
	var profile TextureProfile
	decoder := json.NewDecoder(bytes.NewReader(profileData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("texture profile requires one JSON object")
	}
	// A later null render must not hide an authored resource request.
	if err := checkJSON(checkedJSON{raw: profileData, aliasesByDepth: map[int][]string{1: {"render"}}}); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	var maskData json.RawMessage
	_ = json.Unmarshal(profileData, &fields)
	for key, raw := range fields {
		if strings.EqualFold(key, "render") {
			if err := checkJSON(checkedJSON{raw: raw, aliasesByDepth: map[int][]string{1: {"permissions", "reconstruction"}}, nonNullByDepth: map[int][]string{1: {"permissions"}}}); err != nil {
				return err
			}
		}
	}
	for key := range fields {
		switch {
		case strings.EqualFold(key, "archive"), strings.EqualFold(key, "index_sha256"):
			if profile.Operation != "manifest" {
				return fmt.Errorf("json: unknown field %q", key)
			}
		case strings.EqualFold(key, "contacts"):
			if profile.Operation != "contacts" {
				return fmt.Errorf("json: unknown field %q", key)
			}
		case strings.EqualFold(key, "preview"):
			if profile.Operation != "comparison" {
				return fmt.Errorf("json: unknown field %q", key)
			}
		}
	}

	sourceLimit := int64(64 << 20)
	if profile.Operation == "manifest" {
		sourceLimit = 1 << 30
	} else if profile.Operation == "contacts" {
		sourceLimit = 128 << 20
	}
	if profile.SourceSize < 12 || profile.SourceSize > sourceLimit || profile.Evidence == "" || len(profile.Rectangles) > 64 || profile.PNG == "" && (profile.PNGSHA256 != "" || len(profile.Rectangles) != 0) {
		return fmt.Errorf("invalid texture source, selector, evidence or PNG policy")
	}
	if profile.Operation != "specification" && profile.Operation != "manifest" && profile.Specifications != nil {
		return fmt.Errorf("specifications require the read-only specification operation")
	}
	if profile.Preview != nil && profile.Operation != "comparison" {
		return fmt.Errorf("preview layout requires the comparison operation")
	}

	switch profile.Operation {
	case "":
		if profile.Texture == "" {
			return fmt.Errorf("texture authoring requires an exact selector")
		}
	case "inventory", "specification":
		if apply || output != "" || profile.Texture != "" || profile.PNG != "" || profile.PNGSHA256 != "" || len(profile.Rectangles) != 0 || profile.Render != nil || profile.PalettePolicy != "" || profile.PixelPolicy != "" {
			return fmt.Errorf("texture %s is read-only and takes no selector, image, render or pixel policy", profile.Operation)
		}

	case "manifest":
		if profile.Texture != "" || profile.PNG != "" || profile.PNGSHA256 != "" || len(profile.Rectangles) != 0 || profile.Render != nil || profile.PalettePolicy != "" || profile.PixelPolicy != "" || strings.TrimSpace(profile.Archive) == "" || len(profile.Archive) > 256 || len(profile.Specifications) > 100000 {
			return fmt.Errorf("manifest requires an archive label without single-texture authoring policies")
		}
	case "contacts":
		if profile.Contacts == nil || profile.Texture != "" || profile.PNG != "" || profile.PNGSHA256 != "" || len(profile.Rectangles) != 0 || profile.Render != nil || profile.PalettePolicy != "" || profile.PixelPolicy != "" || len(profile.Contacts.Sources) > 63 {
			return fmt.Errorf("contacts requires pinned manifest bundles and font without native authoring policies")
		}
		rootFields := []string{"operation", "source_sha256", "source_size", "evidence", "contacts"}
		contactFields := []string{"font", "sources"}
		inputFields := []string{"path", "size", "sha256"}
		if err := checkJSON(checkedJSON{raw: profileData, allObjects: true, text: true, nonNull: true, aliasesByDepth: map[int][]string{1: rootFields, 2: contactFields, 3: inputFields, 4: inputFields}, fieldsByDepth: map[int][]string{1: rootFields, 2: contactFields, 3: inputFields, 4: inputFields}}); err != nil {
			return err
		}
	case "comparison":
		if profile.Preview == nil || profile.PNG == "" || profile.Texture != "" || profile.Render != nil || len(profile.Rectangles) != 0 || profile.PalettePolicy != "" || profile.PixelPolicy != "" {
			return fmt.Errorf("comparison requires two pinned PNGs and preview layout without native authoring policies")
		}
		fields := []string{"operation", "source_sha256", "source_size", "png", "png_sha256", "evidence", "preview"}
		layoutFields := []string{"scale", "crop", "layout", "font"}
		fontFields := []string{"path", "size", "sha256"}
		if err := checkJSON(checkedJSON{raw: profileData, allObjects: true, text: true, nonNull: true,
			aliasesByDepth: map[int][]string{1: fields, 2: layoutFields, 3: fontFields}, fieldsByDepth: map[int][]string{1: fields, 2: layoutFields, 3: fontFields}}); err != nil {
			return err
		}
		if profile.Preview.Scale < 1 || profile.Preview.Scale > 16384 || len(profile.Preview.Crop) != 0 && len(profile.Preview.Crop) != 4 {
			return fmt.Errorf("comparison requires positive bounded scale and optional XYWH crop")
		}
		switch profile.Preview.Layout {
		case "", "checker", "flat":
			if profile.Preview.Font != nil {
				return fmt.Errorf("comparison font requires the weekday layout")
			}
		case "weekday":
			if profile.Preview.Font == nil || len(profile.Preview.Crop) != 0 {
				return fmt.Errorf("weekday comparison requires a pinned font and its fixed source crop")
			}
		default:
			return fmt.Errorf("unknown comparison layout")
		}

	default:
		return fmt.Errorf("unknown texture profile operation")
	}

	if profile.Operation == "specification" || profile.Operation == "manifest" {
		rootFields := []string{"operation", "source_sha256", "source_size", "texture", "png", "png_sha256", "rectangles", "palette_policy", "pixel_policy", "evidence", "render", "specifications"}
		if profile.Operation == "manifest" {
			rootFields = append(rootFields, "archive", "index_sha256")
		}
		specFields := []string{"texture", "archive", "entry", "kind", "description", "jp_text", "proposed_en", "difficulty", "screen_hint", "notes"}
		if err := checkJSON(checkedJSON{raw: profileData, allObjects: true, text: true, aliasesByDepth: map[int][]string{1: rootFields, 3: specFields}, fieldsByDepth: map[int][]string{1: rootFields, 3: specFields}}); err != nil {
			return err
		}
		if profile.Operation == "specification" && (len(profile.Specifications) < 1 || len(profile.Specifications) > 64) {
			return fmt.Errorf("specification requires 1..64 keyed authored entries")
		}
	}

	switch profile.PalettePolicy {
	case "":
	case "source":
		if profile.PNG == "" && profile.Render == nil {
			return fmt.Errorf("source color policy requires a candidate PNG or render recipe")
		}
	case "exact", "quantize":
		if profile.PNG == "" || len(profile.Rectangles) != 0 {
			return fmt.Errorf("palette generation requires a whole candidate PNG without rectangles")
		}
	default:
		return fmt.Errorf("palette generation requires a whole candidate PNG without rectangles")
	}
	if profile.PixelPolicy != "" && (profile.PixelPolicy != "rgba" || profile.PalettePolicy != "") {
		return fmt.Errorf("pixel policy requires rgba without a palette policy")
	}
	if render := profile.Render; render != nil {
		if render.Permissions != nil && render.Reconstruction == nil {
			return fmt.Errorf("shared permissions require reconstruction steps")
		}
		hasCells := len(render.Cells) > 0
		if profile.PNG != "" || len(profile.Rectangles) != 0 || len(render.Cells) > 64 || hasCells && render.Font == "" || !hasCells && (render.Reconstruction == nil || render.Font != "" || render.FontSHA256 != "" || len(render.Icons) > 0) {
			return fmt.Errorf("bitmap rendering requires a font and cells without PNG, rectangles or palette generation")
		}
		if render.Reconstruction != nil {
			var renderFields, reconstructionFields map[string]json.RawMessage
			_ = json.Unmarshal(fields["render"], &renderFields)
			_ = json.Unmarshal(renderFields["reconstruction"], &reconstructionFields)
			maskData = reconstructionFields["masks"]
			var erases []json.RawMessage
			_ = json.Unmarshal(reconstructionFields["erases"], &erases)
			// Check owned objects separately: icon IDs at the same depth remain data.
			documents := []checkedJSON{
				{raw: profileData, allObjects: true, text: true, nonNull: true, aliasesByDepth: map[int][]string{1: {"render"}}},
				{raw: fields["render"], aliasesByDepth: map[int][]string{1: {"font", "font_sha256", "permissions", "icons", "cells", "reconstruction", "order"}}},
				{raw: renderFields["reconstruction"], aliasesByDepth: map[int][]string{1: {"allow", "exclude", "allow_add", "masks", "erases"}}},
			}
			if render.Permissions != nil {
				for _, key := range []string{"allow", "exclude", "allow_add", "masks"} {
					if _, present := reconstructionFields[key]; present {
						return fmt.Errorf("shared permissions conflict with inline %s", key)
					}
				}
				inputFields := []string{"path", "size", "sha256"}
				documents = append(documents, checkedJSON{raw: renderFields["permissions"], allObjects: true, text: true, nonNull: true, aliasesByDepth: map[int][]string{1: inputFields}, fieldsByDepth: map[int][]string{1: inputFields}, requiredByDepth: map[int][]string{1: inputFields}})
				if strings.TrimSpace(render.Permissions.Path) == "" || render.Permissions.Size < 1 || render.Permissions.Size > 1<<20 {
					return fmt.Errorf("shared permissions require a bounded pinned input")
				}
			}
			eraseFields := append([]string{"id", "rect", "method", "all", "grow", "fill"}, rasterSelectionFields...)
			for _, erase := range erases {
				documents = append(documents, checkedJSON{raw: erase, aliasesByDepth: map[int][]string{1: eraseFields}})
				var clauses struct {
					All []json.RawMessage `json:"all"`
				}
				_ = json.Unmarshal(erase, &clauses)
				for _, clause := range clauses.All {
					documents = append(documents, checkedJSON{raw: clause, aliasesByDepth: map[int][]string{1: rasterSelectionFields}})
				}
			}
			for _, document := range documents {
				if err := checkJSON(document); err != nil {
					return err
				}
			}
		}
	}
	pins := []string{profile.SourceSHA256}
	if profile.Operation == "manifest" {
		pins = append(pins, profile.IndexSHA256)
	}
	if profile.PNG != "" {
		pins = append(pins, profile.PNGSHA256)
	}
	if profile.Render != nil && profile.Render.Font != "" {
		pins = append(pins, profile.Render.FontSHA256)
	}
	if profile.Render != nil && profile.Render.Permissions != nil {
		pins = append(pins, profile.Render.Permissions.SHA256)
	}
	if profile.Contacts != nil {
		pins = append(pins, profile.Contacts.Font.SHA256)
		for _, input := range profile.Contacts.Sources {
			pins = append(pins, input.SHA256)
		}
	}
	if profile.Preview != nil && profile.Preview.Font != nil {
		pins = append(pins, profile.Preview.Font.SHA256)
	}
	for _, pin := range pins {
		decoded, err := hex.DecodeString(pin)
		if err != nil || len(decoded) != sha256.Size {
			return fmt.Errorf("invalid texture SHA-256 pin")
		}
	}
	if profile.Operation == "contacts" {
		return contactSheets(sourcePath, profilePath, output, profile, profileData, apply, stdout)
	}
	if profile.Operation == "manifest" {
		return manifestTextures(sourcePath, profilePath, output, profile, profileData, apply, stdout)
	}
	source, err := readInput(sourcePath, 64<<20)
	if err != nil {
		return err
	}
	if int64(len(source)) != profile.SourceSize || fmt.Sprintf("%x", sha256.Sum256(source)) != profile.SourceSHA256 {
		return fmt.Errorf("texture source identity mismatch")
	}
	if profile.Operation == "comparison" {
		before, _, err := decodePNG(source, 1<<20)
		if err != nil {
			return err
		}
		path := profile.PNG
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(profilePath), path)
		}
		data, err := readInput(path, 16<<20)
		if err != nil {
			return err
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) != profile.PNGSHA256 {
			return fmt.Errorf("candidate PNG hash mismatch")
		}
		after, _, err := decodePNG(data, 1<<20)
		if err != nil {
			return err
		}
		var layouts map[string]TexturePairLayout
		if err := json.Unmarshal(texturePairLayouts, &layouts); err != nil {
			return err
		}
		layoutID := profile.Preview.Layout
		if layoutID == "" {
			layoutID = "checker"
		}
		layout, present := layouts[layoutID]
		if !present || layout.PNGMode != "RGB" && layout.PNGMode != "RGBA" {
			return fmt.Errorf("invalid comparison layout data")
		}
		type pinnedInput struct {
			path  string
			data  []byte
			limit int64
		}
		inputs := []pinnedInput{{sourcePath, source, 64 << 20}, {path, data, 16 << 20}, {profilePath, profileData, 1 << 20}}
		var masks []TextMask
		if len(layout.Labels) > 0 {
			font := profile.Preview.Font
			if font.Size < 1 || font.Size > 4<<20 || font.Path == "" {
				return fmt.Errorf("comparison font exceeds input bounds")
			}
			fontPath := font.Path
			if !filepath.IsAbs(fontPath) {
				fontPath = filepath.Join(filepath.Dir(profilePath), fontPath)
			}
			fontData, err := readInput(fontPath, 4<<20)
			if err != nil || int64(len(fontData)) != font.Size || fmt.Sprintf("%x", sha256.Sum256(fontData)) != font.SHA256 {
				return fmt.Errorf("comparison font identity mismatch: %v", err)
			}
			requests := make([]TextRequest, len(layout.Labels))
			for i, label := range layout.Labels {
				requests[i].Text = label
			}
			masks, err = textMasks(fontData, layout.FontSize, layout.FontLayout, requests)
			if err != nil {
				return err
			}
			inputs = append(inputs, pinnedInput{fontPath, fontData, 4 << 20})
		}
		w, h := before.Rect.Dx(), before.Rect.Dy()
		var crop *image.Rectangle
		cropValues := profile.Preview.Crop
		if len(layout.Crop) > 0 {
			cropValues = layout.Crop
		}
		if c := cropValues; len(c) == 4 {
			x, y := c[0], c[1]
			w, h = c[2], c[3]
			if x < -1<<30 || x > 1<<30 || y < -1<<30 || y > 1<<30 {
				return fmt.Errorf("comparison crop origin exceeds bounds")
			}
			if w < 1 || h < 1 || w > 4096 || h > 4096 || w*h > 1<<20 || x+w > 1<<30 || y+h > 1<<30 {
				return fmt.Errorf("comparison crop dimensions exceed bounds")
			}
			crop = &image.Rectangle{Min: image.Pt(x, y), Max: image.Pt(x+w, y+h)}
		}
		if layoutID == "flat" && crop == nil {
			// Flat pairs crop both sources to the before extent; unequal after pixels pad.
			crop = &image.Rectangle{Max: image.Pt(w, h)}
		}
		renderScale := profile.Preview.Scale
		if len(masks) > 0 {
			renderScale = 1
		}
		width, panelHeight := w*renderScale, h*renderScale
		gap := layout.Gap
		if layout.GapSpace == "source" {
			gap *= renderScale
		}
		height := 2*panelHeight + gap
		panelY := [2]int{0, panelHeight + gap}
		if len(masks) > 0 {
			width, height, panelY = layout.Canvas[0], layout.Canvas[1], layout.PanelY
		}
		outputWidth, outputHeight := width, height
		if len(masks) > 0 {
			outputWidth *= profile.Preview.Scale
			outputHeight *= profile.Preview.Scale
		}
		if width > 16384 || panelHeight > 16384 || outputWidth > 16384 || width*panelHeight > 1<<24 || outputWidth*outputHeight > 1<<25 || len(masks) > 0 && outputWidth*outputHeight > 1<<24 {
			return fmt.Errorf("comparison canvas exceeds pixel bounds")
		}
		raster := image.NewNRGBA(image.Rect(0, 0, width, height))
		draw.Draw(raster, raster.Rect, image.NewUniform(color.NRGBA{layout.Background, layout.Background, layout.Background, 255}), image.Point{}, draw.Src)
		for panel, input := range []*image.NRGBA{before, after} {
			if len(masks) > 0 {
				mask := masks[panel]
				at := image.Pt(layout.LabelAt[panel][0], layout.LabelAt[panel][1]).Add(mask.Bearing)
				for y := 0; y < mask.Coverage.Rect.Dy(); y++ {
					for x := 0; x < mask.Coverage.Rect.Dx(); x++ {
						target := at.Add(image.Pt(x, y))
						if target.In(raster.Rect) {
							raster.SetNRGBA(target.X, target.Y, pixelOver(raster.NRGBAAt(target.X, target.Y), color.NRGBA{layout.Ink[0], layout.Ink[1], layout.Ink[2], mask.Coverage.GrayAt(x, y).Y}))
						}
					}
				}
			}
			scaled, err := resizeRaster(input, width, panelHeight, "nearest", crop)
			if err != nil {
				return err
			}
			pixels := scaled.(*image.NRGBA)
			for y := 0; y < panelHeight; y++ {
				for x := 0; x < width; x++ {
					background := raster.NRGBAAt(x, y+panelY[panel])
					if len(layout.Checker) > 0 {
						shade := layout.Checker[(x/layout.Tile+y/layout.Tile)%2]
						background = color.NRGBA{shade, shade, shade, 255}
					}
					raster.SetNRGBA(x, y+panelY[panel], pixelOver(background, pixels.NRGBAAt(x, y)))
				}
			}
		}
		if len(masks) > 0 && profile.Preview.Scale != 1 {
			scaled, err := resizeRaster(raster, outputWidth, outputHeight, "nearest", nil)
			if err != nil {
				return err
			}
			raster = scaled.(*image.NRGBA)
		}
		var encoded bytes.Buffer
		var pngImage image.Image = raster
		if layout.PNGMode == "RGBA" {
			pngImage = rgbaPNG{raster}
		}
		if err := png.Encode(&encoded, pngImage); err != nil {
			return err
		}
		if encoded.Len() > 128<<20 {
			return fmt.Errorf("comparison PNG exceeds 128MiB")
		}
		for _, input := range inputs {
			current, err := readInput(input.path, input.limit)
			if err != nil || !bytes.Equal(current, input.data) {
				return fmt.Errorf("comparison input changed before publication: %s", input.path)
			}
		}
		digest := fmt.Sprintf("%x", sha256.Sum256(encoded.Bytes()))
		if apply {
			if err := writeNewFile(output, bytes.NewReader(encoded.Bytes()), int64(encoded.Len()), digest, 0o644); err != nil {
				return err
			}
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		report := map[string]any{"operation": "texture_authoring", "mode": "comparison", "applied": apply,
			"source_sha256": profile.SourceSHA256, "candidate_sha256": profile.PNGSHA256, "profile_sha256": fmt.Sprintf("%x", sha256.Sum256(profileData)),
			"before_size": [2]int{before.Rect.Dx(), before.Rect.Dy()}, "after_size": [2]int{after.Rect.Dx(), after.Rect.Dy()}, "crop": profile.Preview.Crop,
			"scale": profile.Preview.Scale, "width": outputWidth, "height": outputHeight, "png_conversion": "Pillow12.3", "png_mode": layout.PNGMode,
			"rgba_sha256": fmt.Sprintf("%x", sha256.Sum256(raster.Pix)), "output_sha256": digest, "output_bytes": encoded.Len(),
			"limits": "Pinned PNG presentation only: common padded crop, before-controlled panel geometry, nearest scaling, independent output-space8px checker150/200, gap6 on40gray. No source edits, native blend simulation, artwork, visual or patch approval. Source/crop1Mpx, panel16Mpx, combined32Mpx; bounded exclusive output."}
		if layoutID != "checker" {
			report["layout"], report["layout_sha256"] = layoutID, fmt.Sprintf("%x", sha256.Sum256(texturePairLayouts))
			report["limits"] = "Pinned PNG presentation only; source/crop1Mpx, panel16Mpx, combined32Mpx (captioned whole-canvas scaling16Mpx). Flat pairs pad unequal crops, use90gray/source-gap4 scaled and RGBA PNG. Weekday strips use fixed crop/captions,232gray RGB and whole-canvas nearest. No source edits, artwork, native blend or patch approval; exclusive output after all input rechecks."
		}
		if profile.Preview.Font != nil {
			report["font"] = profile.Preview.Font
		}
		return encoder.Encode(report)
	}
	if profile.Operation == "inventory" || profile.Operation == "specification" {
		index, err := indexTextures(source)
		if err != nil {
			return err
		}
		report := map[string]any{"operation": "texture_authoring", "mode": "inventory", "source_sha256": profile.SourceSHA256,
			"profile_sha256": fmt.Sprintf("%x", sha256.Sum256(profileData)), "textures": index.Textures, "codec_support": "not_evaluated", "applied": false,
			"limits": "Declared native order, names and raw headers only; metadata errors stay with their entries. No pixel/GS packet validation, decoding, preview, patch authorization or output file."}
		if profile.Operation == "specification" {
			rows := make([]TextureSpecificationRow, 0, len(profile.Specifications))
			selected := make(map[int]bool)
			var requestedPixels uint64
			for _, id := range slices.Sorted(maps.Keys(profile.Specifications)) {
				spec := profile.Specifications[id]
				matches := index.byName[spec.Texture]
				if strings.TrimSpace(id) == "" || len(id) > 256 || spec.Texture == "" || len(spec.Texture) > 1024 || len(matches) != 1 {
					return fmt.Errorf("invalid specification %q or texture selector matches %d native textures", id, len(matches))
				}
				ordinal := matches[0]
				if selected[ordinal] {
					return fmt.Errorf("multiple specifications select native texture %q", spec.Texture)
				}
				selected[ordinal] = true
				native := index.Textures[ordinal]
				if native.Header != nil {
					area := uint64(native.Header.Width) * uint64(native.Header.Height)
					if area <= 1<<20 {
						requestedPixels += area
						if requestedPixels > 1<<24 {
							return fmt.Errorf("specification measurement exceeds pixel work budget")
						}
					}
				}
				rows = append(rows, TextureSpecificationRow{ID: id, NativeOrdinal: ordinal, Specification: spec, Header: native.Header, DecodedStatus: "unavailable"})
			}
			for i := range rows {
				row := &rows[i]
				policy := ""
				if row.Header != nil && row.Header.Depth == 32 {
					policy = "rgba"
				}
				_, raster, err := texture(source, row.Specification.Texture, nil, nil, policy, &index)
				if err != nil {
					row.Diagnostic = err.Error()
					continue
				}
				row.DecodedStatus = "decoded"
				row.DecodedGeometry = &[2]int{raster.Rect.Dx(), raster.Rect.Dy()}
				digest := fmt.Sprintf("%x", sha256.Sum256(raster.Pix))
				row.RGBASHA256 = &digest
				switch row.Header.Depth {
				case 4:
					row.DecodedFormat = "PSMT4"
				case 8:
					row.DecodedFormat = "PSMT8"
				case 32:
					row.DecodedFormat = "PSMCT32"
				}
			}
			delete(report, "textures")
			report["mode"], report["specifications"] = "specification", rows
			report["source_size"], report["codec_support"] = profile.SourceSize, "selected_only"
			report["limits"] = "Exact standalone source/name joins and selected decoded geometry only. Archive/entry and wording/category/context are authored labels. Unavailable measurements remain null with diagnostics. No OCR, discovery scoring/tier/flags, archive placement, visual or patch approval; no output file."
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	rasterPolicy := profile.PalettePolicy
	if profile.PixelPolicy != "" {
		rasterPolicy = profile.PixelPolicy
	}
	imagePath, imagePin, imageDir := profile.PNG, profile.PNGSHA256, filepath.Dir(profilePath)
	if render := profile.Render; render != nil && render.Permissions != nil {
		path := render.Permissions.Path
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(profilePath), path)
		}
		data, err := readInput(path, 1<<20)
		if err != nil || int64(len(data)) != render.Permissions.Size || fmt.Sprintf("%x", sha256.Sum256(data)) != render.Permissions.SHA256 {
			return fmt.Errorf("shared permissions identity mismatch: %v", err)
		}
		permissionFields := []string{"allow", "exclude", "allow_add", "masks"}
		if err := checkJSON(checkedJSON{raw: data, allObjects: true, text: true, nonNull: true, aliasesByDepth: map[int][]string{1: permissionFields}, fieldsByDepth: map[int][]string{1: permissionFields}}); err != nil {
			return err
		}
		var permissions RasterReconstruction
		if err := json.Unmarshal(data, &permissions); err != nil {
			return err
		}
		render.Reconstruction.Allow, render.Reconstruction.Exclude, render.Reconstruction.AllowAdd = permissions.Allow, permissions.Exclude, permissions.AllowAdd
		render.Reconstruction.Masks = permissions.Masks
		var permissionFieldsRaw map[string]json.RawMessage
		_ = json.Unmarshal(data, &permissionFieldsRaw)
		maskData = permissionFieldsRaw["masks"]
	}
	if len(maskData) != 0 {
		stages := []string{"allow", "exclude", "allow_add"}
		footprintFields := []string{"rect", "sample_rect", "any", "core", "core_grow", "kernel", "close", "fill", "grow", "grow_through", "erode", "minimum_size", "components", "clip", "exclude"}
		componentFields := []string{"connectivity", "seeds", "reject", "background_seed"}
		// These objects have fixed depths; scalar-map keys remain finite data properties.
		if err := checkJSON(checkedJSON{raw: maskData, allObjects: true, text: true, nonNull: true,
			aliasesByDepth:  map[int][]string{1: stages, 3: footprintFields, 4: componentFields, 6: rasterSelectionFields},
			fieldsByDepth:   map[int][]string{1: stages, 3: footprintFields, 4: componentFields, 6: rasterSelectionFields},
			requiredByDepth: map[int][]string{3: {"rect", "any", "fill", "grow"}, 4: {"connectivity"}},
		}); err != nil {
			return err
		}
		var stageMasks map[string][]json.RawMessage
		_ = json.Unmarshal(maskData, &stageMasks)
		for _, stage := range stages {
			for _, footprint := range stageMasks[stage] {
				var raw struct {
					Components struct {
						Reject json.RawMessage `json:"reject"`
					} `json:"components"`
				}
				_ = json.Unmarshal(footprint, &raw)
				if len(raw.Components.Reject) == 0 {
					continue
				}
				// Main scalar maps and these selector objects otherwise share depth seven.
				if err := checkJSON(checkedJSON{raw: raw.Components.Reject,
					aliasesByDepth: map[int][]string{3: rasterSelectionFields},
					fieldsByDepth:  map[int][]string{3: rasterSelectionFields},
				}); err != nil {
					return err
				}
			}
		}
	}
	var font RasterFont
	if profile.Render != nil && profile.Render.Font != "" {
		path := profile.Render.Font
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(profilePath), path)
		}
		data, err := readInput(path, 1<<20)
		if err != nil || !utf8.Valid(data) {
			return fmt.Errorf("bitmap font must be readable UTF-8: %v", err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) != profile.Render.FontSHA256 {
			return fmt.Errorf("bitmap font hash mismatch")
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&font); err != nil {
			return err
		}
		if err := decoder.Decode(new(any)); err != io.EOF || font.PNG == "" && font.TrueType == nil {
			return fmt.Errorf("bitmap font requires one JSON object and a PNG")
		}
		// Null silently becomes zero in numeric Go fields; authored data must be explicit.
		for _, document := range [][]byte{profileData, data} {
			if font.TrueType != nil {
				if err := checkJSON(checkedJSON{raw: document, allObjects: true, text: true, nonNull: true}); err != nil {
					return err
				}
				continue
			}
			decoder := json.NewDecoder(bytes.NewReader(document))
			for {
				token, err := decoder.Token()
				if err == io.EOF {
					break
				}
				if err != nil {
					return err
				}
				if token == nil {
					return fmt.Errorf("bitmap JSON must omit unused fields instead of null")
				}
			}
		}
		fontInput := RegistryInput{Path: font.PNG, SHA256: font.PNGSHA256}
		if font.TrueType != nil {
			fontInput = *font.TrueType
			if fontInput.Path == "" || fontInput.Size < 1 || fontInput.Size > 4<<20 || font.Layout != "RAQM" && font.Layout != "BASIC" {
				return fmt.Errorf("TrueType font requires a bounded pinned source and BASIC or RAQM layout")
			}
		}
		pin, err := hex.DecodeString(fontInput.SHA256)
		if err != nil || len(pin) != sha256.Size {
			return fmt.Errorf("invalid bitmap font PNG pin")
		}
		imagePath, imagePin, imageDir = fontInput.Path, fontInput.SHA256, filepath.Dir(path)
	}
	var candidate image.Image
	var rectangles []image.Rectangle
	if imagePath != "" {
		path := imagePath
		if !filepath.IsAbs(path) {
			path = filepath.Join(imageDir, path)
		}
		limit := int64(16 << 20)
		if font.TrueType != nil {
			limit = 4 << 20
		}
		data, err := readInput(path, limit)
		if err != nil {
			return err
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) != imagePin {
			return fmt.Errorf("candidate PNG hash mismatch")
		}
		if font.TrueType != nil {
			if int64(len(data)) != font.TrueType.Size {
				return fmt.Errorf("TrueType font identity mismatch")
			}
			font.TrueTypeData = data
		} else {
			config, err := png.DecodeConfig(bytes.NewReader(data))
			if err != nil || config.Width < 1 || config.Height < 1 || config.Width > 4096 || config.Height > 4096 || config.Width*config.Height > 1<<20 {
				return fmt.Errorf("candidate must be a bounded PNG")
			}
			candidate, err = png.Decode(bytes.NewReader(data))
			if err != nil {
				return err
			}
			for _, rect := range profile.Rectangles {
				if len(rect) != 4 {
					return fmt.Errorf("texture rectangle requires x, y, width and height")
				}
				x, y, w, h := rect[0], rect[1], rect[2], rect[3]
				if x < 0 || y < 0 || w < 1 || h < 1 || w > config.Width-x || h > config.Height-y {
					return fmt.Errorf("invalid texture rectangle")
				}
				rectangles = append(rectangles, image.Rect(x, y, x+w, y+h))
			}
		}
	}
	if profile.Render != nil {
		atlas, ok := candidate.(*image.Gray)
		if len(profile.Render.Cells) > 0 && font.TrueType == nil && !ok {
			return fmt.Errorf("bitmap font PNG requires 8-bit grayscale coverage")
		}
		decodePolicy := rasterPolicy
		if decodePolicy == "source" {
			decodePolicy = ""
		}
		_, base, err := texture(source, profile.Texture, nil, nil, decodePolicy, nil)
		if err != nil {
			return err
		}
		candidate, rectangles, err = composeCells(base, atlas, font, profile.Render.RasterComposition)
		if err != nil {
			return err
		}
	}
	artifact, raster, err := texture(source, profile.Texture, candidate, rectangles, rasterPolicy, nil)
	if err != nil {
		return err
	}
	mode := "import_png"
	if profile.Render != nil {
		mode = "render_bitmap"
		if len(profile.Render.Cells) == 0 {
			mode = "reconstruct"
		} else if font.TrueType != nil {
			mode = "render_truetype"
		}
	}
	if candidate == nil {
		mode = "export_png"
		var encoded bytes.Buffer
		if err := png.Encode(&encoded, raster); err != nil {
			return err
		}
		artifact = encoded.Bytes()
	}
	artifactHash := fmt.Sprintf("%x", sha256.Sum256(artifact))
	if apply {
		if err := writeNewFile(output, bytes.NewReader(artifact), int64(len(artifact)), artifactHash, 0o644); err != nil {
			return err
		}
	}
	palettePolicy := profile.PalettePolicy
	if palettePolicy == "" {
		palettePolicy = "preserve"
	}

	report := map[string]any{"operation": "texture_authoring", "mode": mode, "texture": profile.Texture,
		"source_sha256": profile.SourceSHA256, "profile_sha256": fmt.Sprintf("%x", sha256.Sum256(profileData)),
		"candidate_sha256": profile.PNGSHA256, "output_sha256": artifactHash, "output_bytes": len(artifact), "palette_policy": palettePolicy,
		"width": raster.Bounds().Dx(), "height": raster.Bounds().Dy(), "rgba_sha256": fmt.Sprintf("%x", sha256.Sum256(raster.Pix)), "applied": apply,
		"limits": "Standalone calibrated raster artifact. Default preserves indexed palettes/indices and direct font monochrome guards. Explicit exact/quantize regenerates a whole standard PSMT8 palette; quantize uses eight weighted Lloyd updates above256 normalized colors; rgba permits color in the finite native direct modes. Direct source alpha remains0..128, hidden RGB is preserved and candidate alpha rounds to nearest PS2 value, ties upward. Reported RGBA uses the project PNG convention, not native blend simulation. No other layouts, glyph metrics, palette alias, visual or ISO patch approval."}
	if profile.PixelPolicy != "" {
		report["pixel_policy"] = profile.PixelPolicy
	}
	if profile.Render != nil && profile.Render.Permissions != nil {
		report["permissions_sha256"] = profile.Render.Permissions.SHA256
	}
	if profile.Render != nil && profile.Render.Font != "" {
		report["font_sha256"] = profile.Render.FontSHA256
		if font.TrueType != nil {
			report["font_ttf_sha256"] = font.TrueType.SHA256
			report["font_layout"] = font.Layout
			report["limits"] = "Pinned TrueType metrics and styles share approved cells, native import and exclusive publication. Exact results depend on the calibrated font libraries. Other style operations, native layouts, palette aliases, visual approval and ISO placement remain separate."
		} else {
			report["font_png_sha256"] = font.PNGSHA256
		}
		report["rendered_cells"] = len(profile.Render.Cells)
	}
	if render := profile.Render; render != nil && render.Reconstruction != nil {
		report["rendered_cells"] = len(render.Cells)
		report["reconstruction_steps"] = len(render.Reconstruction.Erases)
		report["limits"] = "Ordered finite flat/clear/row/column reconstruction and text under exact permission masks; native rectangles are coarse guards. Existing font-library, native-format and source-palette limits apply. No other reconstruction algorithms, artwork or ISO placement approval."
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
