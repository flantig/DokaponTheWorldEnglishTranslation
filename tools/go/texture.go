package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"slices"
)

// texture decodes or replaces one calibrated PS2 raster in a complete TXD.
// Indexed rasters preserve raw CLUT and duplicate indices; monochrome font rasters
// use direct pixels with nearest PS2 alpha. Metadata stays intact; other formats
// refuse. Exact/quantize regenerate one whole standard PSMT8 palette;
// default policy preserves raw palettes and font monochrome guards. Explicit rgba
// permits direct color without changing storage or the source-alpha0..128 domain.
// A prepared index must share this exact immutable byte view; nil parses afresh.
func texture(data []byte, selector string, replacement image.Image, rectangles []image.Rectangle, rasterPolicy string, prepared *TextureIndex) ([]byte, *image.NRGBA, error) {
	if len(data) < 12 || len(data) > 64<<20 || selector == "" || len(rectangles) > 64 {
		return nil, nil, fmt.Errorf("texture requires a bounded TXD, exact selector and at most 64 rectangles")
	}
	switch rasterPolicy {
	case "", "exact", "quantize", "rgba", "source":
	default:
		return nil, nil, fmt.Errorf("unknown raster policy")
	}
	if (rasterPolicy == "exact" || rasterPolicy == "quantize") && (replacement == nil || len(rectangles) != 0) {
		return nil, nil, fmt.Errorf("palette generation requires a whole replacement without rectangles")
	}
	if rasterPolicy == "source" && replacement == nil {
		return nil, nil, fmt.Errorf("source color policy requires an indexed replacement")
	}
	index := prepared
	if index == nil {
		parsed, err := indexTextures(data)
		if err != nil {
			return nil, nil, err
		}
		index = &parsed
	} else if len(index.source) != len(data) || &index.source[0] != &data[0] {
		return nil, nil, fmt.Errorf("prepared texture index requires the same immutable source view")
	}
	var selected NativeTexture
	matches, chunkCount := 0, index.chunkCount
	for _, ordinal := range index.byName[selector] {
		entry := index.Textures[ordinal]
		chunkCount += entry.chunkCount
		if chunkCount > 16384 {
			return nil, nil, fmt.Errorf("truncated or excessive RW chunks")
		}
		if entry.MetadataError != "" {
			return nil, nil, fmt.Errorf("%s", entry.MetadataError)
		}
		matches++
		selected = entry
	}
	if matches != 1 {
		return nil, nil, fmt.Errorf("texture selector matches %d native textures", matches)
	}
	metadata := data[selected.infoStart:selected.infoEnd]
	width, height := uint64(selected.Header.Width), uint64(selected.Header.Height)
	tex0 := binary.LittleEndian.Uint64(metadata[0x10:])
	rasterFormat := selected.Header.RasterFormat
	version := selected.Header.Version
	paletteBaseBlocks := binary.LittleEndian.Uint32(metadata[0x18:])
	tex1Low := binary.LittleEndian.Uint32(metadata[0x1c:])
	if width == 0 || height == 0 || width > 4096 || height > 4096 || width*height > 1<<20 {
		return nil, nil, fmt.Errorf("unsupported raster dimensions")
	}
	w, h, count := int(width), int(height), int(width*height)
	depth := selected.Header.Depth
	if tex1Low != 0 {
		return nil, nil, fmt.Errorf("unsupported native TEX1LOW sampling/mipmap mode")
	}
	standard := version == 2
	pixelBytes, paletteEntries, paletteUploadBytes := count, 256, 1024
	footprintWords := count/4 + 2048 // Full PSMT8 pages plus one CLUT page.
	paletteWidth, paletteHeight := 16, 16
	paletteX, paletteY := 0, 0
	expectedTBW := max(1, width/64)
	indexMask := byte(255)
	switch depth {
	case 8:
		expectedTBW = max(2, width/64)
		partialPage := standard && slices.Contains([][2]int{
			{16, 16}, {16, 32}, {16, 64}, {16, 128},
			{32, 16}, {32, 32}, {32, 64}, {32, 128}, {32, 256},
			{64, 16}, {64, 32}, {64, 64}, {64, 128}, {64, 256},
			{128, 16}, {128, 32}, {256, 16}, {256, 32}, {512, 32},
		}, [2]int{w, h})
		// These partial-page rasters place the CLUT in holes in the final page.
		switch {
		case partialPage:
			footprintWords = ((w + 127) / 128) * ((h + 63) / 64) * 2048
			// Only TBW/TW/TH vary; the common guard binds them to the dimensions.
			if tex0&^(uint64(63)<<14|uint64(255)<<26) != 0x2000000401300000 || paletteBaseBlocks != uint32(footprintWords/64-4) {
				return nil, nil, fmt.Errorf("unsupported partial-page PSMT8 metadata")
			}
			if expectedTBW == 2 {
				paletteX, paletteY = 48, footprintWords/64-16
			}
		case width%128 == 0 && height%64 == 0 && paletteBaseBlocks == uint32(count/256) && paletteBaseBlocks%32 == 0:
			// Full-page rasters retain their separate CLUT page.
		default:
			return nil, nil, fmt.Errorf("unsupported PSMT8 geometry, format, version or palette base")
		}
		if tex0>>20&63 != 0x13 || rasterFormat != 0x2504 || version != 1 && version != 2 {
			return nil, nil, fmt.Errorf("unsupported PSMT8 format or version")
		}
	case 4:
		if !standard || tex0>>20&63 != 0x14 || tex0>>61&7 != 1 || rasterFormat != 0x4504 {
			return nil, nil, fmt.Errorf("unsupported PSMT4 geometry, flags or sampling mode")
		}
		switch {
		case w == 128 && h == 32 && paletteBaseBlocks == 28:
			footprintWords = 2048
		case w == 512 && h == 512 && paletteBaseBlocks == 512:
			footprintWords = 34816
		default:
			return nil, nil, fmt.Errorf("unsupported PSMT4 geometry or palette base")
		}
		pixelBytes, paletteEntries, paletteUploadBytes = count/2, 16, 96
		paletteWidth, paletteHeight, indexMask = 8, 3, 15
	case 32:
		if rasterFormat != 0x0504 || paletteBaseBlocks != 0 || rasterPolicy != "rgba" && tex0 != 0x664020000 {
			return nil, nil, fmt.Errorf("unsupported direct font raster mode")
		}
		// shortcut: only these native direct layouts; other modes need storage proof.
		switch tex0 {
		case 0x664020000, 0x660010000, 0x624020000: // Headerless512x512,256x512,512x256.
			if version != 0 {
				return nil, nil, fmt.Errorf("unsupported headerless direct version")
			}
		case 0x620010000, 0x51c008000, 0x510004000: // One-header256x256,128x16,16x16.
			if !standard {
				return nil, nil, fmt.Errorf("unsupported standard direct version")
			}
		default:
			return nil, nil, fmt.Errorf("unsupported direct raster mode")
		}
		pixelBytes, paletteEntries, paletteUploadBytes = count*4, 0, 0
		footprintWords = ((w + 63) / 64) * ((h + 31) / 32) * 2048
	default:
		return nil, nil, fmt.Errorf("unsupported raster depth")
	}
	if (rasterPolicy == "exact" || rasterPolicy == "quantize") && (depth != 8 || !standard) {
		return nil, nil, fmt.Errorf("palette generation requires calibrated standard PSMT8")
	}
	if rasterPolicy == "source" && depth == 32 {
		return nil, nil, fmt.Errorf("source color policy requires indexed pixels")
	}
	if rasterPolicy == "rgba" && depth != 32 {
		return nil, nil, fmt.Errorf("rgba pixel policy requires calibrated direct32")
	}
	if tex0>>14&63 != expectedTBW || tex0>>51&15 != 0 || tex0>>55&1 != 0 || tex0>>56&31 != 0 || 1<<(tex0>>26&15) != width || 1<<(tex0>>30&15) != height {
		return nil, nil, fmt.Errorf("unsupported TEX0 buffer size or CLUT mode")
	}
	if binary.LittleEndian.Uint32(metadata[0x38:]) != uint32(footprintWords) {
		return nil, nil, fmt.Errorf("unsupported native GS allocation footprint")
	}
	const gsHeaderBytes = 0x50
	pixelOffset := selected.pixelStart
	infoPixels, infoPalette := int(binary.LittleEndian.Uint32(metadata[0x30:])), int(binary.LittleEndian.Uint32(metadata[0x34:]))
	paletteOffset := 0
	switch {
	case standard && depth == 32 && selected.pixelEnd-selected.pixelStart == pixelBytes+gsHeaderBytes && infoPixels == pixelBytes+gsHeaderBytes && infoPalette == 0:
		pixelOffset += gsHeaderBytes
	case standard && depth != 32 && selected.pixelEnd-selected.pixelStart == pixelBytes+2*gsHeaderBytes+paletteUploadBytes && infoPixels == pixelBytes+gsHeaderBytes && infoPalette == gsHeaderBytes+paletteUploadBytes:
		pixelOffset += gsHeaderBytes
		paletteOffset = pixelOffset + pixelBytes + gsHeaderBytes
	case !standard && selected.pixelEnd-selected.pixelStart == pixelBytes+paletteUploadBytes && infoPixels == pixelBytes && infoPalette == paletteUploadBytes:
		paletteOffset = pixelOffset + pixelBytes
	default:
		return nil, nil, fmt.Errorf("unsupported standard/headerless raster storage")
	}
	if depth == 4 && bytes.Count(data[paletteOffset+paletteEntries*4:paletteOffset+paletteUploadBytes], []byte{0xcd}) != 32 {
		return nil, nil, fmt.Errorf("unsupported PSMT4 CLUT upload padding")
	}
	if standard {
		if depth == 8 && w == 128 && slices.Contains([]int{64, 128, 256}, h) {
			// Native TBW2 reuses the pixel upload base; its CLUT occupies the next page.
			paletteY = int(paletteBaseBlocks)
		}
		packets := []struct{ offset, width, height, bytes, destinationX, destinationY int }{
			{selected.pixelStart, w / 2, h / 2, pixelBytes, 0, 0},
			{paletteOffset - gsHeaderBytes, paletteWidth, paletteHeight, paletteUploadBytes, paletteX, paletteY},
		}
		if depth == 32 {
			packets = packets[:1] // Direct rasters have no CLUT packet.
			packets[0].width, packets[0].height = w, h
		}
		for _, packet := range packets {
			if packet.bytes%16 != 0 || packet.bytes/16 > 0x7fff {
				return nil, nil, fmt.Errorf("unsupported GS IMAGE transfer count")
			}
			// Calibrated A+D setup, destination position, host transfer and one IMAGE payload.
			words := [...]uint64{0x1000000000000003, 0x0e, uint64(packet.destinationX)<<32 | uint64(packet.destinationY)<<48, 0x51,
				uint64(packet.width) | uint64(packet.height)<<32, 0x52, 0, 0x53,
				0x0800000000000000 | uint64(packet.bytes/16), 0}
			for i, word := range words {
				if binary.LittleEndian.Uint64(data[packet.offset+8*i:]) != word {
					return nil, nil, fmt.Errorf("unsupported GS upload packet at %#x", packet.offset)
				}
			}
		}
	}
	bounds := image.Rect(0, 0, w, h)
	if replacement == nil && len(rectangles) != 0 || replacement != nil && (replacement.Bounds().Dx() != w || replacement.Bounds().Dy() != h) {
		return nil, nil, fmt.Errorf("replacement dimensions or rectangle policy mismatch")
	}
	var mask []bool
	if len(rectangles) != 0 {
		mask = make([]bool, count)
		for _, rect := range rectangles {
			if rect.Empty() || !rect.In(bounds) {
				return nil, nil, fmt.Errorf("invalid texture rectangle")
			}
			for y := rect.Min.Y; y < rect.Max.Y; y++ {
				for x := rect.Min.X; x < rect.Max.X; x++ {
					mask[y*w+x] = true
				}
			}
		}
	}
	var artifact []byte
	if replacement != nil {
		artifact = slices.Clone(data)
	}
	palette := make([]color.NRGBA, paletteEntries)
	originalPalette := make([]color.NRGBA, paletteEntries)
	paletteIndices := make(map[color.NRGBA]byte)
	if rasterPolicy == "exact" || rasterPolicy == "quantize" {
		var err error
		replacement, palette, paletteIndices, err = generatePalette(replacement, rasterPolicy)
		if err != nil {
			return nil, nil, err
		}
	}
	for logical := range palette {
		physical := logical
		switch {
		case depth == 4:
			// The16-entry CLUT is already in logical order.
		case logical&0x18 == 0x08:
			physical += 8
		case logical&0x18 == 0x10:
			physical -= 8
		}
		entry := data[paletteOffset+4*physical : paletteOffset+4*physical+4]
		originalPalette[logical] = color.NRGBA{entry[0], entry[1], entry[2], uint8(min(255, 2*int(entry[3])))}
		if rasterPolicy == "exact" || rasterPolicy == "quantize" {
			pixel := palette[logical]
			copy(artifact[paletteOffset+4*physical:], []byte{pixel.R, pixel.G, pixel.B, uint8((int(pixel.A) + 1) / 2)})
		} else {
			// Preserve duplicate entries and raw alpha values above0x80 in default mode.
			palette[logical] = originalPalette[logical]
		}
	}
	colorPools := [][]color.NRGBA{palette}
	colorCaches := []map[color.NRGBA]byte{paletteIndices}
	if rasterPolicy == "source" {
		// Literal default export terminates at one level and reuses GS decoding.
		_, source, err := texture(data, selector, nil, nil, "", index)
		if err != nil {
			return nil, nil, err
		}
		unique := make(map[uint32]bool)
		for at := 0; at < len(source.Pix); at += 4 {
			p := source.Pix[at : at+4]
			unique[uint32(p[0])<<24|uint32(p[1])<<16|uint32(p[2])<<8|uint32(p[3])] = true
		}
		keys := make([]uint32, 0, len(unique))
		for key := range unique {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		sourceColors := make([]color.NRGBA, len(keys))
		for i, key := range keys {
			sourceColors[i] = color.NRGBA{uint8(key >> 24), uint8(key >> 16), uint8(key >> 8), uint8(key)}
		}
		colorPools = [][]color.NRGBA{sourceColors, palette}
		colorCaches = []map[color.NRGBA]byte{make(map[color.NRGBA]byte), paletteIndices}
	}
	decoded := image.NewNRGBA(bounds)
	seen := make([]bool, count)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			at, shift := 0, 0
			switch depth {
			case 8:
				block := (y&^15)*w + (x&^15)*2
				swap := ((y + 2) >> 2 & 1) * 4
				row := (((y &^ 3) >> 1) + (y & 1)) & 7
				at = block + row*w*2 + ((x+swap)&7)*4 + (y >> 1 & 1) + (x >> 2 & 2)
			case 32:
				at = (y*w + x) * 4
			case 4:
				// Compose PSMCT16 upload and PSMT4 sampling with matching page rows.
				column := ((x & 7) << 1) | ((x & 8) >> 3) | (x &^ 15)
				row := (y&1)*w | (y&^3)*(w/2)
				bank := (((y >> 1) ^ (y >> 2)) & 1) << 3
				at, shift = (column|row)^bank, (y&2)*2
			}
			key := at
			switch depth {
			case 4:
				key = at*2 + shift/4
			case 32:
				key = at / 4
			}
			if at < 0 || at >= pixelBytes || key >= count || seen[key] {
				return nil, nil, fmt.Errorf("raster mapping is not bijective")
			}
			seen[key] = true
			index := data[pixelOffset+at] >> shift & indexMask
			var original color.NRGBA
			if depth == 32 {
				raw := data[pixelOffset+at : pixelOffset+at+4]
				if raw[3] > 128 {
					return nil, nil, fmt.Errorf("direct source requires native alpha0..128")
				}
				if rasterPolicy != "rgba" && (raw[0] != raw[1] || raw[0] != raw[2]) {
					return nil, nil, fmt.Errorf("direct font source must be monochrome")
				}
				original = color.NRGBA{raw[0], raw[1], raw[2], uint8(min(255, 2*int(raw[3])))}
			} else {
				original = originalPalette[index]
			}
			if replacement != nil {
				pixel := color.NRGBAModel.Convert(replacement.At(x+replacement.Bounds().Min.X, y+replacement.Bounds().Min.Y)).(color.NRGBA)
				if pixel != original {
					if mask != nil && !mask[y*w+x] {
						return nil, nil, fmt.Errorf("candidate changes a pixel outside approved rectangles")
					}
					if depth == 32 {
						if rasterPolicy != "rgba" && (pixel.R != pixel.G || pixel.R != pixel.B) {
							return nil, nil, fmt.Errorf("direct font candidate must be monochrome")
						}
						rawAlpha := uint8((int(pixel.A) + 1) / 2)
						copy(artifact[pixelOffset+at:pixelOffset+at+4], []byte{pixel.R, pixel.G, pixel.B, rawAlpha})
						original = color.NRGBA{pixel.R, pixel.G, pixel.B, uint8(min(255, 2*int(rawAlpha)))}
					} else if rasterPolicy == "" || rasterPolicy == "source" {
						for stage, pool := range colorPools {
							// Snapping back to the original must retain duplicate indices.
							if pixel == original {
								break
							}
							cache := colorCaches[stage]
							value, cached := cache[pixel]
							if !cached {
								if len(cache) >= 4096 && stage == len(colorPools)-1 {
									return nil, nil, fmt.Errorf("too many distinct candidate colors")
								}
								best := int(^uint(0) >> 1)
								for candidate, p := range pool {
									r, g, b, a := int(p.R)-int(pixel.R), int(p.G)-int(pixel.G), int(p.B)-int(pixel.B), int(p.A)-int(pixel.A)
									distance := (r*r+g*g+b*b)*min(int(p.A), int(pixel.A))/255 + 3*a*a
									if distance < best {
										best, value = distance, byte(candidate)
									}
								}
								// Source raw-color cache bounds storage, never acceptance.
								if len(cache) < 4096 {
									cache[pixel] = value
								}
							}
							if stage == len(colorPools)-1 {
								index = value
							} else {
								pixel = pool[value]
							}
						}
					}
				}
				if depth != 32 {
					if rasterPolicy == "exact" || rasterPolicy == "quantize" {
						index = paletteIndices[pixel]
					}
					artifact[pixelOffset+at] = artifact[pixelOffset+at]&^(indexMask<<shift) | index<<shift
				}
			}
			if depth != 32 {
				original = palette[index]
			}
			decoded.SetNRGBA(x, y, original)
		}
	}
	return artifact, decoded, nil
}
