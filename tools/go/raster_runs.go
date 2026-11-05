package main

import (
	"fmt"
	"image"
	"image/color"
	"math"
	"strings"
	"unicode/utf8"
)

// pixelOver preserves Pillow's seven-bit integer RGBA compositing contract.
// A transparent source copies all destination bytes, including hidden RGB.
// Derived from Pillow's AlphaComposite.c; see licenses/Pillow.txt.
func pixelOver(dst, src color.NRGBA) color.NRGBA {
	if src.A == 0 {
		return dst
	}
	alpha := uint32(src.A)*255 + uint32(dst.A)*(255-uint32(src.A))
	front := uint32(src.A) * 255 * 255 * 128 / alpha
	back := 255*128 - front
	var rgb [3]uint8
	for i, pair := range [3][2]uint8{{src.R, dst.R}, {src.G, dst.G}, {src.B, dst.B}} {
		value := uint32(pair[0])*front + uint32(pair[1])*back + (128 << 7)
		rgb[i] = uint8((((value >> 8) + value) >> 8) >> 7)
	}
	alpha += 128
	return color.NRGBA{rgb[0], rgb[1], rgb[2], uint8(((alpha >> 8) + alpha) >> 8)}
}

// renderRuns builds a styled font layer and its logical origin.
// composeCells preflights font/cell bounds; this owner validates run/layout and
// workspace limits. Quarter-step fitting, per-run cursor resets, float32 area
// sums and ties-even placement preserve the historical supersampled pipeline.
// Ordered strokes preserve four-connected counters and the outline inner rim.
// Implicit TrueType LF lines paint before styling; explicit groups compose later.
// Final area samples stay unrounded for the caller's composition contract.
// TrueType paint retains the original fixed-canvas crop before styling; bitmap
// glyph spill is refused. The caller still checks all final word-layer ink.
func renderRuns(atlas *image.Gray, font RasterFont, cell BitmapCell, icons map[string][]int) (*BitmapLayer, image.Point, error) {
	trueType := font.TrueType != nil
	if !trueType && (atlas == nil || font.Em < 1) || cell.Layout == nil || len(cell.Rect) != 4 || len(cell.Runs) < 1 || len(cell.Runs) > 64 {
		return nil, image.Point{}, fmt.Errorf("native runs require a metric font and layout")
	}
	layout := cell.Layout
	if len(layout.At) != 2 {
		return nil, image.Point{}, fmt.Errorf("native anchor requires two coordinates")
	}
	for _, value := range []float64{layout.At[0], layout.At[1], layout.Size, layout.MaxWidth, layout.ScaleX, layout.Stroke, layout.MinSize, layout.Tracking} {
		if math.IsNaN(value) || math.IsInf(value, 0) || math.Abs(value) > 4096 {
			return nil, image.Point{}, fmt.Errorf("native layout requires bounded finite values")
		}
	}
	if layout.Size < 6 || layout.Size > 64 || layout.Size*4 != math.RoundToEven(layout.Size*4) {
		return nil, image.Point{}, fmt.Errorf("native font size requires quarter steps within6..64")
	}
	if layout.MaxWidth <= 0 || layout.MaxWidth > float64(cell.Rect[2]) || layout.ScaleX <= 0 || layout.ScaleX > 2 {
		return nil, image.Point{}, fmt.Errorf("native width or horizontal scale exceeds bounds")
	}
	if layout.At[0] < 0 || layout.At[1] < 0 || layout.At[0] > float64(cell.Rect[2]) || layout.At[1] > float64(cell.Rect[3]) {
		return nil, image.Point{}, fmt.Errorf("native anchor lies outside cell")
	}
	minimum := layout.MinSize
	if minimum == 0 {
		minimum = 6
	}
	if minimum < 6 || minimum > layout.Size || minimum*4 != math.RoundToEven(minimum*4) || math.Abs(layout.Tracking) > 1 {
		return nil, image.Point{}, fmt.Errorf("native minimum size or tracking exceeds bounds")
	}
	gap := 2.0
	if layout.IconGap != nil {
		gap = *layout.IconGap
		if math.IsNaN(gap) || math.IsInf(gap, 0) || gap < 0 || gap > 64 {
			return nil, image.Point{}, fmt.Errorf("native icon gap must be finite within0..64")
		}
	}
	switch layout.Composite {
	case "", "pillow", "float":
	default:
		return nil, image.Point{}, fmt.Errorf("unknown native composition contract")
	}
	switch layout.Align {
	case "", "center", "left":
	default:
		return nil, image.Point{}, fmt.Errorf("unknown native horizontal alignment")
	}
	var strokes []BitmapStroke
	if layout.Strokes == nil {
		if layout.Stroke < 0 || int(math.RoundToEven(layout.Stroke*4)) > 2 {
			return nil, image.Point{}, fmt.Errorf("native glyph stroke exceeds calibrated radius")
		}
		strokes = []BitmapStroke{{Radius: layout.Stroke, Source: "glyph"}}
	} else if layout.Stroke != 0 {
		return nil, image.Point{}, fmt.Errorf("native scalar and ordered strokes conflict")
	} else {
		strokes = *layout.Strokes
	}
	if len(strokes) > 2 || len(strokes) == 0 && !trueType || len(strokes) > 0 && strokes[len(strokes)-1].Source != "glyph" {
		return nil, image.Point{}, fmt.Errorf("native strokes require a final glyph layer and optional outer layer")
	}
	maxStroke, outline := 0.0, false
	radii := make([]int, len(strokes))
	for i, stroke := range strokes {
		if math.IsNaN(stroke.Radius) || math.IsInf(stroke.Radius, 0) || stroke.Radius < 0 || stroke.Radius > 3.75 {
			return nil, image.Point{}, fmt.Errorf("native stroke radius exceeds bounds")
		}
		if i > 0 && stroke.Radius > strokes[i-1].Radius {
			return nil, image.Point{}, fmt.Errorf("native strokes must be outer first")
		}
		switch stroke.Source {
		case "glyph":
			if i != len(strokes)-1 || stroke.Radius > 1 || stroke.Fill != nil {
				return nil, image.Point{}, fmt.Errorf("native glyph stroke requires no color and radius at most1")
			}
		case "color", "outline":
			if i != 0 || len(strokes) != 2 || len(stroke.Fill) != 4 || stroke.Fill[3] != 255 {
				return nil, image.Point{}, fmt.Errorf("native outer stroke requires opaque RGBA")
			}
			for _, value := range stroke.Fill {
				if value < 0 || value > 255 {
					return nil, image.Point{}, fmt.Errorf("native stroke color outside0..255")
				}
			}
			outline = stroke.Source == "outline"
		default:
			return nil, image.Point{}, fmt.Errorf("unknown native stroke source")
		}
		radii[i] = int(math.RoundToEven(stroke.Radius * 4))
		maxStroke = max(maxStroke, stroke.Radius)
	}
	// Build discs once; their X-then-Y order also preserves native EDT ties.
	kernels := make(map[int][]image.Point)
	needed := append([]int(nil), radii...)
	if outline {
		needed = append(needed, 8)
	}
	for _, radius := range needed {
		if kernels[radius] != nil {
			continue
		}
		for dx := -radius; dx <= radius; dx++ {
			for dy := -radius; dy <= radius; dy++ {
				if dx*dx+dy*dy <= radius*radius+radius {
					kernels[radius] = append(kernels[radius], image.Pt(dx, dy))
				}
			}
		}
	}
	characters := 0
	for _, run := range cell.Runs {
		if run.Icon != "" {
			icon := icons[run.Icon]
			if run.Text != "" || len(run.Fill) != 0 || len(icon) != 4 || icon[2] < 1 || icon[2] > 4096 || icon[3] < 1 || icon[3] > 4096 {
				return nil, image.Point{}, fmt.Errorf("native icon run requires a declared rectangle without text or color")
			}
			continue
		}
		if run.Text == "" || !utf8.ValidString(run.Text) || len(run.Fill) != 4 || run.Fill[3] != 255 {
			return nil, image.Point{}, fmt.Errorf("native runs require text and opaque RGBA")
		}
		for _, value := range run.Fill {
			if value < 0 || value > 255 {
				return nil, image.Point{}, fmt.Errorf("native run color outside0..255")
			}
		}
		for _, ch := range run.Text {
			if glyph, ok := font.Glyphs[string(ch)]; !trueType && (!ok || glyph.Advance < 1) {
				return nil, image.Point{}, fmt.Errorf("native font has no advancing glyph %q", ch)
			}
			characters++
		}
	}
	if characters > 128 {
		return nil, image.Point{}, fmt.Errorf("native text exceeds128 characters")
	}
	tracking := layout.Tracking * 4
	size, scale, width := layout.Size, 0.0, 0.0
	advances := make([]float64, len(cell.Runs))
	var measurements []TextMask
	for {
		if trueType {
			requests := make([]TextRequest, len(cell.Runs)+2)
			for i, run := range cell.Runs {
				requests[i].Text = run.Text
			}
			requests[len(cell.Runs)].Text = "H"
			requests[len(cell.Runs)+1].Text = "A"
			var err error
			measurements, err = textMasks(font.TrueTypeData, int(math.RoundToEven(size*4)), font.Layout, requests)
			if err != nil {
				return nil, image.Point{}, err
			}
			scale = 1
		} else {
			scale = math.RoundToEven(size*4) / float64(font.Em)
		}
		width = 0
		for i, run := range cell.Runs {
			advances[i] = 0
			if run.Icon != "" {
				advances[i] = (float64(icons[run.Icon][2]) + 2*gap) * 4 / layout.ScaleX
				width += advances[i]
				continue
			}
			if trueType {
				advances[i] = float64(measurements[i].Advance) / 64
			} else {
				for _, ch := range run.Text {
					advances[i] += float64(font.Glyphs[string(ch)].Advance) * scale
				}
			}
			advances[i] += tracking * float64(utf8.RuneCountInString(run.Text))
			width += advances[i]
		}
		fitWidth := width
		if characters != 0 {
			fitWidth -= tracking
		}
		width -= tracking // The source renderer subtracts tracking even for an icon-only layer.
		if fitWidth/4*layout.ScaleX <= layout.MaxWidth || size <= minimum {
			break
		}
		size -= 0.25
	}
	for _, run := range cell.Runs {
		for _, char := range run.Text {
			if !trueType && float64(font.Glyphs[string(char)].Advance)*scale+tracking <= 0 {
				return nil, image.Point{}, fmt.Errorf("native tracking reverses glyph advance")
			}
		}
	}
	ascent := int(math.RoundToEven(float64(font.Ascent) * scale))
	descent := int(math.RoundToEven(float64(font.Descent) * scale))
	capHeight := int(math.RoundToEven(float64(font.CapHeight) * scale))
	if trueType {
		ascent, descent = measurements[0].Ascent, measurements[0].Descent
		capHeight = ascent - measurements[len(cell.Runs)].Bearing.Y
	}
	pad := int(4*(6+maxStroke)) + 4
	cw, ch := int(width+float64(2*pad)), ascent+descent+2*pad
	resizedWidth := max(1, int(math.RoundToEven(float64(cw)*layout.ScaleX)))
	paddedWidth, paddedHeight := (resizedWidth+3)/4*4, (ch+3)/4*4
	for _, dimensions := range []image.Point{{cw, ch}, {resizedWidth, ch}, {paddedWidth, paddedHeight}} {
		if dimensions.X < 1 || dimensions.Y < 1 || dimensions.X > 4096 || dimensions.Y > 4096 || dimensions.X*dimensions.Y > 1<<20 {
			return nil, image.Point{}, fmt.Errorf("native raster workspace exceeds bounds")
		}
	}
	visits := 0
	for _, radius := range needed {
		visits += len(kernels[radius])
	}
	visits = max(1, visits)
	// shortcut: bounded direct discs; upgrade morphology only for larger workloads.
	if int64(cw)*int64(ch)*int64(visits) > 1<<28 {
		return nil, image.Point{}, fmt.Errorf("native stroke workspace exceeds work bound")
	}
	coverage := image.NewGray(image.Rect(0, 0, cw, ch))
	colors := image.NewNRGBA(coverage.Rect)
	cache := make(map[rune]*image.Gray)
	base := pad + ascent
	glyphY := int(math.RoundToEven(float64(base) - float64(font.Ascent)*scale))
	glyphSize := max(1, int(math.RoundToEven(float64(font.Em)*scale)))
	runX := float64(pad)
	iconCursors := make([]float64, len(cell.Runs))
	for i, run := range cell.Runs {
		if run.Icon != "" {
			iconCursors[i] = runX + gap*4/layout.ScaleX
			runX += advances[i]
			continue
		}
		x := runX
		if trueType {
			parts := []TextRequest{{Text: run.Text}}
			var metrics []TextMask
			switch {
			case tracking != 0:
				parts = make([]TextRequest, 0, utf8.RuneCountInString(run.Text))
				for _, ch := range run.Text {
					parts = append(parts, TextRequest{Text: string(ch)})
				}
				var err error
				metrics, err = textMasks(font.TrueTypeData, int(math.RoundToEven(size*4)), font.Layout, parts)
				if err != nil {
					return nil, image.Point{}, err
				}
			case strings.Contains(run.Text, "\n"):
				parts = nil
				for _, line := range strings.Split(run.Text, "\n") {
					parts = append(parts, TextRequest{Text: line})
				}
			}
			positions := make([]image.Point, len(parts))
			for j := range parts {
				baseline := base
				if tracking == 0 {
					x = runX
					// ImageDraw's implicit lines share this canvas, before styling.
					a := measurements[len(cell.Runs)+1]
					baseline += j * (a.Bearing.Y + a.Coverage.Rect.Dy() + 4)
				}
				whole := math.Trunc(x)
				parts[j].Start[0] = x - whole
				positions[j] = image.Pt(int(whole), baseline)
				if tracking != 0 {
					x += float64(metrics[j].Advance)/64 + tracking
					if parts[j].Text == "\n" {
						parts[j].Text = "" // Blank paint still consumes the original LF advance.
					}
				}
			}
			masks, err := textMasks(font.TrueTypeData, int(math.RoundToEven(size*4)), font.Layout, parts)
			if err != nil {
				return nil, image.Point{}, err
			}
			for j, mask := range masks {
				at := positions[j].Add(mask.Bearing).Sub(image.Pt(0, mask.Ascent))
				for y := 0; y < mask.Coverage.Rect.Dy(); y++ {
					for dx := 0; dx < mask.Coverage.Rect.Dx(); dx++ {
						point := at.Add(image.Pt(dx, y))
						alpha := int(mask.Coverage.GrayAt(dx, y).Y)
						// Original ImageDraw clips combining-mark overflow to this temporary canvas.
						if alpha == 0 || !point.In(coverage.Rect) {
							continue
						}
						under := colors.NRGBAAt(point.X, point.Y)
						var rgba [4]uint8
						for c, value := range [4]uint8{under.R, under.G, under.B, under.A} {
							amount := alpha
							// Pillow's color-plane mask replaces RGB fully when old alpha is zero.
							if c < 3 && under.A == 0 {
								amount = 255
							}
							v := int(value)*(255-amount) + run.Fill[c]*amount + 128
							rgba[c] = uint8((v + (v >> 8)) >> 8)
						}
						colors.SetNRGBA(point.X, point.Y, color.NRGBA{rgba[0], rgba[1], rgba[2], rgba[3]})
						coverage.SetGray(point.X, point.Y, color.Gray{rgba[3]})
					}
				}
			}
		} else {
			for _, char := range run.Text {
				glyph := font.Glyphs[string(char)]
				if len(glyph.Rect) != 0 {
					tile := cache[char]
					if tile == nil {
						r := glyph.Rect
						box := image.Rect(r[0], r[1], r[0]+r[2], r[1]+r[3]).Add(atlas.Rect.Min)
						scaled, err := resizeRaster(atlas.SubImage(box), glyphSize, glyphSize, "lanczos", nil)
						if err != nil {
							return nil, image.Point{}, err
						}
						tile = scaled.(*image.Gray)
						cache[char] = tile
					}
					glyphX := int(math.RoundToEven(x - float64(glyph.Left)*scale))
					for y := 0; y < glyphSize; y++ {
						for dx := 0; dx < glyphSize; dx++ {
							alpha := tile.GrayAt(dx, y).Y
							point := image.Pt(glyphX+dx, glyphY+y)
							if !point.In(coverage.Rect) {
								if alpha != 0 {
									return nil, image.Point{}, fmt.Errorf("native glyph exceeds padded workspace")
								}
								continue
							}
							coverage.SetGray(point.X, point.Y, color.Gray{max(alpha, coverage.GrayAt(point.X, point.Y).Y)})
							ink := color.NRGBA{uint8(run.Fill[0]), uint8(run.Fill[1]), uint8(run.Fill[2]), alpha}
							colors.SetNRGBA(point.X, point.Y, pixelOver(colors.NRGBAAt(point.X, point.Y), ink))
						}
					}
				}
				x += float64(glyph.Advance) * scale
				if tracking != 0 {
					x += tracking
				}
			}
		}
		if tracking != 0 {
			runX = x
		} else {
			// Without tracking, the original caller resets its cursor at each run.
			runX += advances[i]
		}
	}
	foreground := make([]bool, cw*ch)
	for y := 0; y < ch; y++ {
		for x := 0; x < cw; x++ {
			foreground[y*cw+x] = coverage.GrayAt(x, y).Y > 127
		}
	}
	filled, err := transformRasterMask(foreground, cw, RasterMaskTransform{Kind: "fill_holes"})
	if err != nil {
		return nil, image.Point{}, err
	}
	word := image.NewNRGBA(coverage.Rect)
	for y := 0; y < ch; y++ {
		for x := 0; x < cw; x++ {
			alpha := coverage.GrayAt(x, y).Y
			counter := len(strokes) > 0 && alpha <= 127 && filled[y*cw+x]
			rim := false
			if counter && outline {
				for _, step := range kernels[8] {
					if coverage.GrayAt(x+step.X, y+step.Y).Y > 127 {
						rim = true
						break
					}
				}
			}
			if counter && !rim {
				continue
			}
			var out [4]float32
			for i, stroke := range strokes {
				if counter && stroke.Source == "glyph" {
					continue
				}
				grown, distance := uint8(0), math.MaxInt
				nearest := color.NRGBA{}
				if counter && stroke.Source == "outline" {
					// The original normalized mask receives a Boolean1, not1/255.
					grown = 255
				} else {
					for _, step := range kernels[radii[i]] {
						value := coverage.GrayAt(x+step.X, y+step.Y).Y
						if stroke.Source == "outline" {
							if value > 127 {
								grown = 255
								break
							}
							continue
						}
						grown = max(grown, value)
						if stroke.Source == "glyph" {
							d2 := step.X*step.X + step.Y*step.Y
							if value != 0 && d2 < distance {
								distance = d2
								nearest = colors.NRGBAAt(x+step.X, y+step.Y)
							}
						}
					}
				}
				ink := [3]float32{float32(nearest.R), float32(nearest.G), float32(nearest.B)}
				if stroke.Source != "glyph" {
					ink = [3]float32{float32(stroke.Fill[0]), float32(stroke.Fill[1]), float32(stroke.Fill[2])}
				}
				a := float32(grown) / 255
				inverse := float32(1 - a)
				for c, value := range ink {
					out[c] = float32(float32(value*a) + float32(out[c]*inverse))
				}
				out[3] = float32(float32(255*a) + float32(out[3]*inverse))
			}
			fillAlpha := float32(alpha) / 255
			inverse := float32(1 - fillAlpha)
			ink := colors.NRGBAAt(x, y)
			var rgba [4]uint8
			for c, value := range [4]uint8{ink.R, ink.G, ink.B, 255} {
				v := float32(float32(float32(value)*fillAlpha) + float32(out[c]*inverse))
				rgba[c] = uint8(max(0, min(255, math.RoundToEven(float64(v)))))
			}
			word.SetNRGBA(x, y, color.NRGBA{rgba[0], rgba[1], rgba[2], rgba[3]})
		}
	}

	scaled, err := resizeRaster(word, resizedWidth, ch, "lanczos", nil)
	if err != nil {
		return nil, image.Point{}, err
	}
	resized := scaled.(*image.NRGBA)
	layer := &BitmapLayer{Rect: image.Rect(0, 0, paddedWidth/4, paddedHeight/4), Pix: make([]float32, paddedWidth/4*(paddedHeight/4)*4), Size: size, Work: int64(cw) * int64(ch) * int64(visits)}
	for y := 0; y < layer.Rect.Dy(); y++ {
		for x := 0; x < layer.Rect.Dx(); x++ {
			var premultiplied [3]float32
			var alpha float32
			for dy := 0; dy < 4; dy++ {
				for dx := 0; dx < 4; dx++ {
					p := resized.NRGBAAt(x*4+dx, y*4+dy)
					a := float32(p.A) / 255
					for c, value := range [3]uint8{p.R, p.G, p.B} {
						premultiplied[c] = float32(premultiplied[c] + float32(float32(value)*a))
					}
					alpha = float32(alpha + float32(p.A))
				}
			}
			alpha /= 16
			var rgb [3]float32
			if alpha > 0 {
				for c, value := range premultiplied {
					value = float32(float32(value/16) / float32(alpha/255))
					rgb[c] = value
				}
			}
			at := (y*layer.Rect.Dx() + x) * 4
			copy(layer.Pix[at:at+4], []float32{rgb[0], rgb[1], rgb[2], alpha})
		}
	}
	left, textWidth := float64(pad)*layout.ScaleX, width*layout.ScaleX
	if layout.Align != "left" {
		left += textWidth / 2
	}
	ox := math.RoundToEven(float64(cell.Rect[0]) + layout.At[0] - left/4)
	oy := math.RoundToEven(float64(cell.Rect[1]) + layout.At[1] - (float64(base)-float64(capHeight)/2)/4)
	for i, run := range cell.Runs {
		if run.Icon == "" {
			continue
		}
		r := icons[run.Icon]
		// The source rounds the word origin first, then each original-sized icon slot.
		x := math.RoundToEven(ox + iconCursors[i]*layout.ScaleX/4)
		y := math.RoundToEven(oy + (float64(base)-float64(capHeight)/2)/4 - float64(r[3])/2)
		layer.Icons = append(layer.Icons, BitmapIconPlacement{Source: image.Rect(r[0], r[1], r[0]+r[2], r[1]+r[3]), At: image.Pt(int(x), int(y))})
	}
	return layer, image.Pt(int(ox), int(oy)), nil
}
