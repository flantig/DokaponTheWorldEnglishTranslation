package main

import (
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"maps"
	"math"
	"slices"
	"unicode/utf8"
)

// composeCells preflights an ordered raster composition and returns coarse native bounds.
// Metric runs or line groups share fitting and ordered, per-line byte composition.
// Inline icons copy complete original RGBA after each line, within approved cells.
// Pixel fonts retain their centered outline/shade style.
// A narrower background paint preserves original pixels under fractional ink.
// It rejects final word-layer ink outside cells before placement, preserves inputs and
// uses whole-cell Src replacement to preserve hidden RGB while erasing old ink.
// Reconstruction and text share exact permissions; icons retain immutable source reads.
func composeCells(base *image.NRGBA, atlas *image.Gray, font RasterFont, composition RasterComposition) (*image.NRGBA, []image.Rectangle, error) {
	cells, icons := composition.Cells, composition.Icons
	glyphs := font.Glyphs
	if base == nil || len(glyphs) > 256 || len(cells) == 0 && composition.Reconstruction == nil || len(cells) > 64 {
		return nil, nil, fmt.Errorf("bitmap rendering requires bounded images, glyphs and cells")
	}
	trueType := font.TrueType != nil
	bounds := []image.Rectangle{base.Bounds()}
	if len(cells) > 0 {
		if trueType {
			if atlas != nil || font.PNG != "" || font.PNGSHA256 != "" || len(glyphs) != 0 || font.Em != 0 || font.Ascent != 0 || font.Descent != 0 || font.CapHeight != 0 || len(font.TrueTypeData) == 0 || len(font.TrueTypeData) > 4<<20 {
				return nil, nil, fmt.Errorf("TrueType font conflicts with bitmap metadata or has no bounded owned data")
			}
		} else {
			if atlas == nil || len(glyphs) == 0 || font.Layout != "" || font.TrueTypeData != nil {
				return nil, nil, fmt.Errorf("bitmap font requires an atlas and glyphs without TrueType fields")
			}
			bounds = append(bounds, atlas.Bounds())
		}
	}
	for _, bounds := range bounds {
		if bounds.Dx() < 1 || bounds.Dy() < 1 || bounds.Dx() > 4096 || bounds.Dy() > 4096 || bounds.Dx()*bounds.Dy() > 1<<20 {
			return nil, nil, fmt.Errorf("bitmap image dimensions exceed bounds")
		}
	}
	metric := len(cells) > 0 && (font.Em != 0 || trueType)
	boxes := make(map[string]image.Rectangle, len(glyphs))
	if len(cells) > 0 {
		if !trueType {
			if metric {
				if font.Em < 1 || font.Em > 256 || font.Ascent < 1 || font.Ascent > font.Em || font.Descent < 0 || font.Descent > font.Em || font.CapHeight < 1 || font.CapHeight > font.Ascent {
					return nil, nil, fmt.Errorf("invalid bitmap font metrics")
				}
			} else if font.Ascent != 0 || font.Descent != 0 || font.CapHeight != 0 {
				return nil, nil, fmt.Errorf("invalid bitmap font metrics")
			}
		}
		if len(icons) > 64 || len(icons) != 0 && !metric {
			return nil, nil, fmt.Errorf("inline icons require a metric font and at most64 declarations")
		}
		for _, name := range slices.Sorted(maps.Keys(icons)) {
			r := icons[name]
			if name == "" || len(name) > 128 || !utf8.ValidString(name) || len(r) != 4 {
				return nil, nil, fmt.Errorf("invalid inline icon identity or rectangle")
			}
			if r[0] < 0 || r[1] < 0 || r[2] < 1 || r[3] < 1 || r[2] > base.Rect.Dx()-r[0] || r[3] > base.Rect.Dy()-r[1] {
				return nil, nil, fmt.Errorf("inline icon source lies outside original image: %s", name)
			}
		}
		if atlas != nil {
			for y := atlas.Rect.Min.Y; y < atlas.Rect.Max.Y; y++ {
				for x := atlas.Rect.Min.X; x < atlas.Rect.Max.X; x++ {
					if value := atlas.GrayAt(x, y).Y; !metric && value != 0 && value != 255 {
						return nil, nil, fmt.Errorf("bitmap font requires binary grayscale coverage")
					}
				}
			}
		}
		for _, key := range slices.Sorted(maps.Keys(glyphs)) {
			glyph := glyphs[key]
			if !utf8.ValidString(key) || utf8.RuneCountInString(key) != 1 || glyph.Advance < 1 || glyph.Advance > 4096 || glyph.Left < 0 {
				return nil, nil, fmt.Errorf("invalid bitmap glyph %q", key)
			}
			if metric {
				if glyph.Left > font.Em {
					return nil, nil, fmt.Errorf("invalid bitmap glyph %q", key)
				}
				if len(glyph.Rect) == 0 && glyph.Left == 0 {
					continue
				}
			} else if glyph.Left != 0 {
				return nil, nil, fmt.Errorf("invalid bitmap glyph %q", key)
			}
			if len(glyph.Rect) != 4 {
				return nil, nil, fmt.Errorf("invalid bitmap glyph rectangle %q", key)
			}
			x, y, w, h := glyph.Rect[0], glyph.Rect[1], glyph.Rect[2], glyph.Rect[3]
			if x < 0 || y < 0 || w < 1 || h < 3 || w > atlas.Rect.Dx()-x || h > atlas.Rect.Dy()-y {
				return nil, nil, fmt.Errorf("invalid bitmap glyph bounds or advance: %q", key)
			}
			if metric {
				if w != font.Em || h != font.Em {
					return nil, nil, fmt.Errorf("invalid bitmap glyph bounds or advance: %q", key)
				}
			} else if glyph.Advance < w {
				return nil, nil, fmt.Errorf("invalid bitmap glyph bounds or advance: %q", key)
			}
			box := image.Rect(x, y, x+w, y+h).Add(atlas.Rect.Min)
			ink := false
			for y := box.Min.Y; y < box.Max.Y; y++ {
				for x := box.Min.X; x < box.Max.X; x++ {
					ink = ink || atlas.GrayAt(x, y).Y != 0
				}
			}
			if !ink {
				return nil, nil, fmt.Errorf("empty bitmap glyph %q", key)
			}
			boxes[key] = box
		}
	} else if len(icons) > 0 {
		return nil, nil, fmt.Errorf("reconstruction-only composition cannot declare unused icons")
	}
	type placedWord struct {
		layer  *BitmapLayer
		origin image.Point
	}
	type cellLayout struct {
		bounds image.Rectangle
		origin image.Point
		words  []placedWord
		paint  image.Rectangle
	}
	layouts := make([]cellLayout, len(cells))
	rectangles := make([]image.Rectangle, 0, len(cells))
	cellIndices := make(map[string]int)
	for i, cell := range cells {
		_, duplicate := cellIndices[cell.ID]
		if cell.ID == "" || len(cell.ID) > 128 || !utf8.ValidString(cell.ID) || duplicate || len(cell.Rect) != 4 {
			return nil, nil, fmt.Errorf("invalid bitmap cell identity, text, rectangle or colors")
		}
		colors := [][]int{cell.Fill, cell.Shade}
		if metric {
			if cell.Text != "" || len(cell.Fill) != 0 || len(cell.Shade) != 0 || cell.Layout == nil || cell.Group == nil && len(cell.Runs) == 0 {
				return nil, nil, fmt.Errorf("metric cells require runs/layout without pixel-font fields")
			}
			if cell.Group != nil && len(cell.Runs) != 0 {
				return nil, nil, fmt.Errorf("native group and scalar runs conflict")
			}
			colors = nil
			if len(cell.Background) != 0 {
				colors = [][]int{cell.Background}
			}
		} else if cell.Text == "" || !utf8.ValidString(cell.Text) || utf8.RuneCountInString(cell.Text) > 128 || len(cell.Runs) != 0 || cell.Group != nil || cell.Layout != nil || len(cell.Background) != 0 || cell.BackgroundRect != nil {
			return nil, nil, fmt.Errorf("pixel cells require text without metric-font fields")
		}
		for _, rgba := range colors {
			if len(rgba) != 4 || rgba[3] != 255 {
				return nil, nil, fmt.Errorf("bitmap cell requires opaque RGBA colors")
			}
			for _, channel := range rgba {
				if channel < 0 || channel > 255 {
					return nil, nil, fmt.Errorf("bitmap color channel outside0..255: %s", cell.ID)
				}
			}
		}
		cellIndices[cell.ID] = i
		x, y, w, h := cell.Rect[0], cell.Rect[1], cell.Rect[2], cell.Rect[3]
		if x < 0 || y < 0 || w < 1 || h < 1 || w > base.Rect.Dx()-x || h > base.Rect.Dy()-y {
			return nil, nil, fmt.Errorf("invalid bitmap cell bounds or opacity: %s", cell.ID)
		}
		rect := image.Rect(x, y, x+w, y+h).Add(base.Rect.Min)
		paint := image.Rect(x, y, x+w, y+h).Add(base.Rect.Min)
		if metric && len(cell.Background) == 0 {
			paint = image.Rectangle{}
			if cell.BackgroundRect != nil {
				return nil, nil, fmt.Errorf("bitmap background rectangle requires a paint color")
			}
		}
		if cell.BackgroundRect != nil {
			if len(cell.BackgroundRect) != 4 {
				return nil, nil, fmt.Errorf("bitmap background requires a rectangle")
			}
			p := cell.BackgroundRect
			if p[0] < x || p[1] < y || p[2] < 1 || p[3] < 1 || p[0]-x > w-p[2] || p[1]-y > h-p[3] {
				return nil, nil, fmt.Errorf("bitmap background rectangle lies outside approved cell")
			}
			paint = image.Rect(p[0], p[1], p[0]+p[2], p[1]+p[3]).Add(base.Rect.Min)
		}

		for _, prior := range rectangles {
			if rect.Overlaps(prior) {
				return nil, nil, fmt.Errorf("bitmap cells overlap: %s", cell.ID)
			}
		}
		if metric {
			lines := []BitmapCell{cell}
			var work int64
			if group := cell.Group; group != nil {
				if len(group.Box) != 4 || len(group.Lines) == 0 || len(group.Lines) > 16 || cell.Layout.At != nil || cell.Layout.MaxWidth != 0 {
					return nil, nil, fmt.Errorf("native group requires a box and1..16 lines without a scalar anchor or width")
				}
				for _, value := range append(slices.Clone(group.Box), group.Leading) {
					if math.IsNaN(value) || math.IsInf(value, 0) || math.Abs(value) > 4096 {
						return nil, nil, fmt.Errorf("native group requires bounded finite geometry")
					}
				}
				b := group.Box
				if b[0] < 0 || b[1] < 0 || b[2] <= 0 || b[3] <= 0 || b[0]+b[2] > float64(w) || b[1]+b[3] > float64(h) || group.Leading < 0 {
					return nil, nil, fmt.Errorf("native group box or leading exceeds approved cell")
				}
				switch group.VerticalAlign {
				case "", "middle", "top":
				default:
					return nil, nil, fmt.Errorf("unknown native vertical alignment")
				}
				leading := group.Leading
				if leading == 0 {
					leading = 1.25 * cell.Layout.Size
				}
				size := cell.Layout.Size
				lines = make([]BitmapCell, len(group.Lines))
				for j, runs := range group.Lines {
					line := cell
					style := *cell.Layout
					style.At = []float64{float64(w) / 2, float64(h) / 2}
					style.MaxWidth = b[2]
					line.Group, line.Runs, line.Layout = nil, runs, &style
					probe, _, err := renderRuns(atlas, font, line, icons)
					if err != nil {
						return nil, nil, err
					}
					work += probe.Work
					if work > 1<<28 {
						return nil, nil, fmt.Errorf("native group exceeds render work bound")
					}
					size = min(size, probe.Size)
					lines[j] = line
				}
				minimum := cell.Layout.MinSize
				if minimum == 0 {
					minimum = 6
				}
				ratio := leading / cell.Layout.Size
				// At minimum, estimated overflow is allowed; actual ink must still fit Rect.
				for size > minimum && ratio*size*float64(len(lines)) > b[3]+0.01 {
					size -= 0.25
				}
				leading = ratio * size
				ax, cy := b[0]+b[2]/2, b[1]+b[3]/2-leading*float64(len(lines)-1)/2
				if cell.Layout.Align == "left" {
					ax = b[0]
				}
				if group.VerticalAlign == "top" {
					cy = b[1] + leading/2
				}
				for j := range lines {
					lines[j].Layout.Size, lines[j].Layout.MinSize = size, size
					// Rerender at final anchors: translating a rounded probe breaks half ties.
					lines[j].Layout.At = []float64{ax, cy + float64(j)*leading}
				}
			}
			layout := cellLayout{bounds: rect, paint: paint}
			for _, line := range lines {
				word, origin, err := renderRuns(atlas, font, line, icons)
				if err != nil {
					return nil, nil, err
				}
				work += word.Work
				if cell.Group != nil && work > 1<<28 {
					return nil, nil, fmt.Errorf("native group exceeds render work bound")
				}
				origin = origin.Add(base.Rect.Min)
				for _, icon := range word.Icons {
					destination := image.Rectangle{Min: icon.At, Max: icon.At.Add(icon.Source.Size())}.Add(base.Rect.Min)
					if !destination.In(rect) {
						return nil, nil, fmt.Errorf("native icon spills outside cell %s", cell.ID)
					}
				}
				for y := 0; y < word.Rect.Dy(); y++ {
					for x := 0; x < word.Rect.Dx(); x++ {
						alpha := word.Pix[(y*word.Rect.Dx()+x)*4+3]
						if cell.Layout.Composite != "float" {
							alpha = float32(math.RoundToEven(float64(alpha)))
						}
						if alpha > 0 && !image.Pt(x+origin.X, y+origin.Y).In(rect) {
							return nil, nil, fmt.Errorf("native word spills outside cell %s", cell.ID)
						}
					}
				}
				layout.words = append(layout.words, placedWord{layer: word, origin: origin.Sub(rect.Min)})
			}
			layouts[i] = layout
			rectangles = append(rectangles, rect)
			continue
		}
		width, height, trailing := 0, 0, 0
		for _, ch := range cell.Text {
			key := string(ch)
			box, ok := boxes[key]
			if !ok || height != 0 && height != box.Dy() {
				return nil, nil, fmt.Errorf("missing glyph or unequal glyph heights in cell %s: %q", cell.ID, key)
			}
			height = box.Dy()
			width += glyphs[key].Advance
			trailing = glyphs[key].Advance - box.Dx()
		}
		width -= trailing
		ox, oy := (w-width)/2, (h-height+1)/2
		if ox < 1 || oy < 1 || ox+width+1 > w || oy+height+1 > h {
			return nil, nil, fmt.Errorf("outlined bitmap word does not fit cell %s", cell.ID)
		}
		layouts[i] = cellLayout{bounds: rect, origin: image.Pt(ox, oy)}
		rectangles = append(rectangles, rect)
	}
	erases := make(map[string]RasterErase)
	var allow *image.Alpha
	if reconstruction := composition.Reconstruction; reconstruction != nil {
		var pixelMasks RasterPermissionMasks
		if reconstruction.Masks != nil {
			pixelMasks = *reconstruction.Masks
		}
		regionCount := len(reconstruction.Allow) + len(reconstruction.Exclude) + len(reconstruction.AllowAdd) + len(pixelMasks.Allow) + len(pixelMasks.Exclude) + len(pixelMasks.AllowAdd)
		if len(reconstruction.Allow)+len(pixelMasks.Allow) == 0 || regionCount > 64 || len(reconstruction.Erases)+len(cells) == 0 || len(reconstruction.Erases)+len(cells) > 64 {
			return nil, nil, fmt.Errorf("reconstruction requires explicit allow regions and1..64 total composition steps")
		}
		var work int64
		for _, operation := range reconstruction.Erases {
			_, cellDuplicate := cellIndices[operation.ID]
			_, eraseDuplicate := erases[operation.ID]
			if operation.ID == "" || len(operation.ID) > 128 || !utf8.ValidString(operation.ID) || cellDuplicate || eraseDuplicate || len(operation.Rect) != 4 {
				return nil, nil, fmt.Errorf("invalid or duplicate reconstruction step identity/rectangle")
			}
			r := operation.Rect
			if r[0] < 0 || r[1] < 0 || r[2] < 1 || r[3] < 1 || r[2] > base.Rect.Dx()-r[0] || r[3] > base.Rect.Dy()-r[1] {
				return nil, nil, fmt.Errorf("reconstruction rectangle exceeds canvas: %s", operation.ID)
			}
			if len(operation.All) > maxRasterSelections {
				return nil, nil, fmt.Errorf("reconstruction exceeds bounded selection clauses")
			}
			work += int64(r[2]) * int64(r[3]) * 12 * int64(1+len(operation.All))
			for _, selection := range append([]RasterSelection{operation.RasterSelection}, operation.All...) {
				work += int64(r[2]) * int64(r[3]) * int64(len(selection.Above)+len(selection.Below))
			}
			if work > 1<<28 {
				return nil, nil, fmt.Errorf("reconstruction exceeds bounded pixel work")
			}
			erases[operation.ID] = operation
			rectangles = append(rectangles, image.Rect(r[0], r[1], r[0]+r[2], r[1]+r[3]).Add(base.Rect.Min))
		}
		allow = image.NewAlpha(base.Rect)
		for stage, regions := range [3]struct {
			rectangles [][]int
			masks      []RasterFootprint
		}{{reconstruction.Allow, pixelMasks.Allow}, {reconstruction.Exclude, pixelMasks.Exclude}, {reconstruction.AllowAdd, pixelMasks.AllowAdd}} {
			value := uint8(255)
			if stage == 1 {
				value = 0
			}
			for _, r := range regions.rectangles {
				if len(r) != 4 || r[0] < 0 || r[1] < 0 || r[2] < 1 || r[3] < 1 || r[2] > base.Rect.Dx()-r[0] || r[3] > base.Rect.Dy()-r[1] {
					return nil, nil, fmt.Errorf("allow rectangle exceeds canvas")
				}
				rect := image.Rect(r[0], r[1], r[0]+r[2], r[1]+r[3]).Add(base.Rect.Min)
				draw.Draw(allow, rect, image.NewUniform(color.Alpha{value}), image.Point{}, draw.Src)
			}
			for _, spec := range regions.masks {
				mask, charged, err := selectRaster(base, spec, (1<<28)-work)
				if err != nil {
					return nil, nil, err
				}
				work += charged
				origin := base.Rect.Min.Add(image.Pt(spec.Rect[0], spec.Rect[1]))
				for at, selected := range mask {
					if selected {
						allow.SetAlpha(origin.X+at%spec.Rect[2], origin.Y+at/spec.Rect[2], color.Alpha{value})
					}
				}
			}
		}
		// Native rectangles are coarse guards; the exact permission mask also protects text.
		footprint := image.NewAlpha(base.Rect)
		for _, rect := range rectangles {
			draw.Draw(footprint, rect, image.NewUniform(color.Alpha{255}), image.Point{}, draw.Src)
		}
		for y := base.Rect.Min.Y; y < base.Rect.Max.Y; y++ {
			for x := base.Rect.Min.X; x < base.Rect.Max.X; x++ {
				allow.Pix[allow.PixOffset(x, y)] &= footprint.AlphaAt(x, y).A
			}
		}
	}
	order := composition.Order
	if len(order) == 0 {
		order = make([]string, 0, len(cells)+len(erases))
		if len(cells) > 0 && len(erases) > 0 {
			return nil, nil, fmt.Errorf("mixed text and reconstruction requires explicit ordered step IDs")
		}
		for _, cell := range cells {
			order = append(order, cell.ID)
		}
		if composition.Reconstruction != nil {
			for _, operation := range composition.Reconstruction.Erases {
				order = append(order, operation.ID)
			}
		}
	}
	if len(order) != len(cells)+len(erases) {
		return nil, nil, fmt.Errorf("composition order must name each step once")
	}
	seen := make(map[string]bool, len(order))
	for _, id := range order {
		_, isCell := cellIndices[id]
		_, isErase := erases[id]
		if seen[id] || !isCell && !isErase {
			return nil, nil, fmt.Errorf("composition order contains unknown or duplicate step %q", id)
		}
		seen[id] = true
	}
	canvas := image.NewNRGBA(base.Rect)
	draw.Draw(canvas, canvas.Rect, base, base.Rect.Min, draw.Src)
	for _, id := range order {
		if operation, ok := erases[id]; ok {
			if err := reconstructRaster(canvas, allow, operation); err != nil {
				return nil, nil, err
			}
			continue
		}
		i := cellIndices[id]
		cell := cells[i]
		layout := layouts[i]
		tile := image.NewNRGBA(image.Rect(0, 0, layout.bounds.Dx(), layout.bounds.Dy()))
		background := color.NRGBA{255, 255, 255, 0}
		if metric && len(cell.Background) != 0 {
			background = color.NRGBA{uint8(cell.Background[0]), uint8(cell.Background[1]), uint8(cell.Background[2]), uint8(cell.Background[3])}
		}
		for y := 0; y < tile.Rect.Dy(); y++ {
			for x := 0; x < tile.Rect.Dx(); x++ {
				under := background
				if metric && !image.Pt(x+layout.bounds.Min.X, y+layout.bounds.Min.Y).In(layout.paint) {
					under = canvas.NRGBAAt(x+layout.bounds.Min.X, y+layout.bounds.Min.Y)
				}
				tile.SetNRGBA(x, y, under)
			}
		}
		for _, word := range layout.words {
			visible := word.layer.Rect.Add(word.origin).Intersect(tile.Rect)
			for y := visible.Min.Y; y < visible.Max.Y; y++ {
				for x := visible.Min.X; x < visible.Max.X; x++ {
					point := image.Pt(x-word.origin.X, y-word.origin.Y)
					at := (point.Y*word.layer.Rect.Dx() + point.X) * 4
					rgba := word.layer.Pix[at : at+4]
					under := tile.NRGBAAt(x, y)
					pixel := under
					switch cell.Layout.Composite {
					case "float":
						if rgba[3] > 0 {
							a := float32(rgba[3] / 255)
							ba := float32(under.A) / 255
							inverse := float32(1 - a)
							oa := float32(a + float32(ba*inverse))
							var rgb [3]uint8
							for c, value := range [3]uint8{under.R, under.G, under.B} {
								front := float32(rgba[c] * a)
								back := float32(float32(float32(value)*ba) * inverse)
								v := float32(float32(front+back) / oa)
								rgb[c] = uint8(max(0, min(255, math.RoundToEven(float64(v)))))
							}
							pixel = color.NRGBA{rgb[0], rgb[1], rgb[2], uint8(math.RoundToEven(float64(float32(oa * 255))))}
						}
					default:
						var rounded [4]uint8
						for c, value := range rgba {
							rounded[c] = uint8(max(0, min(255, math.RoundToEven(float64(value)))))
						}
						pixel = pixelOver(under, color.NRGBA{rounded[0], rounded[1], rounded[2], rounded[3]})
					}
					tile.SetNRGBA(x, y, pixel)
				}
			}
			for _, icon := range word.layer.Icons {
				at := icon.At.Add(base.Rect.Min).Sub(layout.bounds.Min)
				destination := image.Rectangle{Min: at, Max: at.Add(icon.Source.Size())}
				// Exact replacement includes transparent hidden RGB from the immutable input.
				draw.Draw(tile, destination, base, icon.Source.Min.Add(base.Rect.Min), draw.Src)
			}
		}
		if !metric {
			ink := image.NewNRGBA(tile.Rect)
			fill := color.NRGBA{uint8(cell.Fill[0]), uint8(cell.Fill[1]), uint8(cell.Fill[2]), uint8(cell.Fill[3])}
			shade := color.NRGBA{uint8(cell.Shade[0]), uint8(cell.Shade[1]), uint8(cell.Shade[2]), uint8(cell.Shade[3])}
			x := layout.origin.X
			for _, ch := range cell.Text {
				box := boxes[string(ch)]
				for y := 0; y < box.Dy(); y++ {
					pixel := fill
					if y >= box.Dy()-2 {
						pixel = shade
					}
					for dx := 0; dx < box.Dx(); dx++ {
						if atlas.GrayAt(box.Min.X+dx, box.Min.Y+y).Y != 0 {
							ink.SetNRGBA(x+dx, layout.origin.Y+y, pixel)
						}
					}
				}
				x += glyphs[string(ch)].Advance
			}
			for y := 0; y < ink.Rect.Dy(); y++ {
				for x := 0; x < ink.Rect.Dx(); x++ {
					if ink.NRGBAAt(x, y).A == 0 {
						continue
					}
					for dy := -1; dy <= 1; dy++ {
						for dx := -1; dx <= 1; dx++ {
							if ink.NRGBAAt(x+dx, y+dy).A == 0 {
								tile.SetNRGBA(x+dx, y+dy, color.NRGBA{0, 0, 0, 255})
							}
						}
					}
				}
			}
			// Over compositing can discard hidden RGB when both alphas are zero.
			for y := 0; y < ink.Rect.Dy(); y++ {
				for x := 0; x < ink.Rect.Dx(); x++ {
					if pixel := ink.NRGBAAt(x, y); pixel.A != 0 {
						tile.SetNRGBA(x, y, pixel)
					}
				}
			}
		}
		if allow != nil {
			for y := 0; y < tile.Rect.Dy(); y++ {
				for x := 0; x < tile.Rect.Dx(); x++ {
					at := layout.bounds.Min.Add(image.Pt(x, y))
					if allow.AlphaAt(at.X, at.Y).A == 0 && tile.NRGBAAt(x, y) != canvas.NRGBAAt(at.X, at.Y) {
						return nil, nil, fmt.Errorf("text step %s changes a pixel outside allow at %v", cell.ID, at.Sub(base.Rect.Min))
					}
				}
			}
		}
		draw.Draw(canvas, layout.bounds, tile, tile.Rect.Min, draw.Src)
	}
	return canvas, rectangles, nil
}
