package main

import (
	"image"
	"regexp"
	"strings"
)

var (
	textureModelPath = regexp.MustCompile(`^(battle\\(player|monster|bg|weapon|shield|textures\\(player|monster))|field\\(fp|map)|event\\(npc|evtkao|bg|race\\rm))`)
	textureIconPath  = regexp.MustCompile(`^textures\\win_(pl|wep|mon)\\`)
	textureNameHint  = regexp.MustCompile(`(?i)help|tut|rule|setumei|guide|illust|title|logo|news|kojityu|mini_|card_|casino|prize|sale|button|panel|ready|start|gameset|survive|wanted|jikai|food_t|f_title|op_p|win_`)
)

// inspectRaster preserves explainer_scan's successful 8x8-tile measurements.
// Scores are discovery leads, not OCR. The reference crashes on cropped masks
// and returns a short tuple below 8px; these cases remain explicitly unavailable.
// Callers supply a well-formed, bounded raster; nonzero origins and strides work.
func inspectRaster(raster *image.NRGBA, entry, texture string) TextureDiscovery {
	result := TextureDiscovery{Tier: "ui", Status: "unavailable", FlagReasons: []string{}}
	// Python lower expands dotted I; Go's simple lowercase mapping does not.
	path := strings.ToLower(strings.ReplaceAll(entry, "İ", "i\u0307"))
	switch {
	case textureModelPath.MatchString(path):
		result.Tier = "model"
	case textureIconPath.MatchString(path):
		result.Tier = "icons"
	}
	if raster == nil {
		result.Diagnostic = "pixels were not decoded"
		return result
	}
	w, h := raster.Rect.Dx(), raster.Rect.Dy()
	switch {
	case w < 8 || h < 8:
		result.Diagnostic = "reference detector returns an incomplete score below 8 pixels"
	case w%8 != 0 || h%8 != 0:
		result.Diagnostic = "reference detector has an incompatible cropped opacity mask"
	default:
		cols, rows := w/8, h/8
		glyphs := make([]bool, cols*rows)
		opaqueTiles, opaquePixels, dominant := 0, 0, 0
		colors := make(map[uint16]int)
		score := &TextureDiscoveryScore{}
		for ty := 0; ty < rows; ty++ {
			for tx := 0; tx < cols; tx++ {
				edges, opaque, dark, light := 0, 0, 0, 0
				for dy := 0; dy < 8; dy++ {
					for dx := 0; dx < 8; dx++ {
						x, y := raster.Rect.Min.X+tx*8+dx, raster.Rect.Min.Y+ty*8+dy
						p := raster.NRGBAAt(x, y)
						if p.A <= 128 {
							continue
						}
						opaque++
						lum := (299*int(p.R) + 587*int(p.G) + 114*int(p.B)) / 1000
						if lum < 90 {
							dark++
						}
						if lum > 150 {
							light++
						}
						key := uint16(p.R/8)*1024 + uint16(p.G/8)*32 + uint16(p.B/8)
						colors[key]++
						dominant = max(dominant, colors[key])
						if x+1 < raster.Rect.Max.X {
							next := raster.NRGBAAt(x+1, y)
							diff := lum - (299*int(next.R)+587*int(next.G)+114*int(next.B))/1000
							if next.A > 128 && (diff > 90 || diff < -90) {
								edges++
							}
						}
					}
				}
				opaquePixels += opaque
				if opaque > 32 {
					opaqueTiles++
				}
				// These integer bounds are exactly the reference's strict fractions of 64.
				if edges >= 6 && dark >= 4 && dark <= 44 && light >= 10 && opaque > 32 {
					glyphs[ty*cols+tx] = true
					score.GlyphTiles++
				}
			}
		}
		for y := 0; y < rows; y++ {
			run, best := 0, 0
			for x := 0; x < cols; x++ {
				if !glyphs[y*cols+x] {
					run = 0
					continue
				}
				run++
				best = max(best, run)
				neighbors := 0
				for ny := max(0, y-1); ny <= min(rows-1, y+1); ny++ {
					for nx := max(0, x-1); nx <= min(cols-1, x+1); nx++ {
						if glyphs[ny*cols+nx] {
							neighbors++
						}
					}
				}
				if neighbors >= 3 {
					score.GlyphClusters++
				}
			}
			if best >= 8 {
				score.TextLineRows++
			}
		}
		score.ClusterFraction = float64(score.GlyphClusters) / float64(max(1, opaqueTiles))
		if opaquePixels != 0 {
			score.DominantColorFraction = float64(dominant) / float64(opaquePixels)
		}
		score.OpaqueFraction = float64(opaquePixels) / float64(w*h)
		result.Status, result.Score = "measured", score
	}
	if result.Tier == "ui" || result.Tier == "icons" {
		result.FlagReasons = append(result.FlagReasons, "ui-folder")
	}
	if result.Score != nil {
		if result.Tier == "model" && result.Score.TextLineRows >= 1 {
			result.FlagReasons = append(result.FlagReasons, "detector-text-lines")
		}
		if result.Tier == "ui" && result.Score.GlyphClusters >= 40 && result.Score.DominantColorFraction >= 0.3 {
			result.FlagReasons = append(result.FlagReasons, "detector-glyphs")
		}
	}
	// Python's Unicode IGNORECASE additionally matches dotted and dotless I.
	hint := strings.ReplaceAll(strings.ReplaceAll(entry+" "+texture, "İ", "i"), "ı", "i")
	if textureNameHint.MatchString(hint) {
		result.FlagReasons = append(result.FlagReasons, "name-hint")
	}
	return result
}
