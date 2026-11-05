//go:build nativefonts && cgo && linux

package main

/*
#cgo pkg-config: freetype2
#cgo LDFLAGS: -l:libraqm.so.0
#include <stdlib.h>
#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_GLYPH_H
#include "native/raqm.h"
*/
import "C"

import (
	"fmt"
	"image"
	"math"
	"unicode/utf8"
	"unsafe"
)

// textMasks shapes and hints whole labels using one owned face per batch.
// Bearing remains ascender-relative; Start preserves Pillow fractional pen phases.
// Zero Start retains integer preview pixels; metrics belong to the owned face.
// RAQM's unhinted shaping metrics deliberately differ from hinted final masks.
func textMasks(font []byte, size int, layout string, requests []TextRequest) ([]TextMask, error) {
	if len(font) == 0 || len(font) > 4<<20 || size < 1 || size > 256 || len(requests) > 4096 {
		return nil, fmt.Errorf("font batch bounds")
	}
	if layout != "BASIC" && layout != "RAQM" {
		return nil, fmt.Errorf("unknown font layout")
	}
	characters := 0
	for _, request := range requests {
		label := request.Text
		if !utf8.ValidString(label) || utf8.RuneCountInString(label) > 4096 {
			return nil, fmt.Errorf("invalid or oversized font label")
		}
		for _, phase := range request.Start {
			if math.IsNaN(phase) || math.IsInf(phase, 0) || phase <= -1 || phase >= 1 {
				return nil, fmt.Errorf("font start must be a finite fractional coordinate within(-1,1)")
			}
		}
		characters += utf8.RuneCountInString(label)
	}
	if characters > 1<<20 {
		return nil, fmt.Errorf("font batch character budget")
	}
	var library C.FT_Library
	if code := C.FT_Init_FreeType(&library); code != 0 {
		return nil, fmt.Errorf("FreeType initialization: %d", code)
	}
	defer C.FT_Done_FreeType(library)
	fontMemory := C.CBytes(font)
	defer C.free(fontMemory)
	var face C.FT_Face
	if code := C.FT_New_Memory_Face(library, (*C.FT_Byte)(fontMemory), C.FT_Long(len(font)), 0, &face); code != 0 {
		return nil, fmt.Errorf("FreeType font: %d", code)
	}
	defer C.FT_Done_Face(face)
	request := C.FT_Size_RequestRec{_type: C.FT_SIZE_REQUEST_TYPE_NOMINAL, width: C.FT_Long(size * 64), height: C.FT_Long(size * 64)}
	if code := C.FT_Request_Size(face, &request); code != 0 {
		return nil, fmt.Errorf("FreeType size: %d", code)
	}
	var shaper *C.raqm_t
	if layout == "RAQM" {
		shaper = C.raqm_create()
		if shaper == nil {
			return nil, fmt.Errorf("RAQM initialization")
		}
		defer C.raqm_destroy(shaper)
	}
	result := make([]TextMask, 0, len(requests))
	pixels := 0
	for _, request := range requests {
		label := request.Text
		var glyphs []C.raqm_glyph_t
		if label != "" {
			runes := []rune(label)
			switch layout {
			case "RAQM":
				C.raqm_clear_contents(shaper)
				if !bool(C.raqm_set_text(shaper, (*C.uint32_t)(unsafe.Pointer(&runes[0])), C.size_t(len(runes)))) || !bool(C.raqm_set_freetype_face(shaper, face)) || !bool(C.raqm_layout(shaper)) {
					return nil, fmt.Errorf("RAQM label layout")
				}
				var count C.size_t
				data := C.raqm_get_glyphs(shaper, &count)
				if count > 16384 || (data == nil && count != 0) {
					return nil, fmt.Errorf("RAQM glyph bounds")
				}
				glyphs = unsafe.Slice(data, int(count))
			case "BASIC":
				glyphs = make([]C.raqm_glyph_t, len(runes))
				var previous C.FT_UInt
				for i, ch := range runes {
					index := C.FT_Get_Char_Index(face, C.FT_ULong(ch))
					if code := C.FT_Load_Glyph(face, index, C.FT_LOAD_DEFAULT); code != 0 {
						return nil, fmt.Errorf("FreeType advance: %d", code)
					}
					if face.face_flags&C.FT_FACE_FLAG_KERNING != 0 && previous != 0 && index != 0 {
						var delta C.FT_Vector
						if C.FT_Get_Kerning(face, previous, index, C.FT_KERNING_DEFAULT, &delta) == 0 {
							// Pillow BASIC adds rounded pixels directly to a 26.6 advance.
							glyphs[i-1].x_advance += C.int((int64(delta.x) + 32) >> 6)
							glyphs[i-1].y_advance += C.int((int64(delta.y) + 32) >> 6)
						}
					}
					glyphs[i].index = C.uint(index)
					glyphs[i].x_advance = C.int(face.glyph.metrics.horiAdvance)
					previous = index
				}
			}
		}
		xMin, xMax, yMin, yMax, pen := 0, 0, 0, 0, int64(0)
		for _, g := range glyphs {
			x := int((pen + int64(g.x_offset) + 32) >> 6)
			y := int((int64(g.y_offset) + 32) >> 6)
			pen += int64(g.x_advance)
			xMax = max(xMax, int((pen+32)>>6))
			if code := C.FT_Load_Glyph(face, C.FT_UInt(g.index), C.FT_LOAD_DEFAULT); code != 0 {
				return nil, fmt.Errorf("FreeType bounds: %d", code)
			}
			var glyph C.FT_Glyph
			if code := C.FT_Get_Glyph(face.glyph, &glyph); code != 0 {
				return nil, fmt.Errorf("FreeType glyph bounds: %d", code)
			}
			var box C.FT_BBox
			C.FT_Glyph_Get_CBox(glyph, C.FT_GLYPH_BBOX_PIXELS, &box)
			C.FT_Done_Glyph(glyph)
			xMin, xMax = min(xMin, x+int(box.xMin)), max(xMax, x+int(box.xMax))
			yMin, yMax = min(yMin, y+int(box.yMin)), max(yMax, y+int(box.yMax))
		}
		// Pillow parses these as Cfloat before ceil and pen-origin rounding.
		startX, startY := float32(request.Start[0]), float32(request.Start[1])
		width := xMax - xMin + int(math.Ceil(float64(startX)))
		height := yMax - yMin + int(math.Ceil(float64(startY)))
		if width < 0 || height < 0 || width > 16384 || height > 4096 || uint64(width)*uint64(height) > 1<<20 {
			return nil, fmt.Errorf("font mask bounds")
		}
		pixels += width * height
		if pixels > 16<<20 {
			return nil, fmt.Errorf("font batch pixel budget")
		}
		mask := image.NewGray(image.Rect(0, 0, width, height))
		ascent := int((int64(face.size.metrics.ascender) + 32) >> 6)
		descent := -int((int64(face.size.metrics.descender) + 32) >> 6)
		bearing := image.Pt(xMin, ascent-yMax)
		if len(glyphs) == 0 {
			bearing = image.Point{}
		}
		result = append(result, TextMask{Coverage: mask, Bearing: bearing, Advance: pen, Ascent: ascent, Descent: descent})
		if width == 0 || height == 0 {
			continue
		}
		// Raster extents can differ from the outline bounds used for allocation.
		x, y, left, top := int64(0), int64(0), 0, 0
		for _, g := range glyphs {
			if code := C.FT_Load_Glyph(face, C.FT_UInt(g.index), C.FT_LOAD_DEFAULT|C.FT_LOAD_RENDER); code != 0 {
				return nil, fmt.Errorf("FreeType raster extents: %d", code)
			}
			left = min(left, int((x+int64(g.x_offset)+32)>>6)+int(face.glyph.bitmap_left))
			top = max(top, int((y+int64(g.y_offset)+32)>>6)+int(face.glyph.bitmap_top))
			x += int64(g.x_advance)
			y += int64(g.y_advance)
		}
		// C round is ties-away; both arithmetic and the start narrow to float32.
		x = int64(math.Round(float64((float32(-left) + startX) * 64)))
		y = int64(math.Round(float64((float32(-top) - startY) * 64)))
		for _, g := range glyphs {
			if code := C.FT_Load_Glyph(face, C.FT_UInt(g.index), C.FT_LOAD_DEFAULT|C.FT_LOAD_RENDER); code != 0 {
				return nil, fmt.Errorf("FreeType mask: %d", code)
			}
			slot := face.glyph
			bitmap := slot.bitmap
			atX := int((x+int64(g.x_offset)+32)>>6) + int(slot.bitmap_left)
			atY := -int((y+int64(g.y_offset)+32)>>6) - int(slot.bitmap_top)
			if bitmap.buffer != nil {
				if bitmap.pixel_mode != C.FT_PIXEL_MODE_GRAY || bitmap.width > 16384 || bitmap.rows > 4096 || int64(bitmap.pitch) < -16384 || int64(bitmap.pitch) > 16384 || int64(bitmap.width) > max(int64(bitmap.pitch), -int64(bitmap.pitch)) {
					return nil, fmt.Errorf("unsupported font bitmap")
				}
				for row := 0; row < int(bitmap.rows); row++ {
					yy := atY + row
					if yy < 0 || yy >= height {
						continue
					}
					data := unsafe.Slice((*byte)(unsafe.Add(unsafe.Pointer(bitmap.buffer), row*int(bitmap.pitch))), int(bitmap.width))
					for column := max(0, -atX); column < min(int(bitmap.width), width-atX); column++ {
						i := yy*mask.Stride + atX + column
						alpha := int(data[column])
						product := int(mask.Pix[i])*(255-alpha) + 128
						mask.Pix[i] = byte(min(255, alpha+((product+(product>>8))>>8)))
					}
				}
			}
			x += int64(g.x_advance)
			y += int64(g.y_advance)
		}
	}
	return result, nil
}
