package main

import "image"

// RasterFont selects a pinned grayscale atlas or a pinned TrueType source.
// For atlases, Em zero selects binary pixels; metric fonts use full-cell tiles.
// TrueType metrics come from its owned face, never authored bitmap metadata.
type RasterFont struct {
	TrueType     *RegistryInput         `json:"truetype,omitempty"`
	Layout       string                 `json:"layout,omitempty"` // BASIC or RAQM for a TrueType source.
	TrueTypeData []byte                 `json:"-"`                // Owned, pinned bytes loaded by authorTexture.
	PNG          string                 `json:"png,omitempty"`
	PNGSHA256    string                 `json:"png_sha256,omitempty"`
	Glyphs       map[string]BitmapGlyph `json:"glyphs,omitempty"`
	Em           int                    `json:"em,omitempty"`
	Ascent       int                    `json:"ascent,omitempty"`
	Descent      int                    `json:"descent,omitempty"`
	CapHeight    int                    `json:"cap_height,omitempty"`
}

type BitmapGlyph struct {
	Rect    []int `json:"rect,omitempty"`
	Advance int   `json:"advance"`
	Left    int   `json:"left,omitempty"`
}

// RasterRender binds shared font resources to an ordered composition.
// IDs identify asset facts; they do not invent canonical registry entries.
type RasterRender struct {
	Font        string         `json:"font,omitempty"`
	FontSHA256  string         `json:"font_sha256,omitempty"`
	Permissions *RegistryInput `json:"permissions,omitempty"` // Shared rectangle facts; local steps remain in Reconstruction.
	RasterComposition
}

// RasterComposition groups pixel operations independently of font-file loading.
// Mixed erases and text require a complete Order; old text-only wire data is unchanged.
type RasterComposition struct {
	Icons          map[string][]int      `json:"icons,omitempty"`
	Cells          []BitmapCell          `json:"cells,omitempty"`
	Reconstruction *RasterReconstruction `json:"reconstruction,omitempty"`
	Order          []string              `json:"order,omitempty"`
}

type BitmapCell struct {
	ID         string           `json:"id"`
	Rect       []int            `json:"rect"`
	Text       string           `json:"text,omitempty"`
	Fill       []int            `json:"fill,omitempty"`
	Shade      []int            `json:"shade,omitempty"`
	Runs       []BitmapRun      `json:"runs,omitempty"`
	Group      *BitmapLineGroup `json:"group,omitempty"`
	Layout     *BitmapRunLayout `json:"layout,omitempty"`
	Background []int            `json:"background,omitempty"`
	// Omitted Background preserves input pixels. BackgroundRect limits explicit paint.
	BackgroundRect []int `json:"background_rect,omitempty"`
}

type BitmapRun struct {
	Text string `json:"text,omitempty"`
	Fill []int  `json:"fill,omitempty"`
	Icon string `json:"icon,omitempty"` // Alternative to text/color; retains source pixel size.
}

// BitmapLineGroup fits all lines at one size; Box is relative to the approved cell.
// Layout supplies the shared style; its At and MaxWidth are omitted for groups.
type BitmapLineGroup struct {
	Box           []float64     `json:"box"`
	Lines         [][]BitmapRun `json:"lines"`
	Leading       float64       `json:"leading,omitempty"`
	VerticalAlign string        `json:"vertical_align,omitempty"`
}

// BitmapRunLayout uses a cell-relative anchor at the font's cap height center.
type BitmapRunLayout struct {
	At        []float64       `json:"at,omitempty"`
	Size      float64         `json:"size"`
	MaxWidth  float64         `json:"max_width,omitempty"`
	ScaleX    float64         `json:"scale_x"`
	Stroke    float64         `json:"stroke,omitempty"`
	MinSize   float64         `json:"min_size,omitempty"`
	Tracking  float64         `json:"tracking,omitempty"`
	Strokes   *[]BitmapStroke `json:"strokes,omitempty"` // Nil selects scalar stroke; explicit [] omits all TrueType strokes.
	Composite string          `json:"composite,omitempty"`
	Align     string          `json:"align,omitempty"`
	IconGap   *float64        `json:"icon_gap,omitempty"` // Nil means two pixels on each side; zero is explicit.
}

// BitmapStroke is a glyph stroke with an optional outer color or outline layer.
// Outline uses a binary mask and fixed inner rim; its role is independent of RGB.
type BitmapStroke struct {
	Radius float64 `json:"radius"`
	Source string  `json:"source"`
	Fill   []int   `json:"fill,omitempty"`
}

// BitmapLayer retains straight float32 RGBA after supersampled area averaging.
// The cell compositor owns final rounding; Pix is tightly packed at Rect.Min=0.
type BitmapLayer struct {
	Rect  image.Rectangle
	Pix   []float32
	Size  float64               // Chosen quarter-step size, shared by all lines of a group.
	Work  int64                 // Direct stroke visits; groups bound their combined render work.
	Icons []BitmapIconPlacement // Copied after this line, before the next line paints.
}

// BitmapIconPlacement connects fitted run geometry to an immutable source crop.
type BitmapIconPlacement struct {
	Source image.Rectangle
	At     image.Point // Sheet coordinates, before adding base.Rect.Min.
}

// TextRequest keeps each label's fractional raster start with its text.
// Start is the signed remainder after truncating the caller's pixel coordinate.
type TextRequest struct {
	Text  string
	Start [2]float64
}

// TextMask owns grayscale coverage and ascender-relative placement for one whole label.
type TextMask struct {
	Coverage *image.Gray
	Bearing  image.Point
	Advance  int64 // Unrounded 26.6 horizontal advance; whitespace can have no ink.
	Ascent   int
	Descent  int
}
