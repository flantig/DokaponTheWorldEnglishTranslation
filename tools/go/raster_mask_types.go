package main

// RasterMaskTransform describes one finite operation on a row-major binary mask.
// Nonpositive morphology iterations converge; hole filling takes no count.
// MinimumSize filters foreground components and leaves background unselected.
// Kernel is empty/cross or square and applies only to morphology.
// Admission, when present, permits new pixels only in positive-count dilation.
// Initial selected pixels remain selected even when Admission excludes them.
// Only components accepts Connectivity, seed offsets and a same-sized rejection mask.
// Nil Seeds keeps every foreground component; a nonnil empty slice keeps none.
type RasterMaskTransform struct {
	Kind           string
	Kernel         string
	Iterations     int
	Admission      []bool
	MinimumSize    float64
	Connectivity   int
	Seeds          []int
	Reject         []bool
	BackgroundSeed string
}

// RasterComponentFilter keeps foreground components containing any declared seed,
// then vetoes a whole component if any of its pixels satisfies Reject.
// Absent Seeds keeps all components; explicit empty Seeds keeps none.
// Connectivity affects component membership, not subsequent four-neighbor growth.
// BackgroundSeed label-zero includes all input background when explicitly seeded.
// It requires explicit Seeds without size/tag criteria; nil and empty Reject differ.
type RasterComponentFilter struct {
	Connectivity   int                  `json:"connectivity"`
	Seeds          *[][]int             `json:"seeds,omitempty"`
	Reject         *[][]RasterSelection `json:"reject,omitempty"`
	BackgroundSeed string               `json:"background_seed,omitempty"`
}

// RasterFootprint builds an original-pixel permission or a current-pixel selection.
// Any is OR of bounded AND groups; empty Any is false and an empty group is true.
// Core presence enables restriction, even for an explicitly empty core list.
// Rect bounds topology; optional SampleRect limits every initial predicate role.
// SampleRect, seeds, Clip and Exclude use canvas-relative coordinates.
// Fill none and Grow zero skip their phases; negative growth converges.
// GrowThrough limits new pixels during positive final Grow; nil is unrestricted.
// Explicit empty GrowThrough admits none; existing selected pixels survive.
// CoreGrow defaults to four; explicit zero converges, unlike final Grow zero.
// Erode follows component selection inside Rect, before Grow and final clipping.
// Kernel defaults to cross; square changes morphology only, never hole/component connectivity.
type RasterFootprint struct {
	Rect        []int                  `json:"rect"`
	SampleRect  []int                  `json:"sample_rect,omitempty"`
	Any         [][]RasterSelection    `json:"any"`
	Core        *[][]RasterSelection   `json:"core,omitempty"`
	CoreGrow    *int                   `json:"core_grow,omitempty"`
	Kernel      string                 `json:"kernel,omitempty"`
	Close       int                    `json:"close,omitempty"`
	Fill        string                 `json:"fill"`
	Grow        int                    `json:"grow"`
	GrowThrough *[][]RasterSelection   `json:"grow_through,omitempty"`
	Erode       int                    `json:"erode,omitempty"`
	MinimumSize float64                `json:"minimum_size,omitempty"`
	Components  *RasterComponentFilter `json:"components,omitempty"`
	Clip        []int                  `json:"clip,omitempty"`
	Exclude     [][]int                `json:"exclude,omitempty"`
}

// RasterPermissionMasks follows the same three stages as rectangle permissions.
type RasterPermissionMasks struct {
	Allow    []RasterFootprint `json:"allow,omitempty"`
	Exclude  []RasterFootprint `json:"exclude,omitempty"`
	AllowAdd []RasterFootprint `json:"allow_add,omitempty"`
}

// rasterScalarCheck indexes one compiled comparison in the fixed property table.
type rasterScalarCheck struct {
	property  int
	below     bool
	threshold float64
}
