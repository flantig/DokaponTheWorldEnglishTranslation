package main

// RasterReconstruction keeps permission geometry separate from ordered erase facts.
// AllowAdd is applied after the union of Exclude rectangles has been subtracted.
type RasterReconstruction struct {
	Masks    *RasterPermissionMasks `json:"masks,omitempty"`
	Allow    [][]int                `json:"allow"`
	Exclude  [][]int                `json:"exclude,omitempty"`
	AllowAdd [][]int                `json:"allow_add,omitempty"`
	Erases   []RasterErase          `json:"erases,omitempty"`
}

const maxRasterSelections = 32

var rasterSelectionFields = []string{"lum_lt", "lum_gt", "sat_lt", "near", "not_near", "tol", "above", "below"}

// RasterErase reads the current canvas, including preceding text or erase steps.
// Omitted selectors select all permitted pixels; negative Grow means no growth.
type RasterErase struct {
	ID     string `json:"id"`
	Rect   []int  `json:"rect"`
	Method string `json:"method,omitempty"`
	RasterSelection
	All  []RasterSelection `json:"all,omitempty"` // Extra AND clauses, bounded independently of step count.
	Grow int               `json:"grow,omitempty"`
	Fill []int             `json:"fill,omitempty"`
}

// RasterSelection combines current-pixel tests with AND, including both color cubes.
// Tol is inclusive for Near; NotNear is its complement. RGB distance ignores alpha.
type RasterSelection struct {
	Above           map[string]float64 `json:"above,omitempty"`
	Below           map[string]float64 `json:"below,omitempty"`
	LuminanceBelow  *float64           `json:"lum_lt,omitempty"`
	LuminanceAbove  *float64           `json:"lum_gt,omitempty"`
	SaturationBelow *float64           `json:"sat_lt,omitempty"`
	Near            []int              `json:"near,omitempty"`
	NotNear         []int              `json:"not_near,omitempty"`
	Tolerance       int                `json:"tol,omitempty"`
}
