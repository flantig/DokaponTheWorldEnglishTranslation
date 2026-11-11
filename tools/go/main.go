package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// run dispatches image, registry and report operations from reviewed recipe tables.
// Dry runs verify their source; apply requires a new output path. Reports stay read-only.
func run(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("registry-patch", flag.ContinueOnError)
	sourcePath := flags.String("source", "", "source file; always read-only")
	registryPath := flags.String("registry", "", "registry supplying canonical English")
	var recipePaths []string
	flags.Func("recipes", "reviewed recipe file or directory; recipe and alias-base files at most 128 MiB; repeat to compose tables", func(path string) error {
		recipePaths = append(recipePaths, path)
		return nil
	})
	glyphPath := flags.String("glyphmap", "", "glyph map pinned by the recipes")
	fitPath := flags.String("fit-profile", "", "read-only authoring fit profile; separate from patch recipes")
	auditPath := flags.String("stream-audit-profile", "", "read-only paired stream profile with pinned input paths")
	texturePath := flags.String("texture-profile", "", "standalone calibrated TXD/PNG authoring profile")
	snapshot := flags.String("snapshot", "", "artifact snapshot operation: create, list or restore")
	snapshotDir := flags.String("snapshot-dir", "", "directory of immutable tagged snapshots")
	tag := flags.String("tag", "", "unique snapshot tag")
	commit := flags.String("commit", "", "full caller-supplied revision recorded with a snapshot")
	note := flags.String("note", "", "snapshot provenance note")
	output := flags.String("output", "", "new output file; existing files are refused")
	apply := flags.Bool("apply", false, "create a patched copy after preflight")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *auditPath != "" {
		if flags.NArg() != 0 || *sourcePath != "" || *registryPath != "" || *glyphPath != "" || *fitPath != "" || *texturePath != "" || *snapshot != "" || *snapshotDir != "" || *tag != "" || *commit != "" || *note != "" || len(recipePaths) != 0 || *apply || *output != "" {
			return fmt.Errorf("stream audit takes only its own profile; all inputs are pinned there and writes are forbidden")
		}
		return auditStreams(*auditPath, stdout)
	}
	if *snapshot != "" {
		if flags.NArg() != 0 || *fitPath != "" || *texturePath != "" || *registryPath != "" || *glyphPath != "" || len(recipePaths) != 0 {
			return fmt.Errorf("snapshot operations do not take patch, registry or authoring inputs")
		}
		return snapshotArtifacts(SnapshotOptions{Operation: *snapshot, Directory: *snapshotDir, Tag: *tag, Commit: *commit, Note: *note, Source: *sourcePath, Output: *output, Apply: *apply}, stdout)
	}
	if *snapshotDir != "" || *tag != "" || *commit != "" || *note != "" {
		return fmt.Errorf("snapshot metadata requires a snapshot operation")
	}
	if *texturePath != "" {
		if flags.NArg() != 0 || *sourcePath == "" || *fitPath != "" || *registryPath != "" || *glyphPath != "" || len(recipePaths) != 0 {
			return fmt.Errorf("texture authoring requires source and its own profile; other operation inputs are forbidden")
		}
		return authorTexture(*sourcePath, *texturePath, *output, *apply, stdout)
	}
	if *fitPath != "" {
		if flags.NArg() != 0 || *sourcePath == "" || *registryPath == "" || *glyphPath == "" || len(recipePaths) != 0 || *apply || *output != "" {
			return fmt.Errorf("fit preview requires source, registry and glyphmap; recipes, apply and output are forbidden")
		}
		return previewFit(*sourcePath, *registryPath, *glyphPath, *fitPath, stdout)
	}
	if flags.NArg() != 0 || *sourcePath == "" || len(recipePaths) == 0 {
		return fmt.Errorf("source and recipes are required; no positional arguments")
	}
	if *apply != (*output != "") {
		return fmt.Errorf("apply requires a new output path; dry run takes no output")
	}
	var paths []string
	for _, path := range recipePaths {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			matches, err := filepath.Glob(filepath.Join(path, "*.json"))
			if err != nil {
				return err
			}
			if len(matches) == 0 {
				return fmt.Errorf("recipe directory contains no JSON tables")
			}
			paths = append(paths, matches...)
		} else {
			paths = append(paths, path)
		}
	}
	var tables []Recipes
	var registryRecipeData []byte
	var pinnedRecipeData []byte
	var pinnedRecipeInfo os.FileInfo
	for _, path := range paths {
		// The shared reader caps all recipe intake; report profiles keep their tighter cap below.
		recipeData, err := readInput(path, 128<<20)
		if err != nil {
			return err
		}
		var recipes Recipes
		decoder := json.NewDecoder(bytes.NewReader(recipeData))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&recipes); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return fmt.Errorf("%s: recipes must contain one JSON value", path)
		}
		var tableFields map[string]json.RawMessage
		if err := json.Unmarshal(recipeData, &tableFields); err != nil {
			return err
		}
		// Each optional request belongs to one operation, including raw null or alias keys.
		for key, raw := range tableFields {
			var canonical, operation, route string
			policy := checkedJSON{raw: raw, text: true, allObjects: true, nonNull: true}
			switch {
			case strings.EqualFold(key, "registry_import"):
				canonical, operation, route = "registry_import", "registry_add", "registry draft import"
				policy.fieldsByDepth = map[int][]string{1: {"policy", "batches", "glyphmap", "discovered_by", "marker_orders"}}
				policy.requiredByDepth = map[int][]string{1: {"policy", "batches", "glyphmap"}}
			case strings.EqualFold(key, "sentinel"):
				canonical, operation, route = "sentinel", "elf_layout", "read-only ELF layout"
				policy.fieldsByDepth = map[int][]string{1: {"retail_elf_size", "loader_vmas", "window_bases", "window_sizes"}}
			case strings.EqualFold(key, "register_flow"):
				canonical, operation, route = "register_flow", "instruction_index", "instruction_index"
				policy.fieldsByDepth = map[int][]string{1: {"entry_vmas", "queries"}, 3: {"kind", "register", "vma", "context", "delay_of", "max_visited_states"}}
				policy.requiredByDepth = map[int][]string{1: {"entry_vmas", "queries"}, 3: {"kind", "register", "vma", "context", "max_visited_states"}}
			case strings.EqualFold(key, "reference_flow"):
				canonical, operation, route = "reference_flow", "reference_candidates", "reference_candidates"
				policy.fieldsByDepth = map[int][]string{1: {"entry_vmas", "max_visited_states", "entries"}, 3: {"benign_reader_pairs", "zero_padding_allowance"}, 5: {"lui_vma", "use_vma", "evidence"}}
				policy.requiredByDepth = map[int][]string{1: {"entry_vmas", "max_visited_states", "entries"}, 5: {"lui_vma", "use_vma", "evidence"}}
			default:
				continue
			}
			if key != canonical || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || recipes.Operation != operation {
				return fmt.Errorf("%s requires a canonical nonnull field on %s", canonical, route)
			}
			if err := checkJSON(checkedJSON{raw: recipeData, text: true, allObjects: true}); err != nil {
				return err
			}
			if err := checkJSON(policy); err != nil {
				return err
			}
		}
		indexed := recipes.Operation == "reference_gp_index" || recipes.Operation == "instruction_index"
		flow := recipes.ReferenceFlow != nil
		if recipes.Operation == "reference_observed" || indexed || flow {
			fields := []string{"operation", "source_size", "source_sha256", "scope_sha256", "evidence", "registry_patch_ref"}
			if indexed {
				fields = []string{"operation", "source_size", "source_sha256", "evidence", "references"}
				if recipes.Operation == "reference_gp_index" {
					fields = append(fields, "address_ranges")
				}
			}
			if recipes.Operation == "instruction_index" {
				fields = append(fields, "register_flow")
			}
			if flow {
				fields = []string{"operation", "source_size", "source_sha256", "scope_sha256", "glyphmap_sha256", "evidence", "iso_elf_offset", "elf_vma_delta", "references", "reference_flow", "pointer_state"}
			}
			policy := checkedJSON{raw: recipeData, text: true, allObjects: true, fieldsByDepth: map[int][]string{1: fields}}
			if indexed {
				policy.nonNullByDepth = map[int][]string{1: {"references", "address_ranges"}}
				policy.requiredByDepth = map[int][]string{1: {"operation", "source_size", "source_sha256", "evidence", "references"}}
			}
			if flow {
				policy.nonNull = true
				// pointer_state is optional; every preceding root field is explicit.
				policy.requiredByDepth = map[int][]string{1: fields[:len(fields)-1]}
			}
			if err := checkJSON(policy); err != nil {
				return err
			}
			if indexed {
				if err := checkJSON(checkedJSON{raw: tableFields["references"], text: true, allObjects: true, nonNull: true, fieldsByDepth: map[int][]string{1: {"file_range"}, 2: {"start", "end"}}, requiredByDepth: map[int][]string{1: {"file_range"}, 2: {"start", "end"}}}); err != nil {
					return err
				}
				if raw, exists := tableFields["address_ranges"]; exists {
					if err := checkJSON(checkedJSON{raw: raw, text: true, allObjects: true, nonNull: true, fieldsByDepth: map[int][]string{2: {"start", "end"}}, requiredByDepth: map[int][]string{2: {"start", "end"}}}); err != nil {
						return err
					}
				}
			}
			if flow {
				if err := checkJSON(checkedJSON{raw: tableFields["references"], text: true, allObjects: true, nonNull: true,
					fieldsByDepth:   map[int][]string{1: {"file_range", "pointer_min_vma", "skip_words", "decode_words", "queries"}},
					requiredByDepth: map[int][]string{1: {"file_range", "pointer_min_vma", "skip_words", "decode_words", "queries"}}}); err != nil {
					return err
				}
				var scanFields map[string]json.RawMessage
				if err := json.Unmarshal(tableFields["references"], &scanFields); err != nil {
					return err
				}
				if err := checkJSON(checkedJSON{raw: scanFields["file_range"], text: true, allObjects: true, nonNull: true, fieldsByDepth: map[int][]string{1: {"start", "end"}}, requiredByDepth: map[int][]string{1: {"start", "end"}}}); err != nil {
					return err
				}
				var queries map[string]json.RawMessage
				if err := json.Unmarshal(scanFields["queries"], &queries); err != nil {
					return err
				}
				// Query names and owner-ID maps are dynamic; close each typed object separately.
				for _, raw := range queries {
					if err := checkJSON(checkedJSON{raw: raw, text: true, allObjects: true, nonNull: true,
						fieldsByDepth:   map[int][]string{1: {"source_pool", "chapter", "id_range", "content_range", "unlanded_only", "backward", "decode_target", "check_collisions", "struct_rows", "omit_ids", "excluded", "flagged"}},
						requiredByDepth: map[int][]string{1: {"content_range"}}}); err != nil {
						return err
					}
					var queryFields map[string]json.RawMessage
					if err := json.Unmarshal(raw, &queryFields); err != nil {
						return err
					}
					for _, name := range []string{"id_range", "content_range"} {
						if span, present := queryFields[name]; present {
							if err := checkJSON(checkedJSON{raw: span, text: true, allObjects: true, nonNull: true, fieldsByDepth: map[int][]string{1: {"start", "end"}}, requiredByDepth: map[int][]string{1: {"start", "end"}}}); err != nil {
								return err
							}
						}
					}
					if tables, present := queryFields["struct_rows"]; present {
						if err := checkJSON(checkedJSON{raw: tables, text: true, allObjects: true, nonNull: true, fieldsByDepth: map[int][]string{2: {"start", "end", "stride"}}, requiredByDepth: map[int][]string{2: {"start", "end", "stride"}}}); err != nil {
							return err
						}
					}
				}
			}
			pinnedRecipeData = recipeData
			pinnedRecipeInfo, err = os.Stat(path)
			if err != nil || len(recipeData) > 1<<20 || flow && !pinnedRecipeInfo.Mode().IsRegular() {
				return fmt.Errorf("reference recipe must be bounded and regular: %v", err)
			}
		}

		if recipes.Operation == "reuse_table" {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(recipeData, &fields); err != nil {
				return err
			}
			fieldCount := 6
			if _, ok := fields["output_sha256"]; ok {
				fieldCount++
			}
			if len(fields) != fieldCount || recipes.BaseRecipe == "" || filepath.IsAbs(recipes.BaseRecipe) || filepath.Ext(recipes.BaseRecipe) != ".json" || recipes.BaseSHA256 == "" || recipes.SourceSHA256 == "" || recipes.SourceSize <= 0 || recipes.Evidence == "" {
				return fmt.Errorf("%s: invalid source-table alias", path)
			}
			for _, key := range []string{"operation", "base_recipe", "base_sha256", "source_sha256", "source_size", "evidence"} {
				if _, ok := fields[key]; !ok {
					return fmt.Errorf("%s: missing source-table alias field %s", path, key)
				}
			}
			basePath := filepath.Join(filepath.Dir(path), recipes.BaseRecipe)
			baseData, err := readInput(basePath, 128<<20)
			if err != nil {
				return err
			}
			if fmt.Sprintf("%x", sha256.Sum256(baseData)) != recipes.BaseSHA256 {
				return fmt.Errorf("%s: base recipe hash mismatch", path)
			}
			var base Recipes
			decoder = json.NewDecoder(bytes.NewReader(baseData))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&base); err != nil {
				return fmt.Errorf("%s: %w", basePath, err)
			}
			compatible := base.Operation == "fixed_field" && len(fields) == 6 || base.Operation == "cmb_member_replace" && recipes.OutputSHA256 != ""
			if err := decoder.Decode(&extra); err != io.EOF || !compatible || base.SourceSize != recipes.SourceSize || base.SourceSHA256 == recipes.SourceSHA256 {
				return fmt.Errorf("%s: incompatible base recipe", path)
			}
			if base.Operation == "cmb_member_replace" {
				base.OutputSHA256 = recipes.OutputSHA256
				if base.BundlePath != "" && !filepath.IsAbs(base.BundlePath) {
					base.BundlePath, err = filepath.Abs(filepath.Join(filepath.Dir(basePath), base.BundlePath))
					if err != nil {
						return err
					}
				}
			}
			var baseFields map[string]json.RawMessage
			if err := json.Unmarshal(baseData, &baseFields); err != nil {
				return err
			}
			// Alias bases only support fixed/bundle transactions, never report requests.
			for key := range baseFields {
				if strings.EqualFold(key, "reference_flow") || strings.EqualFold(key, "register_flow") || strings.EqualFold(key, "sentinel") {
					return fmt.Errorf("%s: report request %q cannot be used in a source-table base", basePath, key)
				}
			}
			base.SourceSHA256 = recipes.SourceSHA256
			recipes = base
		}
		if recipes.BaseRecipe != "" || recipes.BaseSHA256 != "" {
			return fmt.Errorf("%s: source-table alias fields require reuse_table", path)
		}
		if recipes.WordingField != "" && (recipes.Operation != "stream_slot" || recipes.WordingField != "jp") {
			return fmt.Errorf("%s: wording_field requires jp on a slot table", path)
		}
		namedReplacement := recipes.Operation == "iso_file_replace" || recipes.Operation == "cmb_member_replace"
		if !namedReplacement && (len(recipes.Files) != 0 || recipes.OutputSHA256 != "" && recipes.Operation != "guarded_words" && recipes.Operation != "stream_slot") {
			return fmt.Errorf("%s: named files require a bundle; output pins require a bundle, word or slot table", path)
		}
		if recipes.BundlePath != "" && !filepath.IsAbs(recipes.BundlePath) {
			recipes.BundlePath = filepath.Join(filepath.Dir(path), recipes.BundlePath)
		}
		for name, input := range recipes.RegistryInputs {
			if input.Path != "" && !filepath.IsAbs(input.Path) {
				input.Path = filepath.Join(filepath.Dir(path), input.Path)
				recipes.RegistryInputs[name] = input
			}
		}
		switch recipes.Operation {
		case "registry_author", "registry_add", "registry_merge", "registry_markup", "registry_export", "registry_status", "registry_reconcile", "registry_human", "text_shapes":
			registryRecipeData = recipeData
		}
		tables = append(tables, recipes)
	}
	sourcePathInfo, err := os.Stat(*sourcePath)
	if err != nil {
		return err
	}
	if !sourcePathInfo.Mode().IsRegular() {
		return fmt.Errorf("source size/type mismatch")
	}
	source, err := os.Open(*sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	sourceInfo, err := source.Stat()
	if err != nil {
		return err
	}
	if len(tables) == 0 || !sourceInfo.Mode().IsRegular() || sourceInfo.Size() != tables[0].SourceSize {
		return fmt.Errorf("source size/type mismatch")
	}
	if profile := tables[0]; profile.Operation == "reference_candidates" || profile.Operation == "reference_observed" || profile.Operation == "reference_gp_index" || profile.Operation == "instruction_index" || profile.Operation == "elf_layout" {
		layout := profile.Operation == "elf_layout"
		observed := profile.Operation == "reference_observed"
		gpIndex := profile.Operation == "reference_gp_index"
		indexed := gpIndex || profile.Operation == "instruction_index"
		flow := profile.ReferenceFlow != nil
		if (layout || indexed) && (len(tables) != 1 || *apply || *registryPath != "" || *glyphPath != "" || sourceInfo.Size() < 52 || sourceInfo.Size() > 64<<20) {
			if gpIndex {
				return fmt.Errorf("GP index requires one bounded ELF profile; registry, glyphmap and writes are forbidden")
			}
			if indexed {
				return fmt.Errorf("Instruction index requires one bounded ELF profile; registry, glyphmap and writes are forbidden")
			}
			return fmt.Errorf("ELF layout requires one bounded ELF profile; registry, glyphmap and writes are forbidden")
		}
		if !layout && !indexed && (len(tables) != 1 || *apply || *registryPath == "" || observed && *glyphPath != "" || !observed && *glyphPath == "" || sourceInfo.Size() <= 0 || sourceInfo.Size() > 64<<20) {
			if observed {
				return fmt.Errorf("observed references require one bounded ELF profile and registry; glyphmap and writes are forbidden")
			}
			return fmt.Errorf("reference reports require one bounded ELF profile, registry and glyphmap; reports are read-only")
		}
		data, err := io.ReadAll(io.LimitReader(source, sourceInfo.Size()+1))
		if err != nil {
			return err
		}
		var report any
		var registryBefore, glyphBefore os.FileInfo
		var registryData, glyphData []byte
		if layout {
			if int64(len(data)) != profile.SourceSize || fmt.Sprintf("%x", sha256.Sum256(data)) != profile.SourceSHA256 {
				return fmt.Errorf("ELF layout source hash/size mismatch")
			}
			state, err := inspect(bytes.NewReader(data), nil, &profile)
			if err != nil {
				return err
			}
			report = map[string]any{"operation": profile.Operation, "applied": false, "source_sha256": profile.SourceSHA256,
				"entry_point": state.ELFEntry, "program_headers": state.ELFSegments, "address_ranges": state.ELFMappings,
				"limits": "Read-only ELF32 MIPS LOAD mapping. Ranges are half-open; BSS has no file bytes. Mapping and segment flags do not prove unused storage, runtime ownership, safe caves or patch readiness. No ISO translation or allocation."}
			if state.Sentinel != nil {
				layoutReport := report.(map[string]any)
				layoutReport["sentinel_allocation"] = state.Sentinel
				layoutReport["limits"] = "Read-only ELF32 MIPS LOAD and installed sentinel transport mapping. sentinel_blob has no program header; only the loaded physical intersection is mapped, not the larger dispatch window. Retail EOF is a declared pinned-layout assumption. Mapping and installed instructions do not prove runtime execution, ownership, safe placement or patch readiness. No ISO allocation or writes."
			}
		} else {
			if observed || flow {
				registryBefore, err = os.Stat(*registryPath)
				if err != nil {
					return err
				}
				registryData, err = readInput(*registryPath, 64<<20)
			} else if !indexed {
				registryData, err = os.ReadFile(*registryPath)
			}
			if err != nil {
				return err
			}
			if !observed && !indexed {
				if flow {
					glyphBefore, err = os.Stat(*glyphPath)
					if err != nil {
						return err
					}
					glyphData, err = readInput(*glyphPath, 64<<20)
				} else {
					glyphData, err = os.ReadFile(*glyphPath)
				}
				if err != nil {
					return err
				}
			}
			facts, err := references(data, registryData, glyphData, profile)
			if err != nil {
				return err
			}
			if observed || indexed || flow {
				facts.ProfileSHA256 = fmt.Sprintf("%x", sha256.Sum256(pinnedRecipeData))
			}
			report = facts
		}
		if _, err := source.Seek(0, io.SeekStart); err != nil {
			return err
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, source); err != nil {
			return err
		}
		if after, err := source.Stat(); err != nil || after.Size() != sourceInfo.Size() || after.ModTime() != sourceInfo.ModTime() || fmt.Sprintf("%x", hash.Sum(nil)) != profile.SourceSHA256 {
			if layout {
				return fmt.Errorf("ELF layout source changed during analysis")
			}
			return fmt.Errorf("reference source changed during analysis")
		}
		if observed || indexed || flow {
			pathInfo, err := os.Stat(*sourcePath)
			if err != nil || !os.SameFile(sourceInfo, pathInfo) {
				return fmt.Errorf("observed source path changed")
			}
			for i, input := range []struct {
				path   string
				data   []byte
				limit  int64
				before os.FileInfo
			}{{*registryPath, registryData, 64 << 20, registryBefore}, {paths[0], pinnedRecipeData, 1 << 20, pinnedRecipeInfo}, {*glyphPath, glyphData, 64 << 20, glyphBefore}} {
				if indexed && i == 0 || !flow && i == 2 {
					continue
				}
				current, err := readInput(input.path, input.limit)
				after, statErr := os.Stat(input.path)
				if err != nil || statErr != nil || !bytes.Equal(current, input.data) || !os.SameFile(input.before, after) || input.before.ModTime() != after.ModTime() {
					return fmt.Errorf("observed report input changed: %s", input.path)
				}
			}
		}
		var buffered bytes.Buffer
		var destination io.Writer = stdout
		if indexed || flow {
			destination = &buffered
		}
		encoder := json.NewEncoder(destination)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(report); err != nil {
			return err
		}
		if indexed || flow {
			if buffered.Len() > 64<<20 {
				if flow {
					return fmt.Errorf("Reference flow JSON exceeds64MiB")
				}
				if gpIndex {
					return fmt.Errorf("GP index JSON exceeds64MiB")
				}
				return fmt.Errorf("Instruction index JSON exceeds64MiB")
			}
			_, err := io.Copy(stdout, &buffered)
			return err
		}
		return nil
	}
	switch tables[0].Operation {
	case "registry_author", "registry_add", "registry_merge", "registry_markup", "registry_export", "registry_status", "registry_reconcile", "registry_human", "text_shapes":
		return authorRegistry(source, tables, registryRecipeData, RegistryOptions{RegistryPath: *registryPath, ProfilePath: paths[0], GlyphmapPath: *glyphPath, Output: *output, Apply: *apply}, stdout)
	}
	bundleOnly := len(tables) == 1 && (tables[0].Operation == "cmb_member_replace" || tables[0].Operation == "iso_file_replace")
	if !bundleOnly && (*registryPath == "" || *glyphPath == "") {
		return fmt.Errorf("image transactions require registry and glyphmap")
	}
	var registry Registry
	var glyphs []byte
	if !bundleOnly {
		registryData, err := os.ReadFile(*registryPath)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(registryData, &registry); err != nil {
			return err
		}
		glyphs, err = os.ReadFile(*glyphPath)
		if err != nil {
			return err
		}
	}
	edits, err := plan(tables, registry, glyphs, source)
	if err != nil {
		return err
	}
	if !*apply {
		if err := verifySource(source, tables, edits, registry, glyphs); err != nil {
			return err
		}
	}
	rows := make([]map[string]any, 0, len(edits))
	for _, edit := range edits {
		if edit.Operation == "cmb_member_replace" || edit.Operation == "iso_file_replace" {
			key := "asset_member"
			if edit.Operation == "iso_file_replace" {
				key = "iso_file"
			}
			rows = append(rows, map[string]any{key: edit.ID, "offset": edit.Offset,
				"length": len(edit.New), "old_sha256": fmt.Sprintf("%x", sha256.Sum256(edit.Old)),
				"new_sha256": fmt.Sprintf("%x", sha256.Sum256(edit.New)), "operation": edit.Operation})
			continue
		}
		rows = append(rows, map[string]any{"registry_id": edit.ID, "offset": edit.Offset,
			"old_hex": hex.EncodeToString(edit.Old), "new_hex": hex.EncodeToString(edit.New), "operation": edit.Operation})
	}
	report := map[string]any{"applied": *apply, "edits": rows, "source_sha256": tables[0].SourceSHA256}
	if tables[0].OutputSHA256 != "" {
		report["expected_output_sha256"] = tables[0].OutputSHA256
	}
	if *apply {
		digest, err := patchCopy(source, *output, tables, edits, registry, glyphs)
		if err != nil {
			return err
		}
		report["output"], report["output_sha256"] = *output, digest
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
