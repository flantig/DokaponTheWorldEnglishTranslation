package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

// indexTextures shares bounded RW structure/name parsing between inventory and
// the codec. Unselected raster errors must not invalidate an otherwise valid
// selection. Chunk counts retain the codec's selected-raster traversal budget.
func indexTextures(data []byte) (TextureIndex, error) {
	if len(data) < 12 || len(data) > 64<<20 || binary.LittleEndian.Uint32(data) != 0x16 || uint64(binary.LittleEndian.Uint32(data[4:]))+12 != uint64(len(data)) {
		return TextureIndex{}, fmt.Errorf("invalid TXD dictionary extent")
	}
	type chunk struct {
		kind              uint32
		start, end, entry int
	}
	index := TextureIndex{Textures: []NativeTexture{}, byName: make(map[string][]int), source: data}
	containers := []chunk{{kind: 0x16, start: 12, end: len(data)}}
	for current := 0; current < len(containers); current++ {
		parent := containers[current]
		var children []chunk
		issue := ""
		for at := parent.start; at < parent.end; {
			count := index.chunkCount
			if parent.kind == 1 {
				index.Textures[parent.entry].chunkCount++
				count += index.Textures[parent.entry].chunkCount
			} else {
				index.chunkCount++
				count++
			}
			if parent.end-at < 12 || count > 16384 {
				issue = "truncated or excessive RW chunks"
				break
			}
			size := uint64(binary.LittleEndian.Uint32(data[at+4:]))
			if size > uint64(parent.end-at-12) {
				issue = "RW chunk exceeds its parent"
				break
			}
			end := at + 12 + int(size)
			children = append(children, chunk{kind: binary.LittleEndian.Uint32(data[at:]), start: at + 12, end: end})
			at = end
		}
		if issue != "" {
			if parent.kind != 1 {
				return TextureIndex{}, fmt.Errorf("%s", issue)
			}
			index.Textures[parent.entry].MetadataError = issue
			continue
		}
		switch parent.kind {
		case 0x16:
			count := 0
			for _, child := range children {
				if child.kind == 0x15 {
					containers = append(containers, child)
					count++
				}
			}
			if len(children) == 0 || children[0].kind != 1 || children[0].end-children[0].start != 4 || int(binary.LittleEndian.Uint16(data[children[0].start:])) != count || count > 1024 {
				return TextureIndex{}, fmt.Errorf("invalid native texture count")
			}
		case 0x15:
			if len(children) < 4 || children[0].kind != 1 || children[0].end-children[0].start < 4 || !bytes.Equal(data[children[0].start:children[0].start+4], []byte{'P', 'S', '2', 0}) || children[1].kind != 2 || children[2].kind != 2 || children[3].kind != 1 {
				return TextureIndex{}, fmt.Errorf("unsupported native texture layout")
			}
			name := data[children[1].start:children[1].end]
			zero := bytes.IndexByte(name, 0)
			if zero < 1 || !utf8.Valid(name[:zero]) {
				return TextureIndex{}, fmt.Errorf("invalid native texture name")
			}
			entry := len(index.Textures)
			index.Textures = append(index.Textures, NativeTexture{Name: string(name[:zero])})
			index.byName[string(name[:zero])] = append(index.byName[string(name[:zero])], entry)
			child := children[3]
			child.entry = entry
			containers = append(containers, child)
		case 1:
			entry := &index.Textures[parent.entry]
			if len(children) != 2 || children[0].kind != 1 || children[0].end-children[0].start != 0x40 || children[1].kind != 1 {
				entry.MetadataError = "unsupported texture info/pixel structs"
				continue
			}
			entry.infoStart, entry.infoEnd = children[0].start, children[0].end
			entry.pixelStart, entry.pixelEnd = children[1].start, children[1].end
			metadata := data[entry.infoStart:entry.infoEnd]
			entry.Header = &TextureHeader{
				Width: binary.LittleEndian.Uint32(metadata), Height: binary.LittleEndian.Uint32(metadata[4:]),
				Depth: binary.LittleEndian.Uint32(metadata[8:]), RasterFormat: binary.LittleEndian.Uint16(metadata[0x0c:]),
				Version: binary.LittleEndian.Uint16(metadata[0x0e:]),
			}
		}
	}
	return index, nil
}
