package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestProbeLifecycleChild is a gated test executable, never a production mode.
// One synchronous deadline-bound server owns its socket and flushes its private
// fixture card on SIGTERM, so cold/stop can prove changed post-exit bytes.
func TestProbeLifecycleChild(t *testing.T) {
	if os.Getenv("DOKAPON_PROBE_LIFECYCLE_CHILD") != "1" {
		t.Skip("controlled child only")
	}
	root := os.Getenv("DOKAPON_PROBE_SESSION_ROOT")
	if root == "" {
		t.Fatal("missing controlled root")
	}
	stopped := make(chan os.Signal, 1)
	parentPID := os.Getppid()
	expires := time.Now().Add(30 * time.Second)
	signal.Notify(stopped, syscall.SIGTERM)
	defer signal.Stop(stopped)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(root, "peer.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	entries, err := os.ReadDir(filepath.Join(root, "receipts"))
	if err != nil {
		t.Fatal(err)
	}
	pending := []string{}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".pending.json") {
			pending = append(pending, entry.Name())
		}
	}
	evidence, _ := json.Marshal(map[string]any{"pid": os.Getpid(), "argv": os.Args, "pending": pending})
	if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("child-evidence-%d.json", os.Getpid())), evidence, 0600); err != nil {
		t.Fatal(err)
	}
	mode := uint16(608)
	watchAdvance := slices.Contains(os.Args, "watch-advance")
	watchStall := slices.Contains(os.Args, "watch-stall")
	watchCrash := slices.Contains(os.Args, "watch-crash")
	toggleTimeout := slices.Contains(os.Args, "toggle-timeout")
	watchSample, modeReads, seenPause := 0, 0, 0
	vmStatus := uint32(0)
	failedReady := slices.Contains(os.Args, "failed-ready")
	newGame := slices.Contains(os.Args, "scenario-newgame")
	paired := slices.Contains(os.Args, "scenario-paired") || newGame
	scenario := slices.Contains(os.Args, "scenario-first-save") || paired
	if scenario {
		expires = time.Now().Add(120 * time.Second)
	}
	if paired {
		expires = time.Now().Add(600 * time.Second)
	}
	scenarioStage, boardCursor, tabCursor, fileCursor, eventOffset := 0, 0, 0, 0, 0
	scenarioControl := byte(1)
	activeActor := 0
	tutorialFlag := byte(1)
	yesNoCursor := uint32(0)
	introSamples := 0
	preparationAcks := 0
	preparationImageSamples := 0
	if newGame {
		activeActor = 2
		tutorialFlag = 0
		scenarioControl = 2
		scenarioStage = 8
	}
	scenarioModeReads := 0
	scenarioWrites := 0
	scenarioTrace := []string{}
	var loadedRecords, loadedHeaders []byte
	var playerData []byte
	titleCursor, advanceAtMode := 0, 0
	peerPreviewSamples := 0
	prefixTampered := false
	if failedReady {
		mode = 424
	}
	padBytes, _ := os.ReadFile(filepath.Join(root, "pad-events.bin"))
	if paired {
		for _, name := range pending {
			if strings.Contains(name, "-cold-load-") {
				scenarioStage = 8
				scenarioControl = 2
				eventOffset = len(padBytes)
			}
		}
		prior, _ := os.ReadFile(filepath.Join(root, "scenario-inputs.json"))
		_ = json.Unmarshal(prior, &scenarioTrace)
		priorWrites, _ := os.ReadFile(filepath.Join(root, "scenario-write-count.txt"))
		scenarioWrites, _ = strconv.Atoi(string(priorWrites))
	}
	seenReset := 0
	for offset := 0; offset+24 <= len(padBytes); offset += 24 {
		if binary.LittleEndian.Uint16(padBytes[offset+16:]) == 1 && binary.LittleEndian.Uint16(padBytes[offset+18:]) == 318 && binary.LittleEndian.Uint32(padBytes[offset+20:]) == 1 {
			seenReset++
		}
	}
	for {
		if os.Getppid() != parentPID || time.Now().After(expires) {
			return
		}
		if scenario {
			// The controlled VM observes input independently, as a real renderer
			// would; capture must not need another memory request to create PNG.
			events, _ := os.ReadFile(filepath.Join(root, "pad-events.bin"))
			guideCount := 0
			for offset := 0; offset+24 <= len(events); offset += 24 {
				if binary.LittleEndian.Uint16(events[offset+16:]) == 1 && binary.LittleEndian.Uint16(events[offset+18:]) == 316 && binary.LittleEndian.Uint32(events[offset+20:]) == 1 {
					guideCount++
					name := "first-save.png"
					if guideCount > 1 {
						name = fmt.Sprintf("capture-%d.png", guideCount)
					}
					path := filepath.Join(root, "profile", "PCSX2", "snaps", name)
					if _, err := os.Stat(path); os.IsNotExist(err) {
						var fixture struct {
							ImageHex string `json:"image_hex"`
						}
						data, _ := os.ReadFile("testdata/probe-capture.json")
						if json.Unmarshal(data, &fixture) != nil {
							t.Fatal("capture fixture")
						}
						image, err := hex.DecodeString(fixture.ImageHex)
						if err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(path, image, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
		}
		select {
		case <-stopped:
			card := filepath.Join(root, "profile", "PCSX2", "memcards", "probe-slot1.ps2")
			data, err := os.ReadFile(card)
			if err != nil || len(data) == 0 {
				t.Fatalf("private card: %v", err)
			}
			if !paired {
				data[0]++
			}
			file, err := os.OpenFile(card, os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				t.Fatal(err)
			}
			_, err = file.Write(data)
			if err == nil {
				err = file.Sync()
			}
			closeErr := file.Close()
			if err != nil || closeErr != nil {
				t.Fatalf("flush: %v %v", err, closeErr)
			}
			return
		default:
		}
		_ = listener.SetDeadline(time.Now().Add(50 * time.Millisecond))
		connection, err := listener.AcceptUnix()
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			t.Fatal(err)
		}
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		frameIndex := 0
		var firstFrame []byte
		for {
			header := make([]byte, 4)
			if _, err := io.ReadFull(connection, header); err != nil {
				if err != io.EOF {
					t.Error(err)
				}
				break
			}
			length := int(binary.LittleEndian.Uint32(header))
			if length != 5 && length != 9 && !(scenario && length == 10) {
				t.Errorf("bad frame size%d", length)
				break
			}
			payload := make([]byte, length-4)
			if _, err := io.ReadFull(connection, payload); err != nil {
				t.Error(err)
				break
			}
			if frameIndex == 0 {
				firstFrame = bytes.Clone(payload)
			}
			if paired && scenarioStage == 9 && frameIndex == 1 && bytes.Equal(firstFrame, []byte{1, 0x1c, 0x58, 0x56, 0}) && bytes.Equal(payload, []byte{2, 8, 1, 0x57, 0}) {
				peerPreviewSamples++
			}
			var reply []byte
			if scenario {
				events, _ := os.ReadFile(filepath.Join(root, "pad-events.bin"))
				for ; eventOffset+24 <= len(events); eventOffset += 24 {
					event := events[eventOffset:]
					kind, code, value := binary.LittleEndian.Uint16(event[16:]), binary.LittleEndian.Uint16(event[18:]), int32(binary.LittleEndian.Uint32(event[20:]))
					name := ""
					if kind == 3 && code == 17 && value != 0 {
						delta := int(value)
						name = "DOWN"
						if value < 0 {
							name = "UP"
						}
						switch scenarioStage {
						case 0, 12:
							boardCursor += delta
						case 1:
							tabCursor += delta
						case 2, 6, 9:
							fileCursor += delta
						case 8:
							titleCursor += delta
						case 21, 23:
							yesNoCursor = uint32(int(yesNoCursor) + delta)
						}
					}
					if kind == 1 && value == 1 {
						switch code {
						case 317:
							name = "L3"
						case 318:
							name = "R3"
							if paired {
								scenarioStage = 8
								titleCursor = 0
								fileCursor = 0
								scenarioControl = 2
								if newGame {
									tutorialFlag = 0
								}
								loadedRecords = nil
								loadedHeaders = nil
							}
						case 305:
							name = "CIRCLE"
							switch scenarioStage {
							case 0, 12:
								if boardCursor == 4 {
									scenarioStage = 1
								}
							case 1:
								if tabCursor == 4 {
									scenarioStage = 2
								}
							case 2:
								if fileCursor == 1 {
									scenarioStage = 3
									yesNoCursor = 0
								}
							case 3:
								if paired {
									cardPath := filepath.Join(root, "profile", "PCSX2", "memcards", "probe-slot1.ps2")
									card, err := os.ReadFile(cardPath)
									if err != nil || len(card) != 4112 || len(playerData) != 2032 {
										t.Fatal("controlled card source layout")
									}
									binary.LittleEndian.PutUint32(card[2060:], 1)
									binary.LittleEndian.PutUint32(card[2072:], uint32(activeActor))
									copy(card[2080:], playerData)
									file, err := os.OpenFile(cardPath, os.O_WRONLY|os.O_TRUNC, 0600)
									if err != nil {
										t.Fatal(err)
									}
									_, err = file.Write(card)
									if err == nil {
										err = file.Sync()
									}
									_ = file.Close()
									if err != nil {
										t.Fatal(err)
									}
								}
								scenarioStage = 5
							case 5:
								scenarioStage = 6
							case 8:
								if newGame && titleCursor == 0 {
									scenarioStage = 20
									scenarioControl = 0
									break
								}
								if titleCursor == 2 {
									scenarioStage = 9
									fileCursor = 0
									peerPreviewSamples = 0
								}
							case 9:
								if fileCursor == 1 {
									if paired && peerPreviewSamples != 40 {
										t.Fatalf("Load before all40 successful preview exchanges: %d", peerPreviewSamples)
									}
									scenarioStage = 10
									yesNoCursor = 0
								}
							case 10:
								card, err := os.ReadFile(filepath.Join(root, "profile", "PCSX2", "memcards", "probe-slot1.ps2"))
								if err != nil || len(card) != 4112 {
									t.Fatal("controlled Load card")
								}
								loadedHeaders = bytes.Clone(card[2060:2080])
								loadedRecords = bytes.Clone(card[2080:])
								scenarioControl = loadedRecords[activeActor*508+241]
								scenarioStage = 12
								if newGame && loadedRecords[activeActor*508]&1 == 0 {
									loadedRecords[activeActor*508] |= 1
									tutorialFlag = 1
									scenarioStage = 25
								}
								boardCursor = 0
								tabCursor = 0
							case 20:
								scenarioStage = 21
								yesNoCursor = 1
							case 21:
								if yesNoCursor != 0 {
									t.Fatal("first yes/no not rechecked")
								}
								scenarioStage = 22
							case 22:
								scenarioStage = 23
								yesNoCursor = 0
							case 23:
								if yesNoCursor != 1 {
									t.Fatal("second yes/no not declined/rechecked")
								}
								scenarioStage = 24
								scenarioControl = 0
							case 25:
								if preparationImageSamples < 2 || len(loadedRecords) != 2032 || loadedRecords[activeActor*508]&1 == 0 {
									t.Fatal("ack cannot initialize tutorial flag")
								}
								preparationAcks++
								_ = os.WriteFile(filepath.Join(root, "preparation-acks.txt"), []byte(strconv.Itoa(preparationAcks)), 0600)
								scenarioStage = 12
							}
						case 316:
							name = "GUIDE"
						}
					}
					if name != "" {
						scenarioTrace = append(scenarioTrace, name)
					}
				}
				trace, _ := json.Marshal(scenarioTrace)
				_ = os.WriteFile(filepath.Join(root, "scenario-inputs.json"), trace, 0600)
				if paired && slices.Contains(os.Args, "tampered-prefix") && !prefixTampered && scenarioStage == 6 {
					if _, err := os.Stat(filepath.Join(root, "save-report.json")); err == nil {
						file, err := os.OpenFile(filepath.Join(root, "events.jsonl"), os.O_WRONLY, 0600)
						if err != nil {
							t.Fatal(err)
						}
						_, err = file.WriteAt([]byte{'['}, 0)
						if err == nil {
							err = file.Sync()
						}
						_ = file.Close()
						if err != nil {
							t.Fatal(err)
						}
						prefixTampered = true
					}
				}
				memory := map[uint32]byte{}
				if newGame && scenarioStage == 24 && len(payload) == 5 && binary.LittleEndian.Uint32(payload[1:]) == 0x56581c {
					introSamples++
				}
				if newGame && scenarioStage == 25 && len(payload) == 5 && binary.LittleEndian.Uint32(payload[1:]) == 0x56581c {
					preparationImageSamples++
				}
				if paired && advanceAtMode > 0 && len(payload) == 5 && binary.LittleEndian.Uint32(payload[1:]) == 0x56581c && scenarioModeReads+1 >= advanceAtMode {
					if newGame {
						loadedRecords[activeActor*508+250] = 10
					} else {
						loadedRecords[250] = 13
					}
					scenarioStage = 12
					boardCursor = 0
					advanceAtMode = 0
				}
				for player := 0; player < 4; player++ {
					base := uint32(0x56bed0 + 508*player)
					memory[base] = 1
					memory[base+241] = []byte{scenarioControl, 2, 3, 1}[player]
					memory[base+250] = byte(12 + player)
					if newGame {
						memory[base+241] = []byte{1, 2, scenarioControl, 1}[player]
						memory[base+250] = 9
						if player == activeActor {
							memory[base] = tutorialFlag
						}
						if scenarioStage == 24 && introSamples < 2 && player == 3 {
							memory[base+250] = 10
						}
					}
					for index, word := range []uint32{uint32(65 + player), uint32(66 + player), 0, 0, 0} {
						for b := 0; b < 4; b++ {
							memory[base+252+uint32(index*4+b)] = byte(word >> (8 * b))
						}
					}
					for b := 0; b < 4; b++ {
						memory[base+304+uint32(b)] = byte(uint32(100*(player+1)) >> (8 * b))
					}
				}
				if paired && len(loadedRecords) == 2032 {
					for offset, value := range loadedRecords {
						memory[0x56bed0+uint32(offset)] = value
					}
				}
				playerData = make([]byte, 2032)
				for offset := range playerData {
					playerData[offset] = memory[0x56bed0+uint32(offset)]
				}
				if scenarioControl == 0 && slices.Contains(os.Args, "owner-race") {
					memory[0x56bed0+100] = 7
				}
				innerWidth := uint32(0x1b0)
				if scenarioStage != 0 && scenarioStage != 12 {
					innerWidth = 0x2e0
				}
				if scenarioStage >= 8 && scenarioStage <= 10 {
					innerWidth = 0x260
				}
				if scenarioStage == 20 || scenarioStage == 22 {
					innerWidth = 0x195
				}
				if scenarioStage == 21 || scenarioStage == 23 {
					innerWidth = 0x1b8
				}
				if scenarioStage == 24 {
					innerWidth = 0x192
				}
				if scenarioStage == 25 {
					innerWidth = 0x1d7
				}
				for address, value := range map[uint32]uint32{0x56581c: innerWidth, 0x56b598: 1, 0x56b190: uint32(activeActor), 0x579ba6: yesNoCursor, 0x56a804: 5, 0x56a800: 1, 0x56a808: uint32(boardCursor), 0x56a8e0: 5, 0x56a8e4: 1, 0x56a8e8: 0x200 + uint32(activeActor)} {
					for b := 0; b < 4; b++ {
						memory[address+uint32(b)] = byte(value >> (8 * b))
					}
				}
				if paired && scenarioStage >= 8 && scenarioStage <= 10 {
					memory[0x56b598] = 0
					memory[0x56b190] = 0
				}
				if paired && len(loadedHeaders) == 20 {
					for index, address := range []uint32{0x56b598, 0x56b18c, 0x56b18e, 0x56b190, 0x56b192} {
						width := 2
						if index == 2 || index == 4 {
							width = 1
						}
						for b := 0; b < width; b++ {
							memory[address+uint32(b)] = loadedHeaders[index*4+b]
						}
					}
				}
				texts := map[int]string{19: strings.Repeat("x", 129)}
				selections := map[int]int{}
				sources := map[int]uint32{}
				ready := map[int]byte{}
				if scenarioStage == 0 || scenarioStage == 12 {
					texts[0] = "Move"
					sources[0] = 0x534bc0
					if vmStatus == 0 && scenarioControl == 0 && slices.Contains(os.Args, "move-after-resume") {
						sources[0] = 0x534bc4
					}
				}
				if scenarioStage == 1 {
					texts[0] = "InfoListHelpOptsSave"
					selections[0] = tabCursor
				}
				if scenarioStage == 8 {
					texts[0] = "NewGameFreeBattleContinue"
					selections[0] = titleCursor
				}
				if scenarioStage == 2 || scenarioStage == 6 || scenarioStage == 9 {
					texts[1] = "File1File2"
					selections[1] = fileCursor
					if scenarioStage != 9 {
						memory[0x570104] = 1
					}
					for b := 0; b < 4; b++ {
						memory[0x57011c+uint32(b)] = byte(uint32(1) >> (8 * b))
					}
				}
				if scenarioStage == 3 || scenarioStage == 5 || scenarioStage == 10 {
					texts[2] = "Savetoanewfile"
					if scenarioStage == 5 {
						texts[2] = "Savecomplete."
					}
					if scenarioStage == 10 {
						texts[2] = "LoadFile"
					}
					ready[2] = 1
					memory[0x570108] = 1
					for b := 0; b < 4; b++ {
						memory[0x57010c+uint32(b)] = byte(uint32(2) >> (8 * b))
					}
				}
				for widget, text := range texts {
					base := uint32(0x5657a0 + 196*widget)
					glyphs := uint32(0x300000 + widget*0x10000)
					nodes := uint32(0x500000 + widget*0x10000)
					memory[base] = 1
					memory[base+0x48] = ready[widget]
					for address, word := range map[uint32]uint32{base + 0x70: sources[widget], base + 0x94: glyphs} {
						for b := 0; b < 4; b++ {
							memory[address+uint32(b)] = byte(word >> (8 * b))
						}
					}
					memory[base+0x58] = byte(len(text))
					memory[base+0x59] = byte(len(text) >> 8)
					if selection, ok := selections[widget]; ok {
						cursor := uint32(0x700000 + widget*0x100)
						for b := 0; b < 4; b++ {
							memory[base+0xb0+uint32(b)] = byte(cursor >> (8 * b))
						}
						memory[cursor] = 1
						memory[cursor+4] = 8
						memory[cursor+0x18] = byte(selection)
					}
					for index, character := range []byte(text) {
						node := nodes + uint32(index)*32
						for b := 0; b < 4; b++ {
							memory[glyphs+uint32(index)*96+0x18+uint32(b)] = byte(node >> (8 * b))
						}
						for b, value := range []byte("char" + strconv.Itoa(int(character))) {
							memory[node+0x10+uint32(b)] = value
						}
						if widget == 0 && index == 0 && slices.Contains(os.Args, "unsupported-ui") {
							for b, value := range []byte("char2047\x00") {
								memory[node+0x10+uint32(b)] = value
							}
						}
					}
				}
				if scenarioStage == 25 {
					base := uint32(0x5657a0)
					memory[base] = 1
					memory[base+4] = 9
					memory[base+0x48] = 1
					if preparationImageSamples < 2 {
						memory[base+0x48] = 0
					}
					for address, word := range map[uint32]uint32{base + 0x94: 0, base + 0x58: 0, base + 0xa0: 0x760000, 0x760008: 0x760100} {
						for b := 0; b < 4; b++ {
							memory[address+uint32(b)] = byte(word >> (8 * b))
						}
					}
					for index, value := range []byte("textures\\help_illust00") {
						memory[0x760110+uint32(index)] = value
					}
				}
				if len(payload) == 6 && payload[0] == 4 {
					restore := paired && payload[5] == 1 && scenarioStage == 1 && vmStatus == 0 && scenarioControl == 0
					bootHandoff := newGame && payload[5] == 1 && scenarioStage == 24 && vmStatus == 0 && scenarioControl == 0
					if binary.LittleEndian.Uint32(payload[1:]) != uint32(0x56bfc1+activeActor*508) || !restore && !bootHandoff && (payload[5] != 0 || vmStatus != 1) {
						t.Fatal("unqualified Write8", fmt.Sprintf("%x", payload))
					}
					_ = os.WriteFile(filepath.Join(root, "scenario-write.bin"), append(header, payload...), 0600)
					scenarioControl = payload[5]
					if bootHandoff {
						scenarioStage = 0
					}
					if restore {
						loadedRecords[activeActor*508+241] = 1
						advanceAtMode = scenarioModeReads + 2
					}
					scenarioWrites++
					_ = os.WriteFile(filepath.Join(root, "scenario-write-count.txt"), []byte(strconv.Itoa(scenarioWrites)), 0600)
					if slices.Contains(os.Args, "lost-ack") {
						_ = connection.Close()
						break
					}
					reply = []byte{5, 0, 0, 0, 0}
				} else if len(payload) == 5 && payload[0] <= 3 {
					if binary.LittleEndian.Uint32(payload[1:]) == 0x56581c {
						if scenarioModeReads == 0 {
							memory[0x56581c] = 0x60
							memory[0x56581d] = 2
						}
						scenarioModeReads++
					}
					width := 1 << payload[0]
					address := binary.LittleEndian.Uint32(payload[1:])
					reply = make([]byte, 5+width)
					binary.LittleEndian.PutUint32(reply, uint32(len(reply)))
					for b := 0; b < width; b++ {
						reply[5+b] = memory[address+uint32(b)]
					}
				}
			}
			if reply == nil {
				switch {
				case bytes.Equal(payload, []byte{15}):
					events, _ := os.ReadFile(filepath.Join(root, "pad-events.bin"))
					pauses := 0
					for offset := 0; offset+24 <= len(events); offset += 24 {
						if binary.LittleEndian.Uint16(events[offset+16:]) == 1 && binary.LittleEndian.Uint16(events[offset+18:]) == 317 && binary.LittleEndian.Uint32(events[offset+20:]) == 1 {
							pauses++
						}
					}
					if pauses > seenPause && !toggleTimeout {
						vmStatus ^= uint32((pauses - seenPause) & 1)
					}
					seenPause = pauses
					reply = []byte{9, 0, 0, 0, 0, 0, 0, 0, 0}
					binary.LittleEndian.PutUint32(reply[5:], vmStatus)
				case bytes.Equal(payload, []byte{1, 0x1c, 0x58, 0x56, 0}):
					modeReads++
					if (watchAdvance || watchStall || watchCrash) && modeReads > 1 {
						watchSample++
						if watchCrash {
							_ = connection.Close()
							return
						}
						mode = 0x1b0
						if watchSample%2 == 0 {
							mode = 0x250
						}
					}
					events, _ := os.ReadFile(filepath.Join(root, "pad-events.bin"))
					resets := 0
					for offset := 0; offset+24 <= len(events); offset += 24 {
						if binary.LittleEndian.Uint16(events[offset+16:]) == 1 && binary.LittleEndian.Uint16(events[offset+18:]) == 318 && binary.LittleEndian.Uint32(events[offset+20:]) == 1 {
							resets++
						}
					}
					if resets > seenReset {
						mode = 608
						seenReset = resets
					}
					reply = []byte{7, 0, 0, 0, 0, 0, 0}
					binary.LittleEndian.PutUint16(reply[5:], mode)
					if !failedReady {
						mode = 736
					}
				case len(payload) == 5 && payload[0] <= 2:
					address := binary.LittleEndian.Uint32(payload[1:])
					value := uint32(0)
					known := true
					switch address {
					case 0x56b598:
						value = 1
						if watchAdvance && watchSample >= 4 {
							value = 2
						}
					case 0x56b18c, 0x56b190, 0x56a808:
						value = 0
					case 0x56a804:
						value = 5
					case 0x56a800:
						value = 1
					default:
						known = false
						for player := 0; player < 4; player++ {
							name := uint32(0x56bfcc + player*0x1fc)
							if address == name-2 {
								value = uint32(10 + player)
								known = true
							}
							if address == name+0x34 {
								value = uint32(1000 + player)
								known = true
							}
						}
					}
					if !known {
						t.Errorf("unexpected source read%x", payload)
						break
					}
					width := 1 << payload[0]
					reply = make([]byte, 5+width)
					binary.LittleEndian.PutUint32(reply, uint32(len(reply)))
					var encoded [4]byte
					binary.LittleEndian.PutUint32(encoded[:], value)
					copy(reply[5:], encoded[:width])
				default:
					t.Errorf("unexpected read-only request%x", payload)
				}
			}
			if _, err := connection.Write(reply); err != nil {
				t.Error(err)
				break
			}
			frameIndex++
		}
		_ = connection.Close()
	}
}

// TestProbeLifecycle owns child creation/termination and durable side effects,
// unlike saved-record and local memory-peer tables in TestProbeRecords.
func TestProbeLifecycle(t *testing.T) {
	raw, err := os.ReadFile("testdata/probe-lifecycle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SourceFormat, Settings, SourceCard, PostColdCard, PostStopCard string
		Requests                                                       []ProbeLifecycleRequest
		ExpectedStatus                                                 []string   `json:"expected_status"`
		ExpectedEpoch                                                  []int      `json:"expected_epoch"`
		ExpectedReasons                                                []string   `json:"expected_reasons"`
		ExpectedEffects                                                [][]string `json:"expected_effects"`
		PadSetupSHA                                                    string     `json:"pad_setup_sha256"`
		PadAxesSHA                                                     string     `json:"pad_axes_sha256"`
		PadEventsSHA                                                   string     `json:"pad_events_sha256"`
		PadHatSHA                                                      string     `json:"pad_hat_sha256"`
		PadTriggerSHA                                                  string     `json:"pad_trigger_sha256"`
	}
	// Underscored source fields are explicit, not guessed by JSON field matching.
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fixture) != nil || json.Unmarshal(raw, &fields) != nil {
		t.Fatal("bad literal fixture")
	}
	for key, target := range map[string]*string{"source_format": &fixture.SourceFormat, "source_card": &fixture.SourceCard, "post_cold_card": &fixture.PostColdCard, "post_stop_card": &fixture.PostStopCard} {
		if json.Unmarshal(fields[key], target) != nil {
			t.Fatal(key)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	programBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	sources := t.TempDir()
	profile := ProbeLifecycleProfile{Version: 1, SourceFormat: fixture.SourceFormat, Root: root, Session: "offline-lifecycle", Program: RegistryInput{Path: executable, Size: int64(len(programBytes)), SHA256: fmt.Sprintf("%x", sha256.Sum256(programBytes))}, ProgramArgs: []string{"-test.run=^TestProbeLifecycleChild$", "--"}, Inputs: map[string]RegistryInput{}, Requests: fixture.Requests, ReadyTimeoutMS: 2000, StopTimeoutMS: 2000, QuietMS: 20}
	for role, content := range map[string]string{"iso": "synthetic-iso", "bios": "synthetic-bios", "card": fixture.SourceCard, "settings": fixture.Settings} {
		name := role + ".bin"
		path := filepath.Join(sources, name)
		if err := os.WriteFile(path, []byte(content), 0400); err != nil {
			t.Fatal(err)
		}
		profile.Inputs[role] = RegistryInput{Path: path, Size: int64(len(content)), SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(content)))}
	}
	t.Setenv("DOKAPON_PROBE_LIFECYCLE_CHILD", "1")
	requestRaw, _ := json.Marshal(profile)
	report, err := runProbeLifecycle(requestRaw)
	var failedExpected struct {
		InitialStatus string `json:"initial_status"`
		InitialReason string `json:"initial_reason"`
		StopStatus    string `json:"stop_status"`
		PostStopCard  string `json:"post_stop_card"`
	}
	if json.Unmarshal(fields["failed_ready"], &failedExpected) != nil {
		t.Fatal("failed-ready pre-output oracle")
	}
	failedProfile := profile
	failedProfile.Root = t.TempDir()
	_ = os.Chmod(failedProfile.Root, 0700)
	failedProfile.ProgramArgs = append(slices.Clone(profile.ProgramArgs), "failed-ready")
	failedProfile.Requests = []ProbeLifecycleRequest{fixture.Requests[0], fixture.Requests[len(fixture.Requests)-1]}
	failedProfile.ReadyTimeoutMS = 200
	failedRaw, _ := json.Marshal(failedProfile)
	failedReport, failedErr := runProbeLifecycle(failedRaw)
	for _, outcome := range []ProbeLifecycleReport{report, failedReport} {
		for _, step := range outcome.Steps {
			if strings.HasPrefix(step.Reason, "launched child identity differs") {
				for _, childRoot := range []string{root, failedProfile.Root} {
					log, _ := os.ReadFile(filepath.Join(childRoot, "child-epoch-0.log"))
					t.Logf("controlled child startup log: %s", log)
				}
			}
		}
	}
	// Cleanup only our controlled test executable if a regression left it alive.
	// It never targets a shared emulator or adopts another process.
	for _, step := range append(slices.Clone(report.Steps), failedReport.Steps...) {
		if step.Owned != nil {
			if _, observeErr := observeProbeProcess(ProbeMemoryRuntime{}, step.Owned.PID, step.Owned, profile.Program.SHA256); observeErr == nil {
				_ = syscall.Kill(step.Owned.PID, syscall.SIGTERM)
				var status syscall.WaitStatus
				_, _ = syscall.Wait4(step.Owned.PID, &status, 0, nil)
			}
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	if failedErr != nil || failedReport.Status != "INCOMPLETE" || len(failedReport.Steps) != 2 {
		t.Fatalf("failed-ready outcome: %+v %v", failedReport, failedErr)
	}
	if failedReport.Steps[0].Status != failedExpected.InitialStatus || failedReport.Steps[0].Reason != failedExpected.InitialReason || failedReport.Steps[1].Status != failedExpected.StopStatus || !reflect.DeepEqual(failedReport.Steps[1].Effects, []string{"terminate", "flush"}) || failedReport.Steps[1].CardAfter != fmt.Sprintf("%x", sha256.Sum256([]byte(failedExpected.PostStopCard))) {
		t.Errorf("safe stop after failed-ready: %+v", failedReport)
	}
	if len(report.Steps) != len(fixture.ExpectedStatus) {
		t.Fatalf("steps: %+v", report)
	}
	for index, step := range report.Steps {
		if step.Status != fixture.ExpectedStatus[index] || step.Epoch != fixture.ExpectedEpoch[index] || step.Reason != fixture.ExpectedReasons[index] || !reflect.DeepEqual(step.Effects, fixture.ExpectedEffects[index]) {
			t.Errorf("step%d: %+v", index, step)
		}
	}
	if report.Status != "INCOMPLETE" || !report.Steps[1].Replayed {
		t.Errorf("explicit refusals/replay lost: %+v", report)
	}
	first, warm, cold, stop := report.Steps[0], report.Steps[2], report.Steps[3], report.Steps[6]
	if first.Owned == nil || warm.Owned == nil || cold.Owned == nil {
		t.Fatalf("missing actual ownership: %+v", report)
	}
	if first.Owned.PID != warm.Owned.PID || first.Owned.Starttime != warm.Owned.Starttime || first.Owned.PID == cold.Owned.PID {
		t.Error("warm/cold process distinction")
	}
	if first.WidthAfter == nil || *first.WidthAfter != 608 || warm.WidthBefore == nil || *warm.WidthBefore != 736 || warm.WidthAfter == nil || *warm.WidthAfter != 608 {
		t.Error("boot/saved/reset width observations")
	}
	if cold.CardBefore != fmt.Sprintf("%x", sha256.Sum256([]byte(fixture.SourceCard))) || cold.CardAfter != fmt.Sprintf("%x", sha256.Sum256([]byte(fixture.PostColdCard))) || stop.CardBefore != cold.CardAfter || stop.CardAfter != fmt.Sprintf("%x", sha256.Sum256([]byte(fixture.PostStopCard))) {
		t.Errorf("changed postflush hashes: cold%+v stop%+v", cold, stop)
	}
	for role, input := range profile.Inputs {
		data, err := os.ReadFile(input.Path)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != input.SHA256 {
			t.Errorf("source%s changed", role)
		}
	}
	for _, owned := range []*ProbeProcessRecord{first.Owned, cold.Owned} {
		data, err := os.ReadFile(filepath.Join(root, fmt.Sprintf("child-evidence-%d.json", owned.PID)))
		if err != nil {
			t.Fatal(err)
		}
		var child struct {
			PID           int
			Argv, Pending []string
		}
		if json.Unmarshal(data, &child) != nil || child.PID != owned.PID || !reflect.DeepEqual(child.Argv, owned.Cmdline) || !slices.Contains(child.Pending, map[bool]string{false: "1-initial-02-launch.pending.json", true: "3-cold-03-launch.pending.json"}[owned.PID == cold.Owned.PID]) {
			t.Errorf("pre-effect child witness: %s", data)
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, "receipts"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 33 {
		t.Errorf("durable receipt count%d want33", len(entries))
	}
	var completeCount, pendingCount int
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".pending.json") {
			pendingCount++
			paired := strings.TrimSuffix(entry.Name(), ".pending.json") + ".complete.json"
			if _, err := os.Stat(filepath.Join(root, "receipts", paired)); err != nil {
				t.Error(err)
			}
		}
		if strings.HasSuffix(entry.Name(), ".complete.json") {
			completeCount++
		}
	}
	if pendingCount != 14 || completeCount != 18 {
		t.Errorf("durable effects%d/%d", pendingCount, completeCount)
	}
	beforeEntries := len(entries)
	replay, err := runProbeLifecycle(requestRaw)
	if err != nil {
		t.Fatal(err)
	}
	for index, step := range replay.Steps {
		if fixture.ExpectedStatus[index] == "COMPLETED" && !step.Replayed {
			t.Errorf("not replay%d: %+v", index, step)
		}
	}
	entries, _ = os.ReadDir(filepath.Join(root, "receipts"))
	if len(entries) != beforeEntries {
		t.Error("replay created effects")
	}
	pendingPath := filepath.Join(root, "receipts", "5-warm-00-quiescent.pending.json")
	if err := os.WriteFile(pendingPath, []byte(`{"phase":"pending"}`), 0600); err != nil {
		t.Fatal(err)
	}
	profile.Requests = []ProbeLifecycleRequest{{Session: profile.Session, Operation: "warm", Phase: "requested", Nonce: "5-warm"}, fixture.Requests[len(fixture.Requests)-1]}
	pendingRaw, _ := json.Marshal(profile)
	pendingReport, err := runProbeLifecycle(pendingRaw)
	if err != nil || pendingReport.Steps[0].Status != "UNKNOWN" || pendingReport.Steps[0].Reason != "durable pending effect prevents replay" || !pendingReport.Steps[1].Replayed {
		t.Errorf("pending cannot retry: %+v %v", pendingReport, err)
	}
	// C-global source/header oracle comparisons use only an owned event file.
	padRoot := t.TempDir()
	_ = os.Chmod(padRoot, 0700)
	ctx, cancel := context.WithCancel(context.Background())
	ready, done := make(chan error, 1), make(chan error, 1)
	go serveProbePad(ctx, ProbePadSpec{Root: padRoot, Backend: "event-sink"}, ready, done)
	if err := <-ready; err != nil {
		cancel()
		t.Fatal(err)
	}
	commands := []string{"tap CROSS 0.01", "tap UP 0.01", "tap L2 0.01", "tap CROSS NaN"}
	for index, command := range commands {
		connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(padRoot, "pad.sock"), Net: "unix"})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = io.WriteString(connection, command)
		if err == nil {
			err = connection.CloseWrite()
		}
		ack, readErr := io.ReadAll(io.LimitReader(connection, 257))
		_ = connection.Close()
		expected := "ok\n"
		if index == 3 {
			expected = "err invalid owned pad command\n"
		}
		if err != nil || readErr != nil || string(ack) != expected {
			t.Errorf("pad command%s %q %v %v", command, ack, err, readErr)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	events, err := os.ReadFile(filepath.Join(padRoot, "pad-events.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 288 {
		t.Fatalf("event bytes%d", len(events))
	}
	for index, expected := range []string{fixture.PadEventsSHA, fixture.PadHatSHA, fixture.PadTriggerSHA} {
		if fmt.Sprintf("%x", sha256.Sum256(events[index*96:(index+1)*96])) != expected {
			t.Errorf("independent ABI event%d mismatch", index)
		}
	}
	metadata, err := os.ReadFile(filepath.Join(padRoot, "pad-device.json"))
	if err != nil {
		t.Fatal(err)
	}
	var device struct {
		Setup string `json:"setup_hex"`
		Axes  string `json:"axes_hex"`
	}
	if json.Unmarshal(metadata, &device) != nil {
		t.Fatal("pad metadata")
	}
	for encoded, expected := range map[string]string{device.Setup: fixture.PadSetupSHA, device.Axes: fixture.PadAxesSHA} {
		data, err := hex.DecodeString(encoded)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != expected {
			t.Error("primary-header setup/axis oracle mismatch")
		}
	}
	if _, err := os.Lstat(filepath.Join(padRoot, "pad.sock")); !os.IsNotExist(err) {
		t.Error("owned pad socket survived cleanup")
	}
	var cadence struct {
		Prefixes []struct {
			Seed      string `json:"seed_uint64_decimal"`
			Count     int
			Intervals []int
			Next      int
		}
		Long struct {
			Seed      string `json:"seed_uint64_decimal"`
			Count     int
			Intervals []int
			Next      int
			SHA       string `json:"uint32_le_sha256"`
		} `json:"long_stream"`
	}
	cadenceRaw, err := os.ReadFile("testdata/probe-checkpoint-intervals.json")
	if err != nil || json.Unmarshal(cadenceRaw, &cadence) != nil {
		t.Fatal("independent cadence fixture", err)
	}
	for _, sample := range cadence.Prefixes {
		seed, err := strconv.ParseUint(sample.Seed, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		got, err := probeCheckpointIntervals(seed, sample.Count+1)
		if err != nil || len(got) != sample.Count+1 || !reflect.DeepEqual(got[:sample.Count], sample.Intervals) || got[sample.Count] != sample.Next {
			t.Fatalf("CPython prefix%s: %v %v", sample.Seed, got, err)
		}
	}
	longSeed, err := strconv.ParseUint(cadence.Long.Seed, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	long, err := probeCheckpointIntervals(longSeed, cadence.Long.Count+1)
	if err != nil || len(long) != 701 {
		t.Fatal("long cadence", err)
	}
	encodedIntervals := make([]byte, cadence.Long.Count*4)
	for index, value := range long[:cadence.Long.Count] {
		binary.LittleEndian.PutUint32(encodedIntervals[index*4:], uint32(value))
	}
	if !reflect.DeepEqual(long[:cadence.Long.Count], cadence.Long.Intervals) || long[cadence.Long.Count] != cadence.Long.Next || fmt.Sprintf("%x", sha256.Sum256(encodedIntervals)) != cadence.Long.SHA {
		t.Fatal("independent twist/rejection/continuation cadence")
	}
	for _, count := range []int{-1, 4097} {
		if _, err := probeCheckpointIntervals(0, count); err == nil {
			t.Error("unbounded cadence count admitted")
		}
	}
	var policyFixture struct {
		Policy ProbeLifecyclePolicy `json:"go_policy"`
		Cases  []struct {
			ID, Child            string
			Operations, Statuses []string
			Samples              int    `json:"watch_samples"`
			Repeated             int    `json:"watch_repeated"`
			Warning              bool   `json:"watch_warning"`
			Outcome              string `json:"watch_outcome"`
			Skips                []string
			Taps                 int  `json:"l3_taps"`
			Replay               bool `json:"last_stop_replay"`
			Recoveries           int  `json:"recovery_attempts"`
			MaxRecoveries        int  `json:"max_recoveries"`
		}
	}
	policyRaw, err := os.ReadFile("testdata/probe-lifecycle-policy.json")
	if err != nil || json.Unmarshal(policyRaw, &policyFixture) != nil {
		t.Fatal("source policy fixture", err)
	}
	var actionFacts struct {
		Source struct {
			PollMS   int `json:"poll_ms"`
			Warn     int `json:"warn_repeats"`
			Terminal int `json:"terminal_repeats"`
		} `json:"watch_source_policy"`
		Pause  string `json:"pause_command"`
		Settle int    `json:"pause_settle_ms"`
		Polls  int    `json:"status_polls"`
		PollMS int    `json:"status_poll_ms"`
	}
	if json.Unmarshal(probeLifecycleActions, &actionFacts) != nil || actionFacts.Source.PollMS != 1000 || actionFacts.Source.Warn != 200 || actionFacts.Source.Terminal != 1200 || actionFacts.Pause != "tap L3 0.1" || actionFacts.Settle != 50 || actionFacts.Polls != 20 || actionFacts.PollMS != 50 {
		t.Fatal("canonical source policy changed")
	}
	for _, sample := range policyFixture.Cases {
		candidate := profile
		candidate.Root = t.TempDir()
		_ = os.Chmod(candidate.Root, 0700)
		policy := policyFixture.Policy
		if sample.MaxRecoveries > 0 {
			policy.MaxRecoveries = sample.MaxRecoveries
		}
		candidate.Policy = &policy
		candidate.ProgramArgs = append(slices.Clone(profile.ProgramArgs), sample.Child)
		candidate.Requests = nil
		lastStop := ""
		for index, operation := range sample.Operations {
			nonce := fmt.Sprintf("%d-%s", index+1, operation)
			if operation == "stop" {
				if sample.Replay && index == len(sample.Operations)-1 {
					nonce = lastStop
				} else {
					lastStop = nonce
				}
			}
			candidate.Requests = append(candidate.Requests, ProbeLifecycleRequest{Session: candidate.Session, Operation: operation, Phase: "requested", Nonce: nonce})
		}
		input, _ := json.Marshal(candidate)
		outcome, err := runProbeLifecycle(input)
		for _, step := range outcome.Steps {
			if step.Owned != nil {
				if _, err := observeProbeProcess(ProbeMemoryRuntime{}, step.Owned.PID, step.Owned, candidate.Program.SHA256); err == nil {
					_ = syscall.Kill(step.Owned.PID, syscall.SIGTERM)
					var status syscall.WaitStatus
					_, _ = syscall.Wait4(step.Owned.PID, &status, 0, nil)
				}
			}
		}
		if err != nil || len(outcome.Steps) != len(sample.Statuses) {
			t.Fatalf("%s: %+v %v", sample.ID, outcome, err)
		}
		for index, step := range outcome.Steps {
			if step.Status != sample.Statuses[index] {
				t.Errorf("%s step%d: %+v", sample.ID, index, step)
			}
			if step.Status == "UNKNOWN" && step.Reason == "" {
				t.Error("unknown reason lost")
			}
		}
		if sample.Replay && !outcome.Steps[len(outcome.Steps)-1].Replayed {
			t.Error("completed safe stop repeated")
		}
		if sample.Samples > 0 {
			for _, step := range outcome.Steps {
				if step.Request.Operation == "watch" {
					if step.Samples != sample.Samples || step.Repeated != sample.Repeated || step.Warning != sample.Warning || step.WatchOutcome != sample.Outcome || !reflect.DeepEqual(step.Skips, sample.Skips) {
						t.Errorf("%s typed watch %+v", sample.ID, step)
					}
				}
			}
		}
		if sample.ID == "advance" {
			paused, resumed := outcome.Steps[1], outcome.Steps[2]
			if paused.VMStatusBefore == nil || *paused.VMStatusBefore != 0 || paused.VMStatusAfter == nil || *paused.VMStatusAfter != 1 || resumed.VMStatusBefore == nil || *resumed.VMStatusBefore != 1 || resumed.VMStatusAfter == nil || *resumed.VMStatusAfter != 0 || paused.Owned.PID != resumed.Owned.PID {
				t.Error("guarded same-owner pause/unpause")
			}
		}
		if sample.Recoveries > 0 {
			if !outcome.Steps[2].ExitedBeforeStop || !outcome.Steps[5].ExitedBeforeStop || outcome.Steps[3].RecoveryAttempts != 1 || outcome.Steps[3].Epoch != 1 {
				t.Errorf("crash disposal/recovery budget: %+v", outcome)
			}
			if sample.ID == "crash-recovery-budget" && outcome.Steps[6].Reason != "explicit Go recovery budget exhausted" {
				t.Errorf("recovery budget bypass: %+v", outcome)
			}
			if sample.ID == "per-epoch-recovery" && (outcome.Steps[6].RecoveryAttempts != 2 || outcome.Steps[6].Epoch != 2 || outcome.Steps[8].Reason != "recovery requires proved disposal after a read-only failure") {
				t.Errorf("prior failure reused by later epoch: %+v", outcome)
			}
		}
		events, err := os.ReadFile(filepath.Join(candidate.Root, "pad-events.bin"))
		if err != nil {
			t.Fatal(err)
		}
		taps := 0
		for offset := 0; offset+24 <= len(events); offset += 24 {
			if binary.LittleEndian.Uint16(events[offset+16:]) == 1 && binary.LittleEndian.Uint16(events[offset+18:]) == 317 && binary.LittleEndian.Uint32(events[offset+20:]) == 1 {
				taps++
			}
		}
		if taps != sample.Taps {
			t.Errorf("%s L3 effects%d want%d", sample.ID, taps, sample.Taps)
		}
		for role, input := range candidate.Inputs {
			content, err := os.ReadFile(input.Path)
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(content)) != input.SHA256 {
				t.Errorf("%s source%s changed", sample.ID, role)
			}
		}
	}
	resumeRaw, err := os.ReadFile("testdata/probe-lifecycle-resume.json")
	if err != nil {
		t.Fatal(err)
	}
	var resumeNames struct{ Refusals []string }
	if json.Unmarshal(resumeRaw, &resumeNames) != nil {
		t.Fatal("resume fixture")
	}
	for _, variant := range append([]string{"valid"}, resumeNames.Refusals...) {
		var source struct {
			Bundle   ProbeEvidenceBundle
			Receipt  ProbeResumeFacts
			Run      map[string]any
			Expected struct {
				Epoch     int   `json:"new_epoch"`
				Next      int   `json:"next_interval"`
				Intervals []int `json:"watch_intervals"`
			}
		}
		if json.Unmarshal(resumeRaw, &source) != nil {
			t.Fatal("source resume fixture")
		}
		priorRoot := t.TempDir()
		_ = os.Chmod(priorRoot, 0700)
		if err := os.MkdirAll(filepath.Join(priorRoot, "checkpoints", "screenshots"), 0700); err != nil {
			t.Fatal(err)
		}
		if variant == "native-slot" {
			value := 3
			source.Receipt.Slot = &value
		}
		if variant == "control" {
			value := uint32(2)
			source.Receipt.OriginalControl = &value
		}
		if variant == "cleanup" {
			source.Run["cleanup_complete"] = false
		}
		if variant == "event-order" {
			source.Bundle.Events[17], source.Bundle.Events[18] = source.Bundle.Events[18], source.Bundle.Events[17]
		}
		if variant == "seeded-prefix" {
			source.Receipt.ScheduledIntervals[0]++
			var event map[string]any
			_ = json.Unmarshal(source.Bundle.Events[0].Data, &event)
			event["interval_seconds"] = 5327
			source.Bundle.Events[0].Data, _ = json.Marshal(event)
		}
		if variant == "fingerprint" {
			var event map[string]any
			_ = json.Unmarshal(source.Bundle.Events[18].Data, &event)
			state := event["state"].(map[string]any)
			state["players"].([]any)[0].(map[string]any)["money"] = 101
			source.Bundle.Events[18].Data, _ = json.Marshal(event)
		}
		if variant == "already-resumed" {
			event, _ := json.Marshal(map[string]any{"event": "resumed", "event_id": 22, "checkpoint": 2, "time": "2026-11-13T00:01:06+0000", "slot": 2, "expected": source.Receipt.Expected})
			source.Bundle.Events = append(source.Bundle.Events, ProbeEvidenceEvent{Data: event})
		}
		var pngBytes bytes.Buffer
		if err := png.Encode(&pngBytes, image.NewNRGBA(image.Rect(0, 0, 1, 1))); err != nil {
			t.Fatal(err)
		}
		var eventBytes bytes.Buffer
		for _, saved := range source.Bundle.Events {
			var compact bytes.Buffer
			if err := json.Compact(&compact, saved.Data); err != nil {
				t.Fatal(err)
			}
			eventBytes.Write(compact.Bytes())
			eventBytes.WriteByte('\n')
			var event struct {
				Checkpoint int
				Screenshot string
			}
			_ = json.Unmarshal(saved.Data, &event)
			if event.Checkpoint == 1 && event.Screenshot != "" {
				if err := os.WriteFile(filepath.Join(priorRoot, "checkpoints", event.Screenshot), pngBytes.Bytes(), 0400); err != nil {
					t.Fatal(err)
				}
			}
		}
		card := []byte(fixture.PostColdCard)
		cardSHA := fmt.Sprintf("%x", sha256.Sum256(card))
		source.Run["private_card_final_sha256"] = cardSHA
		runData, _ := json.Marshal(source.Run)
		sequenceData, _ := json.Marshal(map[string]any{"status": "failed", "iso_sha256": source.Receipt.ISOSHA256, "runs": []any{map[string]any{"run": source.Receipt.SourceFrameRoot, "result": source.Run}}})
		source.Receipt.Artifacts = map[string]RegistryInput{}
		for role, data := range map[string][]byte{"run": runData, "sequence": sequenceData, "events": eventBytes.Bytes(), "card": card} {
			path := filepath.Join(priorRoot, role+".json")
			if role == "events" {
				path = filepath.Join(priorRoot, "checkpoints", "events.jsonl")
			}
			if role == "card" {
				path = filepath.Join(priorRoot, "card.ps2")
			}
			if err := os.WriteFile(path, data, 0400); err != nil {
				t.Fatal(err)
			}
			source.Receipt.Artifacts[role] = RegistryInput{Path: path, Size: int64(len(data)), SHA256: fmt.Sprintf("%x", sha256.Sum256(data))}
		}
		receiptData, _ := json.Marshal(source.Receipt)
		source.Bundle.Events = nil // The actual pinned JSONL is the sole event authority.
		evidenceData, _ := json.Marshal(source.Bundle)
		metadata := map[string]RegistryInput{}
		for role, data := range map[string][]byte{"receipt": receiptData, "evidence": evidenceData} {
			path := filepath.Join(priorRoot, role+".json")
			if err := os.WriteFile(path, data, 0400); err != nil {
				t.Fatal(err)
			}
			metadata[role] = RegistryInput{Path: path, Size: int64(len(data)), SHA256: fmt.Sprintf("%x", sha256.Sum256(data))}
		}
		candidate := profile
		candidate.Root = t.TempDir()
		_ = os.Chmod(candidate.Root, 0700)
		candidate.Session = "new-resume-session"
		candidate.Seed = source.Receipt.Seed
		candidate.Policy = &policyFixture.Policy
		candidate.ProgramArgs = append(slices.Clone(profile.ProgramArgs), "watch-advance")
		candidate.Inputs = map[string]RegistryInput{}
		for role, input := range profile.Inputs {
			candidate.Inputs[role] = input
		}
		candidate.Inputs["card"] = source.Receipt.Artifacts["card"]
		candidate.Resume = &ProbeLifecycleResume{Root: priorRoot, Receipt: metadata["receipt"], Evidence: metadata["evidence"]}
		if variant == "artifact-hash" {
			candidate.Resume.Evidence.SHA256 = strings.Repeat("0", 64)
		}
		candidate.Requests = []ProbeLifecycleRequest{{Session: candidate.Session, Operation: "resume", Phase: "requested", Nonce: "1-resume"}, {Session: candidate.Session, Operation: "watch", Phase: "requested", Nonce: "2-watch"}, {Session: candidate.Session, Operation: "stop", Phase: "requested", Nonce: "3-stop"}}
		input, _ := json.Marshal(candidate)
		outcome, runErr := runProbeLifecycle(input)
		for _, step := range outcome.Steps {
			if step.Owned != nil {
				if _, err := observeProbeProcess(ProbeMemoryRuntime{}, step.Owned.PID, step.Owned, candidate.Program.SHA256); err == nil {
					_ = syscall.Kill(step.Owned.PID, syscall.SIGTERM)
					var status syscall.WaitStatus
					_, _ = syscall.Wait4(step.Owned.PID, &status, 0, nil)
				}
			}
		}
		if variant == "valid" {
			if runErr != nil || outcome.Status != "COMPLETED" || len(outcome.Steps) != 3 {
				t.Fatalf("valid bound resume: %+v %v", outcome, runErr)
			}
			if outcome.Steps[0].Epoch != source.Expected.Epoch || outcome.Steps[0].ResumeEvidenceSHA256 == "" || !reflect.DeepEqual(outcome.Steps[1].ScheduledIntervals, source.Expected.Intervals) || outcome.Steps[2].CardAfter != fmt.Sprintf("%x", sha256.Sum256([]byte(fixture.PostStopCard))) {
				t.Errorf("resume preservation/draw prefix: %+v", outcome)
			}
		} else {
			if runErr == nil && (len(outcome.Steps) == 0 || outcome.Steps[0].Status != "REFUSED") {
				t.Errorf("%s invalid resume admitted: %+v", variant, outcome)
			}
			if _, err := os.Lstat(filepath.Join(candidate.Root, "profile")); !os.IsNotExist(err) {
				t.Errorf("%s invalid resume mutated profile", variant)
			}
			entries, _ := os.ReadDir(filepath.Join(candidate.Root, "receipts"))
			if len(entries) != 0 {
				t.Errorf("%s invalid resume emitted effect receipts", variant)
			}
		}
		for role, artifact := range source.Receipt.Artifacts {
			contents, err := os.ReadFile(artifact.Path)
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(contents)) != artifact.SHA256 {
				t.Errorf("%s resume source%s changed", variant, role)
			}
		}
	}
	// Source-literal player bytes and full semantic report expectations are frozen
	// independently of this producer. IDs, epochs and PNG bytes remain real facts.
	scenarioRaw, err := os.ReadFile("testdata/probe-scenario.json")
	if err != nil {
		t.Fatal(err)
	}
	var scenarioFixture struct {
		Players []struct {
			SHA string `json:"sha256"`
		} `json:"players_before"`
		Takeover struct {
			SHA string `json:"actor0_after_sha256"`
		} `json:"takeover"`
		InputOrder []string `json:"expected_input_order"`
		Report     struct {
			Status      string                  `json:"status"`
			Rows        []ProbeEvidenceResult   `json:"rows"`
			Checkpoints []ProbeCheckpointResult `json:"checkpoints"`
		} `json:"expected_report"`
		Refusals []struct {
			ID     string `json:"id"`
			Reason string `json:"reason_prefix"`
			Writes int    `json:"writes"`
		} `json:"refusal_cases"`
	}
	if json.Unmarshal(scenarioRaw, &scenarioFixture) != nil || len(scenarioFixture.Players) != 4 {
		t.Fatal("source scenario oracle")
	}
	scenarioProfile := profile
	scenarioProfile.Root = t.TempDir()
	_ = os.Chmod(scenarioProfile.Root, 0700)
	scenarioProfile.ProgramArgs = append(slices.Clone(profile.ProgramArgs), "scenario-first-save")
	scenarioProfile.Requests = []ProbeLifecycleRequest{{Session: profile.Session, Operation: "initial", Phase: "requested", Nonce: "1-initial"}, {Session: profile.Session, Operation: "scenario", Phase: "requested", Nonce: "2-scenario"}, {Session: profile.Session, Operation: "stop", Phase: "requested", Nonce: "3-stop"}}
	glyphs := map[string]string{}
	for _, character := range "MoveInfoListHelpOptsSavFile12toanewfcm.px" {
		glyphs[strconv.Itoa(int(character))] = string(character)
	}
	glyphRaw, _ := json.Marshal(glyphs)
	glyphPath := filepath.Join(sources, "scenario-glyphmap.json")
	if err := os.WriteFile(glyphPath, glyphRaw, 0400); err != nil {
		t.Fatal(err)
	}
	scenarioProfile.Scenario = &ProbeScenarioSpec{ID: "first-save-nondefault", Glyphmap: RegistryInput{Path: glyphPath, Size: int64(len(glyphRaw)), SHA256: fmt.Sprintf("%x", sha256.Sum256(glyphRaw))}, TimeoutMS: 60000, MaxUIReads: 4096}
	scenarioInput, _ := json.Marshal(scenarioProfile)
	scenarioResult, scenarioErr := runProbeLifecycle(scenarioInput)
	for _, step := range scenarioResult.Steps {
		if step.Owned != nil {
			if _, err := observeProbeProcess(ProbeMemoryRuntime{}, step.Owned.PID, step.Owned, profile.Program.SHA256); err == nil {
				_ = syscall.Kill(step.Owned.PID, syscall.SIGTERM)
				var status syscall.WaitStatus
				_, _ = syscall.Wait4(step.Owned.PID, &status, 0, nil)
			}
		}
	}
	if scenarioErr != nil || scenarioResult.Status != "COMPLETED" || len(scenarioResult.Steps) != 3 {
		t.Fatalf("first producer: %+v %v", scenarioResult, scenarioErr)
	}
	produced := scenarioResult.Steps[1]
	if produced.Status != "COMPLETED" || produced.Capture == nil || produced.Checkpoint == nil {
		t.Fatalf("first producer facts: %+v", produced)
	}
	if produced.Checkpoint.Status != scenarioFixture.Report.Status || !reflect.DeepEqual(produced.Checkpoint.Rows, scenarioFixture.Report.Rows) || !reflect.DeepEqual(produced.Checkpoint.Checkpoints, scenarioFixture.Report.Checkpoints) || len(produced.Checkpoint.CoveredAreas) != 0 || produced.Checkpoint.LiveOwnership {
		t.Errorf("save-only actual report: %+v", produced.Checkpoint)
	}
	if produced.Capture.Status != "CAPTURED" || produced.Capture.Provenance != "owned_go" || produced.Capture.MemoryBefore == nil || !produced.Capture.MemoryBefore.ProcessGuarded || len(produced.Checkpoint.Captures) != 1 || produced.Checkpoint.Captures[0].Status != "ACCEPTED" {
		t.Errorf("source capture linkage: %+v", produced.Capture)
	}
	for player, record := range produced.UI.Saved.Players {
		expected := scenarioFixture.Players[player].SHA
		if player == 0 {
			expected = scenarioFixture.Takeover.SHA
		}
		if record.RecordSHA256 != expected || record.TutorialInitializedSHA256 != expected {
			t.Errorf("player%d full source hash: %+v", player, record)
		}
	}
	longWidget := false
	for _, widget := range produced.UI.Widgets {
		if widget.Index == 19 && !widget.Unsupported && widget.Text == strings.Repeat("x", 129) {
			longWidget = true
		}
	}
	if !longWidget {
		t.Error("129-glyph source widget did not survive bounded decoder chunks")
	}
	admissionRaw, _ := os.ReadFile(filepath.Join(scenarioProfile.Root, "go-records-2-scenario.json"))
	if _, err := readProbeUI(ProbeUIPlan{Admission: admissionRaw, BuildSHA256: profile.Program.SHA256, Glyphmap: glyphRaw, TimeoutMS: 1000, MaxReads: 1}, ProbeMemoryRuntime{Provenance: "owned_go"}); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Errorf("UI explicit budget refusal: %v", err)
	}
	var inputOrder []string
	inputTrace, _ := os.ReadFile(filepath.Join(scenarioProfile.Root, "scenario-inputs.json"))
	_ = json.Unmarshal(inputTrace, &inputOrder)
	if !reflect.DeepEqual(inputOrder, scenarioFixture.InputOrder) {
		t.Errorf("source input order: %v", inputOrder)
	}
	writePacket, _ := os.ReadFile(filepath.Join(scenarioProfile.Root, "scenario-write.bin"))
	if hex.EncodeToString(writePacket) != "0a00000004c1bf560000" {
		t.Errorf("named Write8 packet: %x", writePacket)
	}
	var captureFixture struct {
		ImageHex string `json:"image_hex"`
	}
	captureFixtureRaw, _ := os.ReadFile("testdata/probe-capture.json")
	_ = json.Unmarshal(captureFixtureRaw, &captureFixture)
	pngBytes, _ := hex.DecodeString(captureFixture.ImageHex)
	published, _ := os.ReadFile(filepath.Join(scenarioProfile.Root, "captures", produced.Capture.ImagePath))
	snapshot, _ := os.ReadFile(filepath.Join(scenarioProfile.Root, "profile", "PCSX2", "snaps", "first-save.png"))
	if !bytes.Equal(published, pngBytes) || !bytes.Equal(snapshot, pngBytes) {
		t.Error("original PNG identity/preservation")
	}
	for _, variant := range []string{"blank-nonce", "wrong-operation", "unlinked-request"} {
		admissionRaw, _ := os.ReadFile(filepath.Join(scenarioProfile.Root, "go-records-2-scenario.json"))
		var bundle ProbeRecordBundle
		_ = json.Unmarshal(admissionRaw, &bundle)
		switch variant {
		case "blank-nonce":
			bundle.GoOwner.Step.Request.Nonce = ""
		case "wrong-operation":
			bundle.GoOwner.Step.Request.Operation = "warm"
		case "unlinked-request":
			bundle.GoOwner.Profile.Requests = nil
		}
		bad, _ := json.Marshal(bundle)
		if _, err := admitProbeRecords(bad); err == nil {
			t.Error(variant, "admitted")
		}
	}
	for _, refusal := range scenarioFixture.Refusals {
		candidate := scenarioProfile
		candidate.Root = t.TempDir()
		_ = os.Chmod(candidate.Root, 0700)
		candidate.ProgramArgs = append(slices.Clone(scenarioProfile.ProgramArgs), refusal.ID)
		if refusal.ID == "read-budget" {
			spec := *candidate.Scenario
			spec.MaxUIReads = 1
			candidate.Scenario = &spec
		}
		input, _ := json.Marshal(candidate)
		outcome, runErr := runProbeLifecycle(input)
		for _, step := range outcome.Steps {
			if step.Owned != nil {
				if _, err := observeProbeProcess(ProbeMemoryRuntime{}, step.Owned.PID, step.Owned, candidate.Program.SHA256); err == nil {
					_ = syscall.Kill(step.Owned.PID, syscall.SIGTERM)
					var status syscall.WaitStatus
					_, _ = syscall.Wait4(step.Owned.PID, &status, 0, nil)
				}
			}
		}
		if runErr != nil || len(outcome.Steps) != 3 || outcome.Status != "INCOMPLETE" || outcome.Steps[1].Status != "UNKNOWN" || !strings.HasPrefix(outcome.Steps[1].Reason, refusal.Reason) || outcome.Steps[2].Status != "COMPLETED" {
			t.Fatalf("%s bounded source refusal: %+v %v", refusal.ID, outcome, runErr)
		}
		if outcome.Steps[1].Capture != nil || outcome.Steps[1].Checkpoint != nil {
			t.Error(refusal.ID, "unsafe source became checkpoint")
		}
		written, _ := os.ReadFile(filepath.Join(candidate.Root, "scenario-write-count.txt"))
		count := 0
		if len(written) > 0 {
			count, _ = strconv.Atoi(string(written))
		}
		if count != refusal.Writes {
			t.Errorf("%s transaction repeated or omitted: %d", refusal.ID, count)
		}
		for _, source := range candidate.Inputs {
			data, err := os.ReadFile(source.Path)
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != source.SHA256 {
				t.Error(refusal.ID, "original source changed")
			}
		}
	}
	// The independent paired oracle predates any producer output. A real Load in
	// this controlled VM restores RAM from its private File2 bytes, not a PASS flag.
	for _, cohort := range []string{"newgame", "paired"} {
		pairedOracleRaw, err := os.ReadFile("testdata/probe-" + cohort + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var pairedOracle struct {
			States         map[string]ProbeSavedState `json:"states"`
			ExpectedReport json.RawMessage            `json:"full_normalized_report"`
		}
		if json.Unmarshal(pairedOracleRaw, &pairedOracle) != nil {
			t.Fatal("paired oracle")
		}
		pairedProfile := profile
		// Full source UI reads bracket quiescence; this cohort uses the existing
		// bounded10s readiness policy, while the small legacy child retains2s.
		pairedProfile.ReadyTimeoutMS = 10000
		pairedProfile.Root = t.TempDir()
		_ = os.Chmod(pairedProfile.Root, 0700)
		pairedProfile.ProgramArgs = append(slices.Clone(profile.ProgramArgs), "scenario-"+cohort)
		pairedProfile.Inputs = map[string]RegistryInput{}
		for role, input := range profile.Inputs {
			pairedProfile.Inputs[role] = input
		}
		initialCard, err := os.ReadFile("testdata/probe-paired-card-initial.bin")
		if err != nil {
			t.Fatal(err)
		}
		pairedCardPath := filepath.Join(sources, cohort+"-card.bin")
		if err := os.WriteFile(pairedCardPath, initialCard, 0400); err != nil {
			t.Fatal(err)
		}
		pairedProfile.Inputs["card"] = RegistryInput{Path: pairedCardPath, Size: int64(len(initialCard)), SHA256: fmt.Sprintf("%x", sha256.Sum256(initialCard))}
		pairedGlyphs := map[string]string{}
		for character := 32; character < 127; character++ {
			pairedGlyphs[strconv.Itoa(character)] = string(rune(character))
		}
		pairedGlyphRaw, _ := json.Marshal(pairedGlyphs)
		pairedGlyphPath := filepath.Join(sources, cohort+"-glyphmap.json")
		if err := os.WriteFile(pairedGlyphPath, pairedGlyphRaw, 0400); err != nil {
			t.Fatal(err)
		}
		pairedProfile.Scenario = &ProbeScenarioSpec{ID: "first-save-nondefault", Glyphmap: RegistryInput{Path: pairedGlyphPath, Size: int64(len(pairedGlyphRaw)), SHA256: fmt.Sprintf("%x", sha256.Sum256(pairedGlyphRaw))}, TimeoutMS: 180000, MaxUIReads: 4096}
		pairedProfile.Requests = nil
		operations := []string{"initial", "scenario", "warm-load", "load", "cold-load", "load", "restore", "stop"}
		warmIndex, coldIndex, coldLoadIndex, finalIndex := 3, 4, 5, 6
		if cohort == "newgame" {
			pairedProfile.Scenario.NoTutorial = true
			pairedProfile.Scenario.FrontEndTimeoutMS = 120000
			operations = []string{"initial", "newgame", "prepare-scenario", "warm-load", "prepare-load", "resave", "warm-load", "load", "cold-load", "load", "restore", "stop"}
			warmIndex, coldIndex, coldLoadIndex, finalIndex = 7, 8, 9, 10
		}
		for index, operation := range operations {
			pairedProfile.Requests = append(pairedProfile.Requests, ProbeLifecycleRequest{Session: profile.Session, Operation: operation, Phase: "requested", Nonce: fmt.Sprintf("%d-%s", index+1, operation)})
		}
		pairedInput, _ := json.Marshal(pairedProfile)
		pairedResult, pairedErr := runProbeLifecycle(pairedInput)
		for _, step := range pairedResult.Steps {
			if step.Owned != nil {
				if _, err := observeProbeProcess(ProbeMemoryRuntime{}, step.Owned.PID, step.Owned, pairedProfile.Program.SHA256); err == nil {
					_ = syscall.Kill(step.Owned.PID, syscall.SIGTERM)
					var status syscall.WaitStatus
					_, _ = syscall.Wait4(step.Owned.PID, &status, 0, nil)
				}
			}
		}
		if pairedErr != nil || pairedResult.Status != "COMPLETED" || len(pairedResult.Steps) != len(operations) {
			for _, step := range pairedResult.Steps {
				t.Logf("paired %s %s: %s effects=%v", step.Request.Nonce, step.Status, step.Reason, step.Effects)
			}
			for _, name := range []string{"child-epoch-0.log", "child-epoch-1.log"} {
				log, _ := os.ReadFile(filepath.Join(pairedProfile.Root, name))
				t.Logf("%s: %s", name, log)
			}
			t.Fatalf("paired producer %s %v", pairedResult.Status, pairedErr)
		}
		if pairedResult.Steps[warmIndex].PreviewSamples != 40 || pairedResult.Steps[coldLoadIndex].PreviewSamples != 40 || pairedResult.Steps[0].Owned.PID == pairedResult.Steps[coldIndex].Owned.PID || pairedResult.Steps[coldIndex].Epoch != 1 {
			t.Fatal("paired preview or cold ownership")
		}
		finalStep := pairedResult.Steps[finalIndex]
		if finalStep.Checkpoint == nil || finalStep.Evidence == nil {
			t.Fatal("paired report/evidence missing")
		}
		evidenceRaw, err := os.ReadFile(finalStep.Evidence.Path)
		if err != nil || int64(len(evidenceRaw)) != finalStep.Evidence.Size || fmt.Sprintf("%x", sha256.Sum256(evidenceRaw)) != finalStep.Evidence.SHA256 {
			t.Fatal("paired immutable evidence binding")
		}
		var evidence ProbeEvidenceBundle
		if json.Unmarshal(evidenceRaw, &evidence) != nil {
			t.Fatal("paired saved evidence")
		}
		logBytes, err := os.ReadFile(filepath.Join(pairedProfile.Root, "events.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range evidence.Events {
			end := event.Offset + int64(len(event.Data))
			if event.Offset < 0 || end > int64(len(logBytes)) || !bytes.Equal(logBytes[event.Offset:end], event.Data) {
				t.Fatal("paired source journal prefix/offset differs")
			}
		}
		for index, capture := range evidence.Captures {
			admission, err := admitProbeRecords(capture.Admission)
			if err != nil {
				t.Fatal(err)
			}
			receiptRaw, _ := json.Marshal(capture.Receipt)
			if capture.Receipt.PID != admission.PID || capture.Receipt.Epoch != admission.Epoch || capture.Receipt.MemoryBefore.SessionEvidenceSHA256 != fmt.Sprintf("%x", sha256.Sum256(capture.Admission)) || fmt.Sprintf("%x", sha256.Sum256(receiptRaw)) != finalStep.Checkpoint.Captures[index].ReceiptSHA256 {
				t.Fatal("paired actual owner/hash linkage")
			}
			image, _ := hex.DecodeString(capture.ImageHex)
			published, _ := os.ReadFile(filepath.Join(pairedProfile.Root, "captures", capture.Receipt.ImagePath))
			if !bytes.Equal(image, published) || fmt.Sprintf("%x", sha256.Sum256(image)) != capture.Receipt.ImageSHA256 {
				t.Fatal("paired PNG source identity")
			}
		}
		actualRaw, _ := json.Marshal(finalStep.Checkpoint)
		var normalized map[string]any
		_ = json.Unmarshal(actualRaw, &normalized)
		if normalized["bundle_sha256"] != fmt.Sprintf("%x", sha256.Sum256(evidenceRaw)) {
			t.Fatal("paired full report bundle hash")
		}
		normalized["bundle_sha256"] = "NORMALIZED_BUNDLE_SHA256"
		for _, value := range normalized["events"].([]any) {
			row := value.(map[string]any)
			row["offset"] = float64(0)
			row["data"].(map[string]any)["time"] = "NORMALIZED_TIME"
		}
		for _, value := range normalized["captures"].([]any) {
			value.(map[string]any)["receipt_sha256"] = "NORMALIZED_RECEIPT_SHA256"
		}
		var expected map[string]any
		_ = json.Unmarshal(pairedOracle.ExpectedReport, &expected)
		if !reflect.DeepEqual(normalized, expected) {
			actual, _ := json.Marshal(normalized)
			t.Fatalf("paired full normalized report differs: %s", actual)
		}
		cardFixture := "testdata/probe-paired-card-saved.bin"
		if cohort == "newgame" {
			cardFixture = "testdata/probe-newgame-card-final.bin"
		}
		savedCard, _ := os.ReadFile(cardFixture)
		actualCard, _ := os.ReadFile(filepath.Join(pairedProfile.Root, "profile", "PCSX2", "memcards", "probe-slot1.ps2"))
		if !bytes.Equal(actualCard, savedCard) {
			t.Fatal("paired exact File2 persistence/original File1 sentinel")
		}
		if !reflect.DeepEqual(finalStep.UI.Saved, pairedOracle.States["advanced"]) {
			t.Fatal("paired actual advancement footprint")
		}
		if cohort == "newgame" {
			acks, _ := os.ReadFile(filepath.Join(pairedProfile.Root, "preparation-acks.txt"))
			if string(acks) != "1" {
				t.Fatal("preparation must acknowledge exactly once")
			}
			for _, variant := range []string{"missing-preparation-image", "ack-before-image", "uninitialized-image", "missing-final-resave"} {
				var mutant ProbeEvidenceBundle
				_ = json.Unmarshal(evidenceRaw, &mutant)
				switch variant {
				case "missing-preparation-image":
					mutant.Captures = append(mutant.Captures[:2], mutant.Captures[3:]...)
				case "ack-before-image":
					mutant.Events[4], mutant.Events[5] = mutant.Events[5], mutant.Events[4]
				case "uninitialized-image":
					var row map[string]any
					_ = json.Unmarshal(mutant.Events[4].Data, &row)
					row["state"] = pairedOracle.States["initial"]
					mutant.Events[4].Data, _ = json.Marshal(row)
				case "missing-final-resave":
					mutant.Events = append(mutant.Events[:7], mutant.Events[8:]...)
				}
				mutantRaw, _ := json.Marshal(mutant)
				result, err := reportProbeEvidence(mutantRaw)
				if err == nil && result.Status == "PASS" {
					t.Error(variant, "unsafe preparation evidence accepted")
				}
			}
			continue
		}
		for _, variant := range []string{"wrong-slot", "changed-fingerprint", "incomplete-pair", "missing-capture", "out-of-order", "stale-epoch"} {
			var mutant ProbeEvidenceBundle
			_ = json.Unmarshal(evidenceRaw, &mutant)
			switch variant {
			case "wrong-slot", "changed-fingerprint":
				var row map[string]any
				_ = json.Unmarshal(mutant.Events[3].Data, &row)
				if variant == "wrong-slot" {
					row["slot"] = float64(0)
				} else {
					row["state"].(map[string]any)["players"].([]any)[3].(map[string]any)["record_sha256"] = strings.Repeat("f", 64)
				}
				mutant.Events[3].Data, _ = json.Marshal(row)
			case "incomplete-pair":
				mutant.Events = append(mutant.Events[:6], mutant.Events[7:]...)
				mutant.Captures = append(mutant.Captures[:4], mutant.Captures[5:]...)
			case "missing-capture":
				mutant.Captures = mutant.Captures[1:]
			case "out-of-order":
				mutant.Events[7], mutant.Events[8] = mutant.Events[8], mutant.Events[7]
			case "stale-epoch":
				mutant.Captures[3].Admission = mutant.Captures[1].Admission
			}
			mutantRaw, _ := json.Marshal(mutant)
			result, err := reportProbeEvidence(mutantRaw)
			if err == nil && result.Status == "PASS" {
				t.Error(variant, "unsafe paired evidence accepted")
			}
		}
		prefixProfile := pairedProfile
		prefixProfile.Root = t.TempDir()
		_ = os.Chmod(prefixProfile.Root, 0700)
		prefixProfile.ProgramArgs = append(slices.Clone(pairedProfile.ProgramArgs), "tampered-prefix")
		prefixProfile.Requests = append(slices.Clone(pairedProfile.Requests[:3]), ProbeLifecycleRequest{Session: profile.Session, Operation: "stop", Phase: "requested", Nonce: "4-stop"})
		prefixRaw, _ := json.Marshal(prefixProfile)
		prefixResult, prefixErr := runProbeLifecycle(prefixRaw)
		for _, step := range prefixResult.Steps {
			if step.Owned != nil {
				if _, err := observeProbeProcess(ProbeMemoryRuntime{}, step.Owned.PID, step.Owned, prefixProfile.Program.SHA256); err == nil {
					_ = syscall.Kill(step.Owned.PID, syscall.SIGTERM)
					var status syscall.WaitStatus
					_, _ = syscall.Wait4(step.Owned.PID, &status, 0, nil)
				}
			}
		}
		if prefixErr != nil || len(prefixResult.Steps) != 4 || prefixResult.Status != "INCOMPLETE" || prefixResult.Steps[2].Status != "UNKNOWN" || prefixResult.Steps[2].Reason != "owned event prefix or identity changed" || !reflect.DeepEqual(prefixResult.Steps[2].Effects, []string{"quiescent"}) || prefixResult.Steps[3].Status != "COMPLETED" {
			t.Fatalf("tampered prefix refusal: %+v %v", prefixResult, prefixErr)
		}
		traceRaw, _ := os.ReadFile(filepath.Join(prefixProfile.Root, "scenario-inputs.json"))
		var prefixTrace []string
		_ = json.Unmarshal(traceRaw, &prefixTrace)
		if slices.Contains(prefixTrace, "R3") {
			t.Fatal("tampered journal reached reset effect")
		}
		originalCard, _ := os.ReadFile(pairedCardPath)
		if !bytes.Equal(originalCard, initialCard) {
			t.Fatal("paired original card changed")
		}
	}
}
