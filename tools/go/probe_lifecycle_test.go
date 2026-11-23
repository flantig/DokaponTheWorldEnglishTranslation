package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"maps"
	"net"
	"os"
	"os/exec"
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
	role := os.Getenv("DOKAPON_PROBE_FIXTURE_ROLE")
	if role != "" {
		if role != "launcher" && role != "native" || os.Getenv("XDG_RUNTIME_DIR") != filepath.Join(root, "xdg") {
			t.Fatal("controlled launcher requires its private runtime directory")
		}
		if err := syscall.SetNonblock(3, true); err != nil {
			t.Fatal("missing controlled lifetime pipe", err)
		}
	}
	if role == "launcher" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		child := exec.Command(executable, os.Args[1:]...)
		child.Args[0] = "pcsx2-fixture"
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "DOKAPON_PROBE_FIXTURE_ROLE=") {
				child.Env = append(child.Env, entry)
			}
		}
		child.Env = append(child.Env, "DOKAPON_PROBE_FIXTURE_ROLE=native")
		controller := os.NewFile(3, "controlled-lifetime")
		defer controller.Close()
		child.ExtraFiles = []*os.File{controller}
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		defer child.Process.Release()
		witness, _ := json.Marshal(map[string]any{"launcher_pid": os.Getpid(), "native_pid": child.Process.Pid, "native_args": child.Args})
		if err := os.WriteFile(filepath.Join(root, "launcher-native.json"), witness, 0600); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(filepath.Join(root, "release-launcher")); err == nil {
				return
			} else if !os.IsNotExist(err) {
				t.Fatal(err)
			}
			var data [1]byte
			count, err := syscall.Read(3, data[:])
			if count == 0 && err == nil {
				return
			}
			if count > 0 || err != syscall.EAGAIN && err != syscall.EINTR {
				t.Fatal("controlled lifetime pipe changed", count, err)
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("controlled launcher release timed out")
	}
	if role == "native" {
		if err := os.WriteFile("/proc/self/comm", []byte("pcsx2-fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	stopped := make(chan os.Signal, 1)
	parentPID := os.Getppid()
	expires := time.Now().Add(30 * time.Second)
	signal.Notify(stopped, syscall.SIGTERM)
	defer signal.Stop(stopped)
	socketPath := filepath.Join(root, "peer.sock")
	if role == "native" {
		socketPath = filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "pcsx2.sock")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
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
	childEvidence := map[string]any{"pid": os.Getpid(), "argv": os.Args, "pending": pending}
	if role == "native" {
		childEvidence["launcher_pid"] = parentPID
	}
	evidence, _ := json.Marshal(childEvidence)
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
	streamVariant := ""
	gridVariant := ""
	capacityVariant := ""
	for _, argument := range os.Args {
		if strings.HasPrefix(argument, "stream-") {
			streamVariant = argument
		}
		if strings.HasPrefix(argument, "grid-") {
			gridVariant = argument
		}
		if strings.HasPrefix(argument, "capacity-") {
			capacityVariant = argument
		}
	}
	startupVariant := ""
	for _, argument := range os.Args {
		if strings.HasPrefix(argument, "startup-card-") {
			startupVariant = strings.TrimPrefix(argument, "startup-card-")
		}
	}
	startupReads, startupAcknowledged := 0, false
	startupReady := startupVariant != "unready" && startupVariant != "empty" && startupVariant != "busy"
	newGame := slices.Contains(os.Args, "scenario-newgame")
	sequenceRun := 0
	for index := 1; index <= 3; index++ {
		if slices.Contains(os.Args, fmt.Sprintf("sequence-run%d", index)) {
			sequenceRun = index
			newGame = true
		}
	}
	paired := slices.Contains(os.Args, "scenario-paired") || newGame
	scenario := slices.Contains(os.Args, "scenario-first-save") || paired
	if scenario {
		expires = time.Now().Add(120 * time.Second)
	}
	if paired {
		expires = time.Now().Add(600 * time.Second)
	}
	scenarioStage, boardCursor, tabCursor, fileCursor, eventOffset := 0, 0, 0, 0, 0
	choiceVariant := ""
	for _, argument := range os.Args {
		if strings.HasPrefix(argument, "save-dialog-") {
			choiceVariant = strings.TrimPrefix(argument, "save-dialog-")
		}
	}
	fileSelectionAttempts := 0
	fileLoadAttempts := 0
	ackInjected := false
	scenarioControl := byte(1)
	activeActor := 0
	frameCurrentReads := 0
	tutorialFlag := byte(1)
	yesNoCursor := uint32(0)
	introSamples := 0
	preparationAcks := 0
	preparationImageSamples := 0
	baseSquare := byte(9)
	if sequenceRun > 0 {
		baseSquare = byte(9 + 10*(sequenceRun-1))
	}
	expectedFile := 1
	if sequenceRun == 1 || sequenceRun == 2 {
		expectedFile = 0
	}
	gameDataCreated, overwriting := sequenceRun != 1, false
	if newGame {
		activeActor = 2
		tutorialFlag = 0
		if sequenceRun > 1 {
			tutorialFlag = 1
		}
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
			if sequenceRun == 3 && strings.HasPrefix(name, "12-cold-load-") {
				expectedFile = 0
			}
		}
		prior, _ := os.ReadFile(filepath.Join(root, "scenario-inputs.json"))
		_ = json.Unmarshal(prior, &scenarioTrace)
		priorWrites, _ := os.ReadFile(filepath.Join(root, "scenario-write-count.txt"))
		scenarioWrites, _ = strconv.Atoi(string(priorWrites))
	}
	seenReset, renderedGuides := 0, 0
	var latePNG []byte
	var latePNGAfter time.Time
	for offset := 0; offset+24 <= len(padBytes); offset += 24 {
		if binary.LittleEndian.Uint16(padBytes[offset+16:]) == 1 && binary.LittleEndian.Uint16(padBytes[offset+18:]) == 316 && binary.LittleEndian.Uint32(padBytes[offset+20:]) == 1 {
			renderedGuides++
		}
		if binary.LittleEndian.Uint16(padBytes[offset+16:]) == 1 && binary.LittleEndian.Uint16(padBytes[offset+18:]) == 318 && binary.LittleEndian.Uint32(padBytes[offset+20:]) == 1 {
			seenReset++
		}
	}
	for {
		currentParent := os.Getppid()
		expired := time.Now().After(expires)
		parentLost := currentParent != parentPID
		if role == "native" {
			// The launcher may exit; EOF still detects loss of the original controller.
			var data [1]byte
			count, err := syscall.Read(3, data[:])
			parentLost = count == 0 && err == nil
			if count > 0 || err != nil && err != syscall.EAGAIN && err != syscall.EINTR {
				t.Fatal("controlled lifetime pipe changed", count, err)
			}
		}
		if parentLost || expired {
			fmt.Fprintf(os.Stderr, "controlled child return: parent_loss=%t expected_parent=%d actual_parent=%d expired=%t expires=%s\n", parentLost, parentPID, currentParent, expired, expires.Format(time.RFC3339Nano))
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
					// Cleanup of a rendered PNG must not replay its past GUIDE, including after boot.
					if guideCount <= renderedGuides {
						continue
					}
					renderedGuides = guideCount
					name := "first-save.png"
					if guideCount > 1 {
						name = fmt.Sprintf("capture-%d.png", guideCount)
					}
					if slices.Contains(os.Args, "frame-no-image") {
						continue // Keep the real GUIDE service/ack; omit only the controlled PNG.
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
						imageBytes, err := hex.DecodeString(fixture.ImageHex)
						if err != nil {
							t.Fatal(err)
						}
						if slices.Contains(os.Args, "frame-late-on-stop") {
							latePNG, latePNGAfter = imageBytes, time.Now().Add(10*time.Second)
							continue
						}
						if slices.Contains(os.Args, "frame-checkpoint-contrast") {
							journal, err := os.ReadFile(filepath.Join(root, "events.jsonl"))
							last := bytes.TrimSpace(journal)
							last = last[bytes.LastIndexByte(last, '\n')+1:]
							var event ProbeCaptureEvent
							if err != nil || json.Unmarshal(last, &event) != nil {
								t.Fatal("controlled contrast source event", err)
							}
							if event.Checkpoint != nil && *event.Checkpoint > 0 {
								var contrasting bytes.Buffer
								if err := png.Encode(&contrasting, &image.NRGBA{Pix: []byte{255, 17, 33, 255}, Stride: 4, Rect: image.Rect(0, 0, 1, 1)}); err != nil {
									t.Fatal(err)
								}
								imageBytes = contrasting.Bytes()
							}
						}
						if err := os.WriteFile(path, imageBytes, 0600); err != nil {
							t.Fatal(err)
						}
						if guideCount == 1 && slices.Contains(os.Args, "frame-csv-conflict") {
							if err := os.WriteFile(filepath.Join(root, "frames.csv"), []byte("controlled CSV conflict\n"), 0600); err != nil {
								t.Fatal(err)
							}
						}
					}
				}
			}
		}
		select {
		case <-stopped:
			if latePNG != nil {
				// Finish the first GUIDE after its full acquisition window, even
				// if owned shutdown begins before this delayed producer completes.
				if delay := time.Until(latePNGAfter); delay > 0 {
					time.Sleep(delay)
				}
				if err := os.WriteFile(filepath.Join(root, "profile", "PCSX2", "snaps", "late.png"), latePNG, 0600); err != nil {
					t.Fatal(err)
				}
			}
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
				if slices.Contains(os.Args, "pre-acquisition-delay") {
					_, started := os.Stat(filepath.Join(root, "go-records-2-scenario.json"))
					_, completed := os.Stat(filepath.Join(root, "receipts", "2-scenario-00-acquire-board.complete.json"))
					if started == nil && os.IsNotExist(completed) {
						time.Sleep(700 * time.Millisecond)
					}
				}
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
						case 3, 21, 23:
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
									if sequenceRun > 1 {
										tutorialFlag = 1
									}
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
									if !gameDataCreated {
										scenarioStage = 26
										yesNoCursor = 0
									}
								}
							case 2:
								if fileCursor == expectedFile {
									fileSelectionAttempts++
									_ = os.WriteFile(filepath.Join(root, "file-selection-attempts.txt"), []byte(strconv.Itoa(fileSelectionAttempts)), 0600)
									if choiceVariant == "retry-bound" || (choiceVariant == "delayed-selection" || choiceVariant == "shifted-cursor") && fileSelectionAttempts <= 2 {
										if choiceVariant == "shifted-cursor" {
											fileCursor = 0
										}
										break
									}
									scenarioStage = 3
									yesNoCursor = 0
									if choiceVariant == "header-yes-widget-no" {
										yesNoCursor = 1
									}
									if sequenceRun > 0 {
										card, _ := os.ReadFile(filepath.Join(root, "profile", "PCSX2", "memcards", "probe-slot1.ps2"))
										offset := 8 + fileCursor*2052
										if len(card) != 4112 {
											t.Fatal("sequence card size")
										}
										overwriting = !bytes.Equal(card[offset:offset+2052], make([]byte, 2052))
									}
								}
							case 3:
								if choiceVariant == "header-yes-widget-no" && yesNoCursor != 0 {
									t.Fatal("card confirmation ignored visible No cursor")
								}
								if choiceVariant == "header-no-widget-yes" && yesNoCursor != 0 {
									t.Fatal("stale No header moved the visible Yes cursor")
								}
								if choiceVariant == "dialog-return" {
									scenarioStage = 2
									break
								}
								if paired {
									cardPath := filepath.Join(root, "profile", "PCSX2", "memcards", "probe-slot1.ps2")
									card, err := os.ReadFile(cardPath)
									if err != nil || len(card) != 4112 || len(playerData) != 2032 {
										t.Fatal("controlled card source layout")
									}
									offset := 2060
									if sequenceRun > 0 {
										offset = 8 + fileCursor*2052
									}
									binary.LittleEndian.PutUint32(card[offset:], 1)
									binary.LittleEndian.PutUint32(card[offset+12:], uint32(activeActor))
									copy(card[offset+20:], playerData)
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
								if startupVariant != "" && !startupAcknowledged {
									if !startupReady {
										t.Fatal("startup CIRCLE before ready")
									}
									startupAcknowledged = true
									ack, _ := json.Marshal(map[string]int{"ui_reads": startupReads, "press_offset": eventOffset})
									_ = os.WriteFile(filepath.Join(root, "startup-card-ack.json"), ack, 0600)
									break
								}
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
								if fileCursor == expectedFile {
									if choiceVariant == "delayed-selection" {
										fileLoadAttempts++
										_ = os.WriteFile(filepath.Join(root, "file-load-attempts.txt"), []byte(strconv.Itoa(fileLoadAttempts)), 0600)
										if fileLoadAttempts <= 2 {
											break
										}
									}
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
								offset := 2060
								if sequenceRun > 0 {
									offset = 8 + fileCursor*2052
								}
								loadedHeaders = bytes.Clone(card[offset : offset+20])
								loadedRecords = bytes.Clone(card[offset+20 : offset+2052])
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
							case 26:
								scenarioStage = 27
							case 27:
								gameDataCreated = true
								scenarioStage = 2
							}
						case 316:
							name = "GUIDE"
						}
					}
					if name != "" {
						scenarioTrace = append(scenarioTrace, name)
					}
				}
				if !slices.Contains(os.Args, "frame-no-trace") {
					trace, _ := json.Marshal(scenarioTrace)
					_ = os.WriteFile(filepath.Join(root, "scenario-inputs.json"), trace, 0600)
				}
				if startupVariant != "" && !startupAcknowledged && len(payload) == 5 && payload[0] <= 3 && binary.LittleEndian.Uint32(payload[1:]) == 0x56b192 {
					startupReads++
					if startupVariant == "unready" || startupVariant == "empty" {
						startupReady = startupReads >= 3
					}
				}
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
				if choiceVariant == "unknown-ack" && scenarioStage == 2 && fileCursor == expectedFile && !ackInjected {
					ackInjected = true
					padPath := filepath.Join(root, "pad.sock")
					originalPath := filepath.Join(root, "pad-original.sock")
					if err := os.Rename(padPath, originalPath); err != nil {
						t.Fatal(err)
					}
					peer, err := net.ListenUnix("unix", &net.UnixAddr{Name: padPath, Net: "unix"})
					if err != nil {
						t.Fatal(err)
					}
					go func() {
						connection, err := peer.AcceptUnix()
						if err == nil {
							_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
							command, _ := io.ReadAll(io.LimitReader(connection, 257))
							_ = os.WriteFile(filepath.Join(root, "unknown-ack-command.txt"), command, 0600)
							_, _ = io.WriteString(connection, "unknown\n")
							_ = connection.Close()
						}
						_ = peer.Close()
						_ = os.Rename(originalPath, padPath)
					}()
				}
				if newGame && scenarioStage == 24 && len(payload) == 5 && binary.LittleEndian.Uint32(payload[1:]) == 0x56581c {
					introSamples++
				}
				if newGame && scenarioStage == 25 && len(payload) == 5 && binary.LittleEndian.Uint32(payload[1:]) == 0x56581c {
					preparationImageSamples++
				}
				if paired && advanceAtMode > 0 && len(payload) == 5 && binary.LittleEndian.Uint32(payload[1:]) == 0x56581c && scenarioModeReads+1 >= advanceAtMode {
					if sequenceRun > 0 {
						loadedRecords[activeActor*508+250]++
						scenarioStage = 12
						boardCursor = 0
						tabCursor = 0
						if sequenceRun == 3 {
							expectedFile = 1 - expectedFile
						}
					} else if newGame {
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
						memory[base+250] = baseSquare
						if player == activeActor {
							memory[base] = tutorialFlag
						}
						if scenarioStage == 24 && introSamples < 2 && player == 3 {
							memory[base+250] = baseSquare + 1
						}
					}
					for index, word := range []uint32{uint32(65 + player), uint32(66 + player), 0, 0, 0} {
						if sequenceRun > 1 && player == 0 && index == 0 {
							word = uint32(65 + 10*(sequenceRun-1))
						}
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
				if scenarioStage == 26 || scenarioStage == 27 {
					innerWidth = 0x2e0
				}
				if startupVariant != "" && !startupAcknowledged && scenarioStage == 8 {
					innerWidth = 588
					if startupVariant == "mode" {
						innerWidth = 608
					}
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
				if sequenceRun > 0 {
					pendingRows, _ := os.ReadDir(filepath.Join(root, "receipts"))
					for _, entry := range pendingRows {
						if strings.Contains(entry.Name(), "-finish-") && strings.HasSuffix(entry.Name(), ".pending.json") {
							memory[0x56b598] = 50
							memory[0x56b599] = 0
						}
					}
				}
				texts := map[int]string{}
				if !paired && scenarioStage == 6 {
					texts[19] = strings.Repeat("x", 129)
				}
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
				if scenarioStage == 3 || scenarioStage == 5 || scenarioStage == 10 || scenarioStage == 26 || scenarioStage == 27 {
					texts[2] = "Savetoanewfile"
					if sequenceRun > 0 && scenarioStage == 3 && overwriting {
						texts[2] = "OverwriteFile1"
					}
					if scenarioStage == 26 {
						texts[2] = "Createnewdata"
					}
					if scenarioStage == 27 {
						texts[2] = "Newdatawascreated"
					}
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
				if scenarioStage == 3 && choiceVariant != "" {
					if choiceVariant == "header-yes-widget-no" {
						memory[0x579ba6] = 0
					}
					if choiceVariant == "header-no-widget-yes" {
						memory[0x579ba6] = 1
					}
					if choiceVariant != "missing-widget" && choiceVariant != "delayed-selection" && choiceVariant != "dialog-return" {
						texts[3] = "YesNo"
						selections[3] = int(yesNoCursor)
						if choiceVariant == "invalid-widget" {
							selections[3] = 2
						}
					}
				}
				if startupVariant != "" && !startupAcknowledged && scenarioStage == 8 {
					texts = map[int]string{0: "Checkingthememorycard(PS2)inslot1.Donotremovethememorycard(PS2)."}
					selections = map[int]int{}
					sources[0] = 0x5358a0
					ready[0] = 0
					if startupReady {
						ready[0] = 1
					}
					switch startupVariant {
					case "empty":
						if !startupReady {
							texts[0] = ""
						}
					case "source":
						sources[0] += 4
					case "text":
						texts[0] = "CheckingthememorycardWRONG"
					case "format":
						texts[0] = "Formatthememorycard?"
					case "delete":
						texts[0] = "Deletethedata?"
					case "no-data":
						texts[0] = "Thereisnodataonthememorycard(PS2)."
					case "extra":
						texts[1] = "Unexpectedquestion?"
					case "index":
						texts[1], sources[1], ready[1] = texts[0], sources[0], ready[0]
						delete(texts, 0)
						memory[0x570108] = 1
					case "state":
						memory[0x570114] = 1
					}
				}
				for widget, text := range texts {
					base := uint32(0x5657a0 + 196*widget)
					glyphs := uint32(0x300000 + widget*0x10000)
					nodes := uint32(0x500000 + widget*0x10000)
					memory[base] = 1
					if widget == 3 && choiceVariant == "hidden-widget" {
						memory[base] = 3
					}
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
					if startupVariant != "" && !startupAcknowledged && scenarioStage == 8 && sources[widget] != 0 && text != "" {
						count := len(text) + 1
						if startupVariant == "warnings" {
							count++
						}
						memory[base+0x58], memory[base+0x59] = byte(count), byte(count>>8)
						switch startupVariant {
						case "flags":
							memory[base] = 5
						case "kind":
							memory[base+4] = 1
						case "page":
							memory[base+0x4d] = 1
						case "reason":
							node := nodes + uint32(len(text))*32
							for b := 0; b < 4; b++ {
								memory[glyphs+uint32(len(text))*96+0x18+uint32(b)] = byte(node >> (8 * b))
							}
							copyLabel := []byte("not-a-char")
							for b, value := range copyLabel {
								memory[node+0x10+uint32(b)] = value
							}
						}
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
					if len(loadedRecords) == 2032 {
						loadedRecords[activeActor*508+241] = payload[5]
					}
					if bootHandoff {
						scenarioStage = 0
					}
					if restore {
						loadedRecords[activeActor*508+241] = 1
						advanceAtMode = scenarioModeReads + 2
					}
					scenarioWrites++
					if !slices.Contains(os.Args, "frame-no-trace") {
						_ = os.WriteFile(filepath.Join(root, "scenario-write-count.txt"), []byte(strconv.Itoa(scenarioWrites)), 0600)
					}
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
					if address == 0x56b190 && slices.Contains(os.Args, "frame-selector-drift") {
						frameCurrentReads++
						if frameCurrentReads >= 2 {
							// Selection saw actor0; both complete capture batches see actor1.
							memory[address] = 1
						}
					}
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
							// Unlink only the listener; accepted-peer EOF must follow the actual crash.
							if err := listener.Close(); err != nil {
								t.Fatal("controlled crash listener", err)
							}
							if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
								t.Fatal("controlled crash signal", err)
							}
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
				case len(payload) == 5 && payload[0] == 2 && capacityVariant != "":
					address := binary.LittleEndian.Uint32(payload[1:])
					words := map[uint32]uint32{0x399b30: 0x3c05000a, 0x399b34: 0x34a50000, 0x399b94: 0x240e0140, 0x399c0c: 0x240e0140, 0x4db4a0: 0x3c090010, 0x4db4e0: 0x3c090010, 0x2f39d8: 0x00084d02, 0x537418: 0x00084d02, 0x4ad078: 0x00011d02, 0x4ad0a0: 0x00011d02, 0x4ad0c8: 0x00011d02, 0x4ad0f0: 0x00011d02, 0x4ad118: 0x00011d02}
					word, exists := words[address]
					if !exists {
						t.Fatal("unexpected configured code address", address)
					}
					if capacityVariant == "capacity-window" && address == 0x4db4a0 {
						word = 0x3c090001
					}
					if capacityVariant == "capacity-loader" && address == 0x399b94 {
						word = 0x240e0141
					}
					reply = make([]byte, 9)
					binary.LittleEndian.PutUint32(reply, 9)
					binary.LittleEndian.PutUint32(reply[5:], word)
				case len(payload) == 5 && payload[0] <= 3 && gridVariant != "":
					address := binary.LittleEndian.Uint32(payload[1:])
					words := []uint16{76, 51, 60, 43, 79, 43, 62, 43, 69, 70, 71, 0, 0, 0, 0, 0, 82, 47, 66, 62, 70, 43, 45, 53, 72, 47, 54, 0, 0, 0, 0, 0, 83, 79, 0, 0, 0xf800}
					switch gridVariant {
					case "grid-glyph":
						words[0] = 75
					case "grid-padding":
						words[11] = 69
					case "grid-shift":
						for index := 0; index < 4; index++ {
							words[12+index], words[16+index] = words[16+index], words[12+index]
						}
					case "grid-control":
						words[0] = 0xb002
					case "grid-missing-end":
						words[36] = 0
					}
					var field []byte
					for _, word := range words {
						field = binary.LittleEndian.AppendUint16(field, word)
					}
					width := 1 << payload[0]
					if address < 0x47ea90 || uint64(address)+uint64(width) > 0x47eada {
						t.Fatal("unexpected grid storage request", payload)
					}
					reply = make([]byte, 5+width)
					binary.LittleEndian.PutUint32(reply, uint32(len(reply)))
					copy(reply[5:], field[address-0x47ea90:address-0x47ea90+uint32(width)])
				case len(payload) == 5 && payload[0] <= 3 && streamVariant != "":
					address := binary.LittleEndian.Uint32(payload[1:])
					field := []byte{2, 0xb0, 0, 0xa0, 8, 0xb0, 0x41, 0, 0x39, 0, 0x35, 0, 0x2f, 0, 0, 0, 0x3f, 0, 0x3a, 0, 0xb, 0, 0, 0x10, 0, 0xf8}
					switch streamVariant {
					case "stream-mismatch":
						field[6] = 0x39
					case "stream-early-end":
						field[6], field[7] = 0, 0xf8
					case "stream-missing-end":
						field[25] = 0
					case "stream-unknown":
						field[0], field[1] = 1, 0xe0
					}
					width := 1 << payload[0]
					if address < 0x4755f0 || uint64(address)+uint64(width) > 0x47560a {
						t.Fatal("unexpected narrative storage request", payload)
					}
					reply = make([]byte, 5+width)
					binary.LittleEndian.PutUint32(reply, uint32(len(reply)))
					copy(reply[5:], field[address-0x4755f0:address-0x4755f0+uint32(width)])
				case len(payload) == 5 && payload[0] == 3 && (slices.Contains(os.Args, "storage-match") || slices.Contains(os.Args, "storage-mismatch")):
					address := binary.LittleEndian.Uint32(payload[1:])
					field := []byte{0x54, 0, 0x53, 0, 0x53, 0, 0x54, 0, 0, 0, 0x51, 0, 0x45, 0, 0x52, 0}
					if slices.Contains(os.Args, "storage-mismatch") {
						field[0] = 0x53
					}
					if address != 0x457e10 && address != 0x457e18 {
						t.Fatal("unexpected fixed storage address", address)
					}
					reply = []byte{13, 0, 0, 0, 0}
					reply = append(reply, field[address-0x457e10:address-0x457e10+8]...)
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
	// Every native case stops at preparation, before any device or child can exist.
	var nativeSettings string
	var nativeCases []struct {
		Name, Backend, From, To, Reason, Error string
		Flatpak, PrivateSettings, CRLF         bool
	}
	if json.Unmarshal(fields["native_settings"], &nativeSettings) != nil || json.Unmarshal(fields["native_settings_cases"], &nativeCases) != nil || len(nativeCases) != 30 {
		t.Fatal("literal native settings oracle")
	}
	for _, version := range []string{"missing", "1", "blank", "0", "2", "case", "duplicate", "repeat-ui", "crlf", "prelaunch-cap", "cache-grants"} {
		row := nativeCases[0]
		row.Name, row.Backend, row.From, row.To, row.Error = "flatpak-version-"+version, "event-sink", "", "", ""
		row.Flatpak, row.PrivateSettings = true, version == "missing" || version == "1" || version == "repeat-ui" || version == "crlf"
		row.Reason = "private settings version is unsupported"
		switch version {
		case "missing", "crlf":
			row.Reason = "pad service failed: "
			row.CRLF = version == "crlf"
		case "1", "0", "2":
			row.From, row.To = "[UI]\n", "[UI]\nSettingsVersion="+version+"\n"
			if version == "1" {
				row.Reason = "pad service failed: "
			}
		case "blank":
			row.From, row.To = "[UI]\n", "[UI]\nSettingsVersion=\n"
		case "case":
			row.From, row.To, row.Reason = "[UI]\n", "[UI]\nsettingsversion=1\n", "private settings version is ambiguous"
		case "duplicate":
			row.From, row.To, row.Reason = "[UI]\n", "[UI]\nSettingsVersion=1\nSettingsVersion=1\n", "private settings version is ambiguous"
		case "repeat-ui":
			row.From, row.To, row.Reason = "[UI]\n", "[UI]\nSettingsVersion=1\n[UI]\n", "pad service failed: "
		case "prelaunch-cap":
			row.PrivateSettings, row.Reason = true, "effect completion publication failed"
		case "cache-grants":
			row.PrivateSettings, row.Reason = true, "artifact ordinary capacity exceeded"
		}
		nativeCases = append(nativeCases, row)
	}
	for _, row := range nativeCases {
		prelaunchCap := row.Name == "flatpak-version-prelaunch-cap"
		cacheGrants := row.Name == "flatpak-version-cache-grants"
		candidate := profile
		candidate.PadBackend = row.Backend
		candidate.Root = t.TempDir()
		_ = os.Chmod(candidate.Root, 0700)
		if !row.Flatpak {
			if err := os.Mkdir(filepath.Join(candidate.Root, "profile"), 0700); err != nil {
				t.Fatal(err)
			}
		}
		settings := nativeSettings
		if row.Flatpak {
			settings += "[UI]\nStartFullscreen=false\nSetupWizardIncomplete=false\n[EmuCore]\nEnablePINE=true\nPINESlot=28011\n[MemoryCards]\nMultitap1_Slot2_Enable=false\nMultitap1_Slot3_Enable=false\nMultitap1_Slot4_Enable=false\nMultitap2_Slot2_Enable=false\nMultitap2_Slot3_Enable=false\nMultitap2_Slot4_Enable=false\n"
		}
		if row.From != "" {
			if strings.Count(settings, row.From) != 1 {
				t.Fatal(row.Name, "mutation is not unique")
			}
			settings = strings.Replace(settings, row.From, row.To, 1)
		}
		if row.CRLF {
			settings = strings.ReplaceAll(settings, "\n", "\r\n")
		}
		path := filepath.Join(sources, row.Name+".ini")
		if err := os.WriteFile(path, []byte(settings), 0400); err != nil {
			t.Fatal(err)
		}
		candidate.Inputs = map[string]RegistryInput{}
		for role, input := range profile.Inputs {
			candidate.Inputs[role] = input
		}
		candidate.Inputs["settings"] = RegistryInput{Path: path, Size: int64(len(settings)), SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(settings)))}
		if row.Flatpak {
			project := candidate.Root
			if err := os.MkdirAll(filepath.Join(project, "generated", "work"), 0700); err != nil {
				t.Fatal(err)
			}
			candidate.Root = filepath.Join(project, "generated", strings.Repeat("r", 96))
			if prelaunchCap || cacheGrants {
				candidate.Root = filepath.Join(project, "generated", "cap")
			}
			if !prelaunchCap && !cacheGrants && len(filepath.Join(candidate.Root, "pad.sock")) <= 107 {
				t.Fatal("preparation test must refuse before any launcher through the Unix pathname bound")
			}
			if err := os.Mkdir(candidate.Root, 0700); err != nil {
				t.Fatal(err)
			}
			if prelaunchCap {
				candidate.Frames = &ProbeFramePolicy{MaxRunSeconds: 60, MaxRetainedFrames: 16, MaxManagedFiles: 64, MaxManagedBytes: 256 << 20, MaxJournalBytes: 1 << 20}
				for index := 0; index < 45; index++ {
					if err := os.WriteFile(filepath.Join(candidate.Root, fmt.Sprintf("owned-%02d", index)), []byte("x"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if cacheGrants {
				// All three actual launch grants exceed this ordinary partition;
				// deleting one leaves enough room to reach the refused launcher.
				candidate.Frames = &ProbeFramePolicy{MaxRunSeconds: 60, MaxRetainedFrames: 16, MaxManagedFiles: 64, MaxManagedBytes: 8*probeFinalizerArtifactBytes + 216<<20, MaxJournalBytes: 1 << 20}
			}
			iso := candidate.Inputs["iso"]
			iso.Path = filepath.Join(project, "generated", "work", "source.iso")
			if err := os.WriteFile(iso.Path, []byte("synthetic-iso"), 0400); err != nil {
				t.Fatal(err)
			}
			candidate.Inputs["iso"] = iso
			candidate.ProgramArgs = []string{}
			candidate.Flatpak = &ProbeFlatpakLaunch{ProjectRoot: project, Launcher: candidate.Inputs["settings"], RuntimeArgv0: "pcsx2-qt"}
		}
		candidate.Requests = []ProbeLifecycleRequest{fixture.Requests[0], fixture.Requests[len(fixture.Requests)-1]}
		input, _ := json.Marshal(candidate)
		result, err := runProbeLifecycle(input)
		if row.Error != "" {
			if err == nil || err.Error() != row.Error {
				t.Fatalf("%s early refusal: %v", row.Name, err)
			}
			if entries, _ := os.ReadDir(candidate.Root); len(entries) != 1 {
				t.Fatal(row.Name, "unsupported backend produced effects")
			}
		} else if err != nil || len(result.Steps) != 2 || !strings.HasPrefix(result.Steps[0].Reason, row.Reason) {
			t.Fatalf("%s preparation: %+v %v", row.Name, result, err)
		}
		for _, name := range []string{"pad.sock", "pad-events.bin", "pad-device.json", "child-epoch-0.log", "owned.json"} {
			if row.PrivateSettings && (name == "pad-events.bin" || name == "pad-device.json") {
				continue
			}
			if _, err := os.Lstat(filepath.Join(candidate.Root, name)); !os.IsNotExist(err) {
				t.Fatal(row.Name, "preparation reached pad/child", name)
			}
		}
		if row.PrivateSettings {
			expected := settings
			if row.From == "" {
				ending := "\n"
				if row.CRLF {
					ending = "\r\n"
				}
				expected = strings.Replace(expected, "[UI]"+ending, "[UI]"+ending+"SettingsVersion=1"+ending, 1)
			}
			actual, err := os.ReadFile(filepath.Join(candidate.Root, "profile", "PCSX2", "inis", "PCSX2.ini"))
			expectedEffects := []string{"prepare"}
			if prelaunchCap || cacheGrants {
				expectedEffects = append(expectedEffects, "pad")
			}
			proof := result.Steps[0].Evidence
			if proof == nil || proof.Path != filepath.Join(candidate.Root, "profile", "PCSX2", "inis", "PCSX2.ini") || proof.Size != int64(len(expected)) || proof.SHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(expected))) {
				t.Fatal(row.Name, "prepared settings evidence differs from acknowledged writer bytes", proof)
			}
			if err != nil || string(actual) != expected || !slices.Equal(result.Steps[0].Effects, expectedEffects) {
				t.Fatal(row.Name, "private Flatpak version output differs or reached launch", err, result.Steps[0])
			}
			if prelaunchCap {
				if result.Steps[1].Reason != "safe stop requires an established owned child" || result.Status != "INCOMPLETE" {
					t.Fatal("actual prelaunch failure changed its stop refusal", result.Steps[1])
				}
			}
		} else if row.Flatpak {
			if _, err := os.Lstat(filepath.Join(candidate.Root, "profile")); !os.IsNotExist(err) {
				t.Fatal(row.Name, "invalid version created a private profile", err)
			}
		} else if entries, _ := os.ReadDir(filepath.Join(candidate.Root, "profile")); len(entries) != 0 {
			t.Fatal(row.Name, "preparation copied profile inputs")
		}
		for role, source := range candidate.Inputs {
			readback, err := os.ReadFile(source.Path)
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(readback)) != source.SHA256 {
				t.Fatal(row.Name, role, "source input changed", err)
			}
		}
		if row.Flatpak {
			t.Logf("%s actual Flatpak preparation: private_settings=%t source_unchanged=true effects=%v", row.Name, row.PrivateSettings, result.Steps[0].Effects)
		}
	}
	// Exercise effective backend agreement before sequence locks, pending files or runs.
	for _, variant := range []string{"unsupported", "mixed", "default-equivalent"} {
		spec := ProbeSequenceSpec{Version: 1, SourceFormat: "go-probe-sequence-v1", Root: t.TempDir(), Seed: 17}
		_ = os.Chmod(spec.Root, 0700)
		for index, recipe := range []string{"first-create", "new-game-overwrite", "alternate-slots"} {
			candidate := profile
			candidate.Root = filepath.Join(spec.Root, fmt.Sprintf("run-%d", index))
			_ = os.Mkdir(candidate.Root, 0700)
			candidate.Session = fmt.Sprintf("native-boundary-%d", index)
			candidate.Scenario = &ProbeScenarioSpec{Recipe: recipe}
			seed := spec.Seed + uint64(index)
			candidate.Seed = &seed
			candidate.Requests = []ProbeLifecycleRequest{fixture.Requests[0], fixture.Requests[len(fixture.Requests)-1]}
			candidate.Inputs = map[string]RegistryInput{}
			for role, input := range profile.Inputs {
				candidate.Inputs[role] = input
			}
			if index > 0 {
				candidate.Inputs["card"] = RegistryInput{}
			}
			if index == 1 {
				switch variant {
				case "unsupported":
					candidate.PadBackend = "native"
				case "mixed":
					candidate.PadBackend = "uinput"
				case "default-equivalent":
					candidate.PadBackend = "event-sink"
				}
			}
			spec.Profiles = append(spec.Profiles, candidate)
		}
		// The existing source-lineage guard is the safe next boundary for defaults.
		if variant == "default-equivalent" {
			spec.Profiles[2].Program.SHA256 = strings.Repeat("0", 64)
		}
		input, _ := json.Marshal(spec)
		_, err := runProbeSequence(input)
		expected := "unsupported owned pad backend"
		switch variant {
		case "mixed":
			expected = "sequence pad backend differs"
		case "default-equivalent":
			expected = "sequence source/build/input lineage differs"
		}
		if err == nil || err.Error() != expected {
			t.Fatal(variant, "sequence backend boundary", err)
		}
		if entries, _ := os.ReadDir(spec.Root); len(entries) != 3 {
			t.Fatal(variant, "sequence backend check produced effects")
		}
	}
	t.Setenv("DOKAPON_PROBE_LIFECYCLE_CHILD", "1")
	glyphs := map[string]string{}
	for character := 32; character < 127; character++ {
		glyphs[strconv.Itoa(character)] = string(rune(character))
	}
	glyphRaw, _ := json.Marshal(glyphs)
	glyphPath := filepath.Join(sources, "save-dialog-glyphmap.json")
	if err := os.WriteFile(glyphPath, glyphRaw, 0400); err != nil {
		t.Fatal(err)
	}
	card, err := os.ReadFile("testdata/probe-paired-card-initial.bin")
	if err != nil {
		t.Fatal(err)
	}
	cardPath := filepath.Join(sources, "save-dialog-card.bin")
	if err := os.WriteFile(cardPath, card, 0400); err != nil {
		t.Fatal(err)
	}
	for index, variant := range []string{"ready", "unready", "empty", "busy", "text", "source", "mode", "kind", "flags", "page", "reason", "warnings", "extra", "index", "state", "format", "delete", "no-data"} {
		candidate := profile
		candidate.Root = filepath.Join(root, fmt.Sprintf("startup-%d", index))
		if err := os.Mkdir(candidate.Root, 0700); err != nil {
			t.Fatal(err)
		}
		candidate.ReadyTimeoutMS = 10000
		candidate.ProgramArgs = append(slices.Clone(profile.ProgramArgs), "scenario-newgame", "startup-card-"+variant)
		candidate.Inputs = maps.Clone(profile.Inputs)
		candidate.Inputs["card"] = RegistryInput{Path: cardPath, Size: int64(len(card)), SHA256: fmt.Sprintf("%x", sha256.Sum256(card))}
		candidate.Scenario = &ProbeScenarioSpec{ID: "first-save-nondefault", Glyphmap: RegistryInput{Path: glyphPath, Size: int64(len(glyphRaw)), SHA256: fmt.Sprintf("%x", sha256.Sum256(glyphRaw))}, TimeoutMS: 30000, FrontEndTimeoutMS: 30000, NoTutorial: true, MaxUIReads: 4096}
		if variant == "ready" || variant == "unready" || variant == "empty" {
			// The aggregate front-end includes wait-board after the acknowledged boot handoff.
			candidate.Scenario.FrontEndTimeoutMS = 120000
		}
		if variant == "busy" {
			candidate.Scenario.FrontEndTimeoutMS = 1000
		}
		candidate.Requests = nil
		for ordinal, operation := range []string{"initial", "newgame", "stop"} {
			candidate.Requests = append(candidate.Requests, ProbeLifecycleRequest{Session: profile.Session, Operation: operation, Phase: "requested", Nonce: fmt.Sprintf("%d-%s", ordinal+1, operation)})
		}
		input, _ := json.Marshal(candidate)
		result, err := runProbeLifecycle(input)
		if err != nil || len(result.Steps) != 3 || result.Steps[0].Status != "COMPLETED" || result.Steps[2].Status != "COMPLETED" {
			t.Fatal("startup fixture lifecycle", variant, result, err)
		}
		positive := variant == "ready" || variant == "unready" || variant == "empty"
		events, err := os.ReadFile(filepath.Join(candidate.Root, "pad-events.bin"))
		if err != nil {
			t.Fatal(err)
		}
		if !positive {
			want := "unrecognized startup card prompt"
			if variant == "busy" {
				want = "source scenario deadline expired"
			}
			if result.Steps[1].Status != "UNKNOWN" || result.Steps[1].Reason != want {
				t.Fatal("startup refusal", variant, result.Steps[1])
			}
			for offset := 0; offset+24 <= len(events); offset += 24 {
				if binary.LittleEndian.Uint16(events[offset+16:]) == 1 && binary.LittleEndian.Uint32(events[offset+20:]) == 1 {
					t.Fatal("unsupported startup context emitted a key", variant)
				}
			}
			t.Logf("startup-%s refused without key, reason=%s", variant, want)
			continue
		}
		if result.Steps[1].Status != "COMPLETED" {
			t.Fatal("startup did not reach later supported newgame state", variant, result.Steps[1])
		}
		ackRaw, err := os.ReadFile(filepath.Join(candidate.Root, "startup-card-ack.json"))
		var ack map[string]int
		if err != nil || json.Unmarshal(ackRaw, &ack) != nil || ack["ui_reads"] < 2 || (variant == "unready" || variant == "empty") && ack["ui_reads"] < 3 {
			t.Fatal("startup acknowledgement preceded ready reread", variant, string(ackRaw), err)
		}
		presses, released := 0, false
		for offset := 0; offset+24 <= len(events); offset += 24 {
			kind, code, value := binary.LittleEndian.Uint16(events[offset+16:]), binary.LittleEndian.Uint16(events[offset+18:]), binary.LittleEndian.Uint32(events[offset+20:])
			if kind != 1 {
				continue
			}
			if offset <= ack["press_offset"] && value == 1 {
				if code != 305 {
					t.Fatal("unexpected input before checking acknowledgement", variant, code)
				}
				presses++
			} else if offset > ack["press_offset"] && code == 305 && value == 0 {
				released = true
				break
			} else if offset > ack["press_offset"] && value == 1 {
				t.Fatal("later input preceded checking release", variant)
			}
		}
		if presses != 1 || !released {
			t.Fatal("checking acknowledgement lacks exactly one CIRCLE/release", variant, presses, released)
		}
		entries, err := os.ReadDir(filepath.Join(candidate.Root, "receipts"))
		if err != nil {
			t.Fatal(err)
		}
		warningKept, laterSupported, waited := false, false, false
		for _, entry := range entries {
			if !strings.Contains(entry.Name(), "-select-newgame") || !strings.HasSuffix(entry.Name(), ".complete.json") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(candidate.Root, "receipts", entry.Name()))
			var effect ProbeLifecycleEffect
			var step ProbeLifecycleStep
			if err != nil || json.Unmarshal(raw, &effect) != nil || json.Unmarshal(effect.Details, &step) != nil || step.UI == nil {
				t.Fatal("startup effect receipt missing UI", variant, err)
			}
			for _, widget := range step.UI.Widgets {
				warningKept = warningKept || widget.Unsupported && len(step.UI.Unsupported) == 1 && step.UI.Unsupported[0] == "widget0 glyph pointer unsupported"
				laterSupported = laterSupported || !widget.Unsupported && strings.HasPrefix(widget.Text, "NewGameFreeBattleContinue")
				waited = waited || widget.Ready == 0
			}
		}
		if !warningKept || !laterSupported || (variant == "unready" || variant == "empty") && !waited {
			t.Fatal("startup warning/wait/later state evidence lost", variant, warningKept, waited, laterSupported)
		}
		t.Logf("startup-%s one CIRCLE/release after ready, warning retained, supported transition", variant)
	}
	t.Run("save-dialog", func(t *testing.T) {
		for index, row := range []struct {
			Name, Reason, Source string
			Attempts             int
			Header, Selection    uint64
			Load                 bool
		}{
			{Name: "header-yes-widget-no", Source: "visible_widget", Attempts: 1, Selection: 1},
			{Name: "header-no-widget-yes", Source: "visible_widget", Attempts: 1, Header: 1},
			{Name: "missing-widget", Source: "header", Attempts: 1},
			{Name: "invalid-widget", Source: "header", Attempts: 1},
			{Name: "hidden-widget", Source: "header", Attempts: 1},
			{Name: "delayed-selection", Attempts: 3, Load: true},
			{Name: "shifted-cursor", Attempts: 1, Reason: "source file selection returned without Save completion"},
			{Name: "retry-bound", Attempts: 6, Reason: "source file selection returned without Save completion"},
			{Name: "dialog-return", Attempts: 1, Reason: "source file selection returned without Save completion"},
			{Name: "unknown-ack", Reason: "source input acknowledgement unknown"},
		} {
			t.Run(row.Name, func(t *testing.T) {
				candidate := profile
				candidate.Root = filepath.Join(root, fmt.Sprintf("dialog-%d", index))
				if err := os.Mkdir(candidate.Root, 0700); err != nil {
					t.Fatal(err)
				}
				candidate.ProgramArgs = append(slices.Clone(profile.ProgramArgs), "scenario-first-save", "save-dialog-"+row.Name)
				candidate.Scenario = &ProbeScenarioSpec{ID: "first-save-nondefault", Glyphmap: RegistryInput{Path: glyphPath, Size: int64(len(glyphRaw)), SHA256: fmt.Sprintf("%x", sha256.Sum256(glyphRaw))}, TimeoutMS: 60000, MaxUIReads: 4096}
				operations := []string{"initial", "scenario", "stop"}
				countFile := "file-selection-attempts.txt"
				if row.Load {
					candidate.ReadyTimeoutMS = 10000
					candidate.ProgramArgs = append(candidate.ProgramArgs, "scenario-paired")
					candidate.Inputs = maps.Clone(profile.Inputs)
					candidate.Inputs["card"] = RegistryInput{Path: cardPath, Size: int64(len(card)), SHA256: fmt.Sprintf("%x", sha256.Sum256(card))}
					operations = []string{"initial", "scenario", "warm-load", "load", "stop"}
					countFile = "file-load-attempts.txt"
				}
				candidate.Requests = nil
				for ordinal, operation := range operations {
					candidate.Requests = append(candidate.Requests, ProbeLifecycleRequest{Session: profile.Session, Operation: operation, Phase: "requested", Nonce: fmt.Sprintf("%d-%s", ordinal+1, operation)})
				}
				input, _ := json.Marshal(candidate)
				result, err := runProbeLifecycle(input)
				status := "COMPLETED"
				if row.Reason != "" {
					status = "INCOMPLETE"
				}
				if err != nil || result.Status != status || len(result.Steps) != len(operations) || result.Steps[1].Reason != row.Reason || result.Steps[len(result.Steps)-1].Status != "COMPLETED" {
					t.Fatalf("save dialog lifecycle: %+v %v", result, err)
				}
				attempts, readErr := os.ReadFile(filepath.Join(candidate.Root, countFile))
				if row.Attempts == 0 {
					if !os.IsNotExist(readErr) {
						t.Fatal("unknown acknowledgement was retried", string(attempts), readErr)
					}
					command, err := os.ReadFile(filepath.Join(candidate.Root, "unknown-ack-command.txt"))
					if err != nil || string(command) != "tap CIRCLE 0.1" {
						t.Fatal("uncertain selection did not reach the controlled peer once", string(command), err)
					}
				} else if readErr != nil || string(attempts) != strconv.Itoa(row.Attempts) {
					t.Fatal("selection retry count", string(attempts), readErr)
				}
				if row.Load {
					attempts, err := os.ReadFile(filepath.Join(candidate.Root, "file-selection-attempts.txt"))
					if err != nil || string(attempts) != "3" {
						t.Fatal("first transaction did not require its two acknowledged retries", string(attempts), err)
					}
				}
				if row.Source != "" {
					entries, err := os.ReadDir(filepath.Join(candidate.Root, "receipts"))
					if err != nil {
						t.Fatal(err)
					}
					observed := false
					for _, entry := range entries {
						if !strings.Contains(entry.Name(), "-card-save") || !strings.HasSuffix(entry.Name(), ".complete.json") {
							continue
						}
						data, _ := os.ReadFile(filepath.Join(candidate.Root, "receipts", entry.Name()))
						var effect ProbeLifecycleEffect
						var step ProbeLifecycleStep
						if json.Unmarshal(data, &effect) != nil || json.Unmarshal(effect.Details, &step) != nil || step.UI == nil {
							t.Fatal("missing actual acquired UI receipt")
						}
						choice := step.UI.YesNo
						if choice != nil && choice.Source == row.Source && choice.Selection != nil && *choice.Selection == row.Selection && step.UI.Headers["yesno"] == row.Header {
							observed = true
						}
					}
					if !observed {
						t.Fatal("same-read effective choice or unchanged raw header missing")
					}
				}
			})
		}
	})
	// Storage has no scenario/UI transaction. Keep it selectable without replaying
	// the long baseline or three-story cohort; child and input setup stay shared.
	t.Run("storage", func(t *testing.T) {
		literal, err := os.ReadFile("testdata/probe-storage.json")
		if err != nil {
			t.Fatal(err)
		}
		var oracle struct {
			Registry       json.RawMessage `json:"registry"`
			ID             string          `json:"id"`
			GlyphmapSHA    string          `json:"glyphmap_sha256"`
			Requests       []string        `json:"requests"`
			StreamRequests []string        `json:"stream_requests"`
			StreamTokens   []TextToken     `json:"stream_tokens"`
			GridRequests   []string        `json:"grid_requests"`
			GridTokens     []TextToken     `json:"grid_tokens"`
			Cases          []struct {
				ID           string      `json:"id"`
				Kind         string      `json:"kind"`
				Name         string      `json:"name"`
				Child        string      `json:"child_argument"`
				Actual       string      `json:"actual_hex"`
				Replies      []string    `json:"replies"`
				Decoded      string      `json:"decoded"`
				RowStatus    string      `json:"row_status"`
				ReportStatus string      `json:"report_status"`
				Reason       string      `json:"reason"`
				Refusal      string      `json:"refusal"`
				Tokens       []TextToken `json:"tokens"`
			} `json:"cases"`
		}
		if json.Unmarshal(literal, &oracle) != nil || len(oracle.Cases) != 13 {
			t.Fatal("pre-output storage oracle")
		}
		glyphs, err := os.ReadFile("testdata/probe-storage-glyphmap.json")
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(glyphs)) != oracle.GlyphmapSHA {
			t.Fatal("fixed source glyphmap", err)
		}
		recipe, err := os.ReadFile("recipes/fixed-fields.json")
		if err != nil {
			t.Fatal(err)
		}
		storage := ProbeStorageSpec{ID: oracle.ID}
		for role, data := range map[string][]byte{"glyphmap": glyphs, "registry": oracle.Registry, "recipe": recipe} {
			path := filepath.Join(sources, "storage-"+role+".json")
			if err := os.WriteFile(path, data, 0400); err != nil {
				t.Fatal(err)
			}
			input := RegistryInput{Path: path, Size: int64(len(data)), SHA256: fmt.Sprintf("%x", sha256.Sum256(data))}
			switch role {
			case "glyphmap":
				storage.Glyphmap = input
			case "registry":
				storage.Registry = input
			case "recipe":
				storage.Recipe = &input
			}
		}
		// This serial test projects only the immutable source ISO guard onto a
		// genuinely hashed tiny fixture, without a product override or private ISO dependency.
		originalFacts := bytes.Clone(probeObservationData)
		originalFactsSHA := sha256.Sum256(originalFacts)
		const currentISO = "83cb765a441a78db8678105bee21b3a435462b11999f061091420d1b9f710b22"
		if bytes.Count(originalFacts, []byte(currentISO)) != 5 {
			t.Fatal("real source ISO authority differs")
		}
		unsupported := profile
		unsupported.Root = t.TempDir()
		_ = os.Chmod(unsupported.Root, 0700)
		unsupported.Storage = &storage
		unsupportedRaw, _ := json.Marshal(unsupported)
		if _, err := runProbeLifecycle(unsupportedRaw); err == nil || err.Error() != "storage address is unqualified for this ISO input" {
			t.Fatal("real source guard must refuse unsupported ISO before acquisition", err)
		}
		if _, err := os.Lstat(filepath.Join(unsupported.Root, "profile")); !os.IsNotExist(err) {
			t.Fatal("unsupported source must not create an owned profile")
		}
		unsupportedStorage := storage
		unsupportedStorage.ID, unsupportedStorage.Recipe = "0x4755f0", nil
		unsupported.Storage = &unsupportedStorage
		unsupportedRaw, _ = json.Marshal(unsupported)
		if _, err := runProbeLifecycle(unsupportedRaw); err == nil || err.Error() != "storage address is unqualified for this ISO input" {
			t.Fatal("real narrative source guard must refuse unsupported ISO", err)
		}
		unsupportedStorage.ID = "0x47ea90"
		unsupportedRaw, _ = json.Marshal(unsupported)
		if _, err := runProbeLifecycle(unsupportedRaw); err == nil || err.Error() != "storage address is unqualified for this ISO input" {
			t.Fatal("real grid source guard must refuse unsupported ISO", err)
		}
		// Cleanup owns restoration even on Fatal; no other test uses this global concurrently.
		t.Cleanup(func() {
			probeObservationData = originalFacts
			if sha256.Sum256(probeObservationData) != originalFactsSHA || bytes.Count(probeObservationData, []byte(currentISO)) != 5 {
				t.Error("storage source authority was not restored")
			}
		})
		probeObservationData = bytes.ReplaceAll(originalFacts, []byte(currentISO), []byte(profile.Inputs["iso"].SHA256))
		for _, expected := range oracle.Cases {
			selectedStorage := storage
			requestHex := oracle.Requests
			if expected.Kind == "narrative" || expected.Kind == "positional" {
				selectedStorage.ID, selectedStorage.Recipe = expected.ID, nil
				requestHex = oracle.StreamRequests
				if expected.Kind == "positional" {
					requestHex = oracle.GridRequests
				}
			}
			selected := profile
			selected.Root = t.TempDir()
			_ = os.Chmod(selected.Root, 0700)
			selected.Storage = &selectedStorage
			selected.ProgramArgs = append(slices.Clone(profile.ProgramArgs), expected.Child)
			selected.Requests = []ProbeLifecycleRequest{{Session: profile.Session, Operation: "initial", Phase: "requested", Nonce: "1-initial"}, {Session: profile.Session, Operation: "observe-storage", Phase: "requested", Nonce: "2-observe-storage"}, {Session: profile.Session, Operation: "stop", Phase: "requested", Nonce: "3-stop"}}
			input, _ := json.Marshal(selected)
			outcome, err := runProbeLifecycle(input)
			wantedStatus, wantedStep := "COMPLETED", "COMPLETED"
			if expected.Refusal != "" {
				wantedStatus, wantedStep = "INCOMPLETE", "UNKNOWN"
			}
			if err != nil || outcome.Status != wantedStatus || len(outcome.Steps) != 3 || outcome.Steps[1].Status != wantedStep || outcome.Steps[2].Status != "COMPLETED" {
				t.Fatalf("%s storage transaction: %+v, %v", expected.Name, outcome, err)
			}
			step := outcome.Steps[1]
			if step.Memory == nil || !step.Memory.ProcessGuarded || step.Memory.Provenance != "owned_go" || len(step.Memory.Observations) != len(requestHex) {
				t.Fatalf("%s missing acquired storage facts: %+v", expected.Name, step)
			}
			for index, observed := range step.Memory.Observations {
				if observed.RequestHex != requestHex[index] || observed.ReplyHex != expected.Replies[index] {
					t.Fatalf("%s independent wire oracle: %+v", expected.Name, observed)
				}
			}
			if expected.Refusal != "" {
				retained, err := os.ReadFile(filepath.Join(selected.Root, "storage-2-observe-storage.memory.json"))
				if err != nil || len(retained) == 0 || step.Reason != expected.Refusal || step.Checkpoint != nil || step.Evidence != nil {
					t.Fatalf("%s unsupported stream must retain raw facts without a comparison: %+v, %v", expected.Name, step, err)
				}
				continue
			}
			if step.Checkpoint == nil || step.Evidence == nil || len(step.Memory.Decoded) != 1 || step.Memory.Decoded[0].Text == nil || *step.Memory.Decoded[0].Text != expected.Decoded {
				t.Fatalf("%s missing qualified storage comparison", expected.Name)
			}
			if expected.Kind == "narrative" {
				tokens := slices.Clone(oracle.StreamTokens)
				if expected.Child == "stream-mismatch" {
					tokens[3].Word = 0x39
				}
				if step.Memory.Decoded[0].Kind != "stream" || !reflect.DeepEqual(tokens, step.Memory.Decoded[0].Tokens) || !strings.Contains(step.Memory.Decoded[0].Reason, "A000 is opaque") {
					t.Fatalf("%s lost literal source control/token facts: %+v", expected.Name, step.Memory.Decoded)
				}
			}
			if expected.Kind == "positional" {
				if step.Memory.Decoded[0].Kind != "stream" || !reflect.DeepEqual(expected.Tokens, step.Memory.Decoded[0].Tokens) {
					t.Fatal("grid must preserve acquired cell/SPACE offsets and storedEND")
				}
				if expected.Child == "grid-shift" {
					var before, after []uint16
					for _, token := range oracle.GridTokens {
						if token.Kind == "glyph" {
							before = append(before, token.Word)
						}
					}
					for _, token := range expected.Tokens {
						if token.Kind == "glyph" {
							after = append(after, token.Word)
						}
					}
					if !slices.Equal(before, after) || reflect.DeepEqual(expected.Tokens, oracle.GridTokens) {
						t.Fatal("grid shift witness must retain flattened glyphs but change positions")
					}
				}
			}
			report := step.Checkpoint
			if report.Status != expected.ReportStatus || len(report.Rows) != 1 || report.Rows[0].Status != expected.RowStatus || report.Rows[0].Reason != expected.Reason || len(report.Checkpoints) != 0 || len(report.CoveredAreas) != 0 || report.LiveOwnership {
				t.Fatalf("%s report scope: %+v", expected.Name, report)
			}
			data, err := os.ReadFile(step.Evidence.Path)
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != step.Evidence.SHA256 || int64(len(data)) != step.Evidence.Size {
				t.Fatal("storage evidence identity", err)
			}
			var evidence ProbeEvidenceBundle
			_ = json.Unmarshal(data, &evidence)
			var actual struct {
				Actual   string          `json:"actual_hex"`
				Observed json.RawMessage `json:"actual"`
				Expected json.RawMessage `json:"expected"`
			}
			if len(evidence.Checks) != 1 || json.Unmarshal(evidence.Checks[0].Data, &actual) != nil || evidence.Checks[0].EventID != 1 || len(evidence.Events) != 1 {
				t.Fatal("storage check did not preserve actual acquired bytes")
			}
			switch expected.Kind {
			case "narrative":
				var text string
				if json.Unmarshal(actual.Observed, &text) != nil || text != expected.Decoded {
					t.Fatal("narrative actual must come from acquired decode")
				}
			case "positional":
				var observedTokens, expectedTokens []TextToken
				if json.Unmarshal(actual.Observed, &observedTokens) != nil || json.Unmarshal(actual.Expected, &expectedTokens) != nil || !reflect.DeepEqual(observedTokens, expected.Tokens) || !reflect.DeepEqual(expectedTokens, oracle.GridTokens) {
					t.Fatal("grid expected/actual token ownership differs")
				}
			default:
				if actual.Actual != expected.Actual {
					t.Fatal("fixed actual must come from acquired bytes")
				}
			}
			rederived, err := reportProbeEvidence(data)
			if err != nil || !reflect.DeepEqual(rederived, *report) {
				t.Fatal("saved storage report rederivation", err)
			}
		}
		capacityRaw, err := os.ReadFile("testdata/probe-capacity.json")
		if err != nil {
			t.Fatal(err)
		}
		var capacityOracle struct {
			Code []struct {
				Site string `json:"site"`
				Word uint32 `json:"word"`
			} `json:"code"`
			Synthetic struct {
				Size    int    `json:"source_size"`
				SHA     string `json:"source_sha256"`
				ZeroEnd string `json:"zero_end"`
				Offset  int    `json:"blob_offset"`
				Bytes   int    `json:"blob_bytes"`
				SHA256  string `json:"blob_sha256"`
				Used    int    `json:"blob_used"`
				Cursor  int    `json:"blob_cursor"`
			} `json:"synthetic"`
			Cases []struct {
				Name       string  `json:"name"`
				Child      string  `json:"child"`
				Row        string  `json:"row_status"`
				Report     string  `json:"report_status"`
				Configured *uint64 `json:"configured"`
				Reason     string  `json:"reason"`
			} `json:"cases"`
		}
		if json.Unmarshal(capacityRaw, &capacityOracle) != nil || len(capacityOracle.Code) != 13 || len(capacityOracle.Cases) != 3 {
			t.Fatal("capacity pre-output oracle")
		}
		iso := make([]byte, capacityOracle.Synthetic.Size)
		for _, record := range []struct {
			Offset    int
			LBA, Size uint32
		}{{0x82a62, 319, 5087232}, {0x8289c, 2803, 550912}} {
			iso[record.Offset] = 34
			binary.LittleEndian.PutUint32(iso[record.Offset+2:], record.LBA)
			binary.BigEndian.PutUint32(iso[record.Offset+6:], record.LBA)
			binary.LittleEndian.PutUint32(iso[record.Offset+10:], record.Size)
			binary.BigEndian.PutUint32(iso[record.Offset+14:], record.Size)
		}
		for _, word := range capacityOracle.Code {
			address, err := number(word.Site)
			if err != nil {
				t.Fatal(err)
			}
			binary.LittleEndian.PutUint32(iso[int(address)-0xfff80+0x9f800:], word.Word)
		}
		iso[capacityOracle.Synthetic.Offset+capacityOracle.Synthetic.Used-1] = 1
		if fmt.Sprintf("%x", sha256.Sum256(iso)) != capacityOracle.Synthetic.SHA {
			t.Fatal("regular synthetic ISO differs from independent byte oracle")
		}
		isoPath := filepath.Join(sources, "capacity.iso")
		if err := os.WriteFile(isoPath, iso, 0400); err != nil {
			t.Fatal(err)
		}
		registryRaw := []byte(`{"entries":[{"id":"0x47e980","en":"Switch to carrying|this instead?","landing_vma":"0x04000030","ref_type":"code_immediate"}]}`)
		registryPath := filepath.Join(sources, "capacity-registry.json")
		if err := os.WriteFile(registryPath, registryRaw, 0400); err != nil {
			t.Fatal(err)
		}
		var projected ProbeObservationTable
		if json.Unmarshal(probeObservationData, &projected) != nil {
			t.Fatal("capacity test projection")
		}
		definition := projected.Rows["0x47e980"]
		if definition.Capacity == nil || definition.Capacity.Stream.ZeroEnd != "0x204d9800" || definition.Capacity.ArtifactSHA256 != "d7f4eed144178eadc22988fec354f4793c2fd0541131c91360c131cd6cc70364" {
			t.Fatal("real capacity authority differs")
		}
		definition.SourceISOSHA256 = capacityOracle.Synthetic.SHA
		definition.Capacity.Stream.ZeroEnd = capacityOracle.Synthetic.ZeroEnd
		definition.Capacity.ArtifactSHA256 = capacityOracle.Synthetic.SHA256
		projected.Rows["0x47e980"] = definition
		probeObservationData, _ = json.Marshal(projected)
		for _, expected := range capacityOracle.Cases {
			selected := profile
			selected.Root = t.TempDir()
			_ = os.Chmod(selected.Root, 0700)
			selected.Inputs = map[string]RegistryInput{}
			for role, input := range profile.Inputs {
				selected.Inputs[role] = input
			}
			selected.Inputs["iso"] = RegistryInput{Path: isoPath, Size: int64(len(iso)), SHA256: capacityOracle.Synthetic.SHA}
			selected.Storage = &ProbeStorageSpec{ID: "0x47e980", Registry: RegistryInput{Path: registryPath, Size: int64(len(registryRaw)), SHA256: fmt.Sprintf("%x", sha256.Sum256(registryRaw))}}
			selected.ProgramArgs = append(slices.Clone(profile.ProgramArgs), expected.Child)
			selected.Requests = []ProbeLifecycleRequest{{Session: profile.Session, Operation: "initial", Phase: "requested", Nonce: "1-initial"}, {Session: profile.Session, Operation: "observe-storage", Phase: "requested", Nonce: "2-observe-storage"}, {Session: profile.Session, Operation: "stop", Phase: "requested", Nonce: "3-stop"}}
			input, _ := json.Marshal(selected)
			outcome, err := runProbeLifecycle(input)
			if err != nil || outcome.Status != "COMPLETED" || len(outcome.Steps) != 3 || outcome.Steps[1].Checkpoint == nil {
				t.Fatalf("%s capacity acquisition: %+v %v", expected.Name, outcome, err)
			}
			step := outcome.Steps[1]
			if step.Memory == nil || len(step.Memory.Observations) != 13 || len(step.Memory.Decoded) != 13 {
				t.Fatal("missing actual scalar code observations")
			}
			for index, actual := range step.Memory.Observations {
				word := capacityOracle.Code[index]
				want := word.Word
				if expected.Child == "capacity-window" && word.Site == "0x4db4a0" {
					want = 0x3c090001
				}
				if expected.Child == "capacity-loader" && word.Site == "0x399b94" {
					want = 0x240e0141
				}
				request, _ := hex.DecodeString(actual.RequestHex)
				address, _ := number(word.Site)
				if len(request) != 9 || request[4] != 2 || uint64(binary.LittleEndian.Uint32(request[5:])) != address || actual.Value != uint64(want) {
					t.Fatal("capacity scalar site/value differs", index, actual)
				}
			}
			report := step.Checkpoint
			if report.Status != expected.Report || len(report.Rows) != 1 || report.Rows[0].Status != expected.Row || report.Rows[0].Reason != expected.Reason || !reflect.DeepEqual(report.Rows[0].ConfiguredBytes, expected.Configured) || report.Rows[0].RuntimeAllocation != "UNKNOWN" || report.Rows[0].RuntimeUsed != "UNKNOWN" || len(report.Checkpoints) != 0 || len(report.CoveredAreas) != 0 {
				t.Fatalf("%s capacity report: %+v", expected.Name, report)
			}
			if expected.Configured != nil {
				artifact := report.Rows[0].Artifact
				if artifact == nil || artifact.Bytes != int64(capacityOracle.Synthetic.Bytes) || artifact.SHA256 != capacityOracle.Synthetic.SHA256 || artifact.Used != int64(capacityOracle.Synthetic.Used) || artifact.Cursor != int64(capacityOracle.Synthetic.Cursor) {
					t.Fatal("artifact measurement differs from independent regular file")
				}
			}
			if expected.Child == "capacity-match" {
				raw, err := os.ReadFile(step.Evidence.Path)
				if err != nil {
					t.Fatal(err)
				}
				var bundle ProbeEvidenceBundle
				_ = json.Unmarshal(raw, &bundle)
				var observation ProbeCapacityObservation
				_ = json.Unmarshal(bundle.Checks[0].Data, &observation)
				observation.Artifact.SHA256 = strings.Repeat("0", 64)
				bundle.Checks[0].Data, _ = json.Marshal(observation)
				forged, _ := json.Marshal(bundle)
				refused, err := reportProbeEvidence(forged)
				if err != nil || refused.Rows[0].Status != "FAIL" {
					t.Fatal("artifact identity forgery passed", err)
				}
				one := uint64(1)
				observation.RuntimeUsed = &one
				bundle.Checks[0].Data, _ = json.Marshal(observation)
				forged, _ = json.Marshal(bundle)
				if _, err := reportProbeEvidence(forged); err == nil {
					t.Fatal("artifact became claimed runtime usage")
				}
			}
		}
		// The image uses a real curated native member and an independently approved
		// PNG. Only ISO directory placement/source pins are a serial test projection.
		imageLiteral, err := os.ReadFile("testdata/probe-image.json")
		var imageOracle struct {
			ID, Contract            string
			PNG, RGBA, CLUT, Native string
			Cases                   []struct {
				Name                                string
				Acquire                             bool
				Row, Report, Reason, Refusal, Error string
			}
		}
		var imageFields map[string]json.RawMessage
		if err != nil || json.Unmarshal(imageLiteral, &imageFields) != nil || json.Unmarshal(imageLiteral, &imageOracle) != nil || len(imageOracle.Cases) != 12 {
			t.Fatal("pre-output image oracle", err)
		}
		_ = json.Unmarshal(imageFields["png_sha256"], &imageOracle.PNG)
		_ = json.Unmarshal(imageFields["rgba_sha256"], &imageOracle.RGBA)
		_ = json.Unmarshal(imageFields["clut_sha256"], &imageOracle.CLUT)
		_ = json.Unmarshal(imageFields["native_sha256"], &imageOracle.Native)
		archive, err := zip.OpenReader("assets/cmb-members.zip")
		if err != nil {
			t.Fatal(err)
		}
		var native []byte
		for _, entry := range archive.File {
			if entry.Name == "GRAPHIC/EVENT.CMB/event/guide/mini_g02.txd" {
				reader, err := entry.Open()
				if err != nil {
					t.Fatal(err)
				}
				native, err = io.ReadAll(io.LimitReader(reader, 263573))
				_ = reader.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		_ = archive.Close()
		if len(native) != 263572 || fmt.Sprintf("%x", sha256.Sum256(native)) != imageOracle.Native {
			t.Fatal("curated native member differs from independent reference")
		}
		imageStorage := ProbeStorageSpec{ID: imageOracle.ID}
		for _, role := range []string{"png", "clut"} {
			name, digest := "testdata/probe-image.png", imageOracle.PNG
			if role == "clut" {
				name, digest = "testdata/probe-image-clut.bin", imageOracle.CLUT
			}
			data, err := os.ReadFile(name)
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != digest {
				t.Fatal("approved image fixture", role, err)
			}
			path := filepath.Join(sources, "approved-image-"+role)
			if err := os.WriteFile(path, data, 0400); err != nil {
				t.Fatal(err)
			}
			input := &RegistryInput{Path: path, Size: int64(len(data)), SHA256: digest}
			if role == "png" {
				imageStorage.PNG = input
			} else {
				imageStorage.CLUT = input
			}
		}
		probeObservationData = bytes.Clone(originalFacts)
		imageUnsupported := profile
		imageUnsupported.Storage = &imageStorage
		imageUnsupported.Root = t.TempDir()
		_ = os.Chmod(imageUnsupported.Root, 0700)
		unsupportedImageRaw, _ := json.Marshal(imageUnsupported)
		if _, err := runProbeLifecycle(unsupportedImageRaw); err == nil || err.Error() != "storage address is unqualified for this ISO input" {
			t.Fatal("real image source guard failed", err)
		}
		// Literal ISO9660/CMB envelope: root17, GRAPHIC18, archive19; member
		// starts at39009, deliberately unaligned. No second parser supplies Actual.
		imageISO := make([]byte, 302581)
		copy(imageISO[16*isoSector:], []byte{1, 'C', 'D', '0', '0', '1', 1})
		binary.LittleEndian.PutUint16(imageISO[16*isoSector+128:], 2048)
		binary.BigEndian.PutUint16(imageISO[16*isoSector+130:], 2048)
		for _, record := range []struct {
			At, LBA, Size int
			Name          string
			Flags         byte
		}{
			{16*isoSector + 156, 17, isoSector, "\x00", 2}, {17 * isoSector, 18, isoSector, "GRAPHIC", 2}, {18 * isoSector, 19, 263669, "EVENT.CMB;1", 0},
		} {
			n := 33 + len(record.Name)
			if n%2 != 0 {
				n++
			}
			rec := imageISO[record.At : record.At+n]
			rec[0], rec[25], rec[32] = byte(n), record.Flags, byte(len(record.Name))
			binary.LittleEndian.PutUint32(rec[2:], uint32(record.LBA))
			binary.BigEndian.PutUint32(rec[6:], uint32(record.LBA))
			binary.LittleEndian.PutUint32(rec[10:], uint32(record.Size))
			binary.BigEndian.PutUint32(rec[14:], uint32(record.Size))
			binary.LittleEndian.PutUint16(rec[28:], 1)
			binary.BigEndian.PutUint16(rec[30:], 1)
			copy(rec[33:], record.Name)
		}
		binary.LittleEndian.PutUint32(imageISO[19*isoSector:], 96)
		binary.LittleEndian.PutUint32(imageISO[19*isoSector+4:], 1)
		copy(imageISO[19*isoSector+8:], "event\\guide\\mini_g02.txd")
		binary.LittleEndian.PutUint32(imageISO[19*isoSector+88:], 1)
		binary.LittleEndian.PutUint32(imageISO[19*isoSector+92:], 263572)
		copy(imageISO[39009:], native)
		var imageBase ProbeEvidenceBundle
		for _, expected := range imageOracle.Cases {
			if expected.Acquire {
				carrier := bytes.Clone(imageISO)
				if expected.Name == "clut-mismatch" {
					carrier[39009+262508] ^= 1
				}
				if expected.Name == "index-refusal" {
					carrier[19*isoSector+8] = 'x'
				}
				path := filepath.Join(sources, "image-"+expected.Name+".iso")
				if err := os.WriteFile(path, carrier, 0400); err != nil {
					t.Fatal(err)
				}
				input := RegistryInput{Path: path, Size: int64(len(carrier)), SHA256: fmt.Sprintf("%x", sha256.Sum256(carrier))}
				var table ProbeObservationTable
				_ = json.Unmarshal(originalFacts, &table)
				asset := table.Rows[imageOracle.ID]
				if asset.SourceISOSHA256 != currentISO || asset.Image.IndexSHA256 != "8772c37a59452a579789b9663f075c8f54917699de5235412edf7ebb92be2eee" || asset.ComparisonSourceSHA256 != imageOracle.Contract || asset.Image.Offset != 3223871619 {
					t.Fatal("real image authority differs")
				}
				asset.SourceISOSHA256 = input.SHA256
				asset.Image.Offset = 39009
				asset.Image.IndexSHA256 = fmt.Sprintf("%x", sha256.Sum256(imageISO[19*isoSector:19*isoSector+96]))
				table.Rows[imageOracle.ID] = asset
				probeObservationData, _ = json.Marshal(table)
				selected := profile
				selected.Root = t.TempDir()
				_ = os.Chmod(selected.Root, 0700)
				selected.Storage = &imageStorage
				selected.Inputs = map[string]RegistryInput{}
				for role, input := range profile.Inputs {
					selected.Inputs[role] = input
				}
				selected.Inputs["iso"] = input
				selected.Requests = []ProbeLifecycleRequest{{Session: profile.Session, Operation: "initial", Phase: "requested", Nonce: "1-initial"}, {Session: profile.Session, Operation: "observe-storage", Phase: "requested", Nonce: "2-observe-storage"}, {Session: profile.Session, Operation: "stop", Phase: "requested", Nonce: "3-stop"}}
				inputRaw, _ := json.Marshal(selected)
				outcome, err := runProbeLifecycle(inputRaw)
				if err != nil || len(outcome.Steps) != 3 || outcome.Steps[2].Status != "COMPLETED" {
					t.Fatalf("%s image lifecycle: %+v %v", expected.Name, outcome, err)
				}
				step := outcome.Steps[1]
				if expected.Refusal != "" {
					if outcome.Status != "INCOMPLETE" || !strings.Contains(step.Reason, expected.Refusal) || step.Checkpoint != nil {
						t.Fatalf("%s image refusal: %+v", expected.Name, step)
					}
					continue
				}
				if outcome.Status != "COMPLETED" || step.Memory != nil || step.Checkpoint == nil || len(step.Checkpoint.Rows) != 1 || step.Checkpoint.Rows[0].Status != expected.Row || step.Checkpoint.Rows[0].Reason != expected.Reason || step.Checkpoint.Status != expected.Report || len(step.Checkpoint.Checkpoints) != 0 || len(step.Checkpoint.CoveredAreas) != 0 {
					t.Fatalf("%s image report: %+v", expected.Name, step)
				}
				retained, err := os.ReadFile(step.Evidence.Path)
				if err != nil || len(retained) >= 4<<20 || fmt.Sprintf("%x", sha256.Sum256(retained)) != step.Evidence.SHA256 {
					t.Fatal("complete image evidence retention/budget", err)
				}
				var bundle ProbeEvidenceBundle
				_ = json.Unmarshal(retained, &bundle)
				var facts struct {
					Actual, Expected         []byte
					ActualCLUT, ExpectedCLUT []byte
				}
				var data map[string]json.RawMessage
				_ = json.Unmarshal(bundle.Checks[0].Data, &data)
				_ = json.Unmarshal(data["actual_rgba"], &facts.Actual)
				_ = json.Unmarshal(data["expected_rgba"], &facts.Expected)
				_ = json.Unmarshal(data["actual_clut"], &facts.ActualCLUT)
				_ = json.Unmarshal(data["expected_clut"], &facts.ExpectedCLUT)
				if len(facts.Actual) != 1048576 || len(facts.Expected) != 1048576 || fmt.Sprintf("%x", sha256.Sum256(facts.Expected)) != imageOracle.RGBA || !bytes.Equal(facts.ActualCLUT, carrier[39009+262508:39009+262508+1024]) {
					t.Fatal("image Actual not complete acquired member/approved independent Expected")
				}
				if expected.Name == "match" {
					if !bytes.Equal(facts.Actual, facts.Expected) || !bytes.Equal(facts.ActualCLUT, facts.ExpectedCLUT) {
						t.Fatal("full image equality")
					}
					imageBase = bundle
				}
				readback, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(readback, carrier) {
					t.Fatal("image source changed", err)
				}
			} else {
				// Restore the matching source context before saved-only boundary checks.
				var table ProbeObservationTable
				_ = json.Unmarshal(probeObservationData, &table)
				asset := table.Rows[imageOracle.ID]
				asset.SourceISOSHA256 = imageBase.ISOSHA256
				table.Rows[imageOracle.ID] = asset
				probeObservationData, _ = json.Marshal(table)
				bundle := imageBase
				bundle.Checks = slices.Clone(imageBase.Checks)
				var data map[string]json.RawMessage
				_ = json.Unmarshal(bundle.Checks[0].Data, &data)
				switch expected.Name {
				case "pixel-mismatch", "known-fail-missing-clut":
					var actual []byte
					_ = json.Unmarshal(data["actual_rgba"], &actual)
					actual[3] ^= 1
					data["actual_rgba"], _ = json.Marshal(actual)
					if expected.Name == "known-fail-missing-clut" {
						delete(data, "actual_clut")
					}
				case "geometry-mismatch":
					data["actual_width"] = json.RawMessage(`511`)
				case "missing-actual":
					delete(data, "actual_rgba")
				case "short-actual":
					data["actual_rgba"] = json.RawMessage(`"AA=="`)
				case "mixed-empty-hex":
					data["actual_rgba_hex"] = json.RawMessage(`""`)
				case "mixed-uppercase-hex":
					data["ACTUAL_RGBA_HEX"] = json.RawMessage(`""`)
				case "malformed-base64":
					data["actual_rgba"] = json.RawMessage(`"!"`)
				}
				bundle.Checks[0].Data, _ = json.Marshal(data)
				input, _ := json.Marshal(bundle)
				if expected.Name == "bundle-budget" {
					input = append(input, bytes.Repeat([]byte(" "), 4<<20)...)
				}
				got, err := reportProbeEvidence(input)
				if expected.Error != "" {
					if err == nil || err.Error() != expected.Error {
						t.Fatalf("%s expected refusal %q got %v", expected.Name, expected.Error, err)
					}
				} else if err != nil || got.Status != expected.Report || len(got.Rows) != 1 || got.Rows[0].Status != expected.Row || got.Rows[0].Reason != expected.Reason {
					t.Fatalf("%s image comparison: %+v %v", expected.Name, got, err)
				}
			}
		}
	})
	t.Run("baseline", func(t *testing.T) {
		// Exercise split ownership with only our known fixture PID, never host enumeration.
		for _, controllerLoss := range []bool{false, true} {
			fixtureProject := t.TempDir()
			fixtureRoot := filepath.Join(fixtureProject, "generated", "s")
			xdg := filepath.Join(fixtureRoot, "xdg")
			dataRoot := filepath.Join(fixtureRoot, "profile", "PCSX2")
			cardPath := filepath.Join(dataRoot, "memcards", "probe-slot1.ps2")
			isoPath := filepath.Join(fixtureProject, "generated", "work", "fixture.iso")
			for _, directory := range []string{xdg, filepath.Join(fixtureRoot, "receipts"), filepath.Dir(cardPath), filepath.Join(dataRoot, "bios"), filepath.Join(dataRoot, "snaps"), filepath.Dir(isoPath)} {
				if err := os.MkdirAll(directory, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(cardPath, []byte(fixture.SourceCard), 0600); err != nil {
				t.Fatal(err)
			}
			iso, err := os.ReadFile(profile.Inputs["iso"].Path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(isoPath, iso, 0400); err != nil {
				t.Fatal(err)
			}
			controllerRead, controllerWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer controllerRead.Close()
			defer controllerWrite.Close()
			launcher := exec.Command(executable, profile.ProgramArgs...)
			launcher.Args[0] = "controlled-launcher"
			launcher.Args = append(launcher.Args, "-batch", "-datapath", filepath.Join(fixtureRoot, "profile"), "-logfile", filepath.Join(fixtureRoot, "profile", "emulog.txt"), isoPath)
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "DOKAPON_PROBE_SESSION_ROOT=") && !strings.HasPrefix(entry, "DOKAPON_PROBE_FIXTURE_ROLE=") && !strings.HasPrefix(entry, "XDG_RUNTIME_DIR=") {
					launcher.Env = append(launcher.Env, entry)
				}
			}
			launcher.Env = append(launcher.Env, "DOKAPON_PROBE_SESSION_ROOT="+fixtureRoot, "DOKAPON_PROBE_FIXTURE_ROLE=launcher", "XDG_RUNTIME_DIR="+xdg)
			launcher.ExtraFiles = []*os.File{controllerRead}
			launcher.Stdout, launcher.Stderr = os.Stdout, os.Stderr
			if err := launcher.Start(); err != nil {
				t.Fatal(err)
			}
			defer launcher.Wait()
			defer launcher.Process.Kill()
			_ = controllerRead.Close()
			var witness struct {
				LauncherPID int      `json:"launcher_pid"`
				NativePID   int      `json:"native_pid"`
				NativeArgs  []string `json:"native_args"`
			}
			var launcherIdentity ProbeProcessRecord
			var candidates, uncertain []ProbeProcessRecord
			var selectionErr error
			ready := false
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				launcherIdentity, err = observeProbeProcess(ProbeMemoryRuntime{Provenance: "owned_launcher"}, launcher.Process.Pid, nil, profile.Program.SHA256)
				data, readErr := os.ReadFile(filepath.Join(fixtureRoot, "launcher-native.json"))
				if err == nil && slices.Equal(launcherIdentity.Cmdline, launcher.Args) && readErr == nil && json.Unmarshal(data, &witness) == nil && witness.NativePID > 0 {
					candidates, uncertain, selectionErr = selectProbeProcesses(ProbeMemoryRuntime{Provenance: "owned_flatpak", Root: fixtureRoot}, []int{witness.NativePID}, profile.Program.SHA256, witness.NativeArgs, launcherIdentity.Starttime)
					if selectionErr == nil && len(candidates) == 1 && len(uncertain) == 0 && candidates[0].PINESocket == filepath.Join(xdg, "pcsx2.sock") {
						childData, readErr := os.ReadFile(filepath.Join(fixtureRoot, fmt.Sprintf("child-evidence-%d.json", witness.NativePID)))
						socket, socketErr := os.Lstat(candidates[0].PINESocket)
						if readErr == nil && json.Valid(childData) && socketErr == nil && socket.Mode()&os.ModeSocket != 0 {
							ready = true
							break
						}
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !ready || err != nil || selectionErr != nil || len(candidates) != 1 || len(uncertain) != 0 || witness.LauncherPID != launcher.Process.Pid || witness.NativePID == witness.LauncherPID || !slices.Equal(launcherIdentity.Cmdline, launcher.Args) {
				t.Fatalf("controlled split ownership ready=%t launcher=%+v expected=%q witness=%+v candidates=%+v uncertain=%+v %v %v", ready, launcherIdentity, launcher.Args, witness, candidates, uncertain, err, selectionErr)
			}
			native := candidates[0]
			expectedArgs := append([]string{"pcsx2-fixture"}, profile.ProgramArgs...)
			expectedArgs = append(expectedArgs, "-batch", "-datapath", filepath.Join(fixtureRoot, "profile"), "-logfile", filepath.Join(fixtureRoot, "profile", "emulog.txt"), isoPath)
			if native.PINESocket != filepath.Join(xdg, "pcsx2.sock") || len(native.EnvironmentSHA256) != 64 || !slices.Equal(native.Cmdline, expectedArgs) {
				t.Fatal("native endpoint/argv did not come from the private process", native)
			}
			for _, mismatch := range []string{"argv", "starttime"} {
				args, notBefore := expectedArgs, launcherIdentity.Starttime
				if mismatch == "argv" {
					args = launcher.Args
				} else {
					notBefore = native.Starttime + 1
				}
				matched, refused, err := selectProbeProcesses(ProbeMemoryRuntime{Provenance: "owned_flatpak", Root: fixtureRoot}, []int{native.PID}, profile.Program.SHA256, args, notBefore)
				if err == nil || len(matched) != 0 || len(refused) != 1 || refused[0].PID != native.PID {
					t.Fatal("native identity mismatch accepted", mismatch, matched, refused, err)
				}
			}
			synthetic := ProbeLifecycleProcesses{Launched: true, Native: &native}
			if _, err := terminateProbeProcesses(&synthetic, ProbeMemoryRuntime{Provenance: "synthetic_flatpak", Root: fixtureRoot}, profile.Program.SHA256, time.Second, nil); err == nil || synthetic.CleanupAttempts != 0 {
				t.Fatal("synthetic facts reached signaling", err)
			}
			childData, err := os.ReadFile(filepath.Join(fixtureRoot, fmt.Sprintf("child-evidence-%d.json", native.PID)))
			var nativeWitness struct {
				PID         int
				Argv        []string
				LauncherPID int `json:"launcher_pid"`
			}
			if err != nil || json.Unmarshal(childData, &nativeWitness) != nil || nativeWitness.PID != native.PID || nativeWitness.LauncherPID != launcherIdentity.PID || !slices.Equal(nativeWitness.Argv, expectedArgs) {
				t.Fatal("independent native child witness differs", string(childData), err)
			}
			if err := os.WriteFile(filepath.Join(fixtureRoot, "release-launcher"), []byte("release"), 0600); err != nil {
				t.Fatal(err)
			}
			deadline = time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				_, err = observeProbeProcess(ProbeMemoryRuntime{Provenance: "owned_launcher"}, launcherIdentity.PID, &launcherIdentity, profile.Program.SHA256)
				if errors.Is(err, os.ErrProcessDone) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !errors.Is(err, os.ErrProcessDone) {
				t.Fatal("launcher did not exit independently", err)
			}
			if _, err := observeProbeProcess(ProbeMemoryRuntime{Provenance: "owned_flatpak"}, native.PID, &native, profile.Program.SHA256); err != nil {
				t.Fatal("native did not survive launcher exit", err)
			}
			fixtureProfile := profile
			fixtureProfile.Root = fixtureRoot
			fixtureProfile.Flatpak = &ProbeFlatpakLaunch{Launcher: profile.Program, LauncherArgs: profile.ProgramArgs, ProjectRoot: fixtureProject, RuntimeArgv0: expectedArgs[0]}
			fixtureProfile.Inputs = map[string]RegistryInput{}
			for role, input := range profile.Inputs {
				fixtureProfile.Inputs[role] = input
			}
			fixtureProfile.Inputs["iso"] = RegistryInput{Path: isoPath, Size: int64(len(iso)), SHA256: fmt.Sprintf("%x", sha256.Sum256(iso))}
			epoch := 0
			native.Session, native.Profile, native.ISO, native.ISOSHA256, native.Epoch = fixtureProfile.Session, filepath.Join(fixtureRoot, "profile"), isoPath, fixtureProfile.Inputs["iso"].SHA256, &epoch
			view := ProbeProfileRecord{Datapath: native.Profile, DataRoot: dataRoot, SourceSettings: profile.Inputs["settings"].Path, SourceSettingsSHA256: profile.Inputs["settings"].SHA256, SourceCard: profile.Inputs["card"].Path, SourceCardSHA256: profile.Inputs["card"].SHA256, Card: cardPath, CardInitialSHA256: profile.Inputs["card"].SHA256, BIOS: filepath.Join(dataRoot, "bios", filepath.Base(profile.Inputs["bios"].Path))}
			// Literal startup scaffolding admits this reader test, not a Flatpak boot.
			directories := map[string]string{"DataRoot": dataRoot, "BIOS": filepath.Join(dataRoot, "bios"), "Snapshots": filepath.Join(dataRoot, "snaps"), "MemoryCards": filepath.Join(dataRoot, "memcards")}
			var startupLog strings.Builder
			for _, label := range []string{"DataRoot", "BIOS", "Snapshots", "MemoryCards"} {
				fmt.Fprintf(&startupLog, "%s Directory: %s\n", label, directories[label])
			}
			log := RegistryInput{Path: filepath.Join(fixtureRoot, "startup-epoch-0.log"), Size: int64(startupLog.Len()), SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(startupLog.String())))}
			if err := os.WriteFile(log.Path, []byte(startupLog.String()), 0400); err != nil {
				t.Fatal(err)
			}
			startup, _ := json.Marshal(map[string]any{"epoch": epoch, "native": native, "launcher": launcherIdentity, "directories": directories, "log": log})
			startupInput := RegistryInput{Path: filepath.Join(fixtureRoot, "startup-epoch-0.json"), Size: int64(len(startup)), SHA256: fmt.Sprintf("%x", sha256.Sum256(startup))}
			if err := os.WriteFile(startupInput.Path, startup, 0400); err != nil {
				t.Fatal(err)
			}
			facts := fixtureProfile
			facts.Requests = nil
			factsRaw, _ := json.Marshal(facts)
			step := ProbeLifecycleStep{ProfileSHA256: fmt.Sprintf("%x", sha256.Sum256(factsRaw)), Request: fixtureProfile.Requests[0], Status: "COMPLETED", Epoch: epoch, Owned: &native, Launcher: &launcherIdentity, Startup: &startupInput, Effects: fixture.ExpectedEffects[0]}
			viewRaw, _ := json.Marshal(view)
			ownedRaw, _ := json.Marshal(native)
			observed, err := observeProbeProcess(ProbeMemoryRuntime{Provenance: "owned_flatpak"}, native.PID, &native, profile.Program.SHA256)
			if err != nil {
				t.Fatal(err)
			}
			admission, _ := json.Marshal(ProbeRecordBundle{Version: 1, SourceSchema: "go-probe-records-v1", SourceSHA256: "5439db31097c19d3b92969d5403c2c19dc3518cea4ed4c075df1a3830b8ef56f", ProjectRoot: fixtureRoot, WorkingDirectory: fixtureRoot, RunRoot: fixtureRoot, Context: "owned_go", Records: []ProbeRecord{{Role: "profile", Data: viewRaw}, {Role: "owned", Data: ownedRaw}}, AfterProcess: &observed, GoOwner: &ProbeGoOwner{Profile: fixtureProfile, Step: step, CardSHA256: profile.Inputs["card"].SHA256}})
			evidence := RegistryInput{Path: filepath.Join(fixtureRoot, "records.json"), Size: int64(len(admission)), SHA256: fmt.Sprintf("%x", sha256.Sum256(admission))}
			if err := os.WriteFile(evidence.Path, admission, 0600); err != nil {
				t.Fatal(err)
			}
			opcode, address := uint8(2), uint32(0x56a800)
			memoryPlan, _ := json.Marshal(ProbeMemoryBundle{Version: 1, SourceSHA256: "5439db31097c19d3b92969d5403c2c19dc3518cea4ed4c075df1a3830b8ef56f", Admission: admission, BuildSHA256: profile.Program.SHA256, Requests: []ProbeMemoryRequest{{ID: "story", Opcode: &opcode, Address: &address}}, Decoders: []ProbeMemoryDecoder{{ID: "story", Kind: "scalar", Requests: []string{"story"}}}})
			memoryRuntime, _ := json.Marshal(ProbeMemoryRuntime{Provenance: "owned_go", Root: fixtureRoot, TimeoutMS: 1000, Evidence: &evidence})
			read, err := readProbeMemory(memoryPlan, memoryRuntime)
			if err != nil || !read.ProcessGuarded || read.Provenance != "owned_go" || len(read.Observations) != 1 || read.Observations[0].Value != 1 {
				t.Fatal("owned namespace reader failed after launcher exit", read, err)
			}
			heldSocket := native.PINESocket + ".held"
			if err := os.Rename(native.PINESocket, heldSocket); err != nil {
				t.Fatal(err)
			}
			wrongPeer, err := net.ListenUnix("unix", &net.UnixAddr{Name: native.PINESocket, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			_, peerErr := readProbeMemory(memoryPlan, memoryRuntime)
			_ = wrongPeer.Close()
			restoreErr := os.Rename(heldSocket, native.PINESocket)
			if peerErr == nil || peerErr.Error() != "probe socket peer is not the exact owned process" || restoreErr != nil {
				t.Fatal("owned namespace peer mismatch accepted", peerErr, restoreErr)
			}
			state := ProbeLifecycleProcesses{Command: launcher, Launcher: &launcherIdentity, Native: &native, Candidates: candidates, Launched: true}
			if state.NativeExited || state.LauncherReaped {
				t.Fatal("launcher exit prematurely granted cleanup completion")
			}
			if controllerLoss {
				_ = controllerWrite.Close()
				deadline = time.Now().Add(3 * time.Second)
				for time.Now().Before(deadline) {
					_, err = observeProbeProcess(ProbeMemoryRuntime{Provenance: "owned_flatpak"}, native.PID, &native, profile.Program.SHA256)
					if errors.Is(err, os.ErrProcessDone) {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if !errors.Is(err, os.ErrProcessDone) {
					t.Fatal("native ignored original controller loss", err)
				}
				// Recovery may retain only the unreaped launcher after native exit is proved.
				state.Native, state.Candidates, state.NativeExited = nil, nil, true
				if state.Command == nil || state.LauncherReaped {
					t.Fatal("partial cleanup lost the remaining launcher")
				}
			}
			exitedBefore, err := terminateProbeProcesses(&state, ProbeMemoryRuntime{Provenance: "owned_flatpak", Root: fixtureRoot}, profile.Program.SHA256, 5*time.Second, nil)
			if err != nil || exitedBefore || !state.NativeExited || !state.LauncherReaped || state.Command != nil || state.Native != nil || len(state.Candidates) != 0 {
				t.Fatalf("split cleanup incomplete: %+v before=%t %v", state, exitedBefore, err)
			}
			expectedCard := []byte(fixture.SourceCard)
			if !controllerLoss {
				expectedCard[0]++
			}
			card, err := os.ReadFile(cardPath)
			if err != nil || !bytes.Equal(card, expectedCard) {
				t.Fatal("card readback before confirmed native exit/launcher disposal differs", string(card), err)
			}
			if _, err := terminateProbeProcesses(&state, ProbeMemoryRuntime{Provenance: "owned_flatpak", Root: fixtureRoot}, profile.Program.SHA256, time.Second, nil); err != nil || state.CleanupAttempts != 1 {
				t.Fatal("confirmed cleanup was not idempotent", err)
			}
			_ = controllerWrite.Close()
			t.Logf("split fixture controller_loss=%t launcher=%d native=%d native_exited=%t launcher_reaped=%t card_sha256=%x", controllerLoss, launcherIdentity.PID, native.PID, state.NativeExited, state.LauncherReaped, sha256.Sum256(card))
		}
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
		for _, row := range []struct {
			Extent      int64
			SocketFault string
		}{{}, {Extent: 48}, {Extent: 96}, {SocketFault: "removed"}, {SocketFault: "replaced"}} {
			extent := row.Extent
			padRoot := t.TempDir()
			_ = os.Chmod(padRoot, 0700)
			ctx, cancel := context.WithCancel(context.Background())
			ready, done := make(chan error, 1), make(chan error, 1)
			var removed ProbeArtifactClaim
			go serveProbePad(ctx, ProbePadSpec{Root: padRoot, Backend: "event-sink", MaxEventBytes: extent}, ready, done, &removed)
			if err := <-ready; err != nil {
				cancel()
				t.Fatal(err)
			}
			socketPath := filepath.Join(padRoot, "pad.sock")
			socketInfo, err := os.Lstat(socketPath)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			commands := []string{"tap CROSS 0.01", "tap UP 0.01", "tap L2 0.01", "tap CROSS NaN"}
			if extent != 0 {
				commands = []string{"tap GUIDE 0.01"}
			}
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
				if extent == 48 {
					expected = "err input extent refused\n"
				}
				if err != nil || readErr != nil || string(ack) != expected {
					t.Errorf("pad command%s %q %v %v", command, ack, err, readErr)
				}
			}
			if row.SocketFault != "" {
				if err := os.Remove(socketPath); err != nil {
					cancel()
					t.Fatal(err)
				}
				if row.SocketFault == "replaced" {
					if err := os.WriteFile(socketPath, []byte("foreign"), 0600); err != nil {
						cancel()
						t.Fatal(err)
					}
				}
			}
			cancel()
			padErr := <-done
			if row.SocketFault != "" {
				if padErr == nil || removed.ExpectedInfo != nil {
					t.Fatal("foreign/missing socket produced an owned unlink witness", row.SocketFault, padErr)
				}
			} else if removed.ExpectedInfo == nil || !os.SameFile(socketInfo, removed.ExpectedInfo) || removed.Path != socketPath || removed.ID != "native:"+socketPath || removed.Class != probeArtifactNative {
				t.Fatal("actual pad cleanup did not bind its removed inode", padErr, removed)
			} else if extent == 48 {
				if padErr == nil || padErr.Error() != "owned pad command and release headroom exceed its reservation" {
					t.Fatal("insufficient GUIDE down/up extent did not refuse before input", padErr)
				}
			} else if padErr != nil {
				t.Fatal(padErr)
			}
			events, err := os.ReadFile(filepath.Join(padRoot, "pad-events.bin"))
			if err != nil {
				t.Fatal(err)
			}
			if extent == 0 && len(events) != 288 {
				t.Fatalf("event bytes%d", len(events))
			}
			if extent == 0 {
				for index, expected := range []string{fixture.PadEventsSHA, fixture.PadHatSHA, fixture.PadTriggerSHA} {
					if fmt.Sprintf("%x", sha256.Sum256(events[index*96:(index+1)*96])) != expected {
						t.Errorf("independent ABI event%d mismatch", index)
					}
				}
			} else if extent == 48 {
				if len(events) != 0 {
					t.Fatal("48-byte extent emitted GUIDE down or cleanup input before refusal", len(events))
				}
			} else if len(events) != 96 || binary.LittleEndian.Uint16(events[16:]) != 1 || binary.LittleEndian.Uint16(events[18:]) != 316 || binary.LittleEndian.Uint32(events[20:]) != 1 || binary.LittleEndian.Uint16(events[64:]) != 1 || binary.LittleEndian.Uint16(events[66:]) != 316 || binary.LittleEndian.Uint32(events[68:]) != 0 {
				t.Fatal("96-byte extent did not complete GUIDE down/up and clear held state within cap", len(events))
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
			if row.SocketFault == "replaced" {
				data, err := os.ReadFile(socketPath)
				if err != nil || string(data) != "foreign" {
					t.Fatal("foreign replacement was changed by cleanup", err)
				}
			} else if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
				t.Error("owned pad socket survived cleanup")
			}
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
				ID        string `json:"id"`
				Reason    string `json:"reason_prefix"`
				Writes    int    `json:"writes"`
				Continues bool   `json:"continues_after_acquisition"`
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
		for _, row := range []struct {
			Name, Fault         string
			Interleave, Recover bool
		}{
			{Name: "ordinary first directory"},
			{Name: "ordinary before and after save", Interleave: true},
			{Name: "ordinary stable selector mismatch", Fault: "frame-selector-drift"},
			{Name: "ordinary unavailable then explicit recovery", Fault: "frame-no-image", Recover: true},
		} {
			candidate := profile
			candidate.Root = t.TempDir()
			_ = os.Chmod(candidate.Root, 0700)
			candidate.Scenario = nil
			candidate.ProgramArgs = slices.Clone(scenarioProfile.ProgramArgs)
			if row.Fault != "" {
				candidate.ProgramArgs = append(candidate.ProgramArgs, row.Fault)
			}
			operations := []string{"initial", "observe-frame", "stop"}
			if row.Interleave {
				candidate.Scenario = scenarioProfile.Scenario
				operations = []string{"initial", "observe-frame", "scenario", "observe-frame", "stop"}
			}
			if row.Recover {
				candidate.Policy = &ProbeLifecyclePolicy{PollMS: 1, WarnRepeats: 1, TerminalRepeats: 2, MaxPolls: 1, MaxRecoveries: 1, MaxDistinctSkips: 1}
				operations = []string{"initial", "observe-frame", "stop", "recover", "stop"}
			}
			candidate.Requests = nil
			for i, operation := range operations {
				candidate.Requests = append(candidate.Requests, ProbeLifecycleRequest{Session: candidate.Session, Operation: operation, Phase: "requested", Nonce: fmt.Sprintf("%d-%s", i+1, operation)})
			}
			input, _ := json.Marshal(candidate)
			result, err := runProbeLifecycle(input)
			wantStatus := "COMPLETED"
			if row.Fault != "" {
				wantStatus = "INCOMPLETE"
			}
			if err != nil || result.Status != wantStatus || len(result.Steps) != len(operations) {
				t.Fatalf("%s lifecycle: %+v %v", row.Name, result, err)
			}
			journal, err := os.ReadFile(filepath.Join(candidate.Root, "events.jsonl"))
			if err != nil {
				t.Fatal(row.Name, "journal", err)
			}
			journalRows := bytes.Split(bytes.TrimSpace(journal), []byte{'\n'})
			for i, raw := range journalRows {
				var event ProbeCaptureEvent
				if json.Unmarshal(raw, &event) != nil || event.EventID != i+1 {
					t.Fatal(row.Name, "journal ordinal", i)
				}
			}
			ordinaryCount := 0
			for i, step := range result.Steps {
				if step.Request.Operation != "observe-frame" {
					if step.Status != "COMPLETED" {
						t.Fatal(row.Name, "nonframe action failed", step)
					}
					continue
				}
				ordinaryCount++
				if step.Capture == nil || step.Checkpoint != nil || step.Evidence == nil || step.Evidence.Path != filepath.Join(candidate.Root, step.Request.Nonce+"-evidence.json") {
					t.Fatal(row.Name, "ordinary result roles", step)
				}
				capture := step.Capture
				ack, ackErr := hex.DecodeString(capture.GuideAckHex)
				if capture.Checkpoint != 0 || capture.CaptureID == "" || capture.GuideCommand != "tap GUIDE 0.05" || ackErr != nil || !bytes.Equal(bytes.TrimSpace(ack), []byte("ok")) || capture.MemoryBefore == nil || !capture.MemoryBefore.ProcessGuarded || capture.Provenance != "owned_go" {
					t.Fatal(row.Name, "ordinary guarded acquisition", capture)
				}
				log, err := hex.DecodeString(capture.LogHex)
				if err != nil || capture.LogOffset < 0 || capture.LogOffset > int64(len(journal)-len(log)) || !bytes.Equal(journal[capture.LogOffset:capture.LogOffset+int64(len(log))], log) {
					t.Fatal(row.Name, "actual ordinary journal slice", err)
				}
				var event ProbeCaptureEvent
				if json.Unmarshal(log, &event) != nil || event.Event != "go-frame-capture" || event.Checkpoint == nil || *event.Checkpoint != 0 || event.CaptureID != capture.CaptureID || event.EventID != capture.EventID {
					t.Fatal(row.Name, "ordinary source event binding", event)
				}
				if i == 1 && (capture.EventID != 1 || capture.LogOffset != 0) {
					t.Fatal(row.Name, "ordinary was not first journal/directory owner")
				}
				info, err := os.Stat(step.Evidence.Path)
				evidence, readErr := os.ReadFile(step.Evidence.Path)
				var bundle ProbeEvidenceBundle
				if err != nil || readErr != nil || info.Mode().Perm() != 0400 || int64(len(evidence)) != step.Evidence.Size || fmt.Sprintf("%x", sha256.Sum256(evidence)) != step.Evidence.SHA256 || json.Unmarshal(evidence, &bundle) != nil || bundle.Cohort != "go-frame-only-v1" || len(bundle.Events) != 1 || len(bundle.Captures) != 1 || bundle.Captures[0].Admission != nil || len(bundle.Members) != 0 || len(bundle.Checks) != 0 || bundle.Story != nil || bundle.Resume != nil || bundle.Events[0].Offset != capture.LogOffset {
					t.Fatal(row.Name, "immutable ordinary input bundle", err, readErr)
				}
				var persisted ProbeCaptureReceipt
				receiptBytes, receiptErr := os.ReadFile(filepath.Join(candidate.Root, "captures", capture.CaptureID+".json"))
				if receiptErr != nil || json.Unmarshal(receiptBytes, &persisted) != nil || !reflect.DeepEqual(persisted, *capture) {
					t.Fatal(row.Name, "persisted ordinary receipt", receiptErr)
				}
				var report ProbeEvidenceReport
				reportBytes, reportErr := os.ReadFile(filepath.Join(candidate.Root, step.Request.Nonce+"-report.json"))
				if reportErr != nil || json.Unmarshal(reportBytes, &report) != nil || len(report.Captures) != 1 || len(report.Checkpoints) != 0 || len(report.CoveredAreas) != 0 || report.LiveOwnership || !strings.Contains(report.Limits, "not checkpoint, native or retention coverage") {
					t.Fatal(row.Name, "ordinary persisted report scope", reportErr)
				}
				if row.Fault == "frame-no-image" {
					if step.Status != "UNKNOWN" || !strings.HasPrefix(step.Reason, "ordinary frame is unavailable:") || capture.Status != "UNKNOWN" || bundle.Captures[0].ImageHex != "" || report.Status != "UNKNOWN" || report.Captures[0].Status != "UNKNOWN" {
						t.Fatal(row.Name, "unavailable source evidence lost", step, report)
					}
				} else {
					image, imageErr := os.ReadFile(filepath.Join(candidate.Root, "captures", capture.ImagePath))
					snapshot, snapshotErr := os.ReadFile(filepath.Join(candidate.Root, "profile", "PCSX2", "snaps", capture.Snapshot))
					if imageErr != nil || snapshotErr != nil || !bytes.Equal(image, pngBytes) || !bytes.Equal(snapshot, pngBytes) || bundle.Captures[0].ImageHex != hex.EncodeToString(pngBytes) || capture.Status != "CAPTURED" || report.Status != "PASS" || report.Captures[0].Status != "ACCEPTED" {
						t.Fatal(row.Name, "actual ordinary image/receipt/report", imageErr, snapshotErr)
					}
					if row.Fault == "frame-selector-drift" {
						if step.Status != "UNKNOWN" || step.Reason != "ordinary frame selected player changed before capture" || capture.MemoryAfter == nil || capture.MemoryBefore.Decoded[0].Value == nil || *capture.MemoryBefore.Decoded[0].Value != 1 || !reflect.DeepEqual(capture.MemoryBefore.Decoded, capture.MemoryAfter.Decoded) {
							t.Fatal(row.Name, "new selector guard was not isolated from capture DeepEqual", step)
						}
					} else if step.Status != "COMPLETED" {
						t.Fatal(row.Name, "valid ordinary action failed", step)
					}
				}
			}
			wantOrdinary := 1
			if row.Interleave {
				wantOrdinary = 2
			}
			if ordinaryCount != wantOrdinary {
				t.Fatal(row.Name, "ordinary count", ordinaryCount)
			}
			if row.Interleave {
				save := result.Steps[2]
				if save.Capture == nil || save.Capture.Checkpoint != 1 || save.Capture.LogOffset <= 0 || save.Checkpoint == nil || save.Checkpoint.Status != "UNKNOWN" || len(save.Checkpoint.Captures) != 1 || save.Checkpoint.Captures[0].CaptureID != save.Capture.CaptureID || len(save.Checkpoint.Checkpoints) != 1 || len(save.Checkpoint.CoveredAreas) != 0 {
					t.Fatal(row.Name, "ordinary changed required save capture/report", save)
				}
				for _, saved := range save.Checkpoint.Events {
					var event ProbeCaptureEvent
					if json.Unmarshal(saved.Data, &event) != nil || event.Event == "go-frame-capture" || event.EventID <= 1 || saved.Offset <= 0 {
						t.Fatal(row.Name, "checkpoint projection relabeled ordinary events", event)
					}
				}
				if result.Steps[3].Capture.EventID <= save.Capture.EventID || result.Steps[3].Capture.LogOffset <= save.Capture.LogOffset {
					t.Fatal(row.Name, "after-save ordinary order")
				}
			}
			if row.Recover && (result.Steps[3].RecoveryAttempts != 1 || result.Steps[3].Epoch != 1 || result.Steps[3].Owned == nil || result.Steps[3].Owned.PID == result.Steps[0].Owned.PID) {
				t.Fatal(row.Name, "explicit recovery did not retain ownership/epoch rules", result.Steps[3])
			}
			last := result.Steps[len(result.Steps)-1]
			card, cardErr := os.ReadFile(filepath.Join(candidate.Root, "profile", "PCSX2", "memcards", "probe-slot1.ps2"))
			if last.Status != "COMPLETED" || last.ExitedBeforeStop || cardErr != nil || fmt.Sprintf("%x", sha256.Sum256(card)) != last.CardAfter {
				t.Fatal(row.Name, "guarded stop/postflush hash", last, cardErr)
			}
			for _, step := range result.Steps {
				if (step.Request.Operation == "initial" || step.Request.Operation == "recover") && step.Owned != nil {
					if _, err := observeProbeProcess(ProbeMemoryRuntime{Provenance: "owned_child", Root: candidate.Root}, step.Owned.PID, step.Owned, candidate.Program.SHA256); !errors.Is(err, os.ErrProcessDone) {
						t.Fatal(row.Name, "owned fixture did not exit", err)
					}
				}
			}
			if _, err := os.Lstat(filepath.Join(candidate.Root, "pad.sock")); !os.IsNotExist(err) {
				t.Fatal(row.Name, "owned pad endpoint survived", err)
			}
		}
		for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
			now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
			policy := ProbeFramePolicy{MaxRunSeconds: 900}
			candidate := profile
			candidate.Frames = &policy
			state := ProbeFrameRun{Policy: policy, Ready: true, Started: now.Add(-300 * time.Second), EpochStarted: now.Add(-120 * time.Second), NextAttempt: now.Add(time.Second), NextStorage: now.Add(time.Second), NextHealth: now.Add(time.Second)}
			journal := ProbeEventJournal{}
			err := sampleProbeFrame(candidate, &journal, &state, now.Add(offset))
			if offset > 0 {
				if err == nil || err.Error() != "frame sampler successful capture gap exceeded120s" || state.Summary.Status != "UNKNOWN" {
					t.Fatal("strict capture gap boundary", offset, err)
				}
			} else if err != nil {
				t.Fatal("not-due tick at/before exact gap boundary", offset, err)
			}
			if state.Summary.Attempts != 0 || state.Summary.SampleSuccesses != 0 || state.Previous != nil || journal.Bytes != nil || len(journal.Events) != 0 {
				t.Fatal("clock-only tick caused acquisition/publication effects", offset)
			}
		}
		freshFinalGap, staleFinalGap, negativeFinalGap := 120.0, 120.001, -1.0
		for _, row := range []struct {
			Name, PriorFailure, WantFailure string
			EpochCaptures                   uint64
			Gap                             time.Duration
			Replay                          bool
			RecordedGap                     *float64
		}{
			{Name: "healthy final epoch", EpochCaptures: 1, Gap: 120 * time.Second},
			{Name: "earlier epoch success cannot satisfy final epoch", Gap: time.Second, WantFailure: "frame sampler lacks a successful capture in the final epoch"},
			{Name: "final stale capture", EpochCaptures: 1, Gap: 120*time.Second + time.Nanosecond, WantFailure: "frame sampler successful capture gap exceeded120s"},
			{Name: "primary failure survives final health check", PriorFailure: "controlled primary failure", Gap: 300 * time.Second, WantFailure: "controlled primary failure"},
			{Name: "replayed healthy final gap", EpochCaptures: 1, Replay: true, RecordedGap: &freshFinalGap},
			{Name: "replayed stale final gap", EpochCaptures: 1, Replay: true, RecordedGap: &staleFinalGap, WantFailure: "frame sampler successful capture gap exceeded120s"},
			{Name: "replayed final gap lacks observation", EpochCaptures: 1, Replay: true, WantFailure: "frame sampler final capture gap is unavailable"},
			{Name: "replayed negative final gap", EpochCaptures: 1, Replay: true, RecordedGap: &negativeFinalGap, WantFailure: "frame sampler final capture gap is unavailable"},
		} {
			now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
			policy := ProbeFramePolicy{MaxRunSeconds: 900}
			candidate := profile
			candidate.Frames = &policy
			state := ProbeFrameRun{Policy: policy, Finalizing: true, Started: now.Add(-600 * time.Second), EpochStarted: now.Add(-400 * time.Second), LastSample: now.Add(-row.Gap)}
			state.Summary.SampleSuccesses, state.Summary.SelectedCommits, state.Summary.EpochCaptures = 2, 1, row.EpochCaptures
			state.Summary.Failure = row.PriorFailure
			state.Summary.FinalCaptureGapSeconds = row.RecordedGap
			if row.Replay {
				state.Started, state.EpochStarted, state.LastSample = time.Time{}, time.Time{}, time.Time{}
			}
			journal := ProbeEventJournal{}
			err := sampleProbeFrame(candidate, &journal, &state, now)
			if (err != nil) != (row.WantFailure != "") || state.Summary.Failure != row.WantFailure {
				t.Fatal(row.Name, "final capture health", err, state.Summary)
			}
			if state.Summary.Attempts != 0 || state.Summary.SampleSuccesses != 2 || state.Summary.SelectedCommits != 1 || state.Previous != nil || journal.Bytes != nil || len(journal.Events) != 0 {
				t.Fatal(row.Name, "final health check caused acquisition/publication effects")
			}
		}
		for _, row := range []struct {
			Name, Fault                                   string
			InnerWait, Reset, Checkpoint, FinalEpochEmpty bool
		}{
			{Name: "sampler stable capture health"},
			{Name: "sampler cold epoch predecessor reset", Reset: true},
			{Name: "sampler final cold epoch has no capture", Reset: true, FinalEpochEmpty: true},
			{Name: "sampler services real acquire-board wait", InnerWait: true},
			{Name: "sampler CSV acknowledgement gates selected baseline", Fault: "frame-csv-conflict"},
			{Name: "sampler refuses missing image and preserves late first birth", Fault: "frame-late-on-stop"},
			{Name: "sampler checkpoint derivative preserves ordinary baseline", Checkpoint: true},
		} {
			candidate := profile
			candidate.Root = t.TempDir()
			if err := os.Chmod(candidate.Root, 0700); err != nil {
				t.Fatal(err)
			}
			candidate.ProgramArgs = append(slices.Clone(scenarioProfile.ProgramArgs), "frame-no-trace")
			if row.Fault != "" {
				candidate.ProgramArgs = append(candidate.ProgramArgs, row.Fault)
			}
			candidate.Scenario = nil
			candidate.Policy = &ProbeLifecyclePolicy{PollMS: 1000, WarnRepeats: 12, TerminalRepeats: 14, MaxPolls: 11, MaxRecoveries: 1, MaxDistinctSkips: 4}
			candidate.Frames = &ProbeFramePolicy{MaxRunSeconds: 90, MaxRetainedFrames: 32, MaxManagedFiles: 4096, MaxManagedBytes: 512 << 20, MaxJournalBytes: 8 << 20}
			operations := []string{"initial", "watch", "stop"}
			if row.Fault == "frame-late-on-stop" {
				candidate.StopTimeoutMS = 10000 // The controlled writer may finish its delayed first screenshot during stop.
				operations = []string{"initial", "watch", "observe-frame", "cold", "watch", "stop"}
			}
			if row.Reset {
				candidate.Policy.MaxPolls = 6
				operations = []string{"initial", "watch", "cold", "watch", "stop"}
				if row.FinalEpochEmpty {
					operations = []string{"initial", "watch", "cold", "stop"}
				}
			}
			if row.InnerWait {
				// Two 20s capture bounds, two 10s UI reads and two 4s waits, plus 2s bookkeeping.
				candidate.Frames.MaxRunSeconds = 70
				seed := uint64(17)
				candidate.Seed = &seed
				spec := *scenarioProfile.Scenario
				spec.Recipe, spec.WaitTimeoutMS = "first-create", 86400000
				candidate.Scenario = &spec
				operations = []string{"initial", "scenario", "stop"}
			}
			if row.Checkpoint {
				candidate.Policy.MaxPolls = 6
				candidate.Scenario = scenarioProfile.Scenario
				candidate.ProgramArgs = append(candidate.ProgramArgs, "frame-checkpoint-contrast")
				operations = []string{"initial", "watch", "scenario", "watch", "stop"}
			}
			candidate.Requests = nil
			for ordinal, operation := range operations {
				candidate.Requests = append(candidate.Requests, ProbeLifecycleRequest{Session: candidate.Session, Operation: operation, Phase: "requested", Nonce: fmt.Sprintf("%d-%s", ordinal+1, operation)})
			}
			input, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			result, err := runProbeLifecycle(input)
			wantStatus := "COMPLETED"
			if row.InnerWait || row.Fault != "" || row.FinalEpochEmpty {
				wantStatus = "INCOMPLETE"
			}
			frames := result.Frames
			csv, csvErr := os.ReadFile(filepath.Join(candidate.Root, "frames.csv"))
			missingFrameFacts := frames != nil && row.Fault == "" && !row.FinalEpochEmpty && (frames.SampleSuccesses < 2 || frames.EpochCaptures < 1 || frames.LastSampleSeconds == nil || frames.LastSelectedSeconds == nil || frames.PreviousComparisonHash == "" || frames.LastJPEG == "" || frames.LastJPEGSHA256 == "" || csvErr != nil || !bytes.HasPrefix(csv, []byte("frame,t,mode,story,week\n")))
			if err != nil || result.Status != wantStatus || len(result.Steps) != len(operations) || frames == nil || frames.CodecQualification != "go-image-jpeg-unqualified" || missingFrameFacts {
				encoded, encodeErr := json.Marshal(result)
				t.Logf("%s full lifecycle report: %s (marshal=%v)", row.Name, encoded, encodeErr)
				if frames != nil && frames.LastSelectedSeconds != nil {
					t.Logf("%s timing: run_limit=%ds selected_ack=%.9fs next_attempt_not_before=%.9fs final_observed=%s", row.Name, candidate.Frames.MaxRunSeconds, *frames.LastSelectedSeconds, *frames.LastSelectedSeconds+4, time.Now().UTC().Format(time.RFC3339Nano))
				}
				for _, name := range []string{"events.jsonl", "pad-events.bin", "child-epoch-0.log"} {
					path := filepath.Join(candidate.Root, name)
					info, statErr := os.Lstat(path)
					if statErr != nil || !info.Mode().IsRegular() {
						t.Logf("%s diagnostic %s unavailable: %v", row.Name, name, statErr)
						continue
					}
					file, openErr := os.Open(path)
					if openErr != nil {
						t.Logf("%s diagnostic %s open: %v", row.Name, name, openErr)
						continue
					}
					data, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
					closeErr := file.Close()
					truncated := len(data) > 1<<20
					if truncated {
						data = data[:1<<20]
					}
					if name == "pad-events.bin" {
						t.Logf("%s diagnostic %s truncated=%t read=%v close=%v hex=%x", row.Name, name, truncated, readErr, closeErr, data)
					} else {
						t.Logf("%s diagnostic %s truncated=%t read=%v close=%v bytes=%q", row.Name, name, truncated, readErr, closeErr, data)
					}
				}
				t.Fatalf("%s lifecycle/codec/frame facts status=%s want=%s missing_frame_facts=%t: %v", row.Name, result.Status, wantStatus, missingFrameFacts, err)
			}
			if row.FinalEpochEmpty {
				before, cold := result.Steps[1].Frames, result.Steps[2]
				if frames.Status != "UNKNOWN" || frames.Failure != "frame sampler lacks a successful capture in the final epoch" || frames.Epoch != 1 || frames.EpochCaptures != 0 || frames.SampleSuccesses == 0 || frames.SelectedCommits != 1 || frames.PreviousComparisonHash != "" || before == nil || before.EpochCaptures == 0 || cold.Status != "COMPLETED" || cold.Epoch != 1 {
					t.Fatal(row.Name, "earlier epoch capture concealed missing final epoch", frames, cold)
				}
			} else if row.Fault == "frame-late-on-stop" {
				if frames.Status != "UNKNOWN" || frames.Attempts != 1 || frames.CaptureErrors != 1 || frames.SampleSuccesses != 0 || frames.Epoch != 0 || frames.EpochCaptures != 0 || frames.SelectedCommits != 0 || frames.CheckpointCommits != 0 || frames.LastSampleSeconds != nil || frames.LastSelectedSeconds != nil || frames.LastJPEG != "" || frames.PreviousComparisonHash != "" || frames.Failure != "frame sampler capture authority: capture deadline expired without a complete stable PNG: <nil>" || csvErr != nil || string(csv) != "frame,t,mode,story,week\n" {
					t.Fatal(row.Name, "expired or late first attempt gained frame health/selection", frames, csvErr)
				}
				for _, rejected := range result.Steps[2:5] {
					if rejected.Status != "REFUSED" || rejected.Reason != "frame sampler failed; only explicit stop remains admitted" || rejected.Epoch != 0 || len(rejected.Effects) != 0 || rejected.Capture != nil || rejected.Checkpoint != nil {
						t.Fatal(row.Name, "failed sampler admitted a new capture or epoch", rejected)
					}
				}
				late, lateErr := os.ReadFile(filepath.Join(candidate.Root, "profile", "PCSX2", "snaps", "late.png"))
				events, eventErr := os.ReadFile(filepath.Join(candidate.Root, "pad-events.bin"))
				guides := 0
				for offset := 0; offset+24 <= len(events); offset += 24 {
					if binary.LittleEndian.Uint16(events[offset+16:]) == 1 && binary.LittleEndian.Uint16(events[offset+18:]) == 316 && binary.LittleEndian.Uint32(events[offset+20:]) == 1 {
						guides++
					}
				}
				if lateErr != nil || !bytes.Equal(late, pngBytes) || eventErr != nil || guides != 1 {
					t.Fatal(row.Name, "late first-trigger bytes lost or GUIDE retriggered", lateErr, eventErr, guides)
				}
			} else if row.Fault != "" {
				if frames.SampleSuccesses != 1 || frames.SelectedCommits != 0 || frames.PreviousComparisonHash != "" || frames.LastSelectedSeconds != nil || frames.LastJPEG != "" || frames.Failure == "" || csvErr != nil || string(csv) != "controlled CSV conflict\n" {
					t.Fatal(row.Name, "unacknowledged publication advanced selected baseline", frames, csvErr)
				}
			} else {
				selected := uint64(1)
				if row.Reset {
					selected = 2
				}
				if frames.SelectedCommits != selected || len(bytes.Split(bytes.TrimSpace(csv), []byte{'\n'})) != int(selected)+1 {
					t.Fatal(row.Name, "stable sampling changed selected count/CSV", frames, string(csv))
				}
				jpegBytes, imageErr := os.ReadFile(filepath.Join(candidate.Root, frames.LastJPEG))
				decoded, decodeErr := jpeg.DecodeConfig(bytes.NewReader(jpegBytes))
				if imageErr != nil || decodeErr != nil || decoded.Width != 640 || decoded.Height != 480 || fmt.Sprintf("%x", sha256.Sum256(jpegBytes)) != frames.LastJPEGSHA256 {
					t.Fatal(row.Name, "selected JPEG geometry/hash", imageErr, decodeErr)
				}
				if row.Reset {
					before, after := result.Steps[1].Frames, result.Steps[3].Frames
					if before == nil || after == nil || before.LastMean == nil || after.LastMean == nil || *before.LastMean != 999 || *after.LastMean != 999 || before.SelectedCommits != 1 || after.SelectedCommits != 2 || before.Epoch != 0 || after.Epoch != 1 || after.EpochCaptures != 1 || before.PreviousComparisonHash != after.PreviousComparisonHash {
						t.Fatal(row.Name, "cold epoch did not reset only its comparison baseline", before, after)
					}
					cold := result.Steps[2]
					if cold.Request.Operation != "cold" || cold.Status != "COMPLETED" || cold.Epoch != 1 || cold.Owned == nil || result.Steps[0].Owned == nil || cold.Owned.PID == result.Steps[0].Owned.PID || cold.CardBefore == "" || cold.CardAfter == "" {
						t.Fatal(row.Name, "epoch reset lacked the healthy stop/flush/backup/fresh-launch transition", cold)
					}
				} else if frames.LastMean == nil || *frames.LastMean != 0 || *frames.LastSampleSeconds <= *frames.LastSelectedSeconds {
					t.Fatal(row.Name, "stable below-threshold sample did not refresh capture health only", frames)
				}
			}
			if row.InnerWait {
				waiting := result.Steps[1]
				if waiting.Status != "UNKNOWN" || waiting.Frames == nil || waiting.Frames.SampleSuccesses < 2 || len(waiting.Effects) != 0 || waiting.Reason == "" || len(waiting.ScheduledIntervals) != 0 {
					t.Fatal(row.Name, "did not fail within actual long acquire-board wait", waiting)
				}
				entries, err := os.ReadDir(filepath.Join(candidate.Root, "receipts"))
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if strings.Contains(entry.Name(), "2-scenario") && entry.Name() != "2-scenario-00-acquire-board.pending.json" && entry.Name() != "2-scenario-00-acquire-board.complete.json" {
						t.Fatal(row.Name, "frame tick emitted a lifecycle effect artifact", entry.Name())
					}
				}
			}
			if row.Checkpoint {
				checkpoint := result.Steps[2]
				if frames.CheckpointCommits != 1 || checkpoint.Capture == nil || checkpoint.Checkpoint == nil || checkpoint.Checkpoint.Status != "UNKNOWN" || result.Steps[1].Frames.PreviousComparisonHash != frames.PreviousComparisonHash {
					t.Fatal(row.Name, "checkpoint derivative changed ordinary predecessor or coverage", frames, checkpoint)
				}
				derivative, err := os.ReadFile(filepath.Join(candidate.Root, "checkpoint-frames", checkpoint.Capture.CaptureID+".jpg"))
				geometry, format, decodeErr := image.DecodeConfig(bytes.NewReader(derivative))
				if err != nil || decodeErr != nil || format != "jpeg" || geometry.Width != 640 || geometry.Height != 480 {
					t.Fatal(row.Name, "checkpoint JPEG derivative", err, decodeErr)
				}
				ordinaryBytes, ordinaryErr := os.ReadFile(filepath.Join(candidate.Root, frames.LastJPEG))
				checkpointImage, checkpointErr := jpeg.Decode(bytes.NewReader(derivative))
				ordinaryImage, ordinaryDecodeErr := jpeg.Decode(bytes.NewReader(ordinaryBytes))
				if ordinaryErr != nil || checkpointErr != nil || ordinaryDecodeErr != nil || checkpoint.Capture.ImageSHA256 == fmt.Sprintf("%x", sha256.Sum256(pngBytes)) {
					t.Fatal(row.Name, "checkpoint contrast source/decoding", ordinaryErr, checkpointErr, ordinaryDecodeErr)
				}
				checkpointRed, _, _, _ := checkpointImage.At(320, 240).RGBA()
				ordinaryRed, _, _, _ := ordinaryImage.At(320, 240).RGBA()
				if checkpointRed < 240*257 || ordinaryRed >= 200*257 {
					t.Fatal(row.Name, "checkpoint contrast did not survive separate JPEG derivatives", checkpointRed, ordinaryRed)
				}
			}
			last := result.Steps[len(result.Steps)-1]
			card, cardErr := os.ReadFile(filepath.Join(candidate.Root, "profile", "PCSX2", "memcards", "probe-slot1.ps2"))
			stopStatus := "COMPLETED"
			if row.Fault == "frame-csv-conflict" {
				stopStatus = "UNKNOWN"
				if last.Reason == "" {
					t.Fatal(row.Name, "CSV authority refusal lost its stop evidence error")
				}
			}
			if last.Request.Operation != "stop" || last.Status != stopStatus || !slices.Equal(last.Effects, []string{"terminate", "flush"}) || last.ExitedBeforeStop || cardErr != nil || fmt.Sprintf("%x", sha256.Sum256(card)) != last.CardAfter {
				t.Fatal(row.Name, "sampler failure blocked explicit stop/final card flush", last, cardErr)
			}
			for _, step := range result.Steps {
				if step.Owned != nil && (step.Request.Operation == "initial" || step.Request.Operation == "cold") {
					if _, err := observeProbeProcess(ProbeMemoryRuntime{Provenance: "owned_child", Root: candidate.Root}, step.Owned.PID, step.Owned, candidate.Program.SHA256); !errors.Is(err, os.ErrProcessDone) {
						t.Fatal(row.Name, "sampler retained its owned fixture process", err)
					}
				}
			}
			if _, err := os.Lstat(filepath.Join(candidate.Root, "pad.sock")); !os.IsNotExist(err) {
				t.Fatal(row.Name, "sampler retained its owned pad endpoint", err)
			}
			if !row.InnerWait && !row.Checkpoint && row.Fault == "" {
				var inventories [2]map[string]string
				for pass := range inventories {
					if pass == 1 {
						replayed, err := runProbeLifecycle(input)
						if err != nil || replayed.Status != result.Status || !reflect.DeepEqual(replayed.Frames, result.Frames) || len(replayed.Steps) != len(result.Steps) {
							t.Fatal(row.Name, "completed sampled replay changed final facts", replayed, err)
						}
						for index, step := range replayed.Steps {
							if !step.Replayed || step.Status != result.Steps[index].Status || !reflect.DeepEqual(step.Frames, result.Steps[index].Frames) {
								t.Fatal(row.Name, "completed sampled replay changed saved per-step facts", index, step)
							}
						}
					}
					inventories[pass] = map[string]string{}
					rootInfo, err := os.Lstat(candidate.Root)
					if err != nil {
						t.Fatal(row.Name, "completed replay root identity", err)
					}
					rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
					if !ok {
						t.Fatal(row.Name, "completed replay root identity unavailable")
					}
					inventories[pass][candidate.Root] = fmt.Sprintf("%d:%d:%o:%d", rootStat.Dev, rootStat.Ino, rootInfo.Mode(), rootInfo.ModTime().UnixNano())
					pending := []string{candidate.Root}
					for len(pending) > 0 {
						directory := pending[0]
						pending = pending[1:]
						entries, err := os.ReadDir(directory)
						if err != nil {
							t.Fatal(row.Name, "completed replay inventory", err)
						}
						for _, entry := range entries {
							path := filepath.Join(directory, entry.Name())
							info, err := os.Lstat(path)
							if err != nil || len(inventories[pass]) >= 4096 {
								t.Fatal(row.Name, "completed replay bounded artifact inventory", err)
							}
							stat, ok := info.Sys().(*syscall.Stat_t)
							if !ok {
								t.Fatal(row.Name, "completed replay artifact identity unavailable")
							}
							pin := fmt.Sprintf("%d:%d:%o:%d", stat.Dev, stat.Ino, info.Mode(), info.ModTime().UnixNano())
							if info.IsDir() {
								pending = append(pending, path)
							} else {
								if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 16<<20 {
									t.Fatal(row.Name, "completed replay artifact is not a bounded regular file")
								}
								file, err := os.Open(path)
								if err != nil {
									t.Fatal(row.Name, "completed replay artifact unavailable", err)
								}
								data, readErr := io.ReadAll(io.LimitReader(file, (16<<20)+1))
								opened, statErr := file.Stat()
								closeErr := file.Close()
								if readErr != nil || statErr != nil || closeErr != nil || !os.SameFile(info, opened) || int64(len(data)) != info.Size() || opened.Size() != info.Size() || opened.ModTime() != info.ModTime() {
									t.Fatal(row.Name, "completed replay artifact bytes changed or unavailable", readErr, statErr, closeErr)
								}
								pin += fmt.Sprintf(":%d:%x", len(data), sha256.Sum256(data))
							}
							inventories[pass][path] = pin
						}
					}
				}
				if !reflect.DeepEqual(inventories[0], inventories[1]) {
					t.Fatal(row.Name, "completed sampled replay changed GUIDE/journal/effect or other owned artifacts")
				}
			}
		}
		for _, variant := range []string{"blank-nonce", "wrong-operation", "unlinked-request", "unsupported-backend", "changed-backend-hash"} {
			admissionRaw, _ := os.ReadFile(filepath.Join(scenarioProfile.Root, "go-records-2-scenario.json"))
			var bundle ProbeRecordBundle
			_ = json.Unmarshal(admissionRaw, &bundle)
			switch variant {
			case "blank-nonce":
				bundle.GoOwner.Step.Request.Nonce = ""
			case "wrong-operation":
				bundle.GoOwner.Step.Request.Operation = "warm"
			case "unsupported-backend":
				bundle.GoOwner.Profile.PadBackend = "native"
			case "changed-backend-hash":
				bundle.GoOwner.Profile.PadBackend = "event-sink"
			case "unlinked-request":
				bundle.GoOwner.Profile.Requests = nil
			}
			bad, _ := json.Marshal(bundle)
			if _, err := admitProbeRecords(bad); err == nil {
				t.Error(variant, "admitted")
			} else if variant == "unsupported-backend" && err.Error() != "unsupported owned pad backend" {
				t.Error(variant, "did not reach declared backend guard", err)
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
			if refusal.ID == "pre-acquisition-delay" {
				spec := *candidate.Scenario
				spec.TimeoutMS = 6000
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
			continued := refusal.Continues && len(outcome.Steps) == 3 && outcome.Steps[1].Status == "COMPLETED" && outcome.Steps[1].Reason == ""
			if runErr != nil || len(outcome.Steps) != 3 || !continued && (outcome.Status != "INCOMPLETE" || outcome.Steps[1].Status != "UNKNOWN" || !strings.HasPrefix(outcome.Steps[1].Reason, refusal.Reason)) || outcome.Steps[2].Status != "COMPLETED" {
				t.Fatalf("%s bounded source refusal: %+v %v", refusal.ID, outcome, runErr)
			}
			if !continued && (outcome.Steps[1].Capture != nil || outcome.Steps[1].Checkpoint != nil) {
				t.Error(refusal.ID, "unsafe source became checkpoint")
			}
			if refusal.ID == "pre-acquisition-delay" && !slices.Contains(outcome.Steps[1].Effects, "verify-human") {
				t.Fatal("expired pre-acquisition budget consumed the fresh transaction budget")
			}
			if refusal.Continues {
				before, _ := os.Stat(filepath.Join(candidate.Root, "receipts", "2-scenario-00-acquire-board.pending.json"))
				after, _ := os.Stat(filepath.Join(candidate.Root, "receipts", "2-scenario-00-acquire-board.complete.json"))
				if before == nil || after == nil || after.ModTime().Sub(before.ModTime()) <= time.Duration(candidate.Scenario.TimeoutMS)*time.Millisecond {
					t.Fatal("witness did not expire pre-acquisition budget")
				}
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
	})
	// The independent paired oracle predates any producer output. A real Load in
	// this controlled VM restores RAM from its private File2 bytes, not a PASS flag.
	type cohortRun struct {
		Profile     ProbeLifecycleProfile
		Result      ProbeLifecycleReport
		Oracle      json.RawMessage
		CardFixture string
	}
	for _, cohort := range []string{"sequence", "newgame", "paired"} {
		t.Run(cohort, func(t *testing.T) {
			pairedOracleRaw, err := os.ReadFile("testdata/probe-" + cohort + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var pairedOracle struct {
				States         map[string]ProbeSavedState `json:"states"`
				ExpectedReport json.RawMessage            `json:"full_normalized_report"`
				Runs           []json.RawMessage          `json:"runs"`
				Outer          json.RawMessage            `json:"outer_projection"`
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
			initialCardPath := "testdata/probe-paired-card-initial.bin"
			if cohort == "sequence" {
				initialCardPath = "testdata/probe-sequence-card-H0.bin"
			}
			initialCard, err := os.ReadFile(initialCardPath)
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
			var records []cohortRun
			var sequenceSpec ProbeSequenceSpec
			var sequenceResult ProbeSequenceReport
			var pairedErr error
			if cohort == "sequence" {
				sequenceSpec = ProbeSequenceSpec{Version: 1, SourceFormat: "go-probe-sequence-v1", Root: pairedProfile.Root, Seed: 17}
				for index, recipe := range []string{"first-create", "new-game-overwrite", "alternate-slots"} {
					candidate := pairedProfile
					candidate.Root = filepath.Join(sequenceSpec.Root, fmt.Sprintf("run-%d", index+1))
					_ = os.Mkdir(candidate.Root, 0700)
					candidate.Session = fmt.Sprintf("sequence-test-run-%d", index+1)
					candidate.ProgramArgs = append(slices.Clone(profile.ProgramArgs), "scenario-newgame", fmt.Sprintf("sequence-run%d", index+1))
					candidate.Inputs = map[string]RegistryInput{}
					for role, input := range pairedProfile.Inputs {
						candidate.Inputs[role] = input
					}
					if index > 0 {
						candidate.Inputs["card"] = RegistryInput{}
					}
					seed := uint64(17 + index)
					candidate.Seed = &seed
					spec := *pairedProfile.Scenario
					spec.Recipe = recipe
					spec.Calibration = true
					spec.WaitTimeoutMS = 180000
					spec.NoTutorial = true
					spec.FrontEndTimeoutMS = 120000
					candidate.Scenario = &spec
					ops := []string{"initial", "newgame", "scenario", "warm-load", "load", "cold-load", "load", "restore", "finish", "stop"}
					if index == 0 {
						ops = []string{"initial", "newgame", "prepare-scenario", "warm-load", "prepare-load", "resave", "warm-load", "load", "cold-load", "load", "restore", "finish", "stop"}
					}
					if index == 2 {
						ops = []string{"initial", "newgame", "scenario", "warm-load", "load", "cold-load", "load", "restore", "scenario", "warm-load", "load", "cold-load", "load", "restore", "finish", "stop"}
					}
					candidate.Requests = nil
					for ordinal, operation := range ops {
						candidate.Requests = append(candidate.Requests, ProbeLifecycleRequest{Session: candidate.Session, Operation: operation, Phase: "requested", Nonce: fmt.Sprintf("%d-%s", ordinal+1, operation)})
					}
					sequenceSpec.Profiles = append(sequenceSpec.Profiles, candidate)
				}
				input, _ := json.Marshal(sequenceSpec)
				sequenceResult, pairedErr = runProbeSequence(input)
				for index, row := range sequenceResult.Runs {
					profileRaw, _ := os.ReadFile(row.Profile.Path)
					var actualProfile ProbeLifecycleProfile
					_ = json.Unmarshal(profileRaw, &actualProfile)
					if int64(len(profileRaw)) != row.Profile.Size || fmt.Sprintf("%x", sha256.Sum256(profileRaw)) != row.Profile.SHA256 {
						t.Fatal("sequence frozen profile hash")
					}
					expectedProfile := sequenceSpec.Profiles[index]
					expectedProfile.Inputs = map[string]RegistryInput{}
					for role, input := range sequenceSpec.Profiles[index].Inputs {
						expectedProfile.Inputs[role] = input
					}
					if index > 0 {
						expectedProfile.Inputs["card"] = *sequenceResult.Runs[index-1].Carry
					}
					if !reflect.DeepEqual(actualProfile, expectedProfile) {
						t.Fatal("sequence immutable profile/card succession")
					}
					records = append(records, cohortRun{Profile: actualProfile, Result: row.Lifecycle, Oracle: pairedOracle.Runs[index], CardFixture: fmt.Sprintf("testdata/probe-sequence-card-H%d.bin", index+1)})
				}
				if pairedErr != nil || sequenceResult.Status != "PASS" || len(records) != 3 {
					for index, row := range sequenceResult.Runs {
						t.Logf("recipe %s initial-card %s carry %+v", row.Recipe, row.InitialCardSHA256, row.Carry)
						for _, step := range row.Lifecycle.Steps {
							t.Logf("%s %s reason=%s effects=%v epoch=%d exited_before_stop=%t", step.Request.Nonce, step.Status, step.Reason, step.Effects, step.Epoch, step.ExitedBeforeStop)
						}
						// Roots were decoded and hash-checked from row.Profile.Path above.
						// Three known epochs, at most4096 bytes each, survive TempDir cleanup.
						for epoch := 0; epoch <= 2; epoch++ {
							path := filepath.Join(records[index].Profile.Root, fmt.Sprintf("child-epoch-%d.log", epoch))
							file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
							if err != nil {
								t.Logf("%s open_error=%v", path, err)
								continue
							}
							info, err := file.Stat()
							if err != nil || !info.Mode().IsRegular() {
								t.Logf("%s not_regular_or_stat_error=%v close_error=%v", path, err, file.Close())
								continue
							}
							data, readErr := io.ReadAll(io.LimitReader(file, 4096))
							closeErr := file.Close()
							t.Logf("%s size=%d truncated=%t read_error=%v close_error=%v: %q", path, info.Size(), info.Size() > int64(len(data)), readErr, closeErr, data)
						}
					}
					t.Fatalf("source sequence: %s %s %v", sequenceResult.Status, sequenceResult.Reason, pairedErr)
				}
				projection := map[string]any{"version": sequenceResult.Version, "source_format": sequenceResult.SourceFormat, "status": sequenceResult.Status, "limits": sequenceResult.Limits}
				for _, key := range []string{"recipes", "initial_card_sha256", "carry_sha256", "request_counts", "terminal_epochs", "checkpoint_slots", "checkpoint_counts", "event_counts", "capture_counts", "accepted_selected_interval_prefixes"} {
					projection[key] = []any{}
				}
				for _, row := range sequenceResult.Runs {
					last := row.Lifecycle.Steps[len(row.Lifecycle.Steps)-2]
					slots := []int{}
					for _, checkpoint := range last.Checkpoint.Checkpoints {
						slots = append(slots, *checkpoint.Slot)
					}
					prefix := []int{}
					for _, step := range row.Lifecycle.Steps {
						if step.Request.Operation == "restore" {
							prefix = step.ScheduledIntervals
						}
					}
					for key, value := range map[string]any{"recipes": row.Recipe, "initial_card_sha256": row.InitialCardSHA256, "carry_sha256": row.Carry.SHA256, "request_counts": len(row.Lifecycle.Steps), "terminal_epochs": last.Epoch, "checkpoint_slots": slots, "checkpoint_counts": len(slots), "event_counts": len(last.Checkpoint.Events), "capture_counts": len(last.Checkpoint.Captures), "accepted_selected_interval_prefixes": prefix} {
						projection[key] = append(projection[key].([]any), value)
					}
				}
				projectionRaw, _ := json.Marshal(projection)
				var actualOuter, expectedOuter map[string]any
				_ = json.Unmarshal(projectionRaw, &actualOuter)
				_ = json.Unmarshal(pairedOracle.Outer, &expectedOuter)
				if !reflect.DeepEqual(actualOuter, expectedOuter) {
					t.Fatalf("source sequence outer projection differs: %s", projectionRaw)
				}
			} else {
				pairedInput, _ := json.Marshal(pairedProfile)
				result, err := runProbeLifecycle(pairedInput)
				pairedErr = err
				cardFixture := "testdata/probe-paired-card-saved.bin"
				if cohort == "newgame" {
					cardFixture = "testdata/probe-newgame-card-final.bin"
				}
				records = []cohortRun{{Profile: pairedProfile, Result: result, Oracle: pairedOracleRaw, CardFixture: cardFixture}}
			}
			for runIndex, record := range records {
				pairedProfile, pairedResult := record.Profile, record.Result
				pairedOracle.States = nil
				_ = json.Unmarshal(record.Oracle, &pairedOracle)
				operations := pairedProfile.Requests
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
				if cohort != "sequence" && (pairedResult.Steps[warmIndex].PreviewSamples != 40 || pairedResult.Steps[coldLoadIndex].PreviewSamples != 40 || pairedResult.Steps[0].Owned.PID == pairedResult.Steps[coldIndex].Owned.PID || pairedResult.Steps[coldIndex].Epoch != 1) {
					t.Fatal("paired preview or cold ownership")
				}
				if cohort == "sequence" {
					finalIndex = len(pairedResult.Steps) - 2
					for _, step := range pairedResult.Steps {
						if (step.Request.Operation == "load" || step.Request.Operation == "prepare-load") && step.PreviewSamples != 40 {
							t.Fatal("sequence Load without40samples")
						}
					}
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
					data := row["data"].(map[string]any)
					data["time"] = "NORMALIZED_TIME"
					if data["event"] == "card-data-created" || data["event"] == "overwrite-confirmed" {
						choice, ok := data["prompt_yesno"].(map[string]any)
						if !ok || choice["source"] != "header" || choice["selection"] != data["prompt_headers"].(map[string]any)["yesno"] || choice["widget"] != nil {
							t.Fatal("current header-source prompt observation differs", data)
						}
						// The frozen oracle predates the additive source observation.
						delete(data, "prompt_yesno")
					}
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
				cardFixture := record.CardFixture
				savedCard, _ := os.ReadFile(cardFixture)
				actualCard, _ := os.ReadFile(filepath.Join(pairedProfile.Root, "profile", "PCSX2", "memcards", "probe-slot1.ps2"))
				if !bytes.Equal(actualCard, savedCard) {
					t.Fatal("paired exact File2 persistence/original File1 sentinel")
				}
				stateKey := "advanced"
				if cohort == "sequence" {
					stateKey = "terminal"
				}
				if !reflect.DeepEqual(finalStep.UI.Saved, pairedOracle.States[stateKey]) {
					t.Fatal("paired actual advancement footprint")
				}
				if cohort == "sequence" {
					row := sequenceResult.Runs[runIndex]
					carry, _ := os.ReadFile(row.Carry.Path)
					if !bytes.Equal(carry, savedCard) || row.Carry.SHA256 != fmt.Sprintf("%x", sha256.Sum256(carry)) || row.InitialCardSHA256 != pairedProfile.Inputs["card"].SHA256 {
						t.Fatal("actual postflush carry binding")
					}
					for _, variant := range []string{"wrong-recipe", "wrong-slot", "missing-terminal", "out-of-order", "unproved-prompt"} {
						if variant == "unproved-prompt" && runIndex == 2 {
							continue
						}
						var mutant ProbeEvidenceBundle
						_ = json.Unmarshal(evidenceRaw, &mutant)
						switch variant {
						case "wrong-recipe":
							mutant.Story.Recipe = "alternate-slots"
							if runIndex == 2 {
								mutant.Story.Recipe = "first-create"
							}
						case "wrong-slot":
							var row map[string]any
							_ = json.Unmarshal(mutant.Events[0].Data, &row)
							row["slot"] = float64(1)
							if runIndex == 2 {
								row["slot"] = float64(0)
							}
							mutant.Events[0].Data, _ = json.Marshal(row)
						case "missing-terminal":
							mutant.Story.TerminalEventID = 0
						case "out-of-order":
							mutant.Events[0], mutant.Events[1] = mutant.Events[1], mutant.Events[0]
						case "unproved-prompt":
							for index, event := range mutant.Events {
								var row map[string]any
								_ = json.Unmarshal(event.Data, &row)
								if row["event"] == "card-data-created" || row["event"] == "overwrite-confirmed" {
									delete(row, "prompt")
									mutant.Events[index].Data, _ = json.Marshal(row)
								}
							}
						}
						mutantRaw, _ := json.Marshal(mutant)
						outcome, err := reportProbeEvidence(mutantRaw)
						if err == nil && outcome.Status == "PASS" {
							t.Error(variant, "promoted incomplete source story")
						}
					}
					continue
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
					return
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
			if cohort == "sequence" {
				original, _ := os.ReadFile(pairedCardPath)
				if !bytes.Equal(original, initialCard) {
					t.Fatal("sequence original H0 mutated")
				}
				input, _ := json.Marshal(sequenceSpec)
				if _, err := runProbeSequence(input); err == nil {
					t.Fatal("pending/source prefix replay admitted")
				}
				for _, variant := range []string{"wrong-carry-claim", "failed-first-run"} {
					var mutant ProbeSequenceSpec
					_ = json.Unmarshal(input, &mutant)
					mutant.Root = t.TempDir()
					_ = os.Chmod(mutant.Root, 0700)
					for index := range mutant.Profiles {
						mutant.Profiles[index].Root = filepath.Join(mutant.Root, fmt.Sprintf("run-%d", index+1))
						_ = os.Mkdir(mutant.Profiles[index].Root, 0700)
					}
					if variant == "wrong-carry-claim" {
						mutant.Profiles[1].Inputs["card"] = mutant.Profiles[0].Inputs["card"]
					} else {
						mutant.Profiles[0].Scenario.MaxUIReads = 1
					}
					mutantRaw, _ := json.Marshal(mutant)
					outcome, err := runProbeSequence(mutantRaw)
					if variant == "wrong-carry-claim" {
						if err == nil || len(outcome.Runs) != 0 {
							t.Fatal("unqualified carry claim reached execution")
						}
					} else if err != nil || outcome.Status != "INCOMPLETE" || len(outcome.Runs) != 1 || outcome.Runs[0].Carry != nil {
						t.Fatal("failed source run promoted carry/next profile")
					}
					for _, name := range []string{"carry-1.ps2", "run-2-profile.json"} {
						if _, err := os.Lstat(filepath.Join(mutant.Root, name)); !os.IsNotExist(err) {
							t.Fatal("failed source run published", name)
						}
					}
				}
			}
		})
	}
}
