package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// readProbeMemory separates admitted planning, bounded acquisition and finite
// decoding. A saved transcript or synthetic peer never acquires live provenance.
// Reads are sequential observations, not an atomic UI snapshot or hook ABI proof.
func readProbeMemory(raw, runtimeRaw []byte) (ProbeMemoryReport, error) {
	var report ProbeMemoryReport
	if len(raw) == 0 || len(raw) > 4<<20 {
		return report, fmt.Errorf("probe memory bundle exceeds its 4MiB input bound")
	}
	if err := checkJSON(checkedJSON{raw: raw, allObjects: true, text: true}); err != nil {
		return report, err
	}
	var plan ProbeMemoryBundle
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return report, err
	}
	if plan.Version != 1 || plan.SourceSHA256 != "5439db31097c19d3b92969d5403c2c19dc3518cea4ed4c075df1a3830b8ef56f" {
		return report, fmt.Errorf("unsupported probe memory version or source")
	}
	admission, err := admitProbeRecords(plan.Admission)
	if err != nil {
		return report, fmt.Errorf("probe memory admission: %w", err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(plan.BuildSHA256) {
		return report, fmt.Errorf("probe memory requires an exact executable build hash")
	}
	if len(plan.Requests) < 1 || len(plan.Requests) > 512 || len(plan.Decoders) < 1 || len(plan.Decoders) > 128 {
		return report, fmt.Errorf("probe memory requires 1..512 reads and 1..128 decoders")
	}
	requests := map[string]ProbeMemoryRequest{}
	for _, request := range plan.Requests {
		if request.ID == "" || len(request.ID) > 128 || requests[request.ID].ID != "" || request.Opcode == nil || request.Address == nil {
			return report, fmt.Errorf("probe memory requests require distinct IDs, opcode and address")
		}
		if *request.Opcode > 3 {
			return report, fmt.Errorf("probe memory permits only read opcodes0..3")
		}
		width := uint32(1) << *request.Opcode
		if *request.Address > 0x2000000-width {
			return report, fmt.Errorf("probe memory address outside EE RAM")
		}
		requests[request.ID] = request
	}
	for id := range plan.WordGuards {
		request, ok := requests[id]
		if !ok || *request.Opcode != 2 {
			return report, fmt.Errorf("probe word guards require declared u32 reads")
		}
	}
	if len(plan.WordGuards) > 0 && strings.TrimSpace(plan.DiagnosticVersion) == "" {
		return report, fmt.Errorf("diagnostic word guards require an explicit version")
	}
	decoderIDs := map[string]bool{}
	for _, decoder := range plan.Decoders {
		if decoder.ID == "" || len(decoder.ID) > 128 || decoderIDs[decoder.ID] || len(decoder.Requests) == 0 || len(decoder.Requests) > 512 {
			return report, fmt.Errorf("probe decoders require distinct IDs and declared reads")
		}
		decoderIDs[decoder.ID] = true
		if !slices.Contains([]string{"scalar", "frame_tags", "fixed", "player", "cursor", "texture", "char"}, decoder.Kind) {
			return report, fmt.Errorf("unsupported probe memory decoder %q", decoder.Kind)
		}
		for _, id := range decoder.Requests {
			if requests[id].ID == "" {
				return report, fmt.Errorf("probe decoder names an undeclared read")
			}
		}
	}
	report = ProbeMemoryReport{Version: 1, BundleSHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), SourceSHA256: plan.SourceSHA256, BuildSHA256: plan.BuildSHA256, Session: admission.Session, Epoch: admission.Epoch, ISOSHA256: admission.ISOSHA256, Provenance: "saved", SessionEvidenceSHA256: fmt.Sprintf("%x", sha256.Sum256(plan.Admission)), Observations: []ProbeMemoryObservation{}, Decoded: []ProbeMemoryDecoded{}, DiagnosticVersion: plan.DiagnosticVersion, Limits: "Sequential source-bound reads, not atomic UI state, visual verification, hook ABI proof or runtime handover. Synthetic peer provenance is never native qualification."}
	var runtime ProbeMemoryRuntime
	var owned ProbeProcessRecord
	var rootInfo os.FileInfo
	var sessionInfo os.FileInfo
	var connection net.Conn
	if len(runtimeRaw) > 0 {
		if len(runtimeRaw) > 65536 {
			return report, fmt.Errorf("probe runtime descriptor exceeds64KiB")
		}
		if err := checkJSON(checkedJSON{raw: runtimeRaw, allObjects: true, text: true, nonNull: true}); err != nil {
			return report, err
		}
		decoder := json.NewDecoder(bytes.NewReader(runtimeRaw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&runtime); err != nil {
			return report, err
		}
		if !slices.Contains([]string{"synthetic_peer", "live"}, runtime.Provenance) || runtime.TimeoutMS < 1 || runtime.TimeoutMS > 1000 || !filepath.IsAbs(runtime.Root) || filepath.Clean(runtime.Root) != runtime.Root {
			return report, fmt.Errorf("probe runtime requires explicit provenance, private root and1..1000ms deadline")
		}
		rootInfo, err = os.Lstat(runtime.Root)
		if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0700 {
			return report, fmt.Errorf("probe runtime root must be an owned private0700 directory")
		}
		stat, ok := rootInfo.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Getuid()) {
			return report, fmt.Errorf("probe runtime root must be owned by this user")
		}
		resolved, resolveErr := filepath.EvalSymlinks(runtime.Root)
		if resolveErr != nil || resolved != runtime.Root {
			return report, fmt.Errorf("probe runtime root must not traverse symlinks")
		}
		if len(plan.Replies) != 0 {
			return report, fmt.Errorf("runtime acquisition must not supply saved replies")
		}
		var records ProbeRecordBundle
		_ = json.Unmarshal(plan.Admission, &records)
		for _, record := range records.Records {
			if record.Role == "owned" {
				_ = json.Unmarshal(record.Data, &owned)
			}
		}
		if owned.PID <= 0 {
			return report, fmt.Errorf("probe runtime requires an admitted owned process")
		}
		report.Provenance = runtime.Provenance
	} else if len(plan.Replies) != len(plan.Requests) {
		return report, fmt.Errorf("saved probe memory requires one complete packet per read")
	}
	// The same checks bracket acquisition. /proc is fixed for actual live reads;
	// the synthetic root is only a protocol-test namespace and stays labeled so.
	values := map[string]uint64{}
	payloads := map[string][]byte{}
	for phase := 0; phase < 2; phase++ {
		if len(runtimeRaw) > 0 {
			currentRoot, rootErr := os.Lstat(runtime.Root)
			if rootErr != nil || !os.SameFile(rootInfo, currentRoot) || currentRoot.Mode().Perm() != 0700 {
				return ProbeMemoryReport{}, fmt.Errorf("probe runtime root identity changed")
			}
			receiptPath := filepath.Join(runtime.Root, "records.json")
			receiptInfo, receiptErr := os.Lstat(receiptPath)
			if receiptErr != nil || !receiptInfo.Mode().IsRegular() || receiptInfo.Mode().Perm() != 0600 {
				return ProbeMemoryReport{}, fmt.Errorf("probe runtime requires a private regular session receipt")
			}
			if phase == 0 {
				sessionInfo = receiptInfo
			} else if !os.SameFile(sessionInfo, receiptInfo) {
				return ProbeMemoryReport{}, fmt.Errorf("probe runtime session receipt identity changed")
			}
			receipt, receiptErr := readInput(receiptPath, 1<<20)
			if receiptErr != nil || !bytes.Equal(receipt, plan.Admission) {
				return ProbeMemoryReport{}, fmt.Errorf("probe runtime admitted session evidence changed")
			}
			procRoot := "/proc"
			if runtime.Provenance == "synthetic_peer" {
				procRoot = filepath.Join(runtime.Root, "proc")
			}
			processRoot := filepath.Join(procRoot, strconv.Itoa(owned.PID))
			if runtime.Provenance == "synthetic_peer" {
				for _, path := range []string{procRoot, processRoot, filepath.Join(processRoot, "stat"), filepath.Join(processRoot, "cmdline"), filepath.Join(processRoot, "exe")} {
					info, err := os.Lstat(path)
					if err != nil || info.Mode()&os.ModeSymlink != 0 {
						return ProbeMemoryReport{}, fmt.Errorf("synthetic probe process paths must not traverse symlinks")
					}
				}
			}
			statFile, statErr := os.Open(filepath.Join(processRoot, "stat"))
			if statErr != nil {
				return ProbeMemoryReport{}, fmt.Errorf("probe runtime process stat unavailable")
			}
			statBytes, readErr := io.ReadAll(io.LimitReader(statFile, 65537))
			_ = statFile.Close()
			end := bytes.LastIndexByte(statBytes, ')')
			fields := []string{}
			if end >= 0 {
				fields = strings.Fields(string(statBytes[end+1:]))
			}
			if readErr != nil || len(statBytes) > 65536 || len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
				return ProbeMemoryReport{}, fmt.Errorf("probe runtime process identity is stale")
			}
			starttime, parseErr := strconv.ParseUint(fields[19], 10, 64)
			pidText, _, _ := strings.Cut(string(statBytes), " ")
			pid, parsePIDErr := strconv.Atoi(pidText)
			if parseErr != nil || parsePIDErr != nil || pid != owned.PID || starttime != owned.Starttime {
				return ProbeMemoryReport{}, fmt.Errorf("probe runtime process identity is stale")
			}
			cmdFile, cmdErr := os.Open(filepath.Join(processRoot, "cmdline"))
			if cmdErr != nil {
				return ProbeMemoryReport{}, fmt.Errorf("probe runtime process command unavailable")
			}
			cmdBytes, cmdErr := io.ReadAll(io.LimitReader(cmdFile, 65537))
			_ = cmdFile.Close()
			cmdline := strings.Split(strings.TrimSuffix(string(cmdBytes), "\x00"), "\x00")
			if cmdErr != nil || len(cmdBytes) > 65536 || !reflect.DeepEqual(cmdline, owned.Cmdline) {
				return ProbeMemoryReport{}, fmt.Errorf("probe runtime process command changed")
			}
			executable, exeErr := os.Open(filepath.Join(processRoot, "exe"))
			if exeErr != nil {
				return ProbeMemoryReport{}, fmt.Errorf("probe runtime executable unavailable")
			}
			before, exeErr := executable.Stat()
			hasher := sha256.New()
			count, hashErr := io.Copy(hasher, io.LimitReader(executable, (256<<20)+1))
			after, afterErr := executable.Stat()
			_ = executable.Close()
			if exeErr != nil || hashErr != nil || afterErr != nil || !before.Mode().IsRegular() || count < 1 || count > 256<<20 || count != before.Size() || before.Size() != after.Size() || before.ModTime() != after.ModTime() || fmt.Sprintf("%x", hasher.Sum(nil)) != plan.BuildSHA256 {
				return ProbeMemoryReport{}, fmt.Errorf("probe runtime executable build differs")
			}
			if phase == 0 {
				socketPath := filepath.Join(processRoot, "root/run/user/1000/pcsx2.sock")
				if runtime.Provenance == "synthetic_peer" {
					socketPath = filepath.Join(runtime.Root, "peer.sock")
				}
				connection, err = net.DialTimeout("unix", socketPath, time.Duration(runtime.TimeoutMS)*time.Millisecond)
				if err != nil {
					return ProbeMemoryReport{}, fmt.Errorf("probe read-only connection failed: %w", err)
				}
				defer connection.Close()
				if runtime.Provenance == "live" {
					file, fileErr := connection.(*net.UnixConn).File()
					if fileErr != nil {
						return ProbeMemoryReport{}, fileErr
					}
					credentials, credentialErr := syscall.GetsockoptUcred(int(file.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
					_ = file.Close()
					if credentialErr != nil || int(credentials.Pid) != owned.PID || credentials.Uid != uint32(os.Getuid()) {
						return ProbeMemoryReport{}, fmt.Errorf("probe socket peer is not the exact owned process")
					}
				}
				if err := connection.SetDeadline(time.Now().Add(time.Duration(runtime.TimeoutMS) * time.Millisecond)); err != nil {
					return ProbeMemoryReport{}, err
				}
			} else {
				report.ProcessGuarded = runtime.Provenance == "live"
			}
		}
		if phase == 1 {
			break
		}
		for index, request := range plan.Requests {
			requestBytes := make([]byte, 9)
			binary.LittleEndian.PutUint32(requestBytes, 9)
			requestBytes[4] = *request.Opcode
			binary.LittleEndian.PutUint32(requestBytes[5:], *request.Address)
			width := 1 << *request.Opcode
			reply := make([]byte, 5+width)
			if connection == nil {
				var decodeErr error
				reply, decodeErr = hex.DecodeString(plan.Replies[index])
				if decodeErr != nil {
					return ProbeMemoryReport{}, fmt.Errorf("probe packet requires hexadecimal bytes")
				}
			} else {
				if _, err := io.Copy(connection, bytes.NewReader(requestBytes)); err != nil {
					return ProbeMemoryReport{}, fmt.Errorf("probe request failed: %w", err)
				}
				if _, err := io.ReadFull(connection, reply[:4]); err != nil {
					return ProbeMemoryReport{}, fmt.Errorf("incomplete probe packet: %w", err)
				}
				if binary.LittleEndian.Uint32(reply) != uint32(len(reply)) {
					return ProbeMemoryReport{}, fmt.Errorf("unexpected probe packet length")
				}
				if _, err := io.ReadFull(connection, reply[4:]); err != nil {
					return ProbeMemoryReport{}, fmt.Errorf("incomplete probe packet: %w", err)
				}
			}
			if len(reply) != 5+width || binary.LittleEndian.Uint32(reply) != uint32(5+width) {
				return ProbeMemoryReport{}, fmt.Errorf("unexpected probe packet length")
			}
			if reply[4] != 0 {
				return ProbeMemoryReport{}, fmt.Errorf("probe memory read failed")
			}
			var padded [8]byte
			copy(padded[:], reply[5:])
			value := binary.LittleEndian.Uint64(padded[:])
			if expected, guard := plan.WordGuards[request.ID]; guard && value != uint64(expected) {
				return ProbeMemoryReport{}, fmt.Errorf("probe diagnostic word guard differs at %s", request.ID)
			}
			values[request.ID] = value
			payloads[request.ID] = reply[5:]
			report.Observations = append(report.Observations, ProbeMemoryObservation{ID: request.ID, RequestHex: hex.EncodeToString(requestBytes), ReplyHex: hex.EncodeToString(reply), Value: value})
		}
	}
	// Decoders consume only the acquired finite read set; they never follow a
	// pointer or open a caller path. Invalid native observations stay unsupported.
	for _, decoder := range plan.Decoders {
		result := ProbeMemoryDecoded{ID: decoder.ID, Kind: decoder.Kind, Status: "KNOWN"}
		var data []byte
		for _, id := range decoder.Requests {
			data = append(data, payloads[id]...)
		}
		first := requests[decoder.Requests[0]]
		switch decoder.Kind {
		case "scalar":
			if len(decoder.Requests) != 1 {
				return report, fmt.Errorf("scalar decoder requires one read")
			}
			value := values[first.ID]
			result.Value = &value
		case "frame_tags":
			if len(decoder.Requests) != 3 {
				return report, fmt.Errorf("frame tags require three source reads")
			}
			expectedAddresses := []uint32{0x56581c, 0x56b598, 0x56b18c}
			expectedOpcodes := []uint8{1, 1, 0}
			for i, id := range decoder.Requests {
				request := requests[id]
				if *request.Address != expectedAddresses[i] || *request.Opcode != expectedOpcodes[i] {
					return report, fmt.Errorf("frame tag source layout differs")
				}
				result.FrameTags = append(result.FrameTags, values[id])
			}
		case "fixed":
			_, glyphs, mapErr := glyphMaps(decoder.Glyphmap, true)
			if mapErr != nil || len(data) != 16 {
				return report, fmt.Errorf("fixed decoder requires16 source bytes and a valid glyphmap")
			}
			next := uint64(*first.Address)
			for _, id := range decoder.Requests {
				request := requests[id]
				if uint64(*request.Address) != next {
					return report, fmt.Errorf("fixed field reads must be contiguous")
				}
				next += uint64(1) << *request.Opcode
			}
			shape, scanErr := controls(data, TextScanOptions{Decode: true, Glyphs: glyphs, FixedWords: 8})
			if scanErr != nil {
				return report, fmt.Errorf("unsupported fixed memory field: %w", scanErr)
			}
			var text strings.Builder
			for _, token := range shape.Tokens {
				if token.Word == 0 {
					text.WriteByte(' ')
				} else {
					text.WriteString(glyphs[token.Word])
				}
			}
			value := strings.TrimRight(text.String(), sourceWhitespace)
			result.Text = &value
		case "player":
			if len(data) != 508 || len(decoder.Requests) != 127 {
				return report, fmt.Errorf("player decoder requires the complete508-byte native record")
			}
			for i, id := range decoder.Requests {
				request := requests[id]
				if *request.Opcode != 2 || uint64(*request.Address) != uint64(*first.Address)+uint64(i*4) {
					return report, fmt.Errorf("player record reads must preserve complete contiguous u32 layout")
				}
			}
			control, square, money, flags := uint32(data[241]), uint32(data[250]), binary.LittleEndian.Uint32(data[304:]), uint32(data[0])
			player := ProbeSavedPlayer{Control: &control, Square: &square, Money: &money, TutorialFlags: &flags, RecordSHA256: fmt.Sprintf("%x", sha256.Sum256(data)), NameWords: []uint32{}}
			for offset := 252; offset < 272; offset += 4 {
				player.NameWords = append(player.NameWords, binary.LittleEndian.Uint32(data[offset:]))
			}
			initialized := bytes.Clone(data)
			initialized[0] |= 1
			player.TutorialInitializedSHA256 = fmt.Sprintf("%x", sha256.Sum256(initialized))
			result.Player = &player
		case "cursor":
			base := *first.Address
			if base < 0x100000 || base > 0x2000000-0x50 {
				result.Status, result.Reason = "UNSUPPORTED", "native cursor pointer outside source bounds"
				break
			}
			if len(decoder.Requests) != 5 {
				return report, fmt.Errorf("cursor decoder requires five source fields")
			}
			offsets := []uint32{0, 0x16, 0x18, 0x1a, 0x1c}
			for i, id := range decoder.Requests {
				request := requests[id]
				opcode := uint8(1)
				if i == 0 {
					opcode = 0
				}
				if *request.Address != base+offsets[i] || *request.Opcode != opcode {
					return report, fmt.Errorf("cursor source field layout differs")
				}
			}
			cursor := values[decoder.Requests[0]]*(values[decoder.Requests[2]]+values[decoder.Requests[4]]) + values[decoder.Requests[1]] + values[decoder.Requests[3]]
			result.Cursor = &cursor
		case "texture":
			primitive := values[first.ID]
			if *first.Opcode != 2 || primitive&3 != 0 || primitive < 0x100000 || primitive > 0x2000000-0x20 {
				result.Status, result.Reason = "UNSUPPORTED", "native image primitive outside source bounds"
				break
			}
			if len(decoder.Requests) < 2 {
				return report, fmt.Errorf("texture decoder lacks its pointer read")
			}
			textureRequest := requests[decoder.Requests[1]]
			texture := values[textureRequest.ID]
			if *textureRequest.Opcode != 2 || uint64(*textureRequest.Address) != primitive+8 {
				return report, fmt.Errorf("texture pointer source layout differs")
			}
			if texture&3 != 0 || texture < 0x100000 || texture > 0x2000000-0x60 {
				result.Status, result.Reason = "UNSUPPORTED", "native texture pointer outside source bounds"
				break
			}
			if len(decoder.Requests) != 6 {
				return report, fmt.Errorf("texture decoder requires its complete32-byte name")
			}
			var name []byte
			for i, id := range decoder.Requests[2:] {
				request := requests[id]
				if *request.Opcode != 3 || uint64(*request.Address) != texture+0x10+uint64(i*8) {
					return report, fmt.Errorf("texture name source layout differs")
				}
				name = append(name, payloads[id]...)
			}
			end := bytes.IndexByte(name, 0)
			if end < 0 {
				result.Status, result.Reason = "UNSUPPORTED", "native texture name lacks ASCII terminator"
				break
			}
			ascii := true
			for _, value := range name[:end] {
				if value > 127 {
					ascii = false
				}
			}
			if !ascii {
				result.Status, result.Reason = "UNSUPPORTED", "native texture name lacks ASCII terminator"
				break
			}
			value := string(name[:end])
			result.Text = &value
		case "char":
			node := values[first.ID]
			if *first.Opcode != 2 || node < 0x100000 || node > 0x2000000-0x20 {
				result.Status, result.Reason = "UNSUPPORTED", "native glyph node outside source bounds"
				break
			}
			if len(decoder.Requests) != 3 {
				return report, fmt.Errorf("glyph node decoder requires two native label words")
			}
			var label []byte
			for i, id := range decoder.Requests[1:] {
				request := requests[id]
				if *request.Opcode != 3 || uint64(*request.Address) != node+0x10+uint64(i*8) {
					return report, fmt.Errorf("glyph node source layout differs")
				}
				label = append(label, payloads[id]...)
			}
			if end := bytes.IndexByte(label, 0); end >= 0 {
				label = label[:end]
			}
			if len(label) <= 4 || !bytes.HasPrefix(label, []byte("char")) {
				result.Status, result.Reason = "UNSUPPORTED", "native glyph label is not charN"
				break
			}
			digits := true
			for _, value := range label[4:] {
				if value < '0' || value > '9' {
					digits = false
				}
			}
			_, _, mapErr := glyphMaps(decoder.Glyphmap, true)
			var sourceGlyphs map[string]string
			_ = json.Unmarshal(decoder.Glyphmap, &sourceGlyphs)
			value := sourceGlyphs[string(label[4:])]
			if !digits || mapErr != nil || value == "" {
				result.Status, result.Reason = "UNSUPPORTED", "native glyph label is unknown"
				break
			}
			result.Text = &value
		}
		report.Decoded = append(report.Decoded, result)
	}
	return report, nil
}
