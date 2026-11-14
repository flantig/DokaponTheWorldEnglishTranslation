package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
		if !slices.Contains([]string{"synthetic_peer", "live", "owned_go"}, runtime.Provenance) || runtime.TimeoutMS < 1 || runtime.TimeoutMS > 1000 || !filepath.IsAbs(runtime.Root) || filepath.Clean(runtime.Root) != runtime.Root {
			return report, fmt.Errorf("probe runtime requires explicit provenance, private root and1..1000ms deadline")
		}
		if runtime.Provenance != "owned_go" && runtime.Evidence != nil || admission.SourceSchema == "go-probe-records-v1" && runtime.Provenance != "owned_go" {
			return report, fmt.Errorf("probe runtime producer and evidence format differ")
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
		if runtime.Provenance == "owned_go" && (records.GoOwner == nil || plan.BuildSHA256 != records.GoOwner.Profile.Program.SHA256 || runtime.Root != records.GoOwner.Profile.Root) {
			return report, fmt.Errorf("Go read build differs from lifecycle owner")
		}
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
			if runtime.Provenance == "owned_go" {
				if admission.SourceSchema != "go-probe-records-v1" || runtime.Evidence == nil {
					return ProbeMemoryReport{}, fmt.Errorf("Go runtime requires its explicit immutable Go evidence")
				}
				rel, err := filepath.Rel(runtime.Root, runtime.Evidence.Path)
				if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || runtime.Evidence.Size != int64(len(plan.Admission)) || runtime.Evidence.SHA256 != fmt.Sprintf("%x", sha256.Sum256(plan.Admission)) {
					return ProbeMemoryReport{}, fmt.Errorf("Go runtime evidence is outside its owned root or differs")
				}
				receiptPath = runtime.Evidence.Path
			}
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
			if _, err := observeProbeProcess(runtime, owned.PID, &owned, plan.BuildSHA256); err != nil {
				return ProbeMemoryReport{}, err
			}
			processRoot := filepath.Join("/proc", strconv.Itoa(owned.PID))
			if runtime.Provenance == "synthetic_peer" {
				processRoot = filepath.Join(runtime.Root, "proc", strconv.Itoa(owned.PID))
			}
			if phase == 0 {
				socketPath := filepath.Join(processRoot, "root/run/user/1000/pcsx2.sock")
				if runtime.Provenance == "synthetic_peer" || runtime.Provenance == "owned_go" {
					socketPath = filepath.Join(runtime.Root, "peer.sock")
				}
				connection, err = net.DialTimeout("unix", socketPath, time.Duration(runtime.TimeoutMS)*time.Millisecond)
				if err != nil {
					return ProbeMemoryReport{}, fmt.Errorf("probe read-only connection failed: %w", err)
				}
				defer connection.Close()
				if runtime.Provenance == "live" || runtime.Provenance == "owned_go" {
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
				report.ProcessGuarded = runtime.Provenance == "live" || runtime.Provenance == "owned_go"
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
				var frameErr error
				reply, frameErr = exchangeProbeFrame(connection, requestBytes, len(reply))
				if frameErr != nil {
					return ProbeMemoryReport{}, frameErr
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
	report.Decoded, err = decodeProbeMemory(requests, payloads, values, plan.Decoders)
	return report, err
}
