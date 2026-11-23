package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// serveProbePad owns one private endpoint and input device/event sink. Clients
// half-close after one bounded legacy command payload; every effect gets an ack.
// Cancellation releases held inputs and only this service's own socket/device.
func serveProbePad(ctx context.Context, spec ProbePadSpec, ready chan<- error, done chan<- error) {
	if spec.Published != nil {
		*spec.Published = ProbeArtifactClaim{}
	}
	var layout ProbePadLayout
	if err := json.Unmarshal(probePadLayout, &layout); err != nil {
		ready <- err
		done <- err
		return
	}
	if spec.Backend != "event-sink" && spec.Backend != "uinput" && spec.Backend != "private-x11" {
		err := fmt.Errorf("unsupported owned pad backend")
		ready <- err
		done <- err
		return
	}
	if spec.Backend == "private-x11" && (!probeX11Available || spec.PrivateX11 == nil || spec.Native == nil || spec.CleanupMS < 1 || spec.CleanupMS > 10000) {
		err := fmt.Errorf("private X11 input requires its available SDK, pinned server and native binding")
		ready <- err
		done <- err
		return
	}
	info, err := os.Lstat(spec.Root)
	resolved, resolveErr := filepath.EvalSymlinks(spec.Root)
	if err != nil || resolveErr != nil || resolved != spec.Root || !info.IsDir() || info.Mode().Perm() != 0700 {
		err = fmt.Errorf("owned pad requires a private canonical root")
		ready <- err
		done <- err
		return
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) {
		err = fmt.Errorf("owned pad root has another owner")
		ready <- err
		done <- err
		return
	}
	setup := make([]byte, 92)
	for index, value := range []uint16{layout.Bus, layout.Vendor, layout.Product, layout.DeviceVersion} {
		binary.LittleEndian.PutUint16(setup[index*2:], value)
	}
	copy(setup[8:88], layout.Name)
	binary.LittleEndian.PutUint32(setup[88:], layout.MaxEffects)
	var axes []byte
	for _, axis := range layout.Axes {
		data := make([]byte, 28)
		binary.LittleEndian.PutUint16(data, axis.Code)
		binary.LittleEndian.PutUint32(data[8:], uint32(axis.Min))
		binary.LittleEndian.PutUint32(data[12:], uint32(axis.Max))
		binary.LittleEndian.PutUint32(data[16:], uint32(axis.Fuzz))
		binary.LittleEndian.PutUint32(data[20:], uint32(axis.Flat))
		axes = append(axes, data...)
	}
	planBytes, _ := json.Marshal(map[string]any{"source_format": "go-owned-pad-v1", "backend": spec.Backend, "setup_hex": hex.EncodeToString(setup), "axes_hex": hex.EncodeToString(axes), "phys": layout.Phys, "layout": json.RawMessage(probePadLayout)})
	var device *os.File
	created := false
	// Setup binds keyboard/mouse IDs before this service's sequential command loop.
	var forwarderIDs [2]uint16
	if spec.Backend == "private-x11" {
		planBytes, _ = json.Marshal(map[string]any{"source_format": "go-owned-private-keyboard-v1", "backend": spec.Backend, "private_x11": spec.PrivateX11, "layout_sha256": fmt.Sprintf("%x", sha256.Sum256(probePadLayout)), "layout": json.RawMessage(probePadLayout)})
		setupCtx, setupCancel := context.WithTimeout(ctx, time.Second)
		_, err = emitProbeX11(setupCtx, *spec.PrivateX11, nil, spec.BuildSHA256, nil, false, &forwarderIDs)
		setupCancel()
	} else if spec.Backend == "event-sink" {
		device, err = os.OpenFile(filepath.Join(spec.Root, "pad-events.bin"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	} else {
		if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
			err = fmt.Errorf("uinput ABI is qualified only for Linux amd64")
		} else {
			device, err = os.OpenFile("/dev/uinput", os.O_WRONLY|syscall.O_NONBLOCK, 0600)
		}
	}
	if err != nil {
		ready <- err
		done <- err
		return
	}
	var result error
	if spec.Backend == "uinput" {
		// _IOW(int) setters take scalar values; setup/abs/phys take direct pointers.
		for _, eventType := range []uint16{1, 3} {
			_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, device.Fd(), 0x40045564, uintptr(eventType))
			if errno != 0 {
				result = errno
				break
			}
		}
		var keys []uint16
		for _, button := range layout.Buttons {
			if button.Type == 1 {
				keys = append(keys, button.Code)
			}
		}
		slices.Sort(keys)
		for _, code := range keys {
			if result != nil {
				break
			}
			_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, device.Fd(), 0x40045565, uintptr(code))
			if errno != 0 {
				result = errno
			}
		}
		for index, axis := range layout.Axes {
			if result != nil {
				break
			}
			_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, device.Fd(), 0x40045567, uintptr(axis.Code))
			if errno != 0 {
				result = errno
				break
			}
			_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, device.Fd(), 0x401c5504, uintptr(unsafe.Pointer(&axes[index*28])))
			if errno != 0 {
				result = errno
			}
		}
		if result == nil {
			phys := append([]byte(layout.Phys), 0)
			_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, device.Fd(), 0x4008556c, uintptr(unsafe.Pointer(&phys[0])))
			if errno != 0 {
				result = errno
			}
		}
		if result == nil {
			_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, device.Fd(), 0x405c5503, uintptr(unsafe.Pointer(&setup[0])))
			if errno != 0 {
				result = errno
			}
		}
		if result == nil {
			_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, device.Fd(), 0x5501, 0)
			if errno != 0 {
				result = errno
			} else {
				created = true
			}
		}
	}
	if result != nil {
		if device != nil {
			_ = device.Close()
		}
		ready <- result
		done <- result
		return
	}
	planSHA := fmt.Sprintf("%x", sha256.Sum256(planBytes))
	verified, err := writeNewFile(filepath.Join(spec.Root, "pad-device.json"), spec.DeviceParent, bytes.NewReader(planBytes), int64(len(planBytes)), planSHA, 0600)
	if err == nil && spec.Published != nil {
		if spec.DeviceParent == nil {
			err = fmt.Errorf("accounted pad setup requires its pinned parent")
		} else {
			err = spec.DeviceParent.Sync()
		}
		if err == nil {
			*spec.Published = ProbeArtifactClaim{ID: "artifact:" + filepath.Join(spec.Root, "pad-device.json"), Path: filepath.Join(spec.Root, "pad-device.json"), Class: probeArtifactNormal, MaxFinalBytes: uint64(len(planBytes)), ExpectedInfo: verified, ExpectedSHA256: planSHA}
		}
	}
	if err != nil {
		if created {
			_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, device.Fd(), 0x5502, 0)
		}
		if device != nil {
			_ = device.Close()
		}
		ready <- err
		done <- err
		return
	}
	socketPath := filepath.Join(spec.Root, "pad.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		if created {
			_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, device.Fd(), 0x5502, 0)
		}
		_ = device.Close()
		ready <- err
		done <- err
		return
	}
	listener.SetUnlinkOnClose(false)
	socketInfo, _ := os.Lstat(socketPath)
	held := map[string]bool{}
	ready <- nil
service:
	for {
		if ctx.Err() != nil {
			break
		}
		_ = listener.SetDeadline(time.Now().Add(100 * time.Millisecond))
		client, err := listener.AcceptUnix()
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			result = err
			break
		}
		peerFile, peerErr := client.File()
		if peerErr != nil {
			_ = client.Close()
			result = peerErr
			break
		}
		credentials, credentialErr := syscall.GetsockoptUcred(int(peerFile.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		_ = peerFile.Close()
		if credentialErr != nil || int(credentials.Pid) != os.Getpid() || credentials.Uid != uint32(os.Getuid()) {
			_, _ = io.WriteString(client, "err not the owned controller\n")
			_ = client.Close()
			continue
		}
		_ = client.SetDeadline(time.Now().Add(time.Second))
		command, readErr := io.ReadAll(io.LimitReader(client, 257))
		fields := strings.Fields(string(command))
		reply := "ok\n"
		names := []string{}
		duration := time.Duration(0)
		valid := readErr == nil && len(command) <= 256
		captureID := ""
		if (len(fields) == 3 || spec.Backend == "private-x11" && len(fields) == 4) && fields[0] == "tap" {
			if len(fields) == 4 {
				captureID = fields[3]
				valid = valid && fields[1] == "GUIDE" && regexp.MustCompile(probeCaptureIDPattern).MatchString(captureID)
			}
			names = strings.Split(strings.ToUpper(fields[1]), "+")
			seconds, err := strconv.ParseFloat(fields[2], 64)
			if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0.01 || seconds > 1 {
				valid = false
			} else {
				duration = time.Duration(seconds * float64(time.Second))
			}
		} else if len(fields) == 1 && fields[0] == "releaseall" {
			for name := range held {
				names = append(names, name)
			}
			slices.Sort(names)
		} else if len(fields) == 1 && fields[0] == "quit" {
			_, _ = io.WriteString(client, reply)
			_ = client.Close()
			break
		} else {
			valid = false
		}
		seen := map[string]bool{}
		for _, name := range names {
			if _, ok := layout.Buttons[name]; !ok || seen[name] {
				valid = false
			}
			if spec.Backend == "private-x11" && layout.Buttons[name].KeyboardBinding == "" {
				valid = false
			}
			seen[name] = true
		}
		if spec.Backend == "private-x11" && len(fields) >= 3 {
			valid = valid && len(names) == 1 && (names[0] != "GUIDE" || captureID != "")
		}
		if !valid {
			_, _ = io.WriteString(client, "err invalid owned pad command\n")
			_ = client.Close()
			continue
		}
		workCtx, workCancel := context.WithTimeout(ctx, time.Second)
		var x11Effect *ProbeX11Effect
		if spec.MaxEventBytes > 0 && spec.Backend == "event-sink" {
			info, statErr := device.Stat()
			needed := int64(len(names)+len(held)) * 48
			if duration > 0 {
				needed += int64(len(names)) * 48
			}
			if statErr != nil || info.Size() < 0 || needed > spec.MaxEventBytes || info.Size() > spec.MaxEventBytes-needed {
				workCancel()
				result = fmt.Errorf("owned pad command and release headroom exceed its reservation")
				_, _ = io.WriteString(client, "err input extent refused\n")
				_ = client.Close()
				break service
			}
		}
		for stage := 0; stage < 2; stage++ {
			if stage == 1 && duration > 0 {
				timer := time.NewTimer(duration)
				select {
				case <-timer.C:
				case <-ctx.Done():
				}
				timer.Stop()
			}
			for _, name := range names {
				button := layout.Buttons[name]
				value := int32(0)
				if stage == 0 && duration > 0 {
					value = button.Down
				}
				if spec.Backend == "private-x11" {
					key := strings.TrimPrefix(button.KeyboardBinding, "Keyboard/")
					if len(key) == 1 {
						key = strings.ToLower(key)
					}
					if value != 0 {
						held[name] = true
					}
					observed, inputErr := emitProbeX11(workCtx, *spec.PrivateX11, spec.Native.Load(), spec.BuildSHA256, []string{key}, value != 0, &forwarderIDs)
					if inputErr != nil {
						result = inputErr
						reply = "err private keyboard effect uncertain\n"
						break
					}
					x11Effect = &observed
					if value == 0 {
						delete(held, name)
					}
					continue
				}
				event := make([]byte, 48)
				binary.LittleEndian.PutUint16(event[16:], button.Type)
				binary.LittleEndian.PutUint16(event[18:], button.Code)
				binary.LittleEndian.PutUint32(event[20:], uint32(value))
				if spec.MaxEventBytes > 0 && spec.Backend == "event-sink" {
					info, statErr := device.Stat()
					if statErr != nil || info.Size() < 0 || info.Size() > spec.MaxEventBytes-int64(len(event)) {
						result = fmt.Errorf("owned pad event extent exceeded its reservation")
						reply = "err input extent refused\n"
						break
					}
				}
				if _, err := io.Copy(device, bytes.NewReader(event)); err != nil {
					result = err
					reply = "err input effect uncertain\n"
					break
				}
				if stage == 1 || duration == 0 {
					delete(held, name)
				} else {
					held[name] = true
				}
			}
			if result != nil {
				break
			}
			if duration == 0 {
				break
			}
		}
		workCancel()
		if spec.Backend == "event-sink" && result == nil {
			result = device.Sync()
		}
		if result != nil {
			reply = "err input effect uncertain\n"
		} else if spec.Backend == "private-x11" && len(names) == 1 && names[0] == "GUIDE" && x11Effect != nil {
			x11Effect.CaptureID = captureID
			encoded, _ := json.Marshal(x11Effect)
			reply = "ok " + string(encoded) + "\n"
		}
		_, _ = io.WriteString(client, reply)
		_ = client.Close()
		if result != nil {
			break service
		}
	}
	var heldNames []string
	for name := range held {
		heldNames = append(heldNames, name)
	}
	slices.Sort(heldNames)
	if spec.Backend == "private-x11" && len(heldNames) > 0 {
		var keys []string
		for _, name := range heldNames {
			key := strings.TrimPrefix(layout.Buttons[name].KeyboardBinding, "Keyboard/")
			if len(key) == 1 {
				key = strings.ToLower(key)
			}
			keys = append(keys, key)
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Duration(spec.CleanupMS)*time.Millisecond)
		_, releaseErr := emitProbeX11(cleanupCtx, *spec.PrivateX11, spec.Native.Load(), spec.BuildSHA256, keys, false, &forwarderIDs)
		cleanupCancel()
		if releaseErr != nil {
			result = errors.Join(result, fmt.Errorf("private keyboard release is uncertain: %w", releaseErr))
		}
		heldNames = nil
	}
	for _, name := range heldNames {
		button := layout.Buttons[name]
		event := make([]byte, 48)
		binary.LittleEndian.PutUint16(event[16:], button.Type)
		binary.LittleEndian.PutUint16(event[18:], button.Code)
		if _, err := io.Copy(device, bytes.NewReader(event)); err != nil && result == nil {
			result = err
		}
	}
	_ = listener.Close()
	if current, err := os.Lstat(socketPath); err == nil && socketInfo != nil && os.SameFile(socketInfo, current) {
		_ = os.Remove(socketPath)
	}
	if created {
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, device.Fd(), 0x5502, 0)
		if errno != 0 && result == nil {
			result = errno
		}
	}
	if device != nil {
		if err := device.Close(); err != nil && result == nil {
			result = err
		}
	}
	done <- result
}

// admit validates one logical-capture ACK against already admitted immutable
// transport/process facts. Live capture and saved replay share this pure gate;
// an F8 release acknowledgement is never a screenshot-completion acknowledgement.
func (effect *ProbeX11Effect) admit(ack []byte, captureID string, spec ProbeX11Spec, owned ProbeProcessRecord) error {
	*effect = ProbeX11Effect{}
	if len(ack) > 65536 || !bytes.HasPrefix(ack, []byte("ok ")) {
		return fmt.Errorf("private screenshot acknowledgement framing differs")
	}
	payload := bytes.TrimSpace(ack[3:])
	if err := checkJSON(checkedJSON{raw: payload, allObjects: true, text: true, requiredByDepth: map[int][]string{1: {"pressed"}}, nonNullByDepth: map[int][]string{1: {"pressed"}}, aliasesByDepth: map[int][]string{1: {"pressed"}}}); err != nil {
		return err
	}
	var decoded ProbeX11Effect
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	if decoded.CaptureID != captureID || !regexp.MustCompile(probeCaptureIDPattern).MatchString(captureID) {
		return fmt.Errorf("private screenshot acknowledgement belongs to another capture")
	}
	if decoded.Display != spec.Display || decoded.AuthoritySHA != spec.Authority.SHA256 || decoded.Server.PID != spec.Server.PID || decoded.Server.Starttime != spec.Server.Starttime || !slices.Equal(decoded.Server.Cmdline, spec.Server.Cmdline) {
		return fmt.Errorf("private screenshot server or credential identity differs")
	}
	if decoded.Window < 2 || decoded.ClientPID != owned.PID || decoded.Target.PID != owned.PID || decoded.Target.Starttime != owned.Starttime || decoded.Target.PINESocket != owned.PINESocket || decoded.Target.PINESlot != owned.PINESlot || decoded.Target.EnvironmentSHA256 != owned.EnvironmentSHA256 || !slices.Equal(decoded.Target.Cmdline, owned.Cmdline) {
		return fmt.Errorf("private screenshot window or owned native identity differs")
	}
	if !decoded.ForwardersOff || decoded.Pressed || !slices.Equal(decoded.Keys, []string{"F8"}) {
		return fmt.Errorf("private screenshot key release or input isolation differs")
	}
	*effect = decoded
	return nil
}
