package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
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
	var layout struct {
		Version              int
		Name                 string
		Phys                 string
		Bus, Vendor, Product uint16
		DeviceVersion        uint16 `json:"device_version"`
		MaxEffects           uint32 `json:"max_effects"`
		Buttons              map[string]struct {
			Type, Code uint16
			Down       int32
		}
		Axes []struct {
			Code                 uint16
			Min, Max, Fuzz, Flat int32
		}
	}
	if err := json.Unmarshal(probePadLayout, &layout); err != nil {
		ready <- err
		done <- err
		return
	}
	if spec.Backend != "event-sink" && spec.Backend != "uinput" {
		err := fmt.Errorf("unsupported owned pad backend")
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
	if spec.Backend == "event-sink" {
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
		_ = device.Close()
		ready <- result
		done <- result
		return
	}
	err = writeNewFile(filepath.Join(spec.Root, "pad-device.json"), bytes.NewReader(planBytes), int64(len(planBytes)), fmt.Sprintf("%x", sha256.Sum256(planBytes)), 0600)
	if err != nil {
		if created {
			_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, device.Fd(), 0x5502, 0)
		}
		_ = device.Close()
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
		if len(fields) == 3 && fields[0] == "tap" {
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
			seen[name] = true
		}
		if !valid {
			_, _ = io.WriteString(client, "err invalid owned pad command\n")
			_ = client.Close()
			continue
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
					held[name] = true
				}
				event := make([]byte, 48)
				binary.LittleEndian.PutUint16(event[16:], button.Type)
				binary.LittleEndian.PutUint16(event[18:], button.Code)
				binary.LittleEndian.PutUint32(event[20:], uint32(value))
				if _, err := io.Copy(device, bytes.NewReader(event)); err != nil {
					result = err
					reply = "err input effect uncertain\n"
					break
				}
				if stage == 1 || duration == 0 {
					delete(held, name)
				}
			}
			if result != nil {
				break
			}
			if duration == 0 {
				break
			}
		}
		if spec.Backend == "event-sink" && result == nil {
			result = device.Sync()
		}
		if result != nil {
			reply = "err input effect uncertain\n"
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
	if err := device.Close(); err != nil && result == nil {
		result = err
	}
	done <- result
}
