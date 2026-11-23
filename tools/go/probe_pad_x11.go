//go:build linux && cgo && nativex11

package main

/*
#cgo pkg-config: xcb xcb-res xcb-xinput xcb-xtest x11
#include <stdlib.h>
#include <X11/Xlib.h>
#include <xcb/xcb.h>
#include <xcb/res.h>
#include <xcb/xinput.h>
#include <xcb/xtest.h>
*/
import "C"

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const probeX11Available = true

// emitProbeX11 is the private server's SDK boundary. Empty keys perform setup only.
// XRes owns window PID proof; only Xephyr's physical forwarders are disabled.
// The caller owns logical holds/releases. Cancellation shuts down this connection,
// including a blocking SDK reply, without touching the server or host input.
// Fresh setup alone publishes keyboard/mouse IDs after verifying their disabled
// floating state. Later effects only read those service-local pins, never adopt.
func emitProbeX11(ctx context.Context, spec ProbeX11Spec, target *ProbeProcessRecord, build string, keys []string, pressed bool, forwarderIDs *[2]uint16) (ProbeX11Effect, error) {
	var effect ProbeX11Effect
	if _, bounded := ctx.Deadline(); !bounded || ctx.Err() != nil {
		return effect, fmt.Errorf("private X11 operation requires a live bounded deadline")
	}
	if forwarderIDs == nil || target == nil && *forwarderIDs != [2]uint16{} || target != nil && (forwarderIDs[0] == 0 || forwarderIDs[1] == 0 || forwarderIDs[0] == forwarderIDs[1]) {
		return effect, fmt.Errorf("private X11 forwarder pins require fresh setup or a complete distinct identity")
	}
	server, err := observeProbeProcess(ProbeMemoryRuntime{Provenance: "owned_child"}, spec.Server.PID, &spec.Server, spec.ServerProgram.SHA256)
	if err != nil {
		return effect, fmt.Errorf("private X11 server identity unavailable: %w", err)
	}
	serverNS, err := os.Stat(filepath.Join("/proc", strconv.Itoa(server.PID), "ns/pid"))
	selfNS, selfErr := os.Stat("/proc/self/ns/pid")
	if err != nil || selfErr != nil || !os.SameFile(serverNS, selfNS) {
		return effect, fmt.Errorf("private X11 server does not share the controller PID namespace")
	}
	if len(keys) > 7 || len(keys) > 0 && target == nil {
		return effect, fmt.Errorf("private X11 input lacks a bounded owned native target")
	}
	var native ProbeProcessRecord
	if target != nil {
		var err error
		if native, err = observeProbeProcess(ProbeMemoryRuntime{}, target.PID, target, build); err != nil {
			return effect, fmt.Errorf("private X11 native target changed: %w", err)
		}
	}
	info, err := os.Lstat(spec.Authority.Path)
	canonical, pathErr := filepath.EvalSymlinks(spec.Authority.Path)
	if err != nil || pathErr != nil || canonical != spec.Authority.Path || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return effect, fmt.Errorf("private X11 authority must be a canonical private file")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Getuid()) || owner.Nlink != 1 {
		return effect, fmt.Errorf("private X11 authority owner or link count differs")
	}
	authority, err := readInput(spec.Authority.Path, 65536)
	if err != nil || int64(len(authority)) != spec.Authority.Size || fmt.Sprintf("%x", sha256.Sum256(authority)) != spec.Authority.SHA256 {
		return effect, fmt.Errorf("private X11 authority identity differs")
	}
	defer clear(authority)
	var secret []byte
	for at := 0; at < len(authority); {
		if len(authority)-at < 2 {
			return effect, fmt.Errorf("private X11 authority record is truncated")
		}
		family := binary.BigEndian.Uint16(authority[at:])
		at += 2
		var fields [4][]byte
		for i := range fields {
			if len(authority)-at < 2 {
				return effect, fmt.Errorf("private X11 authority field is truncated")
			}
			n := int(binary.BigEndian.Uint16(authority[at:]))
			at += 2
			if n > len(authority)-at {
				return effect, fmt.Errorf("private X11 authority field exceeds its record")
			}
			fields[i], at = authority[at:at+n], at+n
		}
		if (family == 256 || family == 65535) && string(fields[1]) == strings.TrimPrefix(spec.Display, ":") && string(fields[2]) == "MIT-MAGIC-COOKIE-1" {
			if secret != nil || len(fields[3]) != 16 {
				return effect, fmt.Errorf("private X11 authority is ambiguous")
			}
			secret = fields[3]
		}
	}
	if secret == nil {
		return effect, fmt.Errorf("private X11 authority has no matching cookie")
	}
	socketPath := filepath.Join("/tmp/.X11-unix", "X"+strings.TrimPrefix(spec.Display, ":"))
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return effect, fmt.Errorf("private X11 socket unavailable: %w", err)
	}
	socket := connection.(*net.UnixConn)
	defer socket.Close()
	file, err := socket.File()
	if err != nil {
		return effect, err
	}
	peer, peerErr := syscall.GetsockoptUcred(int(file.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	fd, dupErr := syscall.Dup(int(file.Fd()))
	_ = file.Close()
	if peerErr != nil || dupErr != nil || int(peer.Pid) != server.PID || peer.Uid != uint32(os.Getuid()) {
		if dupErr == nil {
			_ = syscall.Close(fd)
		}
		return effect, fmt.Errorf("private X11 socket peer is not the pinned server")
	}
	// Go deadlines do not govern a duplicated fd used by C. Shutdown wakes its I/O.
	stop := context.AfterFunc(ctx, func() { _ = socket.CloseRead(); _ = socket.CloseWrite() })
	defer stop()
	name := C.CString("MIT-MAGIC-COOKIE-1")
	data := C.CBytes(secret)
	defer C.free(unsafe.Pointer(name))
	defer C.free(data)
	auth := C.xcb_auth_info_t{namelen: 18, name: name, datalen: 16, data: (*C.char)(data)}
	x := C.xcb_connect_to_fd(C.int(fd), &auth)
	if x == nil {
		_ = syscall.Close(fd)
		return effect, fmt.Errorf("private X11 authentication failed")
	}
	defer C.xcb_disconnect(x)
	if C.xcb_connection_has_error(x) != 0 {
		return effect, fmt.Errorf("private X11 authentication or connection failed")
	}
	version := C.xcb_res_query_version_reply(x, C.xcb_res_query_version(x, 1, 2), nil)
	if version == nil {
		return effect, fmt.Errorf("private X11 XRes unavailable")
	}
	resOK := version.server_major > 1 || version.server_major == 1 && version.server_minor >= 2
	C.free(unsafe.Pointer(version))
	if !resOK {
		return effect, fmt.Errorf("private X11 requires XRes1.2 local-client identity")
	}
	xi := C.xcb_input_xi_query_version_reply(x, C.xcb_input_xi_query_version(x, 2, 0), nil)
	if xi == nil {
		return effect, fmt.Errorf("private X11 XI2 unavailable")
	}
	xiOK := xi.major_version >= 2
	C.free(unsafe.Pointer(xi))
	if !xiOK {
		return effect, fmt.Errorf("private X11 XI2 version unavailable")
	}
	test := C.xcb_test_get_version_reply(x, C.xcb_test_get_version(x, 2, 2), nil)
	if test == nil {
		return effect, fmt.Errorf("private X11 XTEST unavailable")
	}
	C.free(unsafe.Pointer(test))
	propertyName := C.CString("Device Enabled")
	property := C.xcb_intern_atom_reply(x, C.xcb_intern_atom(x, 0, 14, propertyName), nil)
	C.free(unsafe.Pointer(propertyName))
	if property == nil {
		return effect, fmt.Errorf("private X11 input property unavailable")
	}
	atom := property.atom
	C.free(unsafe.Pointer(property))
	candidateIDs := *forwarderIDs
	for pass := 0; pass < 2; pass++ {
		devices := C.xcb_input_xi_query_device_reply(x, C.xcb_input_xi_query_device(x, C.XCB_INPUT_DEVICE_ALL), nil)
		if devices == nil {
			return effect, fmt.Errorf("private X11 device inventory unavailable")
		}
		if devices.num_infos > 32 || devices.length > 16384 {
			C.free(unsafe.Pointer(devices))
			return effect, fmt.Errorf("private X11 device inventory exceeds bounds")
		}
		forwarders, testKeyboard, testPointer := 0, false, false
		seen := map[string]bool{}
		seenIDs := map[uint16]bool{}
		var masters, masterAttachments, testAttachments, forwarderAttachments [2]uint16
		iter := C.xcb_input_xi_query_device_infos_iterator(devices)
		for iter.rem > 0 {
			device := iter.data
			deviceName := C.GoStringN(C.xcb_input_xi_device_info_name(device), C.int(device.name_len))
			id := uint16(device.deviceid)
			deviceType, enabled, attachment := uint16(device._type), uint8(device.enabled), uint16(device.attachment)
			if id == 0 || seen[deviceName] || seenIDs[id] {
				C.free(unsafe.Pointer(devices))
				return effect, fmt.Errorf("private X11 duplicate device: pass=%d name=%q id=%d type=%d enabled=%d", pass, deviceName, id, deviceType, enabled)
			}
			seen[deviceName], seenIDs[id] = true, true
			switch deviceName {
			case "Xephyr virtual keyboard", "Xephyr virtual mouse":
				role := 0
				if deviceName == "Xephyr virtual mouse" {
					role = 1
				}
				if target == nil && pass == 0 {
					if device.enabled != 1 || device.attachment == 0 || role == 0 && device._type != C.XCB_INPUT_DEVICE_TYPE_SLAVE_KEYBOARD || role == 1 && device._type != C.XCB_INPUT_DEVICE_TYPE_SLAVE_POINTER {
						C.free(unsafe.Pointer(devices))
						return effect, fmt.Errorf("private Xephyr initial forwarder differs: pass=%d name=%q id=%d type=%d enabled=%d attachment=%d", pass, deviceName, id, deviceType, enabled, attachment)
					}
					candidateIDs[role] = id
					forwarderAttachments[role] = uint16(device.attachment)
				} else if id != candidateIDs[role] || device._type != C.XCB_INPUT_DEVICE_TYPE_FLOATING_SLAVE || device.enabled != 0 || device.attachment != 0 {
					C.free(unsafe.Pointer(devices))
					return effect, fmt.Errorf("private Xephyr disabled forwarder differs: pass=%d name=%q id=%d expected=%d type=%d enabled=%d attachment=%d", pass, deviceName, id, candidateIDs[role], deviceType, enabled, attachment)
				}
				forwarders++
			case "Virtual core keyboard", "Virtual core pointer":
				role := 0
				if deviceName == "Virtual core pointer" {
					role = 1
				}
				if device.enabled != 1 || role == 0 && device._type != C.XCB_INPUT_DEVICE_TYPE_MASTER_KEYBOARD || role == 1 && device._type != C.XCB_INPUT_DEVICE_TYPE_MASTER_POINTER {
					C.free(unsafe.Pointer(devices))
					return effect, fmt.Errorf("private X11 master differs: pass=%d name=%q id=%d type=%d enabled=%d", pass, deviceName, id, deviceType, enabled)
				}
				masters[role], masterAttachments[role] = id, uint16(device.attachment)
			case "Virtual core XTEST keyboard", "Virtual core XTEST pointer":
				role := 0
				if deviceName == "Virtual core XTEST pointer" {
					role = 1
				}
				if device.enabled != 1 || role == 0 && device._type != C.XCB_INPUT_DEVICE_TYPE_SLAVE_KEYBOARD || role == 1 && device._type != C.XCB_INPUT_DEVICE_TYPE_SLAVE_POINTER {
					C.free(unsafe.Pointer(devices))
					return effect, fmt.Errorf("private X11 XTEST device differs: pass=%d name=%q id=%d type=%d enabled=%d", pass, deviceName, id, deviceType, enabled)
				}
				testAttachments[role] = uint16(device.attachment)
				testKeyboard = testKeyboard || role == 0
				testPointer = testPointer || role == 1
			default:
				C.free(unsafe.Pointer(devices))
				return effect, fmt.Errorf("private X11 unexpected input consumer: pass=%d name=%q id=%d type=%d enabled=%d", pass, deviceName, id, deviceType, enabled)
			}
			C.xcb_input_xi_device_info_next(&iter)
		}
		C.free(unsafe.Pointer(devices))
		if forwarders != 2 || !testKeyboard || !testPointer || masters[0] == 0 || masters[1] == 0 || masterAttachments[0] != masters[1] || masterAttachments[1] != masters[0] || testAttachments != masters || target == nil && pass == 0 && forwarderAttachments != masters {
			return effect, fmt.Errorf("private X11 input device set is incomplete")
		}
		if pass == 0 && target == nil {
			value := C.uint8_t(0)
			for _, id := range candidateIDs {
				problem := C.xcb_request_check(x, C.xcb_input_xi_change_property_checked(x, C.xcb_input_device_id_t(id), C.XCB_PROP_MODE_REPLACE, 8, atom, C.XCB_ATOM_INTEGER, 1, unsafe.Pointer(&value)))
				if problem != nil {
					C.free(unsafe.Pointer(problem))
					return effect, fmt.Errorf("private Xephyr host forwarding could not be disabled")
				}
			}
		}
	}
	effect = ProbeX11Effect{Display: spec.Display, AuthoritySHA: spec.Authority.SHA256, Server: server, Target: native, ForwardersOff: true, Keys: slices.Clone(keys), Pressed: pressed}
	if len(keys) == 0 {
		if _, err := observeProbeProcess(ProbeMemoryRuntime{Provenance: "owned_child"}, spec.Server.PID, &spec.Server, spec.ServerProgram.SHA256); err != nil {
			return effect, fmt.Errorf("private X11 server changed during setup: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return effect, err
		}
		if target == nil {
			*forwarderIDs = candidateIDs
		}
		return effect, nil
	}
	// The private server grab fences focus/XRes and key delivery against other
	// clients. It never grabs the host display; disconnect/cancel releases it.
	problem := C.xcb_request_check(x, C.xcb_grab_server_checked(x))
	if problem != nil {
		C.free(unsafe.Pointer(problem))
		return effect, fmt.Errorf("private X11 transaction fence unavailable")
	}
	focus := C.xcb_get_input_focus_reply(x, C.xcb_get_input_focus(x), nil)
	if focus == nil {
		return effect, fmt.Errorf("private X11 focus unavailable")
	}
	window := focus.focus
	C.free(unsafe.Pointer(focus))
	if window < 2 {
		return effect, fmt.Errorf("private X11 has no owned focused window")
	}
	query := C.xcb_res_client_id_spec_t{client: C.uint32_t(window), mask: C.XCB_RES_CLIENT_ID_MASK_LOCAL_CLIENT_PID}
	clients := C.xcb_res_query_client_ids_reply(x, C.xcb_res_query_client_ids(x, 1, &query), nil)
	if clients == nil {
		return effect, fmt.Errorf("private X11 window client identity unavailable")
	}
	if clients.num_ids != 1 || clients.length > 64 {
		C.free(unsafe.Pointer(clients))
		return effect, fmt.Errorf("private X11 window client identity is ambiguous")
	}
	ids := C.xcb_res_query_client_ids_ids_iterator(clients)
	if ids.rem != 1 || ids.data.spec.mask != C.XCB_RES_CLIENT_ID_MASK_LOCAL_CLIENT_PID || C.xcb_res_client_id_value_value_length(ids.data) != 1 {
		C.free(unsafe.Pointer(clients))
		return effect, fmt.Errorf("private X11 local client PID unavailable")
	}
	clientPID := int(*C.xcb_res_client_id_value_value(ids.data))
	C.free(unsafe.Pointer(clients))
	if clientPID != target.PID {
		return effect, fmt.Errorf("private X11 focused client is not the owned emulator")
	}
	effect.Window, effect.ClientPID = uint32(window), clientPID
	setup := C.xcb_get_setup(x)
	if setup == nil {
		return effect, fmt.Errorf("private X11 keyboard setup unavailable")
	}
	mapping := C.xcb_get_keyboard_mapping_reply(x, C.xcb_get_keyboard_mapping(x, setup.min_keycode, setup.max_keycode-setup.min_keycode+1), nil)
	if mapping == nil {
		return effect, fmt.Errorf("private X11 key mapping unavailable")
	}
	defer C.free(unsafe.Pointer(mapping))
	width := int(mapping.keysyms_per_keycode)
	count := int(C.xcb_get_keyboard_mapping_keysyms_length(mapping))
	if width < 1 || width > 32 || count < width || count > 8192 || count%width != 0 {
		return effect, fmt.Errorf("private X11 key mapping exceeds bounds")
	}
	syms := unsafe.Slice(C.xcb_get_keyboard_mapping_keysyms(mapping), count)
	for _, key := range keys {
		keyName := C.CString(key)
		symbol := C.XStringToKeysym(keyName)
		C.free(unsafe.Pointer(keyName))
		code := 0
		for at := 0; at < count; at += width {
			if C.KeySym(syms[at]) == symbol && symbol != 0 {
				code = int(setup.min_keycode) + at/width
				break
			}
		}
		if code < 1 || code > 255 {
			return effect, fmt.Errorf("private X11 key has no unmodified mapping")
		}
		event := C.uint8_t(C.XCB_KEY_RELEASE)
		if pressed {
			event = C.XCB_KEY_PRESS
		}
		problem := C.xcb_request_check(x, C.xcb_test_fake_input_checked(x, event, C.uint8_t(code), C.XCB_CURRENT_TIME, 0, 0, 0, 0))
		if problem != nil {
			C.free(unsafe.Pointer(problem))
			return effect, fmt.Errorf("private X11 key delivery is uncertain")
		}
	}
	if ctx.Err() != nil || C.xcb_connection_has_error(x) != 0 {
		return effect, fmt.Errorf("private X11 effect deadline or connection failed")
	}
	finalFocus := C.xcb_get_input_focus_reply(x, C.xcb_get_input_focus(x), nil)
	if finalFocus == nil {
		return effect, fmt.Errorf("private X11 effect focus is unavailable")
	}
	stableFocus := finalFocus.focus == window
	C.free(unsafe.Pointer(finalFocus))
	if !stableFocus {
		return effect, fmt.Errorf("private X11 focus changed during the effect")
	}
	if _, err := observeProbeProcess(ProbeMemoryRuntime{}, target.PID, target, build); err != nil {
		return effect, fmt.Errorf("private X11 native target changed after effect: %w", err)
	}
	if _, err := observeProbeProcess(ProbeMemoryRuntime{Provenance: "owned_child"}, spec.Server.PID, &spec.Server, spec.ServerProgram.SHA256); err != nil {
		return effect, fmt.Errorf("private X11 server changed during effect: %w", err)
	}
	problem = C.xcb_request_check(x, C.xcb_ungrab_server_checked(x))
	if problem != nil {
		C.free(unsafe.Pointer(problem))
		return effect, fmt.Errorf("private X11 transaction fence release is uncertain")
	}
	if ctx.Err() != nil {
		return effect, ctx.Err()
	}
	return effect, nil
}
