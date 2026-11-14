package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// exchangeProbeFrame is the existing bounded PINE framing shared by typed reads
// and lifecycle status. Public typed reads keep their separate opcode0..3 gate.
func exchangeProbeFrame(connection io.ReadWriter, request []byte, replySize int) ([]byte, error) {
	write8 := len(request) == 10 && request[4] == 4 && replySize == 5
	if !write8 && (len(request) != 5 && len(request) != 9 || len(request) == 5 && request[4] != 15 || len(request) == 9 && request[4] > 3 || replySize < 6 || replySize > 13) || len(request) < 5 || binary.LittleEndian.Uint32(request) != uint32(len(request)) {
		return nil, fmt.Errorf("unsupported bounded probe frame")
	}
	if _, err := io.Copy(connection, bytes.NewReader(request)); err != nil {
		return nil, fmt.Errorf("probe request failed: %w", err)
	}
	reply := make([]byte, replySize)
	if _, err := io.ReadFull(connection, reply[:4]); err != nil {
		return nil, fmt.Errorf("incomplete probe packet: %w", err)
	}
	if binary.LittleEndian.Uint32(reply) != uint32(len(reply)) {
		return nil, fmt.Errorf("unexpected probe packet length")
	}
	if _, err := io.ReadFull(connection, reply[4:]); err != nil {
		return nil, fmt.Errorf("incomplete probe packet: %w", err)
	}
	if reply[4] != 0 {
		if write8 {
			return nil, fmt.Errorf("probe named control write failed")
		}
		return nil, fmt.Errorf("probe memory read failed")
	}
	return reply, nil
}
