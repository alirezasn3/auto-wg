// Package tlstun carries WireGuard's UDP packets over a TLS connection.
//
// Both peers run a TCP listener and a dial loop and keep a single authenticated TLS connection between
// them. A loopback UDP relay sits in front of it: while the TLS path is active, WireGuard's peer endpoint
// points at the relay, which wraps each UDP packet in a length-prefixed frame.
package tlstun

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	// maxFrame is the largest payload carried in one frame. WireGuard packets stay below the MTU.
	maxFrame  = 2048
	headerLen = 2

	// ctrlFlag marks a control frame (health probes) in the length header. Data frames never set it,
	// so a peer that predates control frames rejects them as oversized and drops the connection
	// instead of handing probe bytes to WireGuard.
	ctrlFlag = 0x8000

	ctrlPing byte = 1
	ctrlPong byte = 2
	// probeHeader is the control type byte plus the 8-byte nonce; the rest of a probe is padding.
	probeHeader = 1 + 8
)

// ErrFrameTooLarge is returned for payloads above maxFrame.
var ErrFrameTooLarge = errors.New("tlstun: frame too large")

func putFrame(w io.Writer, payload []byte, flag uint16) error {
	if len(payload) > maxFrame {
		return ErrFrameTooLarge
	}
	buf := make([]byte, headerLen+len(payload))
	binary.BigEndian.PutUint16(buf, uint16(len(payload))|flag)
	copy(buf[headerLen:], payload)
	_, err := w.Write(buf)
	return err
}

// writeFrame writes uint16 length + payload in a single Write, so each packet is one TLS record.
// A zero-length payload is a keepalive.
func writeFrame(w io.Writer, payload []byte) error { return putFrame(w, payload, 0) }

// writeControl writes a control frame (a health probe or its echo).
func writeControl(w io.Writer, payload []byte) error { return putFrame(w, payload, ctrlFlag) }

// readFrame reads one frame into buf (at least maxFrame bytes) and returns its payload and whether it is
// a control frame. An empty data payload is a keepalive.
func readFrame(r io.Reader, buf []byte) (payload []byte, control bool, err error) {
	var hdr [headerLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, false, err
	}
	h := binary.BigEndian.Uint16(hdr[:])
	control = h&ctrlFlag != 0
	n := int(h &^ ctrlFlag)
	if n > maxFrame {
		return nil, false, ErrFrameTooLarge
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return nil, false, err
	}
	return buf[:n], control, nil
}

// newProbe builds a ping of the given total payload size (clamped to what fits) carrying nonce and random
// padding. The size is part of the point: a path that passes tiny frames but drops realistic ones must fail.
func newProbe(nonce uint64, size int) []byte {
	if size < probeHeader {
		size = probeHeader
	}
	if size > maxFrame {
		size = maxFrame
	}
	p := make([]byte, size)
	p[0] = ctrlPing
	binary.BigEndian.PutUint64(p[1:probeHeader], nonce)
	fillRandom(p[probeHeader:])
	return p
}

// probeNonce extracts the nonce of a ping or pong payload.
func probeNonce(p []byte) (uint64, bool) {
	if len(p) < probeHeader {
		return 0, false
	}
	return binary.BigEndian.Uint64(p[1:probeHeader]), true
}
