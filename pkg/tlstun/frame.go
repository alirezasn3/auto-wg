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
)

// ErrFrameTooLarge is returned for payloads above maxFrame.
var ErrFrameTooLarge = errors.New("tlstun: frame too large")

// writeFrame writes uint16 length + payload in a single Write, so each packet is one TLS record.
// A zero-length payload is a keepalive.
func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxFrame {
		return ErrFrameTooLarge
	}
	buf := make([]byte, headerLen+len(payload))
	binary.BigEndian.PutUint16(buf, uint16(len(payload)))
	copy(buf[headerLen:], payload)
	_, err := w.Write(buf)
	return err
}

// readFrame reads one frame into buf (at least maxFrame bytes) and returns its payload.
// An empty payload is a keepalive.
func readFrame(r io.Reader, buf []byte) ([]byte, error) {
	var hdr [headerLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > maxFrame {
		return nil, ErrFrameTooLarge
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return nil, err
	}
	return buf[:n], nil
}
