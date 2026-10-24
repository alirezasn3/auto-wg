// Package transport carries WireGuard's UDP packets over a TCP connection that looks like TLS or SSH.
//
// Both peers run a TCP listener and a dial loop and keep a single authenticated connection between them:
// a TLS 1.3 session, or a genuine OpenSSH session. A loopback UDP relay sits in front of it: WireGuard's
// peer endpoint points at the relay, which wraps each UDP packet in a length-prefixed frame.
package transport

import (
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
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
	// ctrlPad is a filler frame: its payload is random bytes that the receiver discards.
	ctrlPad byte = 3

	// minPad is the smallest filler frame: header plus the type byte.
	minPad = headerLen + 1
	// probeHeader is the control type byte plus the 8-byte nonce; the rest of a probe is padding.
	probeHeader = 1 + 8
)

// ErrFrameTooLarge is returned for payloads above maxFrame.
var ErrFrameTooLarge = errors.New("transport: frame too large")

// Padding modes of config.LinkConfig.Padding.
const (
	padOff    = "off"
	padBucket = "bucket"
	padRandom = "random"
)

// padBuckets are the sizes a write is rounded up to in bucket mode, so the sizes seen on the wire are a
// few fixed values instead of a fingerprint of WireGuard's message lengths.
var padBuckets = []int{128, 256, 512, 1024, 1500}

// randomPadMax bounds the random filler.
const randomPadMax = 256

// padSize returns how many filler bytes to append to a write of n bytes: zero, or at least minPad.
func padSize(mode string, n int) int {
	switch mode {
	case padBucket:
		for _, b := range padBuckets {
			if n+minPad <= b {
				return b - n
			}
		}
	case padRandom:
		if k := rand.IntN(randomPadMax + 1); k > 0 {
			return max(k, minPad)
		}
	}
	return 0
}

// appendFrame appends one frame to dst.
func appendFrame(dst, payload []byte, flag uint16) []byte {
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(payload))|flag)
	return append(dst, payload...)
}

// appendPad appends a filler control frame that is exactly total bytes long on the wire (total >= minPad).
func appendPad(dst []byte, total int) []byte {
	n := total - headerLen
	dst = binary.BigEndian.AppendUint16(dst, uint16(n)|ctrlFlag)
	start := len(dst)
	dst = append(dst, make([]byte, n)...)
	dst[start] = ctrlPad
	fillRandom(dst[start+1:])
	return dst
}

func putFrame(w io.Writer, payload []byte, flag uint16, pad string) error {
	if len(payload) > maxFrame {
		return ErrFrameTooLarge
	}
	buf := make([]byte, 0, headerLen+len(payload)+minPad)
	buf = appendFrame(buf, payload, flag)
	if extra := padSize(pad, len(buf)); extra >= minPad && extra-headerLen <= maxFrame {
		buf = appendPad(buf, extra)
	}
	_, err := w.Write(buf)
	return err
}

// writeFrame writes uint16 length + payload in a single Write, so each packet is one TLS record.
// A zero-length payload is a keepalive.
func writeFrame(w io.Writer, payload []byte, pad string) error { return putFrame(w, payload, 0, pad) }

// writeControl writes a control frame (a health probe or its echo).
func writeControl(w io.Writer, payload []byte, pad string) error {
	return putFrame(w, payload, ctrlFlag, pad)
}

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
