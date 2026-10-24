package transport

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	pkt := bytes.Repeat([]byte{0xab}, 1420)
	if err := writeFrame(&buf, pkt, padOff); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(&buf, nil, padOff); err != nil { // keepalive
		t.Fatal(err)
	}
	if err := writeFrame(&buf, []byte("x"), padOff); err != nil {
		t.Fatal(err)
	}

	rb := make([]byte, maxFrame)
	got, ctrl, err := readFrame(&buf, rb)
	if err != nil || ctrl || !bytes.Equal(got, pkt) {
		t.Fatalf("first frame: err=%v ctrl=%v len=%d", err, ctrl, len(got))
	}
	got, ctrl, err = readFrame(&buf, rb)
	if err != nil || ctrl || len(got) != 0 {
		t.Fatalf("keepalive must read back as an empty data frame: err=%v ctrl=%v len=%d", err, ctrl, len(got))
	}
	got, ctrl, err = readFrame(&buf, rb)
	if err != nil || ctrl || string(got) != "x" {
		t.Fatalf("third frame: err=%v ctrl=%v got=%q", err, ctrl, got)
	}
}

func TestControlFramesAreDistinguishedFromData(t *testing.T) {
	var buf bytes.Buffer
	probe := newProbe(0xdeadbeefcafe, 300)
	if err := writeControl(&buf, probe, padOff); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(&buf, probe, padOff); err != nil { // same bytes, but as WireGuard data
		t.Fatal(err)
	}

	rb := make([]byte, maxFrame)
	got, ctrl, err := readFrame(&buf, rb)
	if err != nil || !ctrl || !bytes.Equal(got, probe) {
		t.Fatalf("control frame: err=%v ctrl=%v", err, ctrl)
	}
	got, ctrl, err = readFrame(&buf, rb)
	if err != nil || ctrl || !bytes.Equal(got, probe) {
		t.Fatalf("data frame with probe-looking bytes must stay data: err=%v ctrl=%v", err, ctrl)
	}
}

func TestFrameLimits(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, make([]byte, maxFrame+1), padOff); err != ErrFrameTooLarge {
		t.Fatalf("oversize write: got %v", err)
	}
	if err := writeControl(&buf, make([]byte, maxFrame+1), padOff); err != ErrFrameTooLarge {
		t.Fatalf("oversize control write: got %v", err)
	}
	if err := writeFrame(&buf, make([]byte, maxFrame), padOff); err != nil {
		t.Fatalf("max-size frame must be accepted: %v", err)
	}

	// A hostile length header must be rejected before any allocation or read of that size.
	hdr := bytes.NewReader([]byte{0x7f, 0xff})
	if _, _, err := readFrame(hdr, make([]byte, maxFrame)); err != ErrFrameTooLarge {
		t.Fatalf("oversize read: got %v", err)
	}

	// A frame cut short is an error, not a short packet.
	trunc := bytes.NewReader([]byte{0x00, 0x10, 0x01, 0x02})
	if _, _, err := readFrame(trunc, make([]byte, maxFrame)); err == nil {
		t.Fatal("truncated frame must fail")
	}
}

// A peer that predates control frames reads the flag as part of the length and so sees an oversized
// frame, which makes it drop the connection instead of passing probe bytes to WireGuard.
func TestOldPeersRejectControlFrames(t *testing.T) {
	var buf bytes.Buffer
	if err := writeControl(&buf, newProbe(1, 100), padOff); err != nil {
		t.Fatal(err)
	}
	if hdr := uint16(buf.Bytes()[0])<<8 | uint16(buf.Bytes()[1]); int(hdr) <= maxFrame {
		t.Fatalf("a control header (%#x) must read as oversized to a peer that ignores the flag", hdr)
	}
}

func TestProbeFormat(t *testing.T) {
	p := newProbe(42, 1200)
	if len(p) != 1200 || p[0] != ctrlPing {
		t.Fatalf("bad probe: len=%d type=%d", len(p), p[0])
	}
	if n, ok := probeNonce(p); !ok || n != 42 {
		t.Fatalf("nonce round trip failed: %d %v", n, ok)
	}
	if a, b := newProbe(1, 400), newProbe(1, 400); bytes.Equal(a[probeHeader:], b[probeHeader:]) {
		t.Fatal("probe padding must be random, not a fixed pattern")
	}
	if len(newProbe(1, 1)) != probeHeader || len(newProbe(1, 99999)) != maxFrame {
		t.Fatal("probe size must be clamped to what fits")
	}
	if _, ok := probeNonce([]byte{ctrlPong, 1, 2}); ok {
		t.Fatal("a truncated probe has no nonce")
	}
}

// A padded write is one data frame followed by one filler frame, and a reader skips the filler.
func TestPaddedFramesRoundTrip(t *testing.T) {
	for _, mode := range []string{padBucket, padRandom} {
		var buf bytes.Buffer
		pkts := [][]byte{make([]byte, 148), make([]byte, 92), make([]byte, 32), make([]byte, 1200), nil}
		for i, p := range pkts {
			fillRandom(p)
			if err := writeFrame(&buf, p, mode); err != nil {
				t.Fatalf("%s: write %d: %v", mode, i, err)
			}
		}
		rd := bytes.NewReader(buf.Bytes())
		scratch := make([]byte, maxFrame)
		var data [][]byte
		for rd.Len() > 0 {
			p, ctrl, err := readFrame(rd, scratch)
			if err != nil {
				t.Fatalf("%s: read: %v", mode, err)
			}
			if ctrl {
				if len(p) == 0 || p[0] != ctrlPad {
					t.Fatalf("%s: unexpected control frame % x", mode, p[:min(len(p), 4)])
				}
				continue
			}
			data = append(data, append([]byte(nil), p...))
		}
		if len(data) != len(pkts) {
			t.Fatalf("%s: got %d data frames, want %d", mode, len(data), len(pkts))
		}
		for i := range pkts {
			if !bytes.Equal(data[i], pkts[i]) {
				t.Fatalf("%s: packet %d changed", mode, i)
			}
		}
	}
}

// Bucket mode makes every write one of a few sizes, whatever the packet length was.
func TestBucketPaddingQuantisesWriteSizes(t *testing.T) {
	sizes := map[int]bool{}
	for n := 0; n <= 1400; n += 7 {
		var buf bytes.Buffer
		if err := writeFrame(&buf, make([]byte, n), padBucket); err != nil {
			t.Fatal(err)
		}
		sizes[buf.Len()] = true
		if buf.Len() < n+headerLen {
			t.Fatalf("write of %d shrank to %d", n, buf.Len())
		}
	}
	if len(sizes) > len(padBuckets) {
		t.Fatalf("bucket mode produced %d distinct write sizes, want at most %d: %v", len(sizes), len(padBuckets), sizes)
	}
	for s := range sizes {
		ok := false
		for _, b := range padBuckets {
			ok = ok || s == b
		}
		if !ok {
			t.Fatalf("write size %d is not a bucket", s)
		}
	}
	// Anything past the largest bucket goes out as it is.
	var buf bytes.Buffer
	_ = writeFrame(&buf, make([]byte, 1600), padBucket)
	if buf.Len() != 1600+headerLen {
		t.Fatalf("oversized write was padded to %d", buf.Len())
	}
}

func TestRandomPaddingVaries(t *testing.T) {
	sizes := map[int]bool{}
	for i := 0; i < 200; i++ {
		var buf bytes.Buffer
		if err := writeFrame(&buf, make([]byte, 148), padRandom); err != nil {
			t.Fatal(err)
		}
		sizes[buf.Len()] = true
	}
	if len(sizes) < 20 {
		t.Fatalf("random padding gave only %d distinct sizes", len(sizes))
	}
}

func TestPadOffAddsNothing(t *testing.T) {
	var buf bytes.Buffer
	_ = writeFrame(&buf, make([]byte, 148), padOff)
	if buf.Len() != 148+headerLen {
		t.Fatalf("got %d bytes", buf.Len())
	}
}
