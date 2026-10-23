package tlstun

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	pkt := bytes.Repeat([]byte{0xab}, 1420)
	if err := writeFrame(&buf, pkt); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(&buf, nil); err != nil { // keepalive
		t.Fatal(err)
	}
	if err := writeFrame(&buf, []byte("x")); err != nil {
		t.Fatal(err)
	}

	rb := make([]byte, maxFrame)
	got, err := readFrame(&buf, rb)
	if err != nil || !bytes.Equal(got, pkt) {
		t.Fatalf("first frame: err=%v len=%d", err, len(got))
	}
	got, err = readFrame(&buf, rb)
	if err != nil || len(got) != 0 {
		t.Fatalf("keepalive must read back empty: err=%v len=%d", err, len(got))
	}
	got, err = readFrame(&buf, rb)
	if err != nil || string(got) != "x" {
		t.Fatalf("third frame: err=%v got=%q", err, got)
	}
}

func TestFrameLimits(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, make([]byte, maxFrame+1)); err != ErrFrameTooLarge {
		t.Fatalf("oversize write: got %v", err)
	}
	if err := writeFrame(&buf, make([]byte, maxFrame)); err != nil {
		t.Fatalf("max-size frame must be accepted: %v", err)
	}

	// A hostile length header must be rejected before any allocation or read of that size.
	hdr := bytes.NewReader([]byte{0xff, 0xff})
	if _, err := readFrame(hdr, make([]byte, maxFrame)); err != ErrFrameTooLarge {
		t.Fatalf("oversize read: got %v", err)
	}

	// A frame cut short is an error, not a short packet.
	trunc := bytes.NewReader([]byte{0x00, 0x10, 0x01, 0x02})
	if _, err := readFrame(trunc, make([]byte, maxFrame)); err == nil {
		t.Fatal("truncated frame must fail")
	}
}
