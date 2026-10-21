package obfs

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"auto-wg/pkg/config"
)

func handshakePayload(size int, typ byte) []byte {
	b := make([]byte, size)
	b[0] = typ
	for i := 4; i < size; i++ {
		b[i] = byte(i)
	}
	return b
}

func verifyUDPChecksum(t *testing.T, src, dst netip.Addr, udp []byte) {
	t.Helper()
	var sum uint32
	sum = csumAdd(sum, src.AsSlice())
	sum = csumAdd(sum, dst.AsSlice())
	sum += protoUDP + uint32(len(udp))
	sum = csumAdd(sum, udp)
	if csumFold(sum) != 0 {
		t.Fatalf("udp checksum does not verify")
	}
}

func testPacket(v6 bool, payload []byte) *Packet {
	p := &Packet{Src: netip.MustParseAddr("192.0.2.1"), Dst: netip.MustParseAddr("198.51.100.7"),
		SrcPort: 24000, DstPort: 25000, TTL: 64, Payload: payload}
	if v6 {
		p.V6 = true
		p.Src = netip.MustParseAddr("2001:db8::1")
		p.Dst = netip.MustParseAddr("2001:db8::2")
	}
	return p
}

func TestParseRoundTrip(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		p := testPacket(v6, handshakePayload(InitiationSize, 1))
		d := udpDatagram(p.Src, p.Dst, p.SrcPort, p.DstPort, p.Payload)
		var raw []byte
		if v6 {
			raw = ipv6Packet(p.Src, p.Dst, 0, 64, d)
		} else {
			raw = ipv4Packet(p.Src, p.Dst, 0, 64, 7, 0, d)
		}
		got, err := ParsePacket(raw)
		if err != nil {
			t.Fatalf("v6=%v: %v", v6, err)
		}
		if got.Src != p.Src || got.Dst != p.Dst || got.SrcPort != 24000 || got.DstPort != 25000 || got.TTL != 64 {
			t.Fatalf("v6=%v: header mismatch: %+v", v6, got)
		}
		if !got.IsHandshake() || got.IsResponse() {
			t.Fatalf("v6=%v: should be an initiation", v6)
		}
		verifyUDPChecksum(t, p.Src, p.Dst, d)
	}
}

func TestIsHandshake(t *testing.T) {
	cases := []struct {
		size int
		typ  byte
		want bool
	}{
		{InitiationSize, 1, true},
		{ResponseSize, 2, true},
		{InitiationSize, 2, false},
		{ResponseSize, 1, false},
		{64, 3, false},
		{148, 4, false},
	}
	for _, c := range cases {
		p := &Packet{Payload: handshakePayload(c.size, c.typ)}
		if p.IsHandshake() != c.want {
			t.Errorf("size=%d type=%d: got %v", c.size, c.typ, !c.want)
		}
	}
}

func TestParseRejectsFragmentsAndNonUDP(t *testing.T) {
	p := testPacket(false, handshakePayload(InitiationSize, 1))
	frags, err := BuildFragments(p, p.SrcPort, 8)
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range frags {
		if _, err := ParsePacket(f); err == nil {
			t.Errorf("fragment %d should be rejected", i)
		}
	}
	d := udpDatagram(p.Src, p.Dst, 1, 2, []byte("x"))
	raw := ipv4Packet(p.Src, p.Dst, 0, 64, 1, 0, d)
	raw[9] = 6
	if _, err := ParsePacket(raw); err == nil {
		t.Error("tcp packet should be rejected")
	}
}

func TestDecoy(t *testing.T) {
	cfg := config.ObfuscationConfig{DecoyMinSize: 90, DecoyMaxSize: 150, DecoyTTL: 3}
	for _, v6 := range []bool{false, true} {
		p := testPacket(v6, handshakePayload(InitiationSize, 1))
		for i := 0; i < 500; i++ {
			raw := BuildDecoy(p, cfg)
			got, err := ParsePacket(raw)
			if err != nil {
				t.Fatal(err)
			}
			n := len(got.Payload)
			if n < 90 || n > 151 || n == InitiationSize || n == ResponseSize {
				t.Fatalf("bad decoy size %d", n)
			}
			if got.Payload[0] <= 4 {
				t.Fatalf("decoy starts with a WireGuard type byte")
			}
			if got.TTL != 3 || got.SrcPort != p.SrcPort || got.DstPort != p.DstPort || got.Src != p.Src {
				t.Fatalf("decoy header mismatch: %+v", got)
			}
			if got.IsHandshake() {
				t.Fatal("decoy looks like a handshake")
			}
		}
	}
}

func TestDecoyBadChecksum(t *testing.T) {
	p := testPacket(false, handshakePayload(InitiationSize, 1))
	good := BuildDecoy(p, config.ObfuscationConfig{DecoyMinSize: 40, DecoyMaxSize: 40})
	bad := BuildDecoy(p, config.ObfuscationConfig{DecoyMinSize: 40, DecoyMaxSize: 40, DecoyBadChecksum: true})
	verifyUDPChecksum(t, p.Src, p.Dst, good[ipv4HeaderLen:])
	var sum uint32
	sum = csumAdd(sum, p.Src.AsSlice())
	sum = csumAdd(sum, p.Dst.AsSlice())
	sum += protoUDP + uint32(len(bad)-ipv4HeaderLen)
	sum = csumAdd(sum, bad[ipv4HeaderLen:])
	if csumFold(sum) == 0 {
		t.Fatal("checksum should be corrupted")
	}
}

func TestFragmentsReassemble(t *testing.T) {
	p := testPacket(false, handshakePayload(InitiationSize, 1))
	for _, split := range []int{8, 16, 56, 152} {
		frags, err := BuildFragments(p, 31337, split)
		if err != nil {
			t.Fatal(err)
		}
		first, second := frags[0], frags[1]
		if binary.BigEndian.Uint16(first[6:8]) != 0x2000 {
			t.Fatalf("first fragment must have MF set and offset 0")
		}
		if binary.BigEndian.Uint16(second[6:8]) != uint16(split/8) {
			t.Fatalf("second fragment offset wrong")
		}
		if binary.BigEndian.Uint16(first[4:6]) != binary.BigEndian.Uint16(second[4:6]) {
			t.Fatalf("fragments must share an IP id")
		}
		if csumFold(csumAdd(0, first[:ipv4HeaderLen])) != 0 || csumFold(csumAdd(0, second[:ipv4HeaderLen])) != 0 {
			t.Fatal("bad ip header checksum")
		}
		udp := append(append([]byte{}, first[ipv4HeaderLen:]...), second[ipv4HeaderLen:]...)
		verifyUDPChecksum(t, p.Src, p.Dst, udp)
		if binary.BigEndian.Uint16(udp[0:2]) != 31337 {
			t.Fatal("source port override not applied")
		}
		if string(udp[udpHeaderLen:]) != string(p.Payload) {
			t.Fatal("payload corrupted by fragmentation")
		}
	}
	if _, err := BuildFragments(p, 1, 12); err == nil {
		t.Error("split not a multiple of 8 must fail")
	}
	if _, err := BuildFragments(testPacket(true, p.Payload), 1, 8); err == nil {
		t.Error("ipv6 must be refused")
	}
}

const conntrackSample = `ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.5 dst=203.0.113.9 sport=50000 dport=443 src=203.0.113.9 dst=10.0.0.5 sport=443 dport=50000 [ASSURED] mark=0 use=1
ipv4     2 udp      17 25 src=203.0.113.50 dst=192.0.2.1 sport=41000 dport=24500 src=192.0.2.1 dst=203.0.113.50 sport=20001 dport=41000 mark=0 use=1
ipv6     10 udp      17 20 src=2001:db8::50 dst=2001:db8::1 sport=42000 dport=26000 src=2001:db8::1 dst=2001:db8::50 sport=20001 dport=42000 [ASSURED] mark=0 use=1
`

func TestReplyOriginalDstPort(t *testing.T) {
	got, ok := ReplyOriginalDstPort(strings.NewReader(conntrackSample), 20001, netip.MustParseAddr("203.0.113.50"), 41000)
	if !ok || got != 24500 {
		t.Fatalf("ipv4: got %d ok=%v", got, ok)
	}
	got, ok = ReplyOriginalDstPort(strings.NewReader(conntrackSample), 20001, netip.MustParseAddr("2001:db8::50"), 42000)
	if !ok || got != 26000 {
		t.Fatalf("ipv6: got %d ok=%v", got, ok)
	}
	if _, ok := ReplyOriginalDstPort(strings.NewReader(conntrackSample), 20002, netip.MustParseAddr("203.0.113.50"), 41000); ok {
		t.Fatal("different local port must not match")
	}
	if _, ok := ReplyOriginalDstPort(strings.NewReader(conntrackSample), 443, netip.MustParseAddr("203.0.113.9"), 50000); ok {
		t.Fatal("tcp flows must be ignored")
	}
}
