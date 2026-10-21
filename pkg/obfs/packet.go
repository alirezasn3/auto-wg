// Package obfs hides WireGuard handshake packets from DPI.
//
// The kernel WireGuard module cannot be told to send different bytes, and the handshake messages are
// authenticated, so they cannot be edited in flight either. What can be changed is the traffic around
// them: outgoing initiation (148 byte) and response (92 byte) packets are held in an NFQUEUE, decoy
// packets are sent ahead of them from the same 5-tuple, and optionally the real packet is re-sent as
// two IP fragments. The receiving peer needs no changes: it drops the decoys and reassembles the fragments.
package obfs

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"net/netip"
	"strconv"
	"strings"

	"auto-wg/pkg/config"
)

const (
	// WireGuard UDP payload sizes of the handshake messages.
	InitiationSize = 148
	ResponseSize   = 92

	typeInitiation = 1
	typeResponse   = 2

	udpHeaderLen  = 8
	ipv4HeaderLen = 20
	ipv6HeaderLen = 40
	protoUDP      = 17
)

// Packet is a parsed, unfragmented UDP datagram taken from the NFQUEUE (IP header first).
type Packet struct {
	V6      bool
	Src     netip.Addr
	Dst     netip.Addr
	SrcPort uint16
	DstPort uint16
	TTL     uint8
	TOS     uint8
	Payload []byte
}

// ParsePacket decodes an IPv4/IPv6 UDP packet. Fragments and packets with extension headers are rejected.
func ParsePacket(b []byte) (*Packet, error) {
	if len(b) < 1 {
		return nil, errors.New("empty packet")
	}
	p := &Packet{}
	var udp []byte
	switch b[0] >> 4 {
	case 4:
		if len(b) < ipv4HeaderLen {
			return nil, errors.New("short ipv4 header")
		}
		ihl := int(b[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(b[2:4]))
		if ihl < ipv4HeaderLen || total > len(b) || total < ihl+udpHeaderLen {
			return nil, errors.New("bad ipv4 lengths")
		}
		if b[9] != protoUDP {
			return nil, errors.New("not udp")
		}
		if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
			return nil, errors.New("ipv4 fragment")
		}
		p.TOS, p.TTL = b[1], b[8]
		p.Src = netip.AddrFrom4([4]byte(b[12:16]))
		p.Dst = netip.AddrFrom4([4]byte(b[16:20]))
		udp = b[ihl:total]
	case 6:
		if len(b) < ipv6HeaderLen+udpHeaderLen {
			return nil, errors.New("short ipv6 packet")
		}
		if b[6] != protoUDP {
			return nil, errors.New("not udp or has extension headers")
		}
		plen := int(binary.BigEndian.Uint16(b[4:6]))
		if ipv6HeaderLen+plen > len(b) || plen < udpHeaderLen {
			return nil, errors.New("bad ipv6 length")
		}
		p.V6 = true
		p.TOS = uint8(binary.BigEndian.Uint16(b[0:2]) >> 4)
		p.TTL = b[7]
		p.Src = netip.AddrFrom16([16]byte(b[8:24]))
		p.Dst = netip.AddrFrom16([16]byte(b[24:40]))
		udp = b[ipv6HeaderLen : ipv6HeaderLen+plen]
	default:
		return nil, errors.New("not ip")
	}
	ulen := int(binary.BigEndian.Uint16(udp[4:6]))
	if ulen < udpHeaderLen || ulen > len(udp) {
		return nil, errors.New("bad udp length")
	}
	p.SrcPort = binary.BigEndian.Uint16(udp[0:2])
	p.DstPort = binary.BigEndian.Uint16(udp[2:4])
	p.Payload = udp[udpHeaderLen:ulen]
	return p, nil
}

// IsHandshake reports whether the payload is a WireGuard initiation or response message.
func (p *Packet) IsHandshake() bool {
	if len(p.Payload) < 4 || p.Payload[1] != 0 || p.Payload[2] != 0 || p.Payload[3] != 0 {
		return false
	}
	return (len(p.Payload) == InitiationSize && p.Payload[0] == typeInitiation) ||
		(len(p.Payload) == ResponseSize && p.Payload[0] == typeResponse)
}

// IsResponse reports whether this is a handshake response (as opposed to an initiation).
func (p *Packet) IsResponse() bool { return len(p.Payload) == ResponseSize }

func csumAdd(sum uint32, b []byte) uint32 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func csumFold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}

// udpDatagram builds UDP header + payload with a valid checksum for the given addresses.
func udpDatagram(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	d := make([]byte, udpHeaderLen+len(payload))
	binary.BigEndian.PutUint16(d[0:2], sport)
	binary.BigEndian.PutUint16(d[2:4], dport)
	binary.BigEndian.PutUint16(d[4:6], uint16(len(d)))
	copy(d[udpHeaderLen:], payload)

	var sum uint32
	sum = csumAdd(sum, src.AsSlice())
	sum = csumAdd(sum, dst.AsSlice())
	sum += protoUDP + uint32(len(d))
	sum = csumAdd(sum, d)
	c := csumFold(sum)
	if c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(d[6:8], c)
	return d
}

func ipv4Packet(src, dst netip.Addr, tos, ttl uint8, id, flagsFrag uint16, payload []byte) []byte {
	b := make([]byte, ipv4HeaderLen+len(payload))
	b[0] = 0x45
	b[1] = tos
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint16(b[4:6], id)
	binary.BigEndian.PutUint16(b[6:8], flagsFrag)
	b[8] = ttl
	b[9] = protoUDP
	s, d := src.As4(), dst.As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[10:12], csumFold(csumAdd(0, b[:ipv4HeaderLen])))
	copy(b[ipv4HeaderLen:], payload)
	return b
}

func ipv6Packet(src, dst netip.Addr, tclass, hops uint8, payload []byte) []byte {
	b := make([]byte, ipv6HeaderLen+len(payload))
	binary.BigEndian.PutUint32(b[0:4], 6<<28|uint32(tclass)<<20)
	binary.BigEndian.PutUint16(b[4:6], uint16(len(payload)))
	b[6] = protoUDP
	b[7] = hops
	s, d := src.As16(), dst.As16()
	copy(b[8:24], s[:])
	copy(b[24:40], d[:])
	copy(b[ipv6HeaderLen:], payload)
	return b
}

// BuildDecoy returns a complete IP packet carrying random junk from the same 5-tuple as p.
// The junk never starts with a WireGuard message type, and its size never equals a handshake
// message size, so the decoy can neither be mistaken for WireGuard nor re-enter the queue.
func BuildDecoy(p *Packet, cfg config.ObfuscationConfig) []byte {
	size := cfg.DecoyMinSize
	if span := cfg.DecoyMaxSize - cfg.DecoyMinSize; span > 0 {
		size += rand.IntN(span + 1)
	}
	if size < 1 {
		size = 1
	}
	if size == InitiationSize || size == ResponseSize {
		size++
	}
	junk := make([]byte, size)
	for i := range junk {
		junk[i] = byte(rand.UintN(256))
	}
	if junk[0] <= 4 {
		junk[0] += 5
	}

	ttl := p.TTL
	if cfg.DecoyTTL > 0 {
		ttl = uint8(cfg.DecoyTTL)
	}
	d := udpDatagram(p.Src, p.Dst, p.SrcPort, p.DstPort, junk)
	if cfg.DecoyBadChecksum {
		c := binary.BigEndian.Uint16(d[6:8]) ^ 0x5a5a
		if c == 0 {
			c = 1
		}
		binary.BigEndian.PutUint16(d[6:8], c)
	}
	if p.V6 {
		return ipv6Packet(p.Src, p.Dst, p.TOS, ttl, d)
	}
	return ipv4Packet(p.Src, p.Dst, p.TOS, ttl, uint16(rand.UintN(65536)), 0, d)
}

// BuildFragments re-encodes an IPv4 packet as two fragments, the first carrying split bytes of the
// UDP datagram. sport is the source port the peer must see (it can differ from p.SrcPort when a NAT
// rule translates the reply, because fragments bypass connection tracking and so are never translated).
func BuildFragments(p *Packet, sport uint16, split int) ([][]byte, error) {
	if p.V6 {
		return nil, errors.New("ipv6 fragmentation is not supported")
	}
	d := udpDatagram(p.Src, p.Dst, sport, p.DstPort, p.Payload)
	if split < 8 || split%8 != 0 || split >= len(d) {
		return nil, errors.New("invalid fragment split")
	}
	id := uint16(rand.UintN(65535)) + 1
	first := ipv4Packet(p.Src, p.Dst, p.TOS, p.TTL, id, 0x2000, d[:split])
	second := ipv4Packet(p.Src, p.Dst, p.TOS, p.TTL, id, uint16(split/8), d[split:])
	return [][]byte{first, second}, nil
}

// ReplyOriginalDstPort scans connection tracking text (the format of /proc/net/nf_conntrack) for the UDP
// flow whose reply direction is sport -> remote:remotePort and returns the destination port the remote end
// originally dialed. That is the source port the remote end expects on our packets, which differs from
// sport when a REDIRECT rule maps a port range onto the WireGuard listen port.
func ReplyOriginalDstPort(r io.Reader, sport uint16, remote netip.Addr, remotePort uint16) (uint16, bool) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, " udp ") {
			continue
		}
		var dst [2]netip.Addr
		var sp, dp [2]uint16
		var n [4]int
		for _, f := range strings.Fields(line) {
			k, v, ok := strings.Cut(f, "=")
			if !ok {
				continue
			}
			switch k {
			case "dst":
				if n[0] < 2 {
					dst[n[0]], _ = netip.ParseAddr(v)
					n[0]++
				}
			case "sport":
				if n[1] < 2 {
					x, _ := strconv.ParseUint(v, 10, 16)
					sp[n[1]] = uint16(x)
					n[1]++
				}
			case "dport":
				if n[2] < 2 {
					x, _ := strconv.ParseUint(v, 10, 16)
					dp[n[2]] = uint16(x)
					n[2]++
				}
			}
		}
		if n[0] == 2 && n[1] == 2 && n[2] == 2 &&
			dst[1].Unmap() == remote.Unmap() && dp[1] == remotePort && sp[1] == sport {
			return dp[0], true
		}
	}
	return 0, false
}
