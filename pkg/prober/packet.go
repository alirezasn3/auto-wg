package prober

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	ProbeMagic       = "AWGP"
	ProbePacketLen   = 4 + 8 + 16 + 16 + 32 // 76 bytes
	MaxClockSkewSecs = 30
)

type ProbePacket struct {
	Timestamp int64
	PeerID    string
	Nonce     [16]byte
	Signature [32]byte
}

func BuildProbePacket(peerID, secretToken string) ([]byte, error) {
	buf := make([]byte, ProbePacketLen)

	// 1. Magic (4 bytes)
	copy(buf[0:4], ProbeMagic)

	// 2. Timestamp (8 bytes)
	now := time.Now().Unix()
	binary.BigEndian.PutUint64(buf[4:12], uint64(now))

	// 3. PeerID (16 bytes, padded with 0)
	var peerIDBytes [16]byte
	copy(peerIDBytes[:], []byte(peerID))
	copy(buf[12:28], peerIDBytes[:])

	// 4. Random Nonce (16 bytes)
	if _, err := rand.Read(buf[28:44]); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// 5. HMAC-SHA256 (32 bytes) calculated over buf[0:44]
	mac := hmac.New(sha256.New, []byte(secretToken))
	mac.Write(buf[0:44])
	sig := mac.Sum(nil)
	copy(buf[44:76], sig)

	return buf, nil
}

func ParseAndVerifyProbePacket(data []byte, secretToken string) (string, error) {
	if len(data) < ProbePacketLen {
		return "", errors.New("probe packet too short")
	}

	// 1. Magic check
	if string(data[0:4]) != ProbeMagic {
		return "", errors.New("invalid magic header")
	}

	// 2. Timestamp check
	ts := int64(binary.BigEndian.Uint64(data[4:12]))
	now := time.Now().Unix()
	diff := now - ts
	if diff < -MaxClockSkewSecs || diff > MaxClockSkewSecs {
		return "", fmt.Errorf("probe packet timestamp expired (diff=%ds)", diff)
	}

	// 3. HMAC check
	mac := hmac.New(sha256.New, []byte(secretToken))
	mac.Write(data[0:44])
	expectedSig := mac.Sum(nil)

	if !hmac.Equal(data[44:76], expectedSig) {
		return "", errors.New("probe packet signature verification failed")
	}

	// 4. Extract PeerID
	peerID := string(trimNullBytes(data[12:28]))
	return peerID, nil
}

func trimNullBytes(b []byte) []byte {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] != 0 {
			return b[:i+1]
		}
	}
	return []byte{}
}
