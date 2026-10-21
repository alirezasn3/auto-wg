package obfs

import "sync/atomic"

// Status reports what an engine has done since it started.
type Status struct {
	Active     bool   `json:"active"`
	Queue      int    `json:"queue"`
	Handshakes uint64 `json:"handshakes"` // handshake packets intercepted
	Decoys     uint64 `json:"decoys"`     // decoy packets sent
	Fragmented uint64 `json:"fragmented"` // handshakes re-sent as fragments
	Errors     uint64 `json:"errors"`
}

type counters struct {
	handshakes, decoys, fragmented, errors atomic.Uint64
}

func (c *counters) status(queue int) Status {
	return Status{
		Active:     true,
		Queue:      queue,
		Handshakes: c.handshakes.Load(),
		Decoys:     c.decoys.Load(),
		Fragmented: c.fragmented.Load(),
		Errors:     c.errors.Load(),
	}
}
