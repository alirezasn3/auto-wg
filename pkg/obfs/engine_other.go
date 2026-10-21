//go:build !linux

package obfs

import (
	"errors"

	"auto-wg/pkg/config"
	"auto-wg/pkg/logger"
)

// Engine is only functional on Linux, where NFQUEUE exists.
type Engine struct{}

func NewEngine(iface string, queue int, cfg config.ObfuscationConfig, log *logger.Logger) (*Engine, error) {
	return nil, errors.New("handshake obfuscation requires Linux (NFQUEUE)")
}

func (e *Engine) Update(cfg config.ObfuscationConfig) {}
func (e *Engine) Status() Status                      { return Status{} }
func (e *Engine) Close()                              {}
