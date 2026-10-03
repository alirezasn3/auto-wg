package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Level string

const (
	LevelDebug Level = "DEBUG"
	LevelInfo  Level = "INFO"
	LevelWarn  Level = "WARN"
	LevelError Level = "ERROR"
)

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     Level     `json:"level"`
	Component string    `json:"component"`
	Message   string    `json:"message"`
}

type Logger struct {
	mu          sync.RWMutex
	out         io.Writer
	minLevel    Level
	buffer      []LogEntry
	maxBuffer   int
	subscribers map[chan LogEntry]struct{}
}

var defaultLogger *Logger

func init() {
	defaultLogger = New(os.Stdout, LevelInfo, 1000)
}

func Default() *Logger {
	return defaultLogger
}

func New(out io.Writer, minLevel Level, maxBuffer int) *Logger {
	if maxBuffer <= 0 {
		maxBuffer = 1000
	}
	return &Logger{
		out:         out,
		minLevel:    minLevel,
		buffer:      make([]LogEntry, 0, maxBuffer),
		maxBuffer:   maxBuffer,
		subscribers: make(map[chan LogEntry]struct{}),
	}
}

func (l *Logger) SetMinLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.minLevel = level
}

func (l *Logger) levelPriority(lvl Level) int {
	switch lvl {
	case LevelDebug:
		return 1
	case LevelInfo:
		return 2
	case LevelWarn:
		return 3
	case LevelError:
		return 4
	default:
		return 2
	}
}

func (l *Logger) Log(lvl Level, component, format string, args ...interface{}) {
	l.mu.Lock()
	if l.levelPriority(lvl) < l.levelPriority(l.minLevel) {
		l.mu.Unlock()
		return
	}

	msg := fmt.Sprintf(format, args...)
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     lvl,
		Component: component,
		Message:   msg,
	}

	// Add to in-memory ring buffer
	if len(l.buffer) >= l.maxBuffer {
		l.buffer = l.buffer[1:]
	}
	l.buffer = append(l.buffer, entry)

	// Format console output with colors
	var colorCode string
	switch lvl {
	case LevelDebug:
		colorCode = "\033[36m" // Cyan
	case LevelInfo:
		colorCode = "\033[32m" // Green
	case LevelWarn:
		colorCode = "\033[33m" // Yellow
	case LevelError:
		colorCode = "\033[31m" // Red
	}
	resetCode := "\033[0m"

	timeStr := entry.Timestamp.Format("2006-01-02 15:04:05.000")
	fmt.Fprintf(l.out, "%s [%s%-5s%s] [%-9s] %s\n", timeStr, colorCode, lvl, resetCode, component, msg)

	// Broadcast to active SSE subscribers without blocking
	for ch := range l.subscribers {
		select {
		case ch <- entry:
		default:
			// Subscriber buffer full; skip to keep logger non-blocking
		}
	}
	l.mu.Unlock()
}

func (l *Logger) Debug(component, format string, args ...interface{}) {
	l.Log(LevelDebug, component, format, args...)
}

func (l *Logger) Info(component, format string, args ...interface{}) {
	l.Log(LevelInfo, component, format, args...)
}

func (l *Logger) Warn(component, format string, args ...interface{}) {
	l.Log(LevelWarn, component, format, args...)
}

func (l *Logger) Error(component, format string, args ...interface{}) {
	l.Log(LevelError, component, format, args...)
}

func (l *Logger) GetRecentEntries() []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	res := make([]LogEntry, len(l.buffer))
	copy(res, l.buffer)
	return res
}

func (l *Logger) Subscribe() (chan LogEntry, func()) {
	l.mu.Lock()
	defer l.mu.Unlock()

	ch := make(chan LogEntry, 100)
	l.subscribers[ch] = struct{}{}

	unsubscribe := func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		delete(l.subscribers, ch)
		close(ch)
	}

	return ch, unsubscribe
}

func (e LogEntry) JSON() []byte {
	b, _ := json.Marshal(e)
	return b
}
