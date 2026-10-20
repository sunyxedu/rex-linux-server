package main

/*
#cgo CFLAGS: -I/tmp/ghostty/zig-out/include -DGHOSTTY_STATIC
#cgo LDFLAGS: -L/tmp/ghostty/zig-out/lib -lghostty-vt -lm -lpthread

#include <ghostty/vt.h>
#include <stdlib.h>

*/
import "C"
import (
	"fmt"
	"sync"
	"unsafe"
)

// GhosttyTerminal wraps a libghostty-vt terminal instance.
// It maintains the full terminal emulator state (grid, scrollback,
// cursor, styles, etc.) and can produce correct GHOSTSNP snapshots.
type GhosttyTerminal struct {
	term C.GhosttyTerminal
	mu   sync.Mutex
}

// NewGhosttyTerminal creates a new terminal with the given dimensions.
func NewGhosttyTerminal(cols, rows int) (*GhosttyTerminal, error) {
	var term C.GhosttyTerminal
	result := C.ghostty_terminal_new(nil, &term, C.uint16_t(cols), C.uint16_t(rows))
	if result != C.GHOSTTY_SUCCESS {
		return nil, fmt.Errorf("ghostty_terminal_new failed: %d", result)
	}
	return &GhosttyTerminal{term: term}, nil
}

// Write feeds VT-encoded data into the terminal (processes escape sequences).
func (t *GhosttyTerminal) Write(data []byte) {
	if len(data) == 0 || t.term == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	C.ghostty_terminal_vt_write(t.term, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
}

// Resize changes the terminal dimensions.
func (t *GhosttyTerminal) Resize(cols, rows int) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	result := C.ghostty_terminal_resize(t.term, C.uint16_t(cols), C.uint16_t(rows), 0, 0)
	if result != C.GHOSTTY_SUCCESS {
		return fmt.Errorf("ghostty_terminal_resize failed: %d", result)
	}
	return nil
}

// Snapshot encodes the complete terminal state as a GHOSTSNP binary blob.
func (t *GhosttyTerminal) Snapshot() ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var outPtr *C.uint8_t
	var outLen C.size_t
	result := C.ghostty_snapshot_encode_alloc(t.term, nil, &outPtr, &outLen)
	if result != C.GHOSTTY_SUCCESS {
		return nil, fmt.Errorf("ghostty_snapshot_encode_alloc failed: %d", result)
	}
	if outPtr == nil || outLen == 0 {
		return nil, fmt.Errorf("snapshot is empty")
	}

	// Copy to Go-managed memory
	snapshot := C.GoBytes(unsafe.Pointer(outPtr), C.int(outLen))

	// Free the C-allocated buffer
	C.ghostty_free(nil, outPtr, outLen)

	return snapshot, nil
}

// Free releases the terminal resources.
func (t *GhosttyTerminal) Free() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.term != nil {
		C.ghostty_terminal_free(t.term)
		t.term = nil
	}
}
