package file

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// errReader returns a deterministic non-EOF error after emitting some
// bytes, mimicking what compress/flate does when it hits a corrupt
// stream mid-entry.
type errReader struct {
	data []byte
	err  error
	off  int
}

func (r *errReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, r.err
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

func TestSafeCopy(t *testing.T) {
	t.Run("clean copy returns nil", func(t *testing.T) {
		var buf bytes.Buffer
		if err := safeCopy(&buf, strings.NewReader("hello")); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := buf.String(); got != "hello" {
			t.Fatalf("unexpected buffer contents: %q", got)
		}
	})

	t.Run("propagates decompression error", func(t *testing.T) {
		// #4806: safeCopy used to drop non-EOF errors, so the caller
		// would persist a partial buffer as a successful extract and
		// downstream catalogers silently read empty manifests.
		sentinel := errors.New("flate: corrupt input before offset 42")
		var buf bytes.Buffer
		err := safeCopy(&buf, &errReader{data: []byte("partial"), err: sentinel})
		if err == nil {
			t.Fatalf("expected error to be returned, got nil")
		}
		if !errors.Is(err, sentinel) {
			t.Fatalf("error does not wrap sentinel: %v", err)
		}
	})

	t.Run("EOF is not treated as an error", func(t *testing.T) {
		// The old code had a dead io.EOF branch that labelled clean
		// reads as decompression bombs; keep the happy path clean.
		var buf bytes.Buffer
		err := safeCopy(&buf, io.LimitReader(strings.NewReader("abc"), 3))
		if err != nil {
			t.Fatalf("unexpected error on clean copy: %v", err)
		}
	})
}
