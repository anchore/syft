package ui

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_capture(t *testing.T) {
	r, w, _ := os.Pipe()
	t.Logf("pipe1: %+v", w)

	buf := &bytes.Buffer{}
	buf2 := &bytes.Buffer{}

	go func() {
		// write to the main file (e.g. os.Stdout)
		_, _ = w.WriteString("write1")

		// capture the output to the provided buffer
		restoreInitial := capture(&w, buf, 1024)
		t.Logf("pipe2: %+v", w)
		_, _ = w.WriteString("write2")

		// capture output nested
		restoreFirstCapture := capture(&w, buf2, 1024)
		t.Logf("pipe3: %+v", w)
		_, _ = w.WriteString("write3")

		// discard file used to write the "write3"
		restoreFirstCapture()

		// restore should block until all output has been captured, so it's safe to read buf2 here
		require.Equal(t, "write3", buf2.String())

		// restore should be safe to call multiple times
		restoreFirstCapture()
		require.Equal(t, "write3", buf2.String())

		// write again to the initial buffer
		t.Logf("pipe2+: %+v", w)
		_, _ = w.WriteString("write2+")

		// restore the initial file (e.g. os.Stdout) and write more to it
		restoreInitial()
		t.Logf("pipe1+: %+v", w)
		_, _ = w.WriteString("write1+")

		// close the pipe to continue with the io.ReadAll, below
		_ = w.Close()
	}()

	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, "write1write1+", string(got))

	require.Equal(t, "write2write2+", buf.String())
}

func Test_captureBufSizes(t *testing.T) {
	_, w, _ := os.Pipe()

	buf := &bytes.Buffer{}
	restore := capture(&w, buf, 200)

	line := "line1\nline2\nline3"

	_, err := w.WriteString(line)
	require.NoError(t, err)

	restore()
	require.Equal(t, line, buf.String())

	buf.Reset()
	restore = capture(&w, buf, 2)

	_, err = w.WriteString(line)
	require.NoError(t, err)

	restore()
	require.Equal(t, line, buf.String())
}
