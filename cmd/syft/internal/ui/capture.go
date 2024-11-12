package ui

import (
	"io"
	"os"
	"time"

	"github.com/anchore/syft/internal/log"
)

const defaultStdoutLogBufferSize = 1024

// CaptureStdoutToTraceLog replaces stdout and redirects output to the log as trace lines. The return value is a
// function, which is used to stop the current capturing of output and restore the original file.
// Example:
//
//	restore := CaptureStdoutToTraceLog()
//	// here, stdout will be captured and redirected to the provided writer
//	restore() // block until the output has all been sent to the writer and restore the original stdout
func CaptureStdoutToTraceLog() func() {
	return capture(&os.Stdout, newLogWriter(), defaultStdoutLogBufferSize)
}

func capture(target **os.File, writer io.Writer, bufSize int) func() {
	original := *target

	r, w, _ := os.Pipe()

	*target = w

	done := make(chan struct{}, 1)

	go func() {
		defer func() {
			done <- struct{}{}
		}()

		buf := make([]byte, bufSize)
		for {
			if original == nil {
				break
			}

			n, err := r.Read(buf)
			if n > 0 {
				_, _ = writer.Write(buf[0:n])
			}

			if err != nil {
				break
			}
		}
	}()

	return func() {
		if original != nil {
			_ = w.Close()
			select {
			case <-done:
			case <-time.After(1 * time.Second):
				log.Debugf("stdout buffer timed out after 1 second")
			}
			*target = original
			original = nil
		}
	}
}
