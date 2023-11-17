package ui

import (
	"bufio"
	"bytes"
	"io"
	"strings"

	"github.com/anchore/syft/internal/log"
)

func newLogWriter() io.Writer {
	l := logWriter{}
	l.r = bufio.NewReader(&l.buf)
	return &l
}

type logWriter struct {
	buf bytes.Buffer
	r   *bufio.Reader
}

func (l *logWriter) Write(data []byte) (n int, err error) {
	l.buf.Write(data)
	s, err := l.r.ReadString('\n')
	s = strings.TrimRight(s, "\n")
	for s != "" {
		log.Trace("[unexpected stdout] " + s)
		n += len(s)
		if err != nil {
			break
		}
		s, err = l.r.ReadString('\n')
		s = strings.TrimRight(s, "\n")
	}
	return n, err
}
