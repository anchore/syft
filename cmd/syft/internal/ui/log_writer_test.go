package ui

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/go-logger"
	"github.com/anchore/syft/internal/log"
)

func Test_logWriter(t *testing.T) {
	w := newLogWriter()

	orig := log.Get()
	t.Cleanup(func() {
		log.Set(orig)
	})

	bl := &bufferLogger{}
	log.Set(bl)

	_, _ = w.Write([]byte("a\nvalue"))

	expected := []any{"[unexpected stdout] a", "[unexpected stdout] value"}
	require.Equal(t, expected, bl.values)

	bl.values = nil
	_, _ = w.Write([]byte("some"))
	_, _ = w.Write([]byte("thing"))

	expected = []any{"[unexpected stdout] some", "[unexpected stdout] thing"}
	require.Equal(t, expected, bl.values)
}

type bufferLogger struct{ values []any }

func (l *bufferLogger) Tracef(_ string, _ ...interface{}) {}

func (l *bufferLogger) Debugf(_ string, _ ...interface{}) {}

func (l *bufferLogger) Infof(_ string, _ ...interface{}) {}

func (l *bufferLogger) Warnf(_ string, _ ...interface{}) {}

func (l *bufferLogger) Errorf(_ string, _ ...interface{}) {}

func (l *bufferLogger) Trace(vals ...interface{}) {
	l.values = append(l.values, vals...)
}

func (l *bufferLogger) Debug(_ ...interface{}) {}

func (l *bufferLogger) Info(_ ...interface{}) {}

func (l *bufferLogger) Warn(vals ...interface{}) {
	l.values = append(l.values, vals...)
}

func (l *bufferLogger) Error(_ ...interface{}) {}

func (l *bufferLogger) WithFields(_ ...interface{}) logger.MessageLogger { return l }

func (l *bufferLogger) Nested(_ ...interface{}) logger.Logger { return l }

func (l *bufferLogger) SetOutput(_ io.Writer) {}

func (l *bufferLogger) GetOutput() io.Writer { return nil }
