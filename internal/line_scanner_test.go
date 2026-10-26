package internal

import (
	"bufio"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewLineScanner(t *testing.T) {
	long := strings.Repeat("a", 100*1024)
	s := NewLineScanner(strings.NewReader(long + "\nb\n"))
	require.True(t, s.Scan())
	require.Equal(t, long, s.Text())
	require.True(t, s.Scan())
	require.Equal(t, "b", s.Text())
	require.False(t, s.Scan())
	require.NoError(t, s.Err())

	s = NewLineScanner(strings.NewReader(strings.Repeat("a", maxScannedLineSize+1)))
	require.False(t, s.Scan())
	require.ErrorIs(t, s.Err(), bufio.ErrTooLong)
}
