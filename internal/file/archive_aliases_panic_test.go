package file

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// panickingReader stands in for the malformed input that makes archives.Identify panic
// while sniffing a header, rather than return an error.
type panickingReader struct{}

func (panickingReader) Read([]byte) (int, error) {
	panic("simulated panic from archive header sniffing")
}

// A single malformed file must not take down the cataloger walking over it: the panic is
// reported as an ordinary identification failure, which callers already handle.
func TestIdentifyArchiveRecoversFromPanic(t *testing.T) {
	var format, reader, err = func() (f any, r io.Reader, e error) {
		return IdentifyArchive(context.Background(), "/tmp/malformed.tar.gz", panickingReader{})
	}()

	require.Error(t, err, "a panic must surface as an error")
	assert.Contains(t, err.Error(), "recovered from panic")
	assert.Nil(t, format)
	assert.Nil(t, reader)
}

// The compound-alias mapping is the reason this wrapper exists, so the recover must not
// have changed it.
func TestIdentifyArchiveStillMapsCompoundAliases(t *testing.T) {
	assert.Equal(t, "/tmp/x.tar.gz", handleCompoundArchiveAliases("/tmp/x.tgz"))
	assert.Equal(t, "/tmp/x.tar.bz2", handleCompoundArchiveAliases("/tmp/x.tbz2"))
	assert.Equal(t, "/tmp/x.zip", handleCompoundArchiveAliases("/tmp/x.zip"))
}
