package unionreader

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

func Test_getUnionReader_notUnionReader(t *testing.T) {
	expectedContents := "this is a test"
	reader := io.NopCloser(strings.NewReader(expectedContents))

	// make certain that the test fixture does not implement the union reader
	_, ok := reader.(UnionReader)
	require.False(t, ok)

	actual, err := GetUnionReader(reader)
	require.NoError(t, err)

	_, ok = actual.(UnionReader)
	require.True(t, ok)

	b, err := io.ReadAll(actual)
	require.NoError(t, err)

	assert.Equal(t, expectedContents, string(b))
}

type panickingUnionReader struct{}

func (p2 *panickingUnionReader) ReadAt(p []byte, off int64) (n int, err error) {
	panic("don't call this in your unit test!")
}

func (p2 *panickingUnionReader) Seek(offset int64, whence int) (int64, error) {
	panic("don't call this in your unit test!")
}

func (p2 *panickingUnionReader) Read(p []byte) (n int, err error) {
	panic("don't call this in your unit test!")
}

func (p2 *panickingUnionReader) Close() error {
	panic("don't call this in your unit test!")
}

var _ UnionReader = (*panickingUnionReader)(nil)

func Test_getUnionReader_fileLocationReadCloser(t *testing.T) {
	// panickingUnionReader is a UnionReader
	p := &panickingUnionReader{}
	embedsUnionReader := file.NewLocationReadCloser(file.Location{}, p)

	// embedded union reader is returned without "ReadAll" invocation
	ur, err := GetUnionReader(embedsUnionReader)
	require.NoError(t, err)
	require.Equal(t, p, ur)
}
