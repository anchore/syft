package unionreader

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
