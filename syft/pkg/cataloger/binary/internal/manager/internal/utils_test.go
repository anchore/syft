package internal

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitFilepath(t *testing.T) {
	tests := []struct {
		path     string
		expected []string
	}{
		{path: "a/b/c", expected: []string{"a", "b", "c"}},
	}

	for _, test := range tests {
		result := SplitFilepath(test.path)
		assert.Equal(t, test.expected, result)
	}
}

func TestSha256SumFile(t *testing.T) {
	content := "test content"
	reader := strings.NewReader(content)

	hash, err := Sha256SumFile(reader)
	require.NoError(t, err, "Sha256SumFile should not return an error")

	expectedHash := Sha256SumBytes([]byte(content))
	assert.Equal(t, expectedHash, hash)
}

func TestSha256SumBytes(t *testing.T) {

	tests := []struct {
		input    []byte
		expected string
	}{
		{input: []byte("hello"), expected: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
	}

	for _, test := range tests {
		result := Sha256SumBytes(test.input)
		assert.Equal(t, test.expected, result)
	}
}
