package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBinaryFromURL_Key(t *testing.T) {
	tests := []struct {
		name     string
		binary   BinaryFromURL
		expected string
	}{
		{
			name: "gocase",
			binary: BinaryFromURL{
				GenericName: "test",
				Version:     "1.0",
			},
			expected: "test:1.0",
		},
		{
			name: "from urls",
			binary: BinaryFromURL{
				Version: "1.0",
				Targets: []URLTarget{
					{URL: "https://example.com/test"},
				},
			},
			expected: "test:1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.binary.Key())
		})
	}
}

func TestBinaryFromURL_Name(t *testing.T) {
	tests := []struct {
		name     string
		binary   BinaryFromURL
		expected string
	}{
		{
			name: "given name",
			binary: BinaryFromURL{
				GenericName: "given",
				Targets: []URLTarget{
					{URL: "https://example.com/test"},
				},
			},
			expected: "given",
		},
		{
			name: "from url",
			binary: BinaryFromURL{
				Targets: []URLTarget{
					{URL: "https://example.com/test"},
				},
			},
			expected: "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.binary.Name())
		})
	}
}

func TestBinaryFromURL_Filename(t *testing.T) {
	tests := []struct {
		name     string
		binary   BinaryFromURL
		expected string
	}{
		{
			name: "tar.gz format",
			binary: BinaryFromURL{
				Format:        "tar.gz",
				PathInArchive: "bin/test-binary",
			},
			expected: "test-binary",
		},
		{
			name: "raw format",
			binary: BinaryFromURL{
				Format: "raw",
				Targets: []URLTarget{
					{URL: "https://example.com/test"},
				},
			},
			expected: "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.binary.Filename())
		})
	}
}

func TestBinaryFromURL_StorePath(t *testing.T) {
	tests := []struct {
		name     string
		binary   BinaryFromURL
		dest     string
		platform string
		expected string
	}{
		{
			name: "gocase",
			binary: BinaryFromURL{
				GenericName:   "test",
				Version:       "1.0",
				Format:        "tar.gz",
				PathInArchive: "test-binary",
			},
			dest:     "dest",
			platform: "linux-amd64",
			expected: "dest/test/1.0/linux-amd64/test-binary",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.binary.StorePath(tt.dest, tt.platform))
		})
	}
}

func TestBinaryFromURL_Digest(t *testing.T) {
	tests := []struct {
		name     string
		binary   BinaryFromURL
		expected string
	}{
		{
			name: "gocase",
			binary: BinaryFromURL{
				GenericName: "test",
				Version:     "1.0",
				Targets: []URLTarget{
					{URL: "https://example.com/test"},
				},
			},
			expected: "c53a4975115f7964", // expected to match xxhash.New64() sum of marshaled yaml
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.binary.Digest())
		})
	}
}
