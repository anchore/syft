package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKey(t *testing.T) {
	tests := []struct {
		name     string
		binary   BinaryFromImage
		expected string
	}{
		{
			name: "gocase",
			binary: BinaryFromImage{
				GenericName: "test",
				Version:     "1.0",
			},
			expected: "test:1.0",
		},
		{
			name: "binary name",
			binary: BinaryFromImage{
				Version: "1.0",
				PathsInImage: []string{
					"path/to/test",
				},
			},
			expected: "test:1.0",
		},
		{
			name: "first binary name",
			binary: BinaryFromImage{
				Version: "1.0",
				PathsInImage: []string{
					"path/to/test",
					"path/to/nothing",
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

func TestName(t *testing.T) {
	tests := []struct {
		name     string
		binary   BinaryFromImage
		expected string
	}{
		{
			name: "given name",
			binary: BinaryFromImage{
				GenericName: "given",
				PathsInImage: []string{
					"path/to/test",
				},
			},
			expected: "given",
		},
		{
			name: "binary name",
			binary: BinaryFromImage{
				PathsInImage: []string{
					"path/to/test",
				},
			},
			expected: "test",
		},
		{
			name: "first binary name",
			binary: BinaryFromImage{
				PathsInImage: []string{
					"path/to/test",
					"path/to/nothing",
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

func TestAllStorePaths(t *testing.T) {
	tests := []struct {
		name     string
		binary   BinaryFromImage
		dest     string
		expected []string
	}{
		{
			name: "gocase",
			binary: BinaryFromImage{
				GenericName: "test",
				Version:     "1.0",
				Images: []Image{
					{
						Reference: "ref1",
						Platform:  "platform1",
					},
					{
						Reference: "ref2",
						Platform:  "platform2",
					},
				},
				PathsInImage: []string{
					"path/to/test1",
					"path/to/test2",
				},
			},
			dest: "dest",
			expected: []string{
				"dest/test/1.0/platform1/test1",
				"dest/test/1.0/platform1/test2",
				"dest/test/1.0/platform2/test1",
				"dest/test/1.0/platform2/test2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.binary.AllStorePaths(tt.dest))
		})
	}
}

func TestPlatformAsValue(t *testing.T) {
	tests := []struct {
		name     string
		platform string
		expected string
	}{
		{
			name:     "gocase",
			platform: "platform/test",
			expected: "platform-test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, PlatformAsValue(tt.platform))
		})
	}
}

func TestDigest(t *testing.T) {
	tests := []struct {
		name     string
		binary   BinaryFromImage
		expected string
	}{
		{
			name: "gocase",
			binary: BinaryFromImage{
				GenericName: "test",
				Version:     "1.0",
				Images: []Image{
					{
						Reference: "ref",
						Platform:  "platform",
					},
				},
				PathsInImage: []string{
					"path/to/test",
				},
			},
			expected: "fc25c48e3d2f01e3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.binary.Digest())
		})
	}
}
