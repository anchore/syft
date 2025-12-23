package ocimodelsource

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/source"
)

func TestDeriveID(t *testing.T) {
	tests := []struct {
		name           string
		reference      string
		alias          source.Alias
		manifestDigest string
		expectStable   bool // if true, running twice should produce same ID
	}{
		{
			name:           "uses alias when provided",
			reference:      "docker.io/library/model:latest",
			alias:          source.Alias{Name: "my-model", Version: "1.0"},
			manifestDigest: "sha256:abc123",
			expectStable:   true,
		},
		{
			name:           "uses manifest digest when no alias",
			reference:      "docker.io/library/model:latest",
			alias:          source.Alias{},
			manifestDigest: "sha256:abc123",
			expectStable:   true,
		},
		{
			name:           "uses reference as fallback",
			reference:      "docker.io/library/model:latest",
			alias:          source.Alias{},
			manifestDigest: "",
			expectStable:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id1 := deriveID(test.reference, test.alias, test.manifestDigest)
			id2 := deriveID(test.reference, test.alias, test.manifestDigest)

			assert.NotEmpty(t, id1)
			if test.expectStable {
				assert.Equal(t, id1, id2, "ID should be deterministic")
			}
		})
	}
}

func TestDeriveID_DifferentInputsProduceDifferentIDs(t *testing.T) {
	id1 := deriveID("ref1", source.Alias{}, "sha256:abc")
	id2 := deriveID("ref2", source.Alias{}, "sha256:def")

	assert.NotEqual(t, id1, id2)
}
