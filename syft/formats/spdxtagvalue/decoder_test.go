package spdxtagvalue

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TODO: this is a temporary coverage see below
// This test should be covered within the encode decode life cycle however
// we're currently blocked on a couple of SPDX fields that change often
// which causes backward compatibility issues.
// This test was added specifically to smoke test the decode function when
// It failed on a released version of syft.
func TestSPDXTagValueDecoder(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
	}{
		{
			name:    "simple",
			fixture: "tag-value.spdx",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader, err := os.Open("test-fixtures/" + test.fixture)
			assert.NoError(t, err)

			_, err = Format().Decode(reader)
			assert.NoError(t, err)
		})
	}
}
