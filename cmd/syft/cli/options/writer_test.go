package options

import (
	"fmt"
	"testing"

	"github.com/anchore/syft/internal/formats/syftjson"
	"github.com/anchore/syft/internal/formats/table"
	"github.com/anchore/syft/syft/sbom"
	"github.com/stretchr/testify/assert"
)

func TestIsSupportedFormat(t *testing.T) {
	tests := []struct {
		outputs   []string
		supported []sbom.Format
		wantErr   assert.ErrorAssertionFunc
	}{
		{
			outputs:   []string{"json"},
			supported: []sbom.Format{syftjson.Format()},
			wantErr:   assert.NoError,
		},
		{
			outputs:   []string{"table"},
			supported: []sbom.Format{syftjson.Format(), table.Format()},
			wantErr:   assert.NoError,
		},
		{
			outputs: []string{"table"},
			wantErr: func(t assert.TestingT, err error, bla ...interface{}) bool {
				return assert.ErrorContains(t, err, fmt.Sprintf("cannot convert to %s", table.ID))
			},
		},
		{
			outputs:   []string{"table"},
			supported: []sbom.Format{syftjson.Format()},
			wantErr: func(t assert.TestingT, err error, bla ...interface{}) bool {
				return assert.ErrorContains(t, err, fmt.Sprintf("cannot convert to %s", table.ID))
			},
		},
		{
			outputs: []string{"unknown"},
			wantErr: func(t assert.TestingT, err error, bla ...interface{}) bool {
				return assert.ErrorContains(t, err, "bad output format: 'unknown'")
			},
		},
	}

	for _, tt := range tests {
		_, err := MakeWriter(tt.outputs, "", tt.supported...)
		tt.wantErr(t, err)
	}
}
