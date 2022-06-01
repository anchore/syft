package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSupportedFormat(t *testing.T) {
	tests := []struct {
		outputs []string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			outputs: []string{"json"},
			wantErr: assert.NoError,
		},
		{
			outputs: []string{"table", "json"},
			wantErr: assert.NoError,
		},
		{
			outputs: []string{"unknown"},
			wantErr: func(t assert.TestingT, err error, bla ...interface{}) bool {
				return assert.ErrorContains(t, err, "bad output format: 'unknown'")
			},
		},
	}

	for _, tt := range tests {
		_, err := MakeWriter(tt.outputs, "")
		tt.wantErr(t, err)
	}
}
