package task

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/cpe"
)

func Test_hasAuthoritativeCPE(t *testing.T) {
	tests := []struct {
		name string
		cpes []cpe.CPE
		want bool
	}{
		{
			name: "no cpes",
			cpes: []cpe.CPE{},
			want: false,
		},
		{
			name: "no authoritative cpes",
			cpes: []cpe.CPE{
				{
					Source: cpe.GeneratedSource,
				},
			},
			want: false,
		},
		{
			name: "has declared (authoritative) cpe",
			cpes: []cpe.CPE{
				{
					Source: cpe.DeclaredSource,
				},
			},
			want: true,
		},
		{
			name: "has lookup (authoritative) cpe",
			cpes: []cpe.CPE{
				{
					Source: cpe.NVDDictionaryLookupSource,
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hasAuthoritativeCPE(tt.cpes))
		})
	}
}
