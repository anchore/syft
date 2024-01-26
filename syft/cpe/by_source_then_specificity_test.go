package cpe

import (
	"github.com/stretchr/testify/assert"
	"sort"
	"testing"
)

func TestBySourceThenSpecificity(t *testing.T) {
	type args struct {
		i int
		j int
	}
	tests := []struct {
		name  string
		input []SourcedCPE
		want  []SourcedCPE
	}{
		{
			name: "empty case",
		},
		{
			name: "nvd before generated",
			input: []SourcedCPE{
				mustSourcedCPE(GeneratedSource, "cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
				mustSourcedCPE(NVDDictionaryLookupSource, "cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
			},
			want: []SourcedCPE{
				mustSourcedCPE(NVDDictionaryLookupSource, "cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
				mustSourcedCPE(GeneratedSource, "cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sort.Sort(BySourceThenSpecificity(tt.input))
			assert.Equal(t, tt.want, tt.input)
		})
	}
}

func mustSourcedCPE(source Source, str string) SourcedCPE {
	return Must(str).WithSource(source)
}
