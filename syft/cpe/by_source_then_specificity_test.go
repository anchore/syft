package cpe

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBySourceThenSpecificity(t *testing.T) {
	type args struct {
		i int
		j int
	}
	tests := []struct {
		name  string
		input []CPE
		want  []CPE
	}{
		{
			name: "empty case",
		},
		{
			name: "nvd before generated",
			input: []CPE{
				mustSourcedCPE(GeneratedSource, "cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
				mustSourcedCPE(NVDDictionaryLookupSource, "cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
			},
			want: []CPE{
				mustSourcedCPE(NVDDictionaryLookupSource, "cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
				mustSourcedCPE(GeneratedSource, "cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
			},
		},
		{
			name: "declared before generated",
			input: []CPE{
				mustSourcedCPE(GeneratedSource, "cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
				mustSourcedCPE(DeclaredSource, "cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
			},
			want: []CPE{
				mustSourcedCPE(DeclaredSource, "cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
				mustSourcedCPE(GeneratedSource, "cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
			},
		},
		{
			name: "most specific attributes of equal sources",
			input: []CPE{
				mustSourcedCPE(NVDDictionaryLookupSource, "cpe:2.3:a:some:package:*:*:*:*:*:*:*:*"),
				mustSourcedCPE(NVDDictionaryLookupSource, "cpe:2.3:a:some:package:1:*:*:*:*:*:*:*"),
				mustSourcedCPE(NVDDictionaryLookupSource, "cpe:2.3:a:some:package:1:*:*:*:*:some:*:*"),
			},
			want: []CPE{
				mustSourcedCPE(NVDDictionaryLookupSource, "cpe:2.3:a:some:package:1:*:*:*:*:some:*:*"),
				mustSourcedCPE(NVDDictionaryLookupSource, "cpe:2.3:a:some:package:1:*:*:*:*:*:*:*"),
				mustSourcedCPE(NVDDictionaryLookupSource, "cpe:2.3:a:some:package:*:*:*:*:*:*:*:*"),
			},
		},
		{
			name: "most specific attributes of unknown sources",
			input: []CPE{
				mustSourcedCPE("", "cpe:2.3:a:some:package:1:*:*:*:*:*:*:*"),
				mustSourcedCPE("some-other-unknown-source", "cpe:2.3:a:some:package:1:*:*:*:*:some:*:*"),
				mustSourcedCPE("some-unknown-source", "cpe:2.3:a:some:package:*:*:*:*:*:*:*:*"),
			},
			want: []CPE{
				mustSourcedCPE("some-other-unknown-source", "cpe:2.3:a:some:package:1:*:*:*:*:some:*:*"),
				mustSourcedCPE("", "cpe:2.3:a:some:package:1:*:*:*:*:*:*:*"),
				mustSourcedCPE("some-unknown-source", "cpe:2.3:a:some:package:*:*:*:*:*:*:*:*"),
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

func mustSourcedCPE(source Source, str string) CPE {
	return Must(str).WithSource(source)
}
