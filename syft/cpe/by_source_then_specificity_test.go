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
				mustWithSource(GeneratedSource, "cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
				mustWithSource(NVDDictionaryLookupSource, "cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
			},
			want: []CPE{
				mustWithSource(NVDDictionaryLookupSource, "cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
				mustWithSource(GeneratedSource, "cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
			},
		},
		{
			name: "declared before generated",
			input: []CPE{
				mustWithSource(GeneratedSource, "cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
				mustWithSource(DeclaredSource, "cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
			},
			want: []CPE{
				mustWithSource(DeclaredSource, "cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
				mustWithSource(GeneratedSource, "cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
			},
		},
		{
			name: "most specific attributes of equal sources",
			input: []CPE{
				mustWithSource(NVDDictionaryLookupSource, "cpe:2.3:a:some:package:*:*:*:*:*:*:*:*"),
				mustWithSource(NVDDictionaryLookupSource, "cpe:2.3:a:some:package:1:*:*:*:*:*:*:*"),
				mustWithSource(NVDDictionaryLookupSource, "cpe:2.3:a:some:package:1:*:*:*:*:some:*:*"),
			},
			want: []CPE{
				mustWithSource(NVDDictionaryLookupSource, "cpe:2.3:a:some:package:1:*:*:*:*:some:*:*"),
				mustWithSource(NVDDictionaryLookupSource, "cpe:2.3:a:some:package:1:*:*:*:*:*:*:*"),
				mustWithSource(NVDDictionaryLookupSource, "cpe:2.3:a:some:package:*:*:*:*:*:*:*:*"),
			},
		},
		{
			name: "most specific attributes of unknown sources",
			input: []CPE{
				mustWithSource("", "cpe:2.3:a:some:package:1:*:*:*:*:*:*:*"),
				mustWithSource("some-other-unknown-source", "cpe:2.3:a:some:package:1:*:*:*:*:some:*:*"),
				mustWithSource("some-unknown-source", "cpe:2.3:a:some:package:*:*:*:*:*:*:*:*"),
			},
			want: []CPE{
				mustWithSource("some-other-unknown-source", "cpe:2.3:a:some:package:1:*:*:*:*:some:*:*"),
				mustWithSource("", "cpe:2.3:a:some:package:1:*:*:*:*:*:*:*"),
				mustWithSource("some-unknown-source", "cpe:2.3:a:some:package:*:*:*:*:*:*:*:*"),
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

func mustWithSource(source Source, str string) CPE {
	return Must(str).WithSource(source)
}
