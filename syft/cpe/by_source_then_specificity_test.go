package cpe

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBySourceThenSpecificity(t *testing.T) {
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
				Must("cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*", GeneratedSource),
				Must("cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*", NVDDictionaryLookupSource),
			},
			want: []CPE{
				Must("cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*", NVDDictionaryLookupSource),
				Must("cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*", GeneratedSource),
			},
		},
		{
			name: "declared before generated",
			input: []CPE{
				Must("cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*", GeneratedSource),
				Must("cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*", DeclaredSource),
			},
			want: []CPE{
				Must("cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*", DeclaredSource),
				Must("cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*", GeneratedSource),
			},
		},
		{
			name: "most specific attributes of equal sources",
			input: []CPE{
				Must("cpe:2.3:a:some:package:*:*:*:*:*:*:*:*", NVDDictionaryLookupSource),
				Must("cpe:2.3:a:some:package:1:*:*:*:*:*:*:*", NVDDictionaryLookupSource),
				Must("cpe:2.3:a:some:package:1:*:*:*:*:some:*:*", NVDDictionaryLookupSource),
			},
			want: []CPE{
				Must("cpe:2.3:a:some:package:1:*:*:*:*:some:*:*", NVDDictionaryLookupSource),
				Must("cpe:2.3:a:some:package:1:*:*:*:*:*:*:*", NVDDictionaryLookupSource),
				Must("cpe:2.3:a:some:package:*:*:*:*:*:*:*:*", NVDDictionaryLookupSource),
			},
		},
		{
			name: "most specific attributes of unknown sources",
			input: []CPE{
				Must("cpe:2.3:a:some:package:1:*:*:*:*:*:*:*", ""),
				Must("cpe:2.3:a:some:package:1:*:*:*:*:some:*:*", "some-other-unknown-source"),
				Must("cpe:2.3:a:some:package:*:*:*:*:*:*:*:*", "some-unknown-source"),
			},
			want: []CPE{
				Must("cpe:2.3:a:some:package:1:*:*:*:*:some:*:*", "some-other-unknown-source"),
				Must("cpe:2.3:a:some:package:1:*:*:*:*:*:*:*", ""),
				Must("cpe:2.3:a:some:package:*:*:*:*:*:*:*:*", "some-unknown-source"),
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
