package cpe

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_BySpecificity(t *testing.T) {
	tests := []struct {
		name     string
		input    []Attributes
		expected []Attributes
	}{
		{
			name: "sort strictly by wfn *",
			input: []Attributes{
				MustAttributes("cpe:2.3:a:*:package:1:*:*:*:*:*:*:*"),
				MustAttributes("cpe:2.3:a:some:package:1:*:*:*:*:*:*:*"),
				MustAttributes("cpe:2.3:a:*:package:1:*:*:*:*:some:*:*"),
				MustAttributes("cpe:2.3:a:some:package:1:*:*:*:*:some:*:*"),
				MustAttributes("cpe:2.3:a:some:package:*:*:*:*:*:*:*:*"),
			},
			expected: []Attributes{
				MustAttributes("cpe:2.3:a:some:package:1:*:*:*:*:some:*:*"),
				MustAttributes("cpe:2.3:a:some:package:1:*:*:*:*:*:*:*"),
				MustAttributes("cpe:2.3:a:some:package:*:*:*:*:*:*:*:*"),
				MustAttributes("cpe:2.3:a:*:package:1:*:*:*:*:some:*:*"),
				MustAttributes("cpe:2.3:a:*:package:1:*:*:*:*:*:*:*"),
			},
		},
		{
			name: "sort strictly by field length",
			input: []Attributes{
				MustAttributes("cpe:2.3:a:1:22:1:*:*:*:*:1:*:*"),
				MustAttributes("cpe:2.3:a:55555:1:1:*:*:*:*:1:*:*"),
				MustAttributes("cpe:2.3:a:1:1:333:*:*:*:*:1:*:*"),
				MustAttributes("cpe:2.3:a:1:666666:1:*:*:*:*:1:*:*"),
				MustAttributes("cpe:2.3:a:1:1:1:*:*:*:*:1:*:*"),
				MustAttributes("cpe:2.3:a:1:1:1:*:*:*:*:4444:*:*"),
			},
			expected: []Attributes{
				MustAttributes("cpe:2.3:a:1:666666:1:*:*:*:*:1:*:*"),
				MustAttributes("cpe:2.3:a:55555:1:1:*:*:*:*:1:*:*"),
				MustAttributes("cpe:2.3:a:1:1:1:*:*:*:*:4444:*:*"),
				MustAttributes("cpe:2.3:a:1:1:333:*:*:*:*:1:*:*"),
				MustAttributes("cpe:2.3:a:1:22:1:*:*:*:*:1:*:*"),
				MustAttributes("cpe:2.3:a:1:1:1:*:*:*:*:1:*:*"),
			},
		},
		{
			name: "sort by mix of field length and specificity",
			input: []Attributes{
				MustAttributes("cpe:2.3:a:1:666666:*:*:*:*:*:1:*:*"),
				MustAttributes("cpe:2.3:a:*:1:1:*:*:*:*:4444:*:*"),
				MustAttributes("cpe:2.3:a:1:*:333:*:*:*:*:*:*:*"),
				MustAttributes("cpe:2.3:a:1:1:1:*:*:*:*:1:*:*"),
				MustAttributes("cpe:2.3:a:1:22:1:*:*:*:*:1:*:*"),
				MustAttributes("cpe:2.3:a:55555:1:1:*:*:*:*:1:*:*"),
			},
			expected: []Attributes{
				MustAttributes("cpe:2.3:a:55555:1:1:*:*:*:*:1:*:*"),
				MustAttributes("cpe:2.3:a:1:22:1:*:*:*:*:1:*:*"),
				MustAttributes("cpe:2.3:a:1:1:1:*:*:*:*:1:*:*"),
				MustAttributes("cpe:2.3:a:1:666666:*:*:*:*:*:1:*:*"),
				MustAttributes("cpe:2.3:a:*:1:1:*:*:*:*:4444:*:*"),
				MustAttributes("cpe:2.3:a:1:*:333:*:*:*:*:*:*:*"),
			},
		},
		{
			name: "sort by mix of field length, specificity, dash",
			input: []Attributes{
				MustAttributes("cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
				MustAttributes("cpe:2.3:a:alpine_keys:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
				MustAttributes("cpe:2.3:a:alpine-keys:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
				MustAttributes("cpe:2.3:a:alpine:alpine-keys:2.3-r1:*:*:*:*:*:*:*"),
				MustAttributes("cpe:2.3:a:alpine-keys:alpine-keys:2.3-r1:*:*:*:*:*:*:*"),
				MustAttributes("cpe:2.3:a:alpine_keys:alpine-keys:2.3-r1:*:*:*:*:*:*:*"),
			},
			expected: []Attributes{
				MustAttributes("cpe:2.3:a:alpine-keys:alpine-keys:2.3-r1:*:*:*:*:*:*:*"),
				MustAttributes("cpe:2.3:a:alpine-keys:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
				MustAttributes("cpe:2.3:a:alpine_keys:alpine-keys:2.3-r1:*:*:*:*:*:*:*"),
				MustAttributes("cpe:2.3:a:alpine_keys:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
				MustAttributes("cpe:2.3:a:alpine:alpine-keys:2.3-r1:*:*:*:*:*:*:*"),
				MustAttributes("cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sort.Sort(BySpecificity(test.input))
			assert.Equal(t, test.expected, test.input)
		})
	}
}
