package cpe

import (
	"sort"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
)

func mustCPE(c string) pkg.CPE {
	return must(pkg.NewCPE(c))
}

func must(c pkg.CPE, e error) pkg.CPE {
	if e != nil {
		panic(e)
	}
	return c
}

func TestCPESpecificity(t *testing.T) {
	tests := []struct {
		name     string
		input    []pkg.CPE
		expected []pkg.CPE
	}{
		{
			name: "sort strictly by wfn *",
			input: []pkg.CPE{
				mustCPE("cpe:2.3:a:*:package:1:*:*:*:*:*:*:*"),
				mustCPE("cpe:2.3:a:some:package:1:*:*:*:*:*:*:*"),
				mustCPE("cpe:2.3:a:*:package:1:*:*:*:*:some:*:*"),
				mustCPE("cpe:2.3:a:some:package:1:*:*:*:*:some:*:*"),
				mustCPE("cpe:2.3:a:some:package:*:*:*:*:*:*:*:*"),
			},
			expected: []pkg.CPE{
				mustCPE("cpe:2.3:a:some:package:1:*:*:*:*:some:*:*"),
				mustCPE("cpe:2.3:a:some:package:1:*:*:*:*:*:*:*"),
				mustCPE("cpe:2.3:a:some:package:*:*:*:*:*:*:*:*"),
				mustCPE("cpe:2.3:a:*:package:1:*:*:*:*:some:*:*"),
				mustCPE("cpe:2.3:a:*:package:1:*:*:*:*:*:*:*"),
			},
		},
		{
			name: "sort strictly by field length",
			input: []pkg.CPE{
				mustCPE("cpe:2.3:a:1:22:1:*:*:*:*:1:*:*"),
				mustCPE("cpe:2.3:a:55555:1:1:*:*:*:*:1:*:*"),
				mustCPE("cpe:2.3:a:1:1:333:*:*:*:*:1:*:*"),
				mustCPE("cpe:2.3:a:1:666666:1:*:*:*:*:1:*:*"),
				mustCPE("cpe:2.3:a:1:1:1:*:*:*:*:1:*:*"),
				mustCPE("cpe:2.3:a:1:1:1:*:*:*:*:4444:*:*"),
			},
			expected: []pkg.CPE{
				mustCPE("cpe:2.3:a:1:666666:1:*:*:*:*:1:*:*"),
				mustCPE("cpe:2.3:a:55555:1:1:*:*:*:*:1:*:*"),
				mustCPE("cpe:2.3:a:1:1:1:*:*:*:*:4444:*:*"),
				mustCPE("cpe:2.3:a:1:1:333:*:*:*:*:1:*:*"),
				mustCPE("cpe:2.3:a:1:22:1:*:*:*:*:1:*:*"),
				mustCPE("cpe:2.3:a:1:1:1:*:*:*:*:1:*:*"),
			},
		},
		{
			name: "sort by mix of field length and specificity",
			input: []pkg.CPE{
				mustCPE("cpe:2.3:a:1:666666:*:*:*:*:*:1:*:*"),
				mustCPE("cpe:2.3:a:*:1:1:*:*:*:*:4444:*:*"),
				mustCPE("cpe:2.3:a:1:*:333:*:*:*:*:*:*:*"),
				mustCPE("cpe:2.3:a:1:1:1:*:*:*:*:1:*:*"),
				mustCPE("cpe:2.3:a:1:22:1:*:*:*:*:1:*:*"),
				mustCPE("cpe:2.3:a:55555:1:1:*:*:*:*:1:*:*"),
			},
			expected: []pkg.CPE{
				mustCPE("cpe:2.3:a:55555:1:1:*:*:*:*:1:*:*"),
				mustCPE("cpe:2.3:a:1:22:1:*:*:*:*:1:*:*"),
				mustCPE("cpe:2.3:a:1:1:1:*:*:*:*:1:*:*"),
				mustCPE("cpe:2.3:a:1:666666:*:*:*:*:*:1:*:*"),
				mustCPE("cpe:2.3:a:*:1:1:*:*:*:*:4444:*:*"),
				mustCPE("cpe:2.3:a:1:*:333:*:*:*:*:*:*:*"),
			},
		},
		{
			name: "sort by mix of field length, specificity, dash",
			input: []pkg.CPE{
				mustCPE("cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
				mustCPE("cpe:2.3:a:alpine_keys:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
				mustCPE("cpe:2.3:a:alpine-keys:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
				mustCPE("cpe:2.3:a:alpine:alpine-keys:2.3-r1:*:*:*:*:*:*:*"),
				mustCPE("cpe:2.3:a:alpine-keys:alpine-keys:2.3-r1:*:*:*:*:*:*:*"),
				mustCPE("cpe:2.3:a:alpine_keys:alpine-keys:2.3-r1:*:*:*:*:*:*:*"),
			},
			expected: []pkg.CPE{
				mustCPE("cpe:2.3:a:alpine-keys:alpine-keys:2.3-r1:*:*:*:*:*:*:*"),
				mustCPE("cpe:2.3:a:alpine-keys:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
				mustCPE("cpe:2.3:a:alpine_keys:alpine-keys:2.3-r1:*:*:*:*:*:*:*"),
				mustCPE("cpe:2.3:a:alpine_keys:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
				mustCPE("cpe:2.3:a:alpine:alpine-keys:2.3-r1:*:*:*:*:*:*:*"),
				mustCPE("cpe:2.3:a:alpine:alpine_keys:2.3-r1:*:*:*:*:*:*:*"),
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
