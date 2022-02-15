package spdxhelpers

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
)

func Test_ExternalRefs(t *testing.T) {
	testCPE := pkg.MustCPE("cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*")
	tests := []struct {
		name     string
		input    pkg.Package
		expected []ExternalRef
	}{
		{
			name: "cpe + purl",
			input: pkg.Package{
				CPEs: []pkg.CPE{
					testCPE,
				},
				PURL: "a-purl",
			},
			expected: []ExternalRef{
				{
					ReferenceCategory: SecurityReferenceCategory,
					ReferenceLocator:  pkg.CPEString(testCPE),
					ReferenceType:     Cpe23ExternalRefType,
				},
				{
					ReferenceCategory: PackageManagerReferenceCategory,
					ReferenceLocator:  "a-purl",
					ReferenceType:     PurlExternalRefType,
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, ExternalRefs(test.input))
		})
	}
}
