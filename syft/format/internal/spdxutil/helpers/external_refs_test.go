package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
)

func Test_ExternalRefs(t *testing.T) {
	testCPE := cpe.Must("cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*", cpe.Source(""))
	tests := []struct {
		name     string
		input    pkg.Package
		expected []ExternalRef
	}{
		{
			name: "cpe + purl",
			input: pkg.Package{
				CPEs: []cpe.CPE{
					testCPE,
				},
				PURL: "a-purl",
			},
			expected: []ExternalRef{
				{
					ReferenceCategory: SecurityReferenceCategory,
					ReferenceLocator:  testCPE.Attributes.String(),
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
