package spdxhelpers

import (
	"testing"

	"github.com/anchore/syft/internal/formats/spdx22json/model"
	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
)

func Test_ExternalRefs(t *testing.T) {
	testCPE := pkg.MustCPE("cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*")
	tests := []struct {
		name     string
		input    pkg.Package
		expected []model.ExternalRef
	}{
		{
			name: "cpe + purl",
			input: pkg.Package{
				CPEs: []pkg.CPE{
					testCPE,
				},
				PURL: "a-purl",
			},
			expected: []model.ExternalRef{
				{
					ReferenceCategory: model.SecurityReferenceCategory,
					ReferenceLocator:  testCPE.BindToFmtString(),
					ReferenceType:     model.Cpe23ExternalRefType,
				},
				{
					ReferenceCategory: model.PackageManagerReferenceCategory,
					ReferenceLocator:  "a-purl",
					ReferenceType:     model.PurlExternalRefType,
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
