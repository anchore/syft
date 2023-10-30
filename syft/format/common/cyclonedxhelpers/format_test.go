package cyclonedxhelpers

import (
	"fmt"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func Test_formatCPE(t *testing.T) {
	tests := []struct {
		cpe      string
		expected string
	}{
		{
			cpe:      "cpe:2.3:o:amazon:amazon_linux:2",
			expected: "cpe:2.3:o:amazon:amazon_linux:2:*:*:*:*:*:*:*",
		},
		{
			cpe:      "cpe:/o:opensuse:leap:15.2",
			expected: "cpe:2.3:o:opensuse:leap:15.2:*:*:*:*:*:*:*",
		},
		{
			cpe:      "invalid-cpe",
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.cpe, func(t *testing.T) {
			out := formatCPE(test.cpe)
			assert.Equal(t, test.expected, out)
		})
	}
}

func Test_relationships(t *testing.T) {
	p1 := pkg.Package{
		Name: "p1",
	}

	p2 := pkg.Package{
		Name: "p2",
	}

	p3 := pkg.Package{
		Name: "p3",
	}

	p4 := pkg.Package{
		Name: "p4",
	}

	for _, p := range []*pkg.Package{&p1, &p2, &p3, &p4} {
		p.PURL = fmt.Sprintf("pkg:generic/%s@%s", p.Name, p.Name)
		p.SetID()
	}

	tests := []struct {
		name     string
		sbom     sbom.SBOM
		expected *[]cyclonedx.Dependency
	}{
		{
			name: "package dependencyOf relationships output as dependencies",
			sbom: sbom.SBOM{
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(p1, p2, p3, p4),
				},
				Relationships: []artifact.Relationship{
					{
						From: p2,
						To:   p1,
						Type: artifact.DependencyOfRelationship,
					},
					{
						From: p3,
						To:   p1,
						Type: artifact.DependencyOfRelationship,
					},
					{
						From: p4,
						To:   p2,
						Type: artifact.DependencyOfRelationship,
					},
				},
			},
			expected: &[]cyclonedx.Dependency{
				{
					Ref: deriveBomRef(p1),
					Dependencies: &[]string{
						deriveBomRef(p2),
						deriveBomRef(p3),
					},
				},
				{
					Ref: deriveBomRef(p2),
					Dependencies: &[]string{
						deriveBomRef(p4),
					},
				},
			},
		},
		{
			name: "package contains relationships not output",
			sbom: sbom.SBOM{
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(p1, p2, p3),
				},
				Relationships: []artifact.Relationship{
					{
						From: p2,
						To:   p1,
						Type: artifact.ContainsRelationship,
					},
					{
						From: p3,
						To:   p1,
						Type: artifact.ContainsRelationship,
					},
				},
			},
			expected: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cdx := ToFormatModel(test.sbom)
			got := cdx.Dependencies
			require.Equal(t, test.expected, got)
		})
	}
}
