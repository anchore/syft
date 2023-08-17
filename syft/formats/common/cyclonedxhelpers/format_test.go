package cyclonedxhelpers

import (
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
	p1.SetID()

	p2 := pkg.Package{
		Name: "p2",
	}
	p2.SetID()

	p3 := pkg.Package{
		Name: "p3",
	}
	p3.SetID()

	tests := []struct {
		name     string
		sbom     sbom.SBOM
		expected []string
	}{
		{
			name: "package dependencyOf relationships output as dependencies",
			sbom: sbom.SBOM{
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(p1, p2, p3),
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
				},
			},
			expected: []string{p2.Name, p3.Name},
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

			var deps []string
			if got != nil {
				for _, r := range *got {
					for _, d := range *r.Dependencies {
						c := findComponent(cdx, d)
						require.NotNil(t, c)
						deps = append(deps, c.Name)
					}

				}
			}
			require.Equal(t, test.expected, deps)
		})
	}
}

func findComponent(cdx *cyclonedx.BOM, bomRef string) *cyclonedx.Component {
	for _, c := range *cdx.Components {
		if c.BOMRef == bomRef {
			return &c
		}
	}
	return nil
}
