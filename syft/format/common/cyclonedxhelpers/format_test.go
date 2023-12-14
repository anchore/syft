package cyclonedxhelpers

import (
	"fmt"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
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

func Test_toBomDescriptor(t *testing.T) {
	type args struct {
		name        string
		version     string
		srcMetadata source.Description
	}
	tests := []struct {
		name string
		args args
		want *cyclonedx.Metadata
	}{
		{
			name: "with image labels source metadata",
			args: args{
				name:    "test-image",
				version: "1.0.0",
				srcMetadata: source.Description{
					Metadata: source.StereoscopeImageSourceMetadata{
						Labels: map[string]string{
							"key1": "value1",
						},
					},
				},
			},
			want: &cyclonedx.Metadata{
				Timestamp:  "",
				Lifecycles: nil,
				Tools: &cyclonedx.ToolsChoice{
					Components: &[]cyclonedx.Component{
						{
							Type:    cyclonedx.ComponentTypeApplication,
							Author:  "anchore",
							Name:    "test-image",
							Version: "1.0.0",
						},
					},
				},
				Authors: nil,
				Component: &cyclonedx.Component{
					BOMRef:             "",
					MIMEType:           "",
					Type:               "container",
					Supplier:           nil,
					Author:             "",
					Publisher:          "",
					Group:              "",
					Name:               "",
					Version:            "",
					Description:        "",
					Scope:              "",
					Hashes:             nil,
					Licenses:           nil,
					Copyright:          "",
					CPE:                "",
					PackageURL:         "",
					SWID:               nil,
					Modified:           nil,
					Pedigree:           nil,
					ExternalReferences: nil,
					Properties:         nil,
					Components:         nil,
					Evidence:           nil,
					ReleaseNotes:       nil,
				},
				Manufacture: nil,
				Supplier:    nil,
				Licenses:    nil,
				Properties: &[]cyclonedx.Property{
					{
						Name:  "syft:image:labels:key1",
						Value: "value1",
					},
				}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject := toBomDescriptor(tt.args.name, tt.args.version, tt.args.srcMetadata)

			require.NotEmpty(t, subject.Component.BOMRef)
			subject.Timestamp = "" // not under test

			require.NotNil(t, subject.Component)
			require.NotEmpty(t, subject.Component.BOMRef)
			subject.Component.BOMRef = "" // not under test

			if d := cmp.Diff(tt.want, subject); d != "" {
				t.Errorf("toBomDescriptor() mismatch (-want +got):\n%s", d)
			}
		})
	}
}
