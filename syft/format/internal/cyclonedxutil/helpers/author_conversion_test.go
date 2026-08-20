package helpers

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ConvertComponentAuthors(t *testing.T) {
	tests := []struct {
		name    string
		version cyclonedx.SpecVersion
		bom     func() *cyclonedx.BOM
		want    func() *cyclonedx.BOM
	}{
		{
			name:    "1.5 keeps the deprecated field, which is all it has",
			version: cyclonedx.SpecVersion1_5,
			bom:     func() *cyclonedx.BOM { return bomWithAuthors("anchore", "someone") },
			want:    func() *cyclonedx.BOM { return bomWithAuthors("anchore", "someone") },
		},
		{
			name:    "1.6 replaces the deprecated field everywhere it can appear",
			version: cyclonedx.SpecVersion1_6,
			bom:     func() *cyclonedx.BOM { return bomWithAuthors("anchore", "someone") },
			want: func() *cyclonedx.BOM {
				b := bomWithAuthors("", "")
				b.Metadata.Component.Authors = contacts(cyclonedx.OrganizationalContact{Name: "someone"})
				(*b.Metadata.Tools.Components)[0].Authors = contacts(cyclonedx.OrganizationalContact{Name: "anchore"})
				(*b.Components)[0].Authors = contacts(cyclonedx.OrganizationalContact{Name: "someone"})
				(*(*b.Components)[0].Components)[0].Authors = contacts(cyclonedx.OrganizationalContact{Name: "someone"})
				return b
			},
		},
		{
			name:    "1.7 replaces it as well",
			version: cyclonedx.SpecVersion1_7,
			bom: func() *cyclonedx.BOM {
				return &cyclonedx.BOM{Components: &[]cyclonedx.Component{{Name: "p", Author: "someone"}}}
			},
			want: func() *cyclonedx.BOM {
				return &cyclonedx.BOM{Components: &[]cyclonedx.Component{{
					Name:    "p",
					Authors: contacts(cyclonedx.OrganizationalContact{Name: "someone"}),
				}}}
			},
		},
		{
			name:    "an author with an email becomes a contact with an email",
			version: cyclonedx.SpecVersion1_6,
			bom: func() *cyclonedx.BOM {
				return &cyclonedx.BOM{Components: &[]cyclonedx.Component{{Author: "some one <some@one.com>"}}}
			},
			want: func() *cyclonedx.BOM {
				return &cyclonedx.BOM{Components: &[]cyclonedx.Component{{
					Authors: contacts(cyclonedx.OrganizationalContact{Name: "some one", Email: "some@one.com"}),
				}}}
			},
		},
		{
			name:    "authors that are already stated are left alone",
			version: cyclonedx.SpecVersion1_6,
			bom: func() *cyclonedx.BOM {
				return &cyclonedx.BOM{Components: &[]cyclonedx.Component{{
					Author:  "someone",
					Authors: contacts(cyclonedx.OrganizationalContact{Name: "someone else"}),
				}}}
			},
			want: func() *cyclonedx.BOM {
				return &cyclonedx.BOM{Components: &[]cyclonedx.Component{{
					Author:  "someone",
					Authors: contacts(cyclonedx.OrganizationalContact{Name: "someone else"}),
				}}}
			},
		},
		{
			name:    "no author states no authors",
			version: cyclonedx.SpecVersion1_6,
			bom: func() *cyclonedx.BOM {
				return &cyclonedx.BOM{Components: &[]cyclonedx.Component{{Name: "p"}}}
			},
			want: func() *cyclonedx.BOM {
				return &cyclonedx.BOM{Components: &[]cyclonedx.Component{{Name: "p"}}}
			},
		},
		{
			name:    "an empty document is not a special case",
			version: cyclonedx.SpecVersion1_6,
			bom:     func() *cyclonedx.BOM { return &cyclonedx.BOM{} },
			want:    func() *cyclonedx.BOM { return &cyclonedx.BOM{} },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.bom()
			ConvertComponentAuthors(got, tt.version)
			assert.Equal(t, tt.want(), got)
		})
	}
}

func Test_ConvertComponentAuthors_nilBOM(t *testing.T) {
	require.NotPanics(t, func() { ConvertComponentAuthors(nil, cyclonedx.SpecVersion1_6) })
}

func Test_componentAuthor(t *testing.T) {
	tests := []struct {
		name      string
		component cyclonedx.Component
		want      string
	}{
		{
			name:      "the deprecated field",
			component: cyclonedx.Component{Author: "someone"},
			want:      "someone",
		},
		{
			name:      "a single author",
			component: cyclonedx.Component{Authors: contacts(cyclonedx.OrganizationalContact{Name: "someone"})},
			want:      "someone",
		},
		{
			name: "an author with an email",
			component: cyclonedx.Component{
				Authors: contacts(cyclonedx.OrganizationalContact{Name: "some one", Email: "some@one.com"}),
			},
			want: "some one <some@one.com>",
		},
		{
			name: "an author with only an email",
			component: cyclonedx.Component{
				Authors: contacts(cyclonedx.OrganizationalContact{Email: "some@one.com"}),
			},
			want: "some@one.com",
		},
		{
			name: "several authors, as another tool may well write them",
			component: cyclonedx.Component{
				Authors: contacts(
					cyclonedx.OrganizationalContact{Name: "someone"},
					cyclonedx.OrganizationalContact{Name: "someone else"},
				),
			},
			want: "someone,someone else",
		},
		{
			name: "authors that say nothing fall back to the deprecated field",
			component: cyclonedx.Component{
				Author:  "someone",
				Authors: contacts(cyclonedx.OrganizationalContact{}),
			},
			want: "someone",
		},
		{
			name:      "an empty list falls back to the deprecated field",
			component: cyclonedx.Component{Author: "someone", Authors: contacts()},
			want:      "someone",
		},
		{
			name:      "no author at all",
			component: cyclonedx.Component{},
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, componentAuthor(&tt.component))
		})
	}
}

// Test_ConvertComponentAuthors_roundTrip asserts that what the conversion writes is what componentAuthor reads
// back, which is what keeps syft able to decode its own output.
func Test_ConvertComponentAuthors_roundTrip(t *testing.T) {
	authors := []string{
		"anchore",
		"some one <some@one.com>",
		"someone,someone else",
		"<some@one.com>",
	}

	for _, author := range authors {
		t.Run(author, func(t *testing.T) {
			bom := &cyclonedx.BOM{Components: &[]cyclonedx.Component{{Author: author}}}

			ConvertComponentAuthors(bom, cyclonedx.SpecVersion1_6)
			require.Empty(t, (*bom.Components)[0].Author, "the deprecated field should no longer be in use")

			assert.Equal(t, author, componentAuthor(&(*bom.Components)[0]))
		})
	}
}

func contacts(c ...cyclonedx.OrganizationalContact) *[]cyclonedx.OrganizationalContact {
	if c == nil {
		c = []cyclonedx.OrganizationalContact{}
	}
	return &c
}

// bomWithAuthors builds a document with an author in every place a component can appear.
func bomWithAuthors(toolAuthor, packageAuthor string) *cyclonedx.BOM {
	return &cyclonedx.BOM{
		Metadata: &cyclonedx.Metadata{
			Component: &cyclonedx.Component{Name: "the-source", Author: packageAuthor},
			Tools: &cyclonedx.ToolsChoice{
				Components: &[]cyclonedx.Component{{Name: "syft", Author: toolAuthor}},
			},
		},
		Components: &[]cyclonedx.Component{
			{
				Name:   "package-1",
				Author: packageAuthor,
				Components: &[]cyclonedx.Component{
					{Name: "nested-package", Author: packageAuthor},
				},
			},
		},
	}
}
