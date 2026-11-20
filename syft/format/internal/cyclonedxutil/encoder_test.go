package cyclonedxutil

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func Test_dropEvidenceOccurrences(t *testing.T) {
	occurrences := func() *[]cyclonedx.EvidenceOccurrence {
		return &[]cyclonedx.EvidenceOccurrence{{Location: "/usr/bin/example"}}
	}
	copyright := &[]cyclonedx.Copyright{{Text: "Copyright Example"}}

	tests := []struct {
		name       string
		components *[]cyclonedx.Component
		want       *[]cyclonedx.Component
	}{
		{
			name: "no components",
		},
		{
			name:       "a component without evidence is unchanged",
			components: &[]cyclonedx.Component{{Name: "a"}},
			want:       &[]cyclonedx.Component{{Name: "a"}},
		},
		{
			name: "evidence with only occurrences is removed",
			components: &[]cyclonedx.Component{
				{Name: "a", Evidence: &cyclonedx.Evidence{Occurrences: occurrences()}},
			},
			want: &[]cyclonedx.Component{{Name: "a"}},
		},
		{
			name: "other evidence is kept",
			components: &[]cyclonedx.Component{
				{Name: "a", Evidence: &cyclonedx.Evidence{Occurrences: occurrences(), Copyright: copyright}},
			},
			want: &[]cyclonedx.Component{
				{Name: "a", Evidence: &cyclonedx.Evidence{Copyright: copyright}},
			},
		},
		{
			name: "nested components are covered",
			components: &[]cyclonedx.Component{
				{
					Name:     "outer",
					Evidence: &cyclonedx.Evidence{Occurrences: occurrences()},
					Components: &[]cyclonedx.Component{
						{
							Name:     "inner",
							Evidence: &cyclonedx.Evidence{Occurrences: occurrences()},
							Components: &[]cyclonedx.Component{
								{Name: "innermost", Evidence: &cyclonedx.Evidence{Occurrences: occurrences()}},
							},
						},
					},
				},
			},
			want: &[]cyclonedx.Component{
				{
					Name: "outer",
					Components: &[]cyclonedx.Component{
						{
							Name:       "inner",
							Components: &[]cyclonedx.Component{{Name: "innermost"}},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dropEvidenceOccurrences(tt.components)
			assert.Equal(t, tt.want, tt.components)
		})
	}
}
