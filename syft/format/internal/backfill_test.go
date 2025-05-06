package internal

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
)

func Test_Backfill(t *testing.T) {
	tests := []struct {
		name     string
		in       pkg.Package
		expected pkg.Package
	}{
		{
			name: "npm type",
			in: pkg.Package{
				PURL: "pkg:npm/test@3.0.0",
			},
			expected: pkg.Package{
				PURL:     "pkg:npm/test@3.0.0",
				Type:     pkg.NpmPkg,
				Language: pkg.JavaScript,
				Name:     "test",
				Version:  "3.0.0",
			},
		},
		{
			name: "java type",
			in: pkg.Package{
				PURL: "pkg:maven/org.apache/some-thing@1.2.3",
			},
			expected: pkg.Package{
				PURL:     "pkg:maven/org.apache/some-thing@1.2.3",
				Type:     pkg.JavaPkg,
				Language: pkg.Java,
				Name:     "some-thing",
				Version:  "1.2.3",
				Metadata: &pkg.JavaArchive{
					PomProperties: &pkg.JavaPomProperties{
						GroupID:    "org.apache",
						ArtifactID: "some-thing",
						Version:    "1.2.3",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Backfill(&tt.in)
			tt.in.OverrideID("")
			require.Equal(t, tt.expected, tt.in)
		})
	}
}
