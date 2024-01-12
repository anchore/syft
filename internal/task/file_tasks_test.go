package task

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func Test_coordinatesForSelection(t *testing.T) {

	tests := []struct {
		name      string
		selection file.Selection
		sbom      *sbom.SBOM
		files     []file.Coordinates
		ok        bool
	}{
		{
			name:      "all files",
			selection: file.AllFilesSelection,
			files:     nil,
			ok:        true,
		},
		{
			name:      "no files",
			selection: file.NoFilesSelection,
			files:     nil,
			ok:        false,
		},
		{
			name:      "specific files with hits",
			selection: file.FilesOwnedByPackageSelection,
			sbom: &sbom.SBOM{
				Relationships: []artifact.Relationship{
					{
						From: pkg.Package{},
						To: file.Coordinates{
							RealPath:     "path",
							FileSystemID: "fs",
						},
						Type: artifact.ContainsRelationship,
					},
				},
			},
			files: []file.Coordinates{
				{
					RealPath:     "path",
					FileSystemID: "fs",
				},
			},
			ok: true,
		},
		{
			name:      "specific files no hits (by wrong type)",
			selection: file.FilesOwnedByPackageSelection,
			sbom: &sbom.SBOM{
				Relationships: []artifact.Relationship{
					{
						From: pkg.Package{},
						To: file.Coordinates{
							RealPath:     "path",
							FileSystemID: "fs",
						},
						// wrong type
						Type: artifact.DependencyOfRelationship,
					},
				},
			},
			files: nil,
			ok:    false,
		},
		{
			name:      "specific files no hits (by wrong node types)",
			selection: file.FilesOwnedByPackageSelection,
			sbom: &sbom.SBOM{
				Relationships: []artifact.Relationship{
					{
						From: file.Coordinates{}, // wrong type
						To: file.Coordinates{
							RealPath:     "path",
							FileSystemID: "fs",
						},
						Type: artifact.ContainsRelationship,
					},
				},
			},
			files: nil,
			ok:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files, ok := coordinatesForSelection(tt.selection, sbomsync.NewBuilder(tt.sbom).(sbomsync.Accessor))
			assert.Equal(t, tt.files, files)
			assert.Equal(t, tt.ok, ok)
		})
	}
}
