package syftjson

import (
	"errors"
	"io/fs"
	"math"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stereoFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/syftjson/model"
	"github.com/anchore/syft/syft/internal/sourcemetadata"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func Test_toSyftSourceData(t *testing.T) {
	tracker := sourcemetadata.NewCompletionTester(t)

	tests := []struct {
		name     string
		src      model.Source
		expected *source.Description
	}{
		{
			name: "directory",
			src: model.Source{
				ID:      "the-id",
				Name:    "some-name",
				Version: "some-version",
				Type:    "directory",
				Metadata: source.DirectoryMetadata{
					Path: "some/path",
					Base: "some/base",
				},
			},
			expected: &source.Description{
				ID:      "the-id",
				Name:    "some-name",
				Version: "some-version",
				Metadata: source.DirectoryMetadata{
					Path: "some/path",
					Base: "some/base",
				},
			},
		},
		{
			name: "file",
			src: model.Source{
				ID:      "the-id",
				Name:    "some-name",
				Version: "some-version",
				Type:    "file",
				Metadata: source.FileMetadata{
					Path:     "some/path",
					Digests:  []file.Digest{{Algorithm: "sha256", Value: "some-digest"}},
					MIMEType: "text/plain",
				},
			},
			expected: &source.Description{
				ID:      "the-id",
				Name:    "some-name",
				Version: "some-version",
				Metadata: source.FileMetadata{
					Path:     "some/path",
					Digests:  []file.Digest{{Algorithm: "sha256", Value: "some-digest"}},
					MIMEType: "text/plain",
				},
			},
		},
		{
			name: "image",
			src: model.Source{
				ID:      "the-id",
				Name:    "some-name",
				Version: "some-version",
				Type:    "image",
				Metadata: source.ImageMetadata{
					UserInput:      "user-input",
					ID:             "id...",
					ManifestDigest: "digest...",
					MediaType:      "type...",
				},
			},
			expected: &source.Description{
				ID:      "the-id",
				Name:    "some-name",
				Version: "some-version",
				Metadata: source.ImageMetadata{
					UserInput:      "user-input",
					ID:             "id...",
					ManifestDigest: "digest...",
					MediaType:      "type...",
				},
			},
		},
		// below are regression tests for when the name/version are not provided
		// historically we've hoisted up the name/version from the metadata, now it is a simple pass-through
		{
			name: "directory - no name/version",
			src: model.Source{
				ID:   "the-id",
				Type: "directory",
				Metadata: source.DirectoryMetadata{
					Path: "some/path",
					Base: "some/base",
				},
			},
			expected: &source.Description{
				ID: "the-id",
				Metadata: source.DirectoryMetadata{
					Path: "some/path",
					Base: "some/base",
				},
			},
		},
		{
			name: "file - no name/version",
			src: model.Source{
				ID:   "the-id",
				Type: "file",
				Metadata: source.FileMetadata{
					Path:     "some/path",
					Digests:  []file.Digest{{Algorithm: "sha256", Value: "some-digest"}},
					MIMEType: "text/plain",
				},
			},
			expected: &source.Description{
				ID: "the-id",
				Metadata: source.FileMetadata{
					Path:     "some/path",
					Digests:  []file.Digest{{Algorithm: "sha256", Value: "some-digest"}},
					MIMEType: "text/plain",
				},
			},
		},
		{
			name: "image - no name/version",
			src: model.Source{
				ID:   "the-id",
				Type: "image",
				Metadata: source.ImageMetadata{
					UserInput:      "user-input",
					ID:             "id...",
					ManifestDigest: "digest...",
					MediaType:      "type...",
				},
			},
			expected: &source.Description{
				ID: "the-id",
				Metadata: source.ImageMetadata{
					UserInput:      "user-input",
					ID:             "id...",
					ManifestDigest: "digest...",
					MediaType:      "type...",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// assert the model transformation is correct
			actual := toSyftSourceData(test.src)
			assert.Equal(t, test.expected, actual)

			tracker.Tested(t, test.expected.Metadata)
		})
	}
}

func Test_idsHaveChanged(t *testing.T) {
	s := toSyftModel(model.Document{
		Source: model.Source{
			Type:     "file",
			Metadata: source.FileMetadata{Path: "some/path"},
		},
		Artifacts: []model.Package{
			{
				PackageBasicData: model.PackageBasicData{
					ID:   "1",
					Name: "pkg-1",
				},
			},
			{
				PackageBasicData: model.PackageBasicData{
					ID:   "2",
					Name: "pkg-2",
				},
			},
		},
		ArtifactRelationships: []model.Relationship{
			{
				Parent: "1",
				Child:  "2",
				Type:   string(artifact.ContainsRelationship),
			},
		},
	})

	require.Len(t, s.Relationships, 1)

	r := s.Relationships[0]

	from := s.Artifacts.Packages.Package(r.From.ID())
	require.NotNil(t, from)
	assert.Equal(t, "pkg-1", from.Name)

	to := s.Artifacts.Packages.Package(r.To.ID())
	require.NotNil(t, to)
	assert.Equal(t, "pkg-2", to.Name)
}

func Test_toSyftFiles(t *testing.T) {
	coord := file.Coordinates{
		RealPath:     "/somerwhere/place",
		FileSystemID: "abc",
	}

	tests := []struct {
		name  string
		files []model.File
		want  sbom.Artifacts
	}{
		{
			name:  "empty",
			files: []model.File{},
			want: sbom.Artifacts{
				FileMetadata: map[file.Coordinates]file.Metadata{},
				FileDigests:  map[file.Coordinates][]file.Digest{},
				Executables:  map[file.Coordinates]file.Executable{},
				Unknowns:     make(map[file.Coordinates][]string),
			},
		},
		{
			name: "no metadata",
			files: []model.File{
				{
					ID:       string(coord.ID()),
					Location: coord,
					Metadata: nil,
					Digests: []file.Digest{
						{
							Algorithm: "sha256",
							Value:     "123",
						},
					},
					Executable: nil,
				},
			},
			want: sbom.Artifacts{
				FileMetadata: map[file.Coordinates]file.Metadata{},
				FileDigests: map[file.Coordinates][]file.Digest{
					coord: {
						{
							Algorithm: "sha256",
							Value:     "123",
						},
					},
				},
				Executables: map[file.Coordinates]file.Executable{},
			},
		},
		{
			name: "single file",
			files: []model.File{
				{
					ID:       string(coord.ID()),
					Location: coord,
					Metadata: &model.FileMetadataEntry{
						Mode:            777,
						Type:            "RegularFile",
						LinkDestination: "",
						UserID:          42,
						GroupID:         32,
						MIMEType:        "text/plain",
						Size:            92,
					},
					Digests: []file.Digest{
						{
							Algorithm: "sha256",
							Value:     "123",
						},
					},
					Executable: &file.Executable{
						Format: file.ELF,
						ELFSecurityFeatures: &file.ELFSecurityFeatures{
							SymbolTableStripped:           false,
							StackCanary:                   boolRef(true),
							NoExecutable:                  false,
							RelocationReadOnly:            "partial",
							PositionIndependentExecutable: false,
							DynamicSharedObject:           false,
							LlvmSafeStack:                 boolRef(false),
							LlvmControlFlowIntegrity:      boolRef(true),
							ClangFortifySource:            boolRef(true),
						},
					},
				},
			},
			want: sbom.Artifacts{
				FileMetadata: map[file.Coordinates]file.Metadata{
					coord: {
						FileInfo: stereoFile.ManualInfo{
							NameValue: "place",
							SizeValue: 92,
							ModeValue: 511, // 777 octal = 511 decimal
						},
						Path:            coord.RealPath,
						LinkDestination: "",
						UserID:          42,
						GroupID:         32,
						Type:            stereoFile.TypeRegular,
						MIMEType:        "text/plain",
					},
				},
				FileDigests: map[file.Coordinates][]file.Digest{
					coord: {
						{
							Algorithm: "sha256",
							Value:     "123",
						},
					},
				},
				Executables: map[file.Coordinates]file.Executable{
					coord: {
						Format: file.ELF,
						ELFSecurityFeatures: &file.ELFSecurityFeatures{
							SymbolTableStripped:           false,
							StackCanary:                   boolRef(true),
							NoExecutable:                  false,
							RelocationReadOnly:            "partial",
							PositionIndependentExecutable: false,
							DynamicSharedObject:           false,
							LlvmSafeStack:                 boolRef(false),
							LlvmControlFlowIntegrity:      boolRef(true),
							ClangFortifySource:            boolRef(true),
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want.FileContents = make(map[file.Coordinates]string)
			tt.want.FileLicenses = make(map[file.Coordinates][]file.License)
			tt.want.Unknowns = make(map[file.Coordinates][]string)
			assert.Equal(t, tt.want, toSyftFiles(tt.files))
		})
	}
}

func boolRef(b bool) *bool {
	return &b
}

func Test_toSyftRelationship(t *testing.T) {
	packageWithId := func(id string) *pkg.Package {
		p := &pkg.Package{}
		p.OverrideID(artifact.ID(id))
		return p
	}
	childPackage := packageWithId("some-child-id")
	parentPackage := packageWithId("some-parent-id")
	tests := []struct {
		name          string
		idMap         map[string]interface{}
		idAliases     map[string]string
		relationships model.Relationship
		want          *artifact.Relationship
		wantError     error
	}{
		{
			name: "one relationship no warnings",
			idMap: map[string]interface{}{
				"some-child-id":  childPackage,
				"some-parent-id": parentPackage,
			},
			idAliases: map[string]string{},
			relationships: model.Relationship{
				Parent: "some-parent-id",
				Child:  "some-child-id",
				Type:   string(artifact.ContainsRelationship),
			},
			want: &artifact.Relationship{
				To:   childPackage,
				From: parentPackage,
				Type: artifact.ContainsRelationship,
			},
		},
		{
			name: "relationship unknown type one warning",
			idMap: map[string]interface{}{
				"some-child-id":  childPackage,
				"some-parent-id": parentPackage,
			},
			idAliases: map[string]string{},
			relationships: model.Relationship{
				Parent: "some-parent-id",
				Child:  "some-child-id",
				Type:   "some-unknown-relationship-type",
			},
			wantError: errors.New(
				"unknown relationship type: some-unknown-relationship-type",
			),
		},
		{
			name: "relationship missing child ID one warning",
			idMap: map[string]interface{}{
				"some-parent-id": parentPackage,
			},
			idAliases: map[string]string{},
			relationships: model.Relationship{
				Parent: "some-parent-id",
				Child:  "some-child-id",
				Type:   string(artifact.ContainsRelationship),
			},
			wantError: errors.New(
				"relationship mapping to key some-child-id is not a valid artifact.Identifiable type: <nil>",
			),
		},
		{
			name: "relationship missing parent ID one warning",
			idMap: map[string]interface{}{
				"some-child-id": childPackage,
			},
			idAliases: map[string]string{},
			relationships: model.Relationship{
				Parent: "some-parent-id",
				Child:  "some-child-id",
				Type:   string(artifact.ContainsRelationship),
			},
			wantError: errors.New("relationship mapping from key some-parent-id is not a valid artifact.Identifiable type: <nil>"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := toSyftRelationship(tt.idMap, tt.relationships, tt.idAliases)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantError, gotErr)
		})
	}
}

func Test_deduplicateErrors(t *testing.T) {
	tests := []struct {
		name   string
		errors []error
		want   []string
	}{
		{
			name: "no errors, nil slice",
		},
		{
			name: "deduplicates errors",
			errors: []error{
				errors.New("some error"),
				errors.New("some error"),
			},
			want: []string{
				`"some error" occurred 2 time(s)`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deduplicateErrors(tt.errors)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_safeFileModeConvert(t *testing.T) {
	tests := []struct {
		name    string
		val     int
		want    fs.FileMode
		wantErr bool
	}{
		{
			// fs.go ModePerm 511 = FileMode = 0777 // Unix permission bits :192
			name:    "valid perm",
			val:     777,
			want:    os.FileMode(511), // 777 in octal equals 511 in decimal
			wantErr: false,
		},
		{
			name:    "outside int32 high",
			val:     int(math.MaxInt32) + 1,
			want:    0,
			wantErr: true,
		},
		{
			name:    "outside int32 low",
			val:     int(math.MinInt32) - 1,
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := safeFileModeConvert(tt.val)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, tt.want, got)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
