package syftjson

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/syftjson/model"
	"github.com/anchore/syft/syft/internal/sourcemetadata"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func Test_toSourceModel_IgnoreBase(t *testing.T) {
	tests := []struct {
		name string
		src  source.Description
	}{
		{
			name: "directory",
			src: source.Description{
				ID: "test-id",
				Metadata: source.DirectoryMetadata{
					Path: "some/path",
					Base: "some/base",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// assert the model transformation is correct
			actual := toSourceModel(test.src)

			by, err := json.Marshal(actual)
			require.NoError(t, err)
			assert.NotContains(t, string(by), "some/base")
		})
	}
}

func Test_toSourceModel(t *testing.T) {
	tracker := sourcemetadata.NewCompletionTester(t)

	tests := []struct {
		name     string
		src      source.Description
		expected model.Source
	}{
		{
			name: "directory",
			src: source.Description{
				ID:      "test-id",
				Name:    "some-name",
				Version: "some-version",
				Metadata: source.DirectoryMetadata{
					Path: "some/path",
					Base: "some/base",
				},
			},
			expected: model.Source{
				ID:      "test-id",
				Name:    "some-name",
				Version: "some-version",
				Type:    "directory",
				Metadata: source.DirectoryMetadata{
					Path: "some/path",
					Base: "some/base",
				},
			},
		},
		{
			name: "file",
			src: source.Description{
				ID:      "test-id",
				Name:    "some-name",
				Version: "some-version",
				Metadata: source.FileMetadata{
					Path:     "some/path",
					Digests:  []file.Digest{{Algorithm: "sha256", Value: "some-digest"}},
					MIMEType: "text/plain",
				},
			},
			expected: model.Source{
				ID:      "test-id",
				Name:    "some-name",
				Version: "some-version",
				Type:    "file",
				Metadata: source.FileMetadata{
					Path:     "some/path",
					Digests:  []file.Digest{{Algorithm: "sha256", Value: "some-digest"}},
					MIMEType: "text/plain",
				},
			},
		},
		{
			name: "image",
			src: source.Description{
				ID:      "test-id",
				Name:    "some-name",
				Version: "some-version",
				Metadata: source.ImageMetadata{
					UserInput:      "user-input",
					ID:             "id...",
					ManifestDigest: "digest...",
					MediaType:      "type...",
				},
			},
			expected: model.Source{
				ID:      "test-id",
				Name:    "some-name",
				Version: "some-version",
				Type:    "image",
				Metadata: source.ImageMetadata{
					UserInput:      "user-input",
					ID:             "id...",
					ManifestDigest: "digest...",
					MediaType:      "type...",
					RepoDigests:    []string{},
					Tags:           []string{},
				},
			},
		},
		// below are regression tests for when the name/version are not provided
		// historically we've hoisted up the name/version from the metadata, now it is a simple pass-through
		{
			name: "directory - no name/version",
			src: source.Description{
				ID: "test-id",
				Metadata: source.DirectoryMetadata{
					Path: "some/path",
					Base: "some/base",
				},
			},
			expected: model.Source{
				ID:   "test-id",
				Type: "directory",
				Metadata: source.DirectoryMetadata{
					Path: "some/path",
					Base: "some/base",
				},
			},
		},
		{
			name: "file - no name/version",
			src: source.Description{
				ID: "test-id",
				Metadata: source.FileMetadata{
					Path:     "some/path",
					Digests:  []file.Digest{{Algorithm: "sha256", Value: "some-digest"}},
					MIMEType: "text/plain",
				},
			},
			expected: model.Source{
				ID:   "test-id",
				Type: "file",
				Metadata: source.FileMetadata{
					Path:     "some/path",
					Digests:  []file.Digest{{Algorithm: "sha256", Value: "some-digest"}},
					MIMEType: "text/plain",
				},
			},
		},
		{
			name: "image - no name/version",
			src: source.Description{
				ID: "test-id",
				Metadata: source.ImageMetadata{
					UserInput:      "user-input",
					ID:             "id...",
					ManifestDigest: "digest...",
					MediaType:      "type...",
				},
			},
			expected: model.Source{
				ID:   "test-id",
				Type: "image",
				Metadata: source.ImageMetadata{
					UserInput:      "user-input",
					ID:             "id...",
					ManifestDigest: "digest...",
					MediaType:      "type...",
					RepoDigests:    []string{},
					Tags:           []string{},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// assert the model transformation is correct
			actual := toSourceModel(test.src)
			assert.Equal(t, test.expected, actual)

			// track each scheme tested (passed or not)
			tracker.Tested(t, test.expected.Metadata)
		})
	}
}

func Test_toFileType(t *testing.T) {

	badType := stereoscopeFile.Type(0x1337)
	var allTypesTested []stereoscopeFile.Type
	tests := []struct {
		ty   stereoscopeFile.Type
		name string
	}{
		{
			ty:   stereoscopeFile.TypeRegular,
			name: "RegularFile",
		},
		{
			ty:   stereoscopeFile.TypeDirectory,
			name: "Directory",
		},
		{
			ty:   stereoscopeFile.TypeSymLink,
			name: "SymbolicLink",
		},
		{
			ty:   stereoscopeFile.TypeHardLink,
			name: "HardLink",
		},
		{
			ty:   stereoscopeFile.TypeSocket,
			name: "Socket",
		},
		{
			ty:   stereoscopeFile.TypeCharacterDevice,
			name: "CharacterDevice",
		},
		{
			ty:   stereoscopeFile.TypeBlockDevice,
			name: "BlockDevice",
		},
		{
			ty:   stereoscopeFile.TypeFIFO,
			name: "FIFONode",
		},
		{
			ty:   stereoscopeFile.TypeIrregular,
			name: "IrregularFile",
		},
		{
			ty:   badType,
			name: "Unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.name, toFileType(tt.ty), "toFileType(%v)", tt.ty)
			if tt.ty != badType {
				allTypesTested = append(allTypesTested, tt.ty)
			}
		})
	}

	assert.ElementsMatch(t, allTypesTested, stereoscopeFile.AllTypes(), "not all file.Types are under test")
}

func Test_toFileMetadataEntry(t *testing.T) {
	coords := file.Coordinates{
		RealPath:     "/path",
		FileSystemID: "x",
	}
	tests := []struct {
		name     string
		metadata *file.Metadata
		want     *model.FileMetadataEntry
	}{
		{
			name: "no metadata",
		},
		{
			name: "no file info",
			metadata: &file.Metadata{
				FileInfo: nil,
			},
			want: &model.FileMetadataEntry{
				Type: stereoscopeFile.TypeRegular.String(),
			},
		},
		{
			name: "with file info",
			metadata: &file.Metadata{
				FileInfo: &stereoscopeFile.ManualInfo{
					ModeValue: 1,
				},
			},
			want: &model.FileMetadataEntry{
				Mode: 1,
				Type: stereoscopeFile.TypeRegular.String(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, toFileMetadataEntry(coords, tt.metadata))
		})
	}
}

func Test_toPackageModel_metadataType(t *testing.T) {
	tests := []struct {
		name string
		p    pkg.Package
		cfg  EncoderConfig
		want model.Package
	}{
		{
			name: "empty config",
			p: pkg.Package{
				Metadata: pkg.RpmDBEntry{},
			},
			cfg: EncoderConfig{},
			want: model.Package{
				PackageCustomData: model.PackageCustomData{
					MetadataType: "rpm-db-entry",
					Metadata:     pkg.RpmDBEntry{},
				},
			},
		},
		{
			name: "legacy config",
			p: pkg.Package{
				Metadata: pkg.RpmDBEntry{},
			},
			cfg: EncoderConfig{
				Legacy: true,
			},
			want: model.Package{
				PackageCustomData: model.PackageCustomData{
					MetadataType: "RpmMetadata",
					Metadata:     pkg.RpmDBEntry{},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if d := cmp.Diff(tt.want, toPackageModel(tt.p, tt.cfg), cmpopts.EquateEmpty()); d != "" {
				t.Errorf("unexpected package (-want +got):\n%s", d)
			}
		})
	}
}
