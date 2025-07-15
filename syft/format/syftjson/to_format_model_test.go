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
		{
			name: "snap",
			src: source.Description{
				ID:      "test-id",
				Name:    "some-name",
				Version: "some-version",
				Metadata: source.SnapMetadata{
					Summary:       "some summary",
					Base:          "some/base",
					Grade:         "some grade",
					Confinement:   "some confinement",
					Architectures: []string{"x86_64", "arm64"},
					Digests:       []file.Digest{{Algorithm: "sha256", Value: "some-digest"}},
				},
			},
			expected: model.Source{
				ID:      "test-id",
				Name:    "some-name",
				Version: "some-version",
				Type:    "snap",
				Metadata: source.SnapMetadata{
					Summary:       "some summary",
					Base:          "some/base",
					Grade:         "some grade",
					Confinement:   "some confinement",
					Architectures: []string{"x86_64", "arm64"},
					Digests:       []file.Digest{{Algorithm: "sha256", Value: "some-digest"}},
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
			if d := cmp.Diff(tt.want, toPackageModel(tt.p, file.LocationSorter(nil), tt.cfg), cmpopts.EquateEmpty()); d != "" {
				t.Errorf("unexpected package (-want +got):\n%s", d)
			}
		})
	}
}

func Test_toPackageModel_layerOrdering(t *testing.T) {
	tests := []struct {
		name       string
		p          pkg.Package
		layerOrder []string
		cfg        EncoderConfig
		want       model.Package
	}{
		{
			name: "with layer ordering",
			p: pkg.Package{
				Name: "pkg-1",
				Licenses: pkg.NewLicenseSet(pkg.License{
					Value: "MIT",
					Locations: file.NewLocationSet(
						file.NewLocationFromCoordinates(file.Coordinates{
							RealPath:     "/lic-a",
							FileSystemID: "fsid-3",
						}),
						file.NewLocationFromCoordinates(file.Coordinates{
							RealPath:     "/lic-a",
							FileSystemID: "fsid-1",
						}),
						file.NewLocationFromCoordinates(file.Coordinates{
							RealPath:     "/lic-b",
							FileSystemID: "fsid-0",
						}),
						file.NewLocationFromCoordinates(file.Coordinates{
							RealPath:     "/lic-a",
							FileSystemID: "fsid-2",
						}),
					),
				}),
				Locations: file.NewLocationSet(
					file.NewLocationFromCoordinates(file.Coordinates{
						RealPath:     "/a",
						FileSystemID: "fsid-3",
					}),
					file.NewLocationFromCoordinates(file.Coordinates{
						RealPath:     "/a",
						FileSystemID: "fsid-1",
					}),
					file.NewLocationFromCoordinates(file.Coordinates{
						RealPath:     "/b",
						FileSystemID: "fsid-0",
					}),
					file.NewLocationFromCoordinates(file.Coordinates{
						RealPath:     "/a",
						FileSystemID: "fsid-2",
					}),
				),
			},
			layerOrder: []string{
				"fsid-0",
				"fsid-1",
				"fsid-2",
				"fsid-3",
			},
			want: model.Package{
				PackageBasicData: model.PackageBasicData{
					Name: "pkg-1",
					Licenses: []model.License{
						{
							Value: "MIT",
							Locations: []file.Location{
								{
									LocationData: file.LocationData{
										Coordinates: file.Coordinates{
											RealPath:     "/lic-b",
											FileSystemID: "fsid-0", // important!
										},
										AccessPath: "/lic-b",
									},
								},
								{
									LocationData: file.LocationData{
										Coordinates: file.Coordinates{
											RealPath:     "/lic-a",
											FileSystemID: "fsid-1", // important!
										},
										AccessPath: "/lic-a",
									},
								},
								{
									LocationData: file.LocationData{
										Coordinates: file.Coordinates{
											RealPath:     "/lic-a",
											FileSystemID: "fsid-2", // important!
										},
										AccessPath: "/lic-a",
									},
								},
								{
									LocationData: file.LocationData{
										Coordinates: file.Coordinates{
											RealPath:     "/lic-a",
											FileSystemID: "fsid-3", // important!
										},
										AccessPath: "/lic-a",
									},
								},
							},
						},
					},
					Locations: []file.Location{
						{
							LocationData: file.LocationData{
								Coordinates: file.Coordinates{
									RealPath:     "/b",
									FileSystemID: "fsid-0", // important!
								},
								AccessPath: "/b",
							},
						},
						{
							LocationData: file.LocationData{
								Coordinates: file.Coordinates{
									RealPath:     "/a",
									FileSystemID: "fsid-1", // important!
								},
								AccessPath: "/a",
							},
						},
						{
							LocationData: file.LocationData{
								Coordinates: file.Coordinates{
									RealPath:     "/a",
									FileSystemID: "fsid-2", // important!
								},
								AccessPath: "/a",
							},
						},
						{
							LocationData: file.LocationData{
								Coordinates: file.Coordinates{
									RealPath:     "/a",
									FileSystemID: "fsid-3", // important!
								},
								AccessPath: "/a",
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if d := cmp.Diff(tt.want, toPackageModel(tt.p, file.LocationSorter(tt.layerOrder), tt.cfg), cmpopts.EquateEmpty(), cmpopts.IgnoreUnexported(file.LocationData{})); d != "" {
				t.Errorf("unexpected package (-want +got):\n%s", d)
			}
		})
	}
}

func Test_toLocationModel(t *testing.T) {
	tests := []struct {
		name      string
		locations file.LocationSet
		layers    []string
		want      []file.Location
	}{
		{
			name:      "empty location set",
			locations: file.NewLocationSet(),
			layers:    []string{"fsid-1"},
			want:      []file.Location{},
		},
		{
			name: "nil layer order map",
			locations: file.NewLocationSet(
				file.NewLocationFromCoordinates(file.Coordinates{
					RealPath:     "/a",
					FileSystemID: "fsid-1",
				}),
				file.NewLocationFromCoordinates(file.Coordinates{
					RealPath:     "/b",
					FileSystemID: "fsid-2",
				}),
			),
			layers: nil, // please don't panic!
			want: []file.Location{
				{
					LocationData: file.LocationData{
						Coordinates: file.Coordinates{
							RealPath:     "/a",
							FileSystemID: "fsid-1",
						},
						AccessPath: "/a",
					},
					LocationMetadata: file.LocationMetadata{Annotations: map[string]string{}},
				},
				{
					LocationData: file.LocationData{
						Coordinates: file.Coordinates{
							RealPath:     "/b",
							FileSystemID: "fsid-2",
						},
						AccessPath: "/b",
					},
					LocationMetadata: file.LocationMetadata{Annotations: map[string]string{}},
				},
			},
		},
		{
			name: "go case",
			locations: file.NewLocationSet(
				file.NewLocationFromCoordinates(file.Coordinates{
					RealPath:     "/a",
					FileSystemID: "fsid-3",
				}),
				file.NewLocationFromCoordinates(file.Coordinates{
					RealPath:     "/b",
					FileSystemID: "fsid-1",
				}),
				file.NewLocationFromCoordinates(file.Coordinates{
					RealPath:     "/c",
					FileSystemID: "fsid-2",
				}),
			),
			layers: []string{
				"fsid-1",
				"fsid-2",
				"fsid-3",
			},
			want: []file.Location{
				{
					LocationData: file.LocationData{
						Coordinates: file.Coordinates{
							RealPath:     "/b",
							FileSystemID: "fsid-1",
						},
						AccessPath: "/b",
					},
					LocationMetadata: file.LocationMetadata{Annotations: map[string]string{}},
				},
				{
					LocationData: file.LocationData{
						Coordinates: file.Coordinates{
							RealPath:     "/c",
							FileSystemID: "fsid-2",
						},
						AccessPath: "/c",
					},
					LocationMetadata: file.LocationMetadata{Annotations: map[string]string{}},
				},
				{
					LocationData: file.LocationData{
						Coordinates: file.Coordinates{
							RealPath:     "/a",
							FileSystemID: "fsid-3",
						},
						AccessPath: "/a",
					},
					LocationMetadata: file.LocationMetadata{Annotations: map[string]string{}},
				},
			},
		},
		{
			name: "same layer different paths", // prove we can sort by path irrespective of layer
			locations: file.NewLocationSet(
				file.NewLocationFromCoordinates(file.Coordinates{
					RealPath:     "/c",
					FileSystemID: "fsid-1",
				}),
				file.NewLocationFromCoordinates(file.Coordinates{
					RealPath:     "/a",
					FileSystemID: "fsid-1",
				}),
				file.NewLocationFromCoordinates(file.Coordinates{
					RealPath:     "/b",
					FileSystemID: "fsid-1",
				}),
			),
			layers: []string{
				"fsid-1",
			},
			want: []file.Location{
				{
					LocationData: file.LocationData{
						Coordinates: file.Coordinates{
							RealPath:     "/a",
							FileSystemID: "fsid-1",
						},
						AccessPath: "/a",
					},
					LocationMetadata: file.LocationMetadata{Annotations: map[string]string{}},
				},
				{
					LocationData: file.LocationData{
						Coordinates: file.Coordinates{
							RealPath:     "/b",
							FileSystemID: "fsid-1",
						},
						AccessPath: "/b",
					},
					LocationMetadata: file.LocationMetadata{Annotations: map[string]string{}},
				},
				{
					LocationData: file.LocationData{
						Coordinates: file.Coordinates{
							RealPath:     "/c",
							FileSystemID: "fsid-1",
						},
						AccessPath: "/c",
					},
					LocationMetadata: file.LocationMetadata{Annotations: map[string]string{}},
				},
			},
		},
		{
			name: "mixed layers and paths",
			locations: file.NewLocationSet(
				file.NewLocationFromCoordinates(file.Coordinates{
					RealPath:     "/z",
					FileSystemID: "fsid-3",
				}),
				file.NewLocationFromCoordinates(file.Coordinates{
					RealPath:     "/a",
					FileSystemID: "fsid-2",
				}),
				file.NewLocationFromCoordinates(file.Coordinates{
					RealPath:     "/b",
					FileSystemID: "fsid-1",
				}),
				file.NewLocationFromCoordinates(file.Coordinates{
					RealPath:     "/c",
					FileSystemID: "fsid-2",
				}),
			),
			layers: []string{
				"fsid-1",
				"fsid-2",
				"fsid-3",
			},
			want: []file.Location{
				{
					LocationData: file.LocationData{
						Coordinates: file.Coordinates{
							RealPath:     "/b",
							FileSystemID: "fsid-1",
						},
						AccessPath: "/b",
					},
					LocationMetadata: file.LocationMetadata{Annotations: map[string]string{}},
				},
				{
					LocationData: file.LocationData{
						Coordinates: file.Coordinates{
							RealPath:     "/a",
							FileSystemID: "fsid-2",
						},
						AccessPath: "/a",
					},
					LocationMetadata: file.LocationMetadata{Annotations: map[string]string{}},
				},
				{
					LocationData: file.LocationData{
						Coordinates: file.Coordinates{
							RealPath:     "/c",
							FileSystemID: "fsid-2",
						},
						AccessPath: "/c",
					},
					LocationMetadata: file.LocationMetadata{Annotations: map[string]string{}},
				},
				{
					LocationData: file.LocationData{
						Coordinates: file.Coordinates{
							RealPath:     "/z",
							FileSystemID: "fsid-3",
						},
						AccessPath: "/z",
					},
					LocationMetadata: file.LocationMetadata{Annotations: map[string]string{}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toLocationsModel(tt.locations, file.LocationSorter(tt.layers))
			if d := cmp.Diff(tt.want, got, cmpopts.IgnoreUnexported(file.LocationData{})); d != "" {
				t.Errorf("toLocationsModel() mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func Test_sortFiles(t *testing.T) {
	tests := []struct {
		name   string
		files  []model.File
		layers []string
		want   []model.File
	}{
		{
			name:   "empty files slice",
			files:  []model.File{},
			layers: []string{"fsid-1"},
			want:   []model.File{},
		},
		{
			name: "nil layer order map",
			files: []model.File{
				{
					ID: "file-1",
					Location: file.Coordinates{
						RealPath:     "/a",
						FileSystemID: "fsid-1",
					},
				},
				{
					ID: "file-2",
					Location: file.Coordinates{
						RealPath:     "/b",
						FileSystemID: "fsid-2",
					},
				},
			},
			layers: nil,
			want: []model.File{
				{
					ID: "file-1",
					Location: file.Coordinates{
						RealPath:     "/a",
						FileSystemID: "fsid-1",
					},
				},
				{
					ID: "file-2",
					Location: file.Coordinates{
						RealPath:     "/b",
						FileSystemID: "fsid-2",
					},
				},
			},
		},
		{
			name: "layer ordering",
			files: []model.File{
				{
					ID: "file-1",
					Location: file.Coordinates{
						RealPath:     "/a",
						FileSystemID: "fsid-3",
					},
				},
				{
					ID: "file-2",
					Location: file.Coordinates{
						RealPath:     "/b",
						FileSystemID: "fsid-1",
					},
				},
				{
					ID: "file-3",
					Location: file.Coordinates{
						RealPath:     "/c",
						FileSystemID: "fsid-2",
					},
				},
			},
			layers: []string{
				"fsid-1",
				"fsid-2",
				"fsid-3",
			},
			want: []model.File{
				{
					ID: "file-2",
					Location: file.Coordinates{
						RealPath:     "/b",
						FileSystemID: "fsid-1",
					},
				},
				{
					ID: "file-3",
					Location: file.Coordinates{
						RealPath:     "/c",
						FileSystemID: "fsid-2",
					},
				},
				{
					ID: "file-1",
					Location: file.Coordinates{
						RealPath:     "/a",
						FileSystemID: "fsid-3",
					},
				},
			},
		},
		{
			name: "same layer different paths",
			files: []model.File{
				{
					ID: "file-1",
					Location: file.Coordinates{
						RealPath:     "/c",
						FileSystemID: "fsid-1",
					},
				},
				{
					ID: "file-2",
					Location: file.Coordinates{
						RealPath:     "/a",
						FileSystemID: "fsid-1",
					},
				},
				{
					ID: "file-3",
					Location: file.Coordinates{
						RealPath:     "/b",
						FileSystemID: "fsid-1",
					},
				},
			},
			layers: []string{
				"fsid-1",
			},
			want: []model.File{
				{
					ID: "file-2",
					Location: file.Coordinates{
						RealPath:     "/a",
						FileSystemID: "fsid-1",
					},
				},
				{
					ID: "file-3",
					Location: file.Coordinates{
						RealPath:     "/b",
						FileSystemID: "fsid-1",
					},
				},
				{
					ID: "file-1",
					Location: file.Coordinates{
						RealPath:     "/c",
						FileSystemID: "fsid-1",
					},
				},
			},
		},
		{
			name: "stability test - preserve original order for equivalent items",
			files: []model.File{
				{
					ID: "file-1",
					Location: file.Coordinates{
						RealPath:     "/a",
						FileSystemID: "fsid-1",
					},
				},
				{
					ID: "file-2",
					Location: file.Coordinates{
						RealPath:     "/a",
						FileSystemID: "fsid-1",
					},
				},
				{
					ID: "file-3",
					Location: file.Coordinates{
						RealPath:     "/a",
						FileSystemID: "fsid-1",
					},
				},
			},
			layers: []string{
				"fsid-1",
			},
			want: []model.File{
				{
					ID: "file-1",
					Location: file.Coordinates{
						RealPath:     "/a",
						FileSystemID: "fsid-1",
					},
				},
				{
					ID: "file-2",
					Location: file.Coordinates{
						RealPath:     "/a",
						FileSystemID: "fsid-1",
					},
				},
				{
					ID: "file-3",
					Location: file.Coordinates{
						RealPath:     "/a",
						FileSystemID: "fsid-1",
					},
				},
			},
		},
		{
			name: "complex file metadata doesn't affect sorting",
			files: []model.File{
				{
					ID: "file-1",
					Location: file.Coordinates{
						RealPath:     "/a",
						FileSystemID: "fsid-2",
					},
					Metadata: &model.FileMetadataEntry{
						Mode:     0644,
						Type:     "file",
						UserID:   1000,
						GroupID:  1000,
						MIMEType: "text/plain",
						Size:     100,
					},
					Contents: "content1",
					Digests: []file.Digest{
						{
							Algorithm: "sha256",
							Value:     "abc123",
						},
					},
				},
				{
					ID: "file-2",
					Location: file.Coordinates{
						RealPath:     "/b",
						FileSystemID: "fsid-1",
					},
					Metadata: &model.FileMetadataEntry{
						Mode:     0755,
						Type:     "directory",
						UserID:   0,
						GroupID:  0,
						MIMEType: "application/directory",
						Size:     4096,
					},
				},
			},
			layers: []string{
				"fsid-1",
				"fsid-2",
			},
			want: []model.File{
				{
					ID: "file-2",
					Location: file.Coordinates{
						RealPath:     "/b",
						FileSystemID: "fsid-1",
					},
					Metadata: &model.FileMetadataEntry{
						Mode:     0755,
						Type:     "directory",
						UserID:   0,
						GroupID:  0,
						MIMEType: "application/directory",
						Size:     4096,
					},
				},
				{
					ID: "file-1",
					Location: file.Coordinates{
						RealPath:     "/a",
						FileSystemID: "fsid-2",
					},
					Metadata: &model.FileMetadataEntry{
						Mode:     0644,
						Type:     "file",
						UserID:   1000,
						GroupID:  1000,
						MIMEType: "text/plain",
						Size:     100,
					},
					Contents: "content1",
					Digests: []file.Digest{
						{
							Algorithm: "sha256",
							Value:     "abc123",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := make([]model.File, len(tt.files))
			copy(files, tt.files)

			sortFiles(files, file.CoordinatesSorter(tt.layers))

			if d := cmp.Diff(tt.want, files); d != "" {
				t.Errorf("sortFiles() mismatch (-want +got):\n%s", d)
			}
		})
	}
}
