package split

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func TestParseDropOptions(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   []DropOption
	}{
		{
			name:   "single option",
			values: []string{"source"},
			want:   []DropOption{DropSource},
		},
		{
			name:   "multiple options",
			values: []string{"source", "descriptor", "file:digests"},
			want:   []DropOption{DropSource, DropDescriptor, DropFileDigests},
		},
		{
			name:   "all option expands",
			values: []string{"all"},
			want:   AllDropOptions(),
		},
		{
			name:   "case insensitive",
			values: []string{"SOURCE", "File:Digests"},
			want:   []DropOption{DropSource, DropFileDigests},
		},
		{
			name:   "with whitespace",
			values: []string{" source ", "  location:fsid"},
			want:   []DropOption{DropSource, DropLocationFSID},
		},
		{
			name:   "empty values",
			values: []string{},
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseDropOptions(tt.values)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidDropOption(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "valid source", input: "source", want: true},
		{name: "valid descriptor", input: "descriptor", want: true},
		{name: "valid distro", input: "distro", want: true},
		{name: "valid file:metadata", input: "file:metadata", want: true},
		{name: "valid file:digests", input: "file:digests", want: true},
		{name: "valid file:executable", input: "file:executable", want: true},
		{name: "valid file:unknowns", input: "file:unknowns", want: true},
		{name: "valid file:licenses", input: "file:licenses", want: true},
		{name: "valid file:contents", input: "file:contents", want: true},
		{name: "valid location:fsid", input: "location:fsid", want: true},
		{name: "valid location:non-primary-evidence", input: "location:non-primary-evidence", want: true},
		{name: "valid pkg:licenses", input: "pkg:licenses", want: true},
		{name: "valid pkg:metadata.files", input: "pkg:metadata.files", want: true},
		{name: "valid all", input: "all", want: true},
		{name: "case insensitive", input: "SOURCE", want: true},
		{name: "invalid option", input: "invalid", want: false},
		{name: "partial match", input: "file", want: false},
		{name: "empty string", input: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidDropOption(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestApplyDropOptions(t *testing.T) {
	coord := file.Coordinates{
		RealPath:     "/test/path",
		FileSystemID: "layer123",
	}

	baseSBOM := func() *sbom.SBOM {
		return &sbom.SBOM{
			Source: source.Description{
				ID:   "test-id",
				Name: "test-source",
			},
			Descriptor: sbom.Descriptor{
				Name:    "syft",
				Version: "1.0.0",
			},
			Artifacts: sbom.Artifacts{
				Packages:     pkg.NewCollection(),
				FileMetadata: map[file.Coordinates]file.Metadata{coord: {}},
				FileDigests:  map[file.Coordinates][]file.Digest{coord: {{Algorithm: "sha256", Value: "abc"}}},
				FileContents: map[file.Coordinates]string{coord: "contents"},
				FileLicenses: map[file.Coordinates][]file.License{coord: {{Value: "MIT"}}},
				Executables:  map[file.Coordinates]file.Executable{coord: {}},
				Unknowns:     map[file.Coordinates][]string{coord: {"unknown"}},
			},
			Relationships: []artifact.Relationship{
				{
					From: coord,
					To:   coord,
					Type: artifact.EvidentByRelationship,
				},
			},
		}
	}

	tests := []struct {
		name   string
		opts   []DropOption
		verify func(t *testing.T, s *sbom.SBOM)
	}{
		{
			name: "drop source",
			opts: []DropOption{DropSource},
			verify: func(t *testing.T, s *sbom.SBOM) {
				assert.Empty(t, s.Source.ID)
				assert.Empty(t, s.Source.Name)
				// other fields should be preserved
				assert.Equal(t, "syft", s.Descriptor.Name)
			},
		},
		{
			name: "drop descriptor",
			opts: []DropOption{DropDescriptor},
			verify: func(t *testing.T, s *sbom.SBOM) {
				assert.Empty(t, s.Descriptor.Name)
				assert.Empty(t, s.Descriptor.Version)
				// other fields should be preserved
				assert.Equal(t, "test-id", s.Source.ID)
			},
		},
		{
			name: "drop distro",
			opts: []DropOption{DropDistro},
			verify: func(t *testing.T, s *sbom.SBOM) {
				assert.Nil(t, s.Artifacts.LinuxDistribution)
				// other fields should be preserved
				assert.Equal(t, "test-id", s.Source.ID)
			},
		},
		{
			name: "drop file:metadata",
			opts: []DropOption{DropFileMetadata},
			verify: func(t *testing.T, s *sbom.SBOM) {
				assert.Nil(t, s.Artifacts.FileMetadata)
				// other file artifacts should be preserved
				assert.NotNil(t, s.Artifacts.FileDigests)
			},
		},
		{
			name: "drop file:digests",
			opts: []DropOption{DropFileDigests},
			verify: func(t *testing.T, s *sbom.SBOM) {
				assert.Nil(t, s.Artifacts.FileDigests)
				// other file artifacts should be preserved
				assert.NotNil(t, s.Artifacts.FileMetadata)
			},
		},
		{
			name: "drop file:executable",
			opts: []DropOption{DropFileExecutable},
			verify: func(t *testing.T, s *sbom.SBOM) {
				assert.Nil(t, s.Artifacts.Executables)
			},
		},
		{
			name: "drop file:unknowns",
			opts: []DropOption{DropFileUnknowns},
			verify: func(t *testing.T, s *sbom.SBOM) {
				assert.Nil(t, s.Artifacts.Unknowns)
			},
		},
		{
			name: "drop file:licenses",
			opts: []DropOption{DropFileLicenses},
			verify: func(t *testing.T, s *sbom.SBOM) {
				assert.Nil(t, s.Artifacts.FileLicenses)
			},
		},
		{
			name: "drop file:contents",
			opts: []DropOption{DropFileContents},
			verify: func(t *testing.T, s *sbom.SBOM) {
				assert.Nil(t, s.Artifacts.FileContents)
			},
		},
		{
			name: "drop location:fsid clears FileSystemID",
			opts: []DropOption{DropLocationFSID},
			verify: func(t *testing.T, s *sbom.SBOM) {
				// check that FileSystemID is cleared from file metadata
				for coord := range s.Artifacts.FileMetadata {
					assert.Empty(t, coord.FileSystemID, "FileSystemID should be empty in FileMetadata")
					assert.Equal(t, "/test/path", coord.RealPath)
				}
				// check relationships
				for _, rel := range s.Relationships {
					if c, ok := rel.From.(file.Coordinates); ok {
						assert.Empty(t, c.FileSystemID, "FileSystemID should be empty in relationship From")
					}
					if c, ok := rel.To.(file.Coordinates); ok {
						assert.Empty(t, c.FileSystemID, "FileSystemID should be empty in relationship To")
					}
				}
			},
		},
		{
			name: "drop pkg:metadata.files clears files from ApkDBEntry",
			opts: []DropOption{DropPkgMetadataFiles},
			verify: func(t *testing.T, s *sbom.SBOM) {
				// first add a package with ApkDBEntry metadata
				p := pkg.Package{
					Name:    "test-apk",
					Version: "1.0.0",
					Type:    pkg.ApkPkg,
					Metadata: pkg.ApkDBEntry{
						Package: "test-apk",
						Files: []pkg.ApkFileRecord{
							{Path: "/usr/bin/test"},
						},
					},
				}
				s.Artifacts.Packages.Add(p)

				ApplyDropOptions(s, []DropOption{DropPkgMetadataFiles})

				// verify files were cleared
				for p := range s.Artifacts.Packages.Enumerate() {
					if p.Name == "test-apk" {
						meta, ok := p.Metadata.(pkg.ApkDBEntry)
						require.True(t, ok)
						assert.Nil(t, meta.Files)
					}
				}
			},
		},
		{
			name: "drop pkg:metadata.files clears files from RpmDBEntry",
			opts: []DropOption{DropPkgMetadataFiles},
			verify: func(t *testing.T, s *sbom.SBOM) {
				p := pkg.Package{
					Name:    "test-rpm",
					Version: "1.0.0",
					Type:    pkg.RpmPkg,
					Metadata: pkg.RpmDBEntry{
						Name: "test-rpm",
						Files: []pkg.RpmFileRecord{
							{Path: "/usr/bin/test"},
						},
					},
				}
				s.Artifacts.Packages.Add(p)

				ApplyDropOptions(s, []DropOption{DropPkgMetadataFiles})

				for p := range s.Artifacts.Packages.Enumerate() {
					if p.Name == "test-rpm" {
						meta, ok := p.Metadata.(pkg.RpmDBEntry)
						require.True(t, ok)
						assert.Nil(t, meta.Files)
					}
				}
			},
		},
		{
			name: "drop pkg:metadata.files clears files from DpkgDBEntry",
			opts: []DropOption{DropPkgMetadataFiles},
			verify: func(t *testing.T, s *sbom.SBOM) {
				p := pkg.Package{
					Name:    "test-deb",
					Version: "1.0.0",
					Type:    pkg.DebPkg,
					Metadata: pkg.DpkgDBEntry{
						Package: "test-deb",
						Files: []pkg.DpkgFileRecord{
							{Path: "/usr/bin/test"},
						},
					},
				}
				s.Artifacts.Packages.Add(p)

				ApplyDropOptions(s, []DropOption{DropPkgMetadataFiles})

				for p := range s.Artifacts.Packages.Enumerate() {
					if p.Name == "test-deb" {
						meta, ok := p.Metadata.(pkg.DpkgDBEntry)
						require.True(t, ok)
						assert.Nil(t, meta.Files)
					}
				}
			},
		},
		{
			name: "drop pkg:metadata.files clears files from PythonPackage",
			opts: []DropOption{DropPkgMetadataFiles},
			verify: func(t *testing.T, s *sbom.SBOM) {
				p := pkg.Package{
					Name:    "test-python",
					Version: "1.0.0",
					Type:    pkg.PythonPkg,
					Metadata: pkg.PythonPackage{
						Name: "test-python",
						Files: []pkg.PythonFileRecord{
							{Path: "/usr/lib/python/test.py"},
						},
					},
				}
				s.Artifacts.Packages.Add(p)

				ApplyDropOptions(s, []DropOption{DropPkgMetadataFiles})

				for p := range s.Artifacts.Packages.Enumerate() {
					if p.Name == "test-python" {
						meta, ok := p.Metadata.(pkg.PythonPackage)
						require.True(t, ok)
						assert.Nil(t, meta.Files)
					}
				}
			},
		},
		{
			name: "drop pkg:metadata.files does nothing for non-FileOwner metadata",
			opts: []DropOption{DropPkgMetadataFiles},
			verify: func(t *testing.T, s *sbom.SBOM) {
				// add a package with metadata that doesn't implement FileOwner
				p := pkg.Package{
					Name:    "test-npm",
					Version: "1.0.0",
					Type:    pkg.NpmPkg,
					Metadata: pkg.NpmPackage{
						Name:    "test-npm",
						Version: "1.0.0",
					},
				}
				s.Artifacts.Packages.Add(p)

				ApplyDropOptions(s, []DropOption{DropPkgMetadataFiles})

				// verify package still exists with metadata intact
				for p := range s.Artifacts.Packages.Enumerate() {
					if p.Name == "test-npm" {
						meta, ok := p.Metadata.(pkg.NpmPackage)
						require.True(t, ok)
						assert.Equal(t, "test-npm", meta.Name)
					}
				}
			},
		},
		{
			name: "nil SBOM does not panic",
			opts: []DropOption{DropSource},
			verify: func(t *testing.T, s *sbom.SBOM) {
				// nothing to verify, just ensure no panic
			},
		},
		{
			name: "empty options does nothing",
			opts: []DropOption{},
			verify: func(t *testing.T, s *sbom.SBOM) {
				assert.Equal(t, "test-id", s.Source.ID)
				assert.Equal(t, "syft", s.Descriptor.Name)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s *sbom.SBOM
			if tt.name != "nil SBOM does not panic" {
				s = baseSBOM()
			}

			// should not panic
			require.NotPanics(t, func() {
				ApplyDropOptions(s, tt.opts)
			})

			if s != nil {
				tt.verify(t, s)
			}
		})
	}
}

func TestHasDropLocationFSID(t *testing.T) {
	tests := []struct {
		name string
		opts []DropOption
		want bool
	}{
		{
			name: "has location:fsid",
			opts: []DropOption{DropSource, DropLocationFSID, DropDescriptor},
			want: true,
		},
		{
			name: "no location:fsid",
			opts: []DropOption{DropSource, DropDescriptor},
			want: false,
		},
		{
			name: "empty opts",
			opts: []DropOption{},
			want: false,
		},
		{
			name: "nil opts",
			opts: nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasDropLocationFSID(tt.opts)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetJSONFieldsToRemove(t *testing.T) {
	tests := []struct {
		name string
		opts []DropOption
		want []string
	}{
		{
			name: "source only",
			opts: []DropOption{DropSource},
			want: []string{"source"},
		},
		{
			name: "descriptor only",
			opts: []DropOption{DropDescriptor},
			want: []string{"descriptor"},
		},
		{
			name: "distro only",
			opts: []DropOption{DropDistro},
			want: []string{"distro"},
		},
		{
			name: "all three",
			opts: []DropOption{DropSource, DropDescriptor, DropDistro},
			want: []string{"source", "descriptor", "distro"},
		},
		{
			name: "mixed with file options",
			opts: []DropOption{DropSource, DropFileDigests, DropDescriptor, DropFileMetadata},
			want: []string{"source", "descriptor"},
		},
		{
			name: "file options only returns empty",
			opts: []DropOption{DropFileDigests, DropFileMetadata, DropLocationFSID},
			want: nil,
		},
		{
			name: "empty opts",
			opts: []DropOption{},
			want: nil,
		},
		{
			name: "nil opts",
			opts: nil,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetJSONFieldsToRemove(tt.opts)
			assert.Equal(t, tt.want, got)
		})
	}
}
