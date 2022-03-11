package golang

import (
	"io"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

func TestBuildGoPkgInfo(t *testing.T) {
	const (
		goCompiledVersion = "1.17"
		archDetails       = "amd64"
	)
	tests := []struct {
		name     string
		mod      string
		expected []pkg.Package
	}{
		{
			name:     "buildGoPkgInfo parses a blank mod string and returns no packages",
			mod:      "",
			expected: make([]pkg.Package, 0),
		},
		{
			name: "buildGoPkgInfo parses a populated mod string and returns packages but no source info",
			mod: `path    github.com/anchore/syft mod     github.com/anchore/syft (devel)
				  dep     github.com/adrg/xdg     v0.2.1  h1:VSVdnH7cQ7V+B33qSJHTCRlNgra1607Q8PzEmnvb2Ic=
				  dep     github.com/anchore/client-go    v0.0.0-20210222170800-9c70f9b80bcf      h1:DYssiUV1pBmKqzKsm4mqXx8artqC0Q8HgZsVI3lMsAg=
				  dep     github.com/anchore/client-go    v1.2.3`,
			expected: []pkg.Package{
				{
					Name:     "github.com/adrg/xdg",
					Version:  "v0.2.1",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: []source.Location{
						{
							Coordinates: source.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						},
					},
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						H1Digest:          "h1:VSVdnH7cQ7V+B33qSJHTCRlNgra1607Q8PzEmnvb2Ic=",
					},
				},
				{
					Name:     "github.com/anchore/client-go",
					Version:  "v0.0.0-20210222170800-9c70f9b80bcf",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: []source.Location{
						{
							Coordinates: source.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						},
					},
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						H1Digest:          "h1:DYssiUV1pBmKqzKsm4mqXx8artqC0Q8HgZsVI3lMsAg=",
					},
				},
				{
					Name:     "github.com/anchore/client-go",
					Version:  "v1.2.3",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: []source.Location{
						{
							Coordinates: source.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						},
					},
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
					},
				},
			},
		},
		{
			name: "buildGoPkgInfo parses a populated mod string and returns packages when a replace directive exists",
			mod: `path    github.com/anchore/test
			      mod     github.com/anchore/test (devel)
				  dep     golang.org/x/net        v0.0.0-20211006190231-62292e806868      h1:KlOXYy8wQWTUJYFgkUI40Lzr06ofg5IRXUK5C7qZt1k=
				  dep     golang.org/x/sys        v0.0.0-20211006194710-c8a6f5223071      h1:PjhxBct4MZii8FFR8+oeS7QOvxKOTZXgk63EU2XpfJE=
				  dep     golang.org/x/term       v0.0.0-20210927222741-03fcf44c2211
				  =>      golang.org/x/term       v0.0.0-20210916214954-140adaaadfaf      h1:Ihq/mm/suC88gF8WFcVwk+OV6Tq+wyA1O0E5UEvDglI=
				  dep     github.com/anchore/client-go    v1.2.3`,
			expected: []pkg.Package{
				{
					Name:     "golang.org/x/net",
					Version:  "v0.0.0-20211006190231-62292e806868",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: []source.Location{
						{
							Coordinates: source.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						},
					},
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						H1Digest:          "h1:KlOXYy8wQWTUJYFgkUI40Lzr06ofg5IRXUK5C7qZt1k=",
					},
				},
				{
					Name:     "golang.org/x/sys",
					Version:  "v0.0.0-20211006194710-c8a6f5223071",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: []source.Location{
						{
							Coordinates: source.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						},
					},
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						H1Digest:          "h1:PjhxBct4MZii8FFR8+oeS7QOvxKOTZXgk63EU2XpfJE=",
					},
				},
				{
					Name:     "golang.org/x/term",
					Version:  "v0.0.0-20210916214954-140adaaadfaf",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: []source.Location{
						{
							Coordinates: source.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						},
					},
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						H1Digest:          "h1:Ihq/mm/suC88gF8WFcVwk+OV6Tq+wyA1O0E5UEvDglI=",
					},
				},
				{
					Name:     "github.com/anchore/client-go",
					Version:  "v1.2.3",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: []source.Location{
						{
							Coordinates: source.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						},
					},
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for i := range test.expected {
				p := &test.expected[i]
				p.SetID()
			}
			location := source.Location{
				Coordinates: source.Coordinates{
					RealPath:     "/a-path",
					FileSystemID: "layer-id",
				},
			}
			pkgs := buildGoPkgInfo(location, test.mod, goCompiledVersion, archDetails)
			assert.Equal(t, test.expected, pkgs)
		})
	}
}

func Test_parseGoBin_recoversFromPanic(t *testing.T) {
	freakOut := func(file io.ReadCloser) ([]exe, error) {
		panic("baaahhh!")
	}
	tests := []struct {
		name     string
		wantPkgs []pkg.Package
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name: "recovers from panic",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgs, err := parseGoBin(source.NewLocation("some/path"), nil, freakOut)
			assert.Error(t, err)
			assert.Nil(t, pkgs)
		})
	}
}
