package golang

import (
	"runtime/debug"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

func TestBuildGoPkgInfo(t *testing.T) {
	const (
		goCompiledVersion = "1.18"
		archDetails       = "amd64"
	)
	buildSettings := map[string]string{
		"GOARCH":  "amd64",
		"GOOS":    "darwin",
		"GOAMD64": "v1",
	}

	expectedMain := pkg.Package{
		Name:     "github.com/anchore/syft",
		FoundBy:  catalogerName,
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
			BuildSettings:     buildSettings,
		},
	}

	tests := []struct {
		name     string
		mod      *debug.BuildInfo
		arch     string
		expected []pkg.Package
	}{
		{
			name:     "buildGoPkgInfo parses a nil mod",
			mod:      nil,
			expected: []pkg.Package(nil),
		},
		{
			name:     "buildGoPkgInfo parses a blank mod and returns no packages",
			mod:      &debug.BuildInfo{},
			expected: []pkg.Package(nil),
		},
		{
			name: "buildGoPkgInfo parses a mod without main module",
			arch: archDetails,
			mod: &debug.BuildInfo{
				GoVersion: goCompiledVersion,
				Settings: []debug.BuildSetting{
					{Key: "GOARCH", Value: archDetails},
					{Key: "GOOS", Value: "darwin"},
					{Key: "GOAMD64", Value: "v1"},
				},
				Deps: []*debug.Module{
					{
						Path:    "github.com/adrg/xdg",
						Version: "v0.2.1",
						Sum:     "h1:VSVdnH7cQ7V+B33qSJHTCRlNgra1607Q8PzEmnvb2Ic=",
					},
				},
			},
			expected: []pkg.Package{
				{
					Name:     "github.com/adrg/xdg",
					FoundBy:  catalogerName,
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
			},
		},
		{
			name: "buildGoPkgInfo parses a mod without packages",
			arch: archDetails,
			mod: &debug.BuildInfo{
				GoVersion: goCompiledVersion,
				Main:      debug.Module{Path: "github.com/anchore/syft"},
				Settings: []debug.BuildSetting{
					{Key: "GOARCH", Value: archDetails},
					{Key: "GOOS", Value: "darwin"},
					{Key: "GOAMD64", Value: "v1"},
				},
			},
			expected: []pkg.Package{expectedMain},
		},
		{
			name: "buildGoPkgInfo parses a populated mod string and returns packages but no source info",
			arch: archDetails,
			mod: &debug.BuildInfo{
				GoVersion: goCompiledVersion,
				Main:      debug.Module{Path: "github.com/anchore/syft"},
				Settings: []debug.BuildSetting{
					{Key: "GOARCH", Value: archDetails},
					{Key: "GOOS", Value: "darwin"},
					{Key: "GOAMD64", Value: "v1"},
				},
				Deps: []*debug.Module{
					{
						Path:    "github.com/adrg/xdg",
						Version: "v0.2.1",
						Sum:     "h1:VSVdnH7cQ7V+B33qSJHTCRlNgra1607Q8PzEmnvb2Ic=",
					},
					{
						Path:    "github.com/anchore/client-go",
						Version: "v0.0.0-20210222170800-9c70f9b80bcf",
						Sum:     "h1:DYssiUV1pBmKqzKsm4mqXx8artqC0Q8HgZsVI3lMsAg=",
					},
				},
			},
			expected: []pkg.Package{
				{
					Name:     "github.com/adrg/xdg",
					FoundBy:  catalogerName,
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
					FoundBy:  catalogerName,
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
				expectedMain,
			},
		},
		{
			name: "buildGoPkgInfo parses a populated mod string and returns packages when a replace directive exists",
			arch: archDetails,
			mod: &debug.BuildInfo{
				GoVersion: goCompiledVersion,
				Main:      debug.Module{Path: "github.com/anchore/syft"},
				Settings: []debug.BuildSetting{
					{Key: "GOARCH", Value: archDetails},
					{Key: "GOOS", Value: "darwin"},
					{Key: "GOAMD64", Value: "v1"},
				},
				Deps: []*debug.Module{
					{
						Path:    "golang.org/x/sys",
						Version: "v0.0.0-20211006194710-c8a6f5223071",
						Sum:     "h1:PjhxBct4MZii8FFR8+oeS7QOvxKOTZXgk63EU2XpfJE=",
					},
					{
						Path:    "golang.org/x/term",
						Version: "v0.0.0-20210927222741-03fcf44c2211",
						Sum:     "h1:PjhxBct4MZii8FFR8+oeS7QOvxKOTZXgk63EU2XpfJE=",
						Replace: &debug.Module{
							Path:    "golang.org/x/term",
							Version: "v0.0.0-20210916214954-140adaaadfaf",
							Sum:     "h1:Ihq/mm/suC88gF8WFcVwk+OV6Tq+wyA1O0E5UEvDglI=",
						},
					},
				},
			},
			expected: []pkg.Package{
				{
					Name:     "golang.org/x/sys",
					FoundBy:  catalogerName,
					Version:  "v0.0.0-20211006194710-c8a6f5223071",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: []source.Location{
						{
							Coordinates: source.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							}}},
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						H1Digest:          "h1:PjhxBct4MZii8FFR8+oeS7QOvxKOTZXgk63EU2XpfJE="}},
				{
					Name:     "golang.org/x/term",
					FoundBy:  catalogerName,
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
						H1Digest:          "h1:Ihq/mm/suC88gF8WFcVwk+OV6Tq+wyA1O0E5UEvDglI="},
				},
				expectedMain,
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
			pkgs := buildGoPkgInfo(location, test.mod, test.arch)
			assert.Equal(t, test.expected, pkgs)
		})
	}
}
