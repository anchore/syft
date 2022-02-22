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

	tests := []struct {
		name     string
		mod      *debug.BuildInfo
		expected []pkg.Package
	}{
		{
			name:     "buildGoPkgInfo parses a blank mod string and returns no packages",
			mod:      &debug.BuildInfo{},
			expected: make([]pkg.Package, 0),
		},
		{
			name: "buildGoPkgInfo parses a populated mod string and returns packages but no source info",
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
						BuildSettings:     buildSettings,
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
						BuildSettings:     buildSettings,
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
			mod: &debug.BuildInfo{
				GoVersion: goCompiledVersion,
				Main: debug.Module{
					Path: "github.com/anchore/test",
				},
				Settings: []debug.BuildSetting{
					{Key: "GOARCH", Value: archDetails},
					{Key: "GOOS", Value: "darwin"},
					{Key: "GOAMD64", Value: "v1"},
				},
				Deps: []*debug.Module{
					{
						Path:    "golang.org/x/net",
						Version: "v0.0.0-20211006190231-62292e806868",
						Sum:     "h1:KlOXYy8wQWTUJYFgkUI40Lzr06ofg5IRXUK5C7qZt1k=",
					},
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
					Name:     "golang.org/x/net",
					Version:  "v0.0.0-20211006190231-62292e806868",
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
						H1Digest:          "h1:KlOXYy8wQWTUJYFgkUI40Lzr06ofg5IRXUK5C7qZt1k=",
						BuildSettings:     buildSettings}},
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
							}}},
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						H1Digest:          "h1:PjhxBct4MZii8FFR8+oeS7QOvxKOTZXgk63EU2XpfJE=",
						BuildSettings:     buildSettings}},
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
						BuildSettings:     buildSettings}},
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
			pkgs := buildGoPkgInfo(location, test.mod)
			assert.Equal(t, test.expected, pkgs)
		})
	}
}
