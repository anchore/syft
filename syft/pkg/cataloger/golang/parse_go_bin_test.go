package golang

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

func TestBuildGoPkgInfo(t *testing.T) {
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
				  dep     github.com/anchore/client-go    v0.0.0-20210222170800-9c70f9b80bcf      h1:DYssiUV1pBmKqzKsm4mqXx8artqC0Q8HgZsVI3lMsAg=`,
			expected: []pkg.Package{
				{
					Name:     "github.com/adrg/xdg",
					Version:  "v0.2.1",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: []source.Location{
						{},
					},
				},
				{
					Name:     "github.com/anchore/client-go",
					Version:  "v0.0.0-20210222170800-9c70f9b80bcf",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: []source.Location{
						{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			pkgs := buildGoPkgInfo("", tt.mod)
			assert.Equal(t, tt.expected, pkgs)
		})
	}
}
