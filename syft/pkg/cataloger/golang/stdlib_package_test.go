package golang

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/cmptest"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func Test_stdlibPackageAndRelationships(t *testing.T) {

	tests := []struct {
		name     string
		pkgs     []pkg.Package
		wantPkgs int
		wantRels int
	}{
		{
			name: "no packages",
		},
		{
			name: "ignore non-go-binary packages",
			pkgs: []pkg.Package{
				{
					Name:     "not-go",
					Version:  "1.0.0",
					Metadata: pkg.GolangModuleEntry{},
				},
			},
			wantPkgs: 0,
			wantRels: 0,
		},
		{
			name: "with go-binary packages -- missing location",
			pkgs: []pkg.Package{
				{
					Name:    "github.com/something/go",
					Version: "1.0.0",
					Metadata: pkg.GolangBinaryBuildinfoEntry{
						GoCompiledVersion: "go1.22.2",
						MainModule:        "github.com/something/go",
					},
				},
			},
			wantPkgs: 0,
			wantRels: 0,
		},
		{
			name: "with go-binary packages",
			pkgs: []pkg.Package{
				{
					Name:      "github.com/something/go",
					Version:   "1.0.0",
					Locations: file.NewLocationSet(file.NewLocation("/bin/my-app")),
					Metadata: pkg.GolangBinaryBuildinfoEntry{
						GoCompiledVersion: "go1.22.2",
						MainModule:        "github.com/something/go",
					},
				},
			},
			wantPkgs: 1,
			wantRels: 1,
		},
		{
			name: "go binary package with devel stdlib",
			pkgs: []pkg.Package{
				{
					Name:      "github.com/something/go",
					Version:   "1.0.0",
					Locations: file.NewLocationSet(file.NewLocation("/bin/my-app")),
					Metadata: pkg.GolangBinaryBuildinfoEntry{
						GoCompiledVersion: "devel",
						MainModule:        "github.com/something/go",
					},
				},
			},
			wantPkgs: 0,
			wantRels: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPkgs, gotRels := stdlibPackageAndRelationships(tt.pkgs)
			assert.Len(t, gotPkgs, tt.wantPkgs)
			assert.Len(t, gotRels, tt.wantRels)
		})
	}
}

func Test_stdlibPackageAndRelationships_values(t *testing.T) {
	loc := file.NewLocation("/bin/my-app")
	locSet := file.NewLocationSet(loc)
	p := pkg.Package{
		Name:      "github.com/something/go",
		Version:   "1.0.0",
		Locations: locSet,
		Metadata: pkg.GolangBinaryBuildinfoEntry{
			GoCompiledVersion: "go1.22.2",
			MainModule:        "github.com/something/go",
		},
	}
	p.SetID()

	expectedPkg := pkg.Package{
		Name:     "stdlib",
		Version:  "go1.22.2",
		PURL:     packageURL("stdlib", "1.22.2"),
		Language: pkg.Go,
		Type:     pkg.GoModulePkg,
		Licenses: pkg.NewLicenseSet(pkg.NewLicense("BSD-3-Clause")),
		CPEs: []cpe.CPE{
			{
				Attributes: cpe.MustAttributes("cpe:2.3:a:golang:go:1.22.2:-:*:*:*:*:*:*"),
				Source:     "syft-generated",
			},
		},
		Locations: locSet,
		Metadata: pkg.GolangBinaryBuildinfoEntry{
			GoCompiledVersion: "go1.22.2",
		},
	}

	expectedPkg.SetID()

	expectedRel := artifact.Relationship{
		From: expectedPkg,
		To:   p,
		Type: artifact.DependencyOfRelationship,
	}

	gotPkgs, gotRels := stdlibPackageAndRelationships([]pkg.Package{p})
	require.Len(t, gotPkgs, 1)

	gotPkg := gotPkgs[0]
	if d := cmp.Diff(expectedPkg, gotPkg, cmptest.DefaultCommonOptions()...); d != "" {
		t.Errorf("unexpected package (-want +got): %s", d)
	}

	require.Len(t, gotRels, 1)
	gotRel := gotRels[0]

	if d := cmp.Diff(expectedRel, gotRel, cmptest.DefaultCommonOptions()...); d != "" {
		t.Errorf("unexpected relationship (-want +got): %s", d)
	}

}
