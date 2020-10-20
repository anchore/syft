package pkg

import (
	"testing"

	"github.com/anchore/syft/syft/distro"
	"github.com/sergi/go-diff/diffmatchpatch"
)

func TestPackage_pURL(t *testing.T) {
	tests := []struct {
		pkg      Package
		distro   distro.Distro
		expected string
	}{
		{
			pkg: Package{
				Name:    "github.com/anchore/syft",
				Version: "v0.1.0",
				Type:    GoModulePkg,
			},
			expected: "pkg:golang/github.com/anchore/syft@v0.1.0",
		},
		{
			pkg: Package{
				Name:    "name",
				Version: "v0.1.0",
				Type:    PythonPkg,
			},
			expected: "pkg:pypi/name@v0.1.0",
		},
		{
			pkg: Package{
				Name:    "name",
				Version: "v0.1.0",
				Type:    PythonPkg,
			},
			expected: "pkg:pypi/name@v0.1.0",
		},
		{
			pkg: Package{
				Name:    "name",
				Version: "v0.1.0",
				Type:    PythonPkg,
			},
			expected: "pkg:pypi/name@v0.1.0",
		},
		{
			pkg: Package{
				Name:    "name",
				Version: "v0.1.0",
				Type:    PythonPkg,
			},
			expected: "pkg:pypi/name@v0.1.0",
		},
		{
			pkg: Package{
				Name:    "name",
				Version: "v0.1.0",
				Type:    GemPkg,
			},
			expected: "pkg:gem/name@v0.1.0",
		},
		{
			pkg: Package{
				Name:    "name",
				Version: "v0.1.0",
				Type:    NpmPkg,
			},
			expected: "pkg:npm/name@v0.1.0",
		},
		{
			distro: distro.Distro{
				Type: distro.Ubuntu,
			},
			pkg: Package{
				Name:    "bad-name",
				Version: "bad-v0.1.0",
				Type:    DebPkg,
				Metadata: DpkgMetadata{
					Package:      "name",
					Version:      "v0.1.0",
					Architecture: "amd64",
				},
			},
			expected: "pkg:deb/ubuntu/name@v0.1.0?arch=amd64",
		},
		{
			distro: distro.Distro{
				Type: distro.CentOS,
			},
			pkg: Package{
				Name:    "bad-name",
				Version: "bad-v0.1.0",
				Type:    RpmPkg,
				Metadata: RpmMetadata{
					Name:    "name",
					Version: "v0.1.0",
					Epoch:   2,
					Arch:    "amd64",
					Release: "3",
				},
			},
			expected: "pkg:rpm/centos/name@2:v0.1.0-3?arch=amd64",
		},
		{
			distro: distro.Distro{
				Type: distro.UnknownDistroType,
			},
			pkg: Package{
				Name:    "name",
				Version: "v0.1.0",
				Type:    DebPkg,
			},
			expected: "pkg:deb/name@v0.1.0",
		},
	}

	for _, test := range tests {
		t.Run(string(test.pkg.Type)+"|"+test.expected, func(t *testing.T) {
			actual := test.pkg.PackageURL(test.distro)
			if actual != test.expected {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.expected, actual, true)
				t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}
