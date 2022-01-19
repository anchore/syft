package cataloger

import (
	"testing"

	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/sergi/go-diff/diffmatchpatch"
)

func TestPackageURL(t *testing.T) {
	tests := []struct {
		name     string
		pkg      pkg.Package
		distro   *linux.Release
		expected string
	}{
		{
			name: "golang",
			pkg: pkg.Package{
				Name:    "github.com/anchore/syft",
				Version: "v0.1.0",
				Type:    pkg.GoModulePkg,
			},
			expected: "pkg:golang/github.com/anchore/syft@v0.1.0",
		},
		{
			name: "pip with vcs url",
			pkg: pkg.Package{
				Name:    "bad-name",
				Version: "bad-v0.1.0",
				Type:    pkg.PythonPkg,
				Metadata: pkg.PythonPackageMetadata{
					Name:    "name",
					Version: "v0.1.0",
					DirectURLOrigin: &pkg.PythonDirectURLOriginInfo{
						VCS:      "git",
						URL:      "https://github.com/test/test.git",
						CommitID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					},
				},
			},
			expected: "pkg:pypi/name@v0.1.0?vcs_url=git+https:%2F%2Fgithub.com%2Ftest%2Ftest.git@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			name: "pip without vcs url",
			pkg: pkg.Package{
				Name:    "bad-name",
				Version: "bad-v0.1.0",
				Type:    pkg.PythonPkg,
				Metadata: pkg.PythonPackageMetadata{
					Name:    "name",
					Version: "v0.1.0",
				},
			},
			expected: "pkg:pypi/name@v0.1.0",
		},
		{
			name: "gem",
			pkg: pkg.Package{
				Name:    "name",
				Version: "v0.1.0",
				Type:    pkg.GemPkg,
			},
			expected: "pkg:gem/name@v0.1.0",
		},
		{
			name: "npm",
			pkg: pkg.Package{
				Name:    "name",
				Version: "v0.1.0",
				Type:    pkg.NpmPkg,
			},
			expected: "pkg:npm/name@v0.1.0",
		},
		{
			name: "deb with arch",
			distro: &linux.Release{
				ID: "ubuntu",
			},
			pkg: pkg.Package{
				Name:    "bad-name",
				Version: "bad-v0.1.0",
				Type:    pkg.DebPkg,
				Metadata: pkg.DpkgMetadata{
					Package:      "name",
					Version:      "v0.1.0",
					Architecture: "amd64",
				},
			},
			expected: "pkg:deb/ubuntu/name@v0.1.0?arch=amd64",
		},
		{
			name: "deb with epoch",
			distro: &linux.Release{
				ID: "centos",
			},
			pkg: pkg.Package{
				Name:    "bad-name",
				Version: "bad-v0.1.0",
				Type:    pkg.RpmPkg,
				Metadata: pkg.RpmdbMetadata{
					Name:    "name",
					Version: "0.1.0",
					Epoch:   intRef(2),
					Arch:    "amd64",
					Release: "3",
				},
			},
			expected: "pkg:rpm/centos/name@0.1.0-3?arch=amd64&epoch=2",
		},
		{
			name: "deb with nil epoch",
			distro: &linux.Release{
				ID: "centos",
			},
			pkg: pkg.Package{
				Name:    "bad-name",
				Version: "bad-v0.1.0",
				Type:    pkg.RpmPkg,
				Metadata: pkg.RpmdbMetadata{
					Name:    "name",
					Version: "0.1.0",
					Epoch:   nil,
					Arch:    "amd64",
					Release: "3",
				},
			},
			expected: "pkg:rpm/centos/name@0.1.0-3?arch=amd64",
		},
		{
			name:   "deb with unknown distro",
			distro: nil,
			pkg: pkg.Package{
				Name:    "name",
				Version: "v0.1.0",
				Type:    pkg.DebPkg,
			},
			expected: "pkg:deb/name@v0.1.0",
		},
		{
			name: "cargo",
			pkg: pkg.Package{
				Name:    "name",
				Version: "v0.1.0",
				Type:    pkg.RustPkg,
			},
			expected: "pkg:cargo/name@v0.1.0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := generatePackageURL(test.pkg, test.distro)
			if actual != test.expected {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.expected, actual, true)
				t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}

func intRef(i int) *int {
	return &i
}
