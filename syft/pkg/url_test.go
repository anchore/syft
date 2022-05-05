package pkg

import (
	"testing"

	"github.com/anchore/syft/syft/linux"
	"github.com/scylladb/go-set/strset"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/assert"
)

func TestPackageURL(t *testing.T) {
	tests := []struct {
		name     string
		pkg      Package
		distro   *linux.Release
		expected string
	}{
		{
			name: "golang",
			pkg: Package{
				Name:    "github.com/anchore/syft",
				Version: "v0.1.0",
				Type:    GoModulePkg,
			},
			expected: "pkg:golang/github.com/anchore/syft@v0.1.0",
		},
		{
			name: "pub",
			pkg: Package{
				Name:    "bad-name",
				Version: "0.1.0",
				Type:    DartPubPkg,
				Metadata: DartPubMetadata{
					Name:      "name",
					Version:   "0.2.0",
					HostedURL: "pub.hosted.org",
				},
			},
			expected: "pkg:pub/name@0.2.0?hosted_url=pub.hosted.org",
		},

		{
			name: "dotnet",
			pkg: Package{
				Name:    "Microsoft.CodeAnalysis.Razor",
				Version: "2.2.0",
				Type:    DotnetPkg,
				Metadata: DotnetDepsMetadata{
					Name:    "Microsoft.CodeAnalysis.Razor",
					Version: "2.2.0",
				},
			},
			expected: "pkg:dotnet/Microsoft.CodeAnalysis.Razor@2.2.0",
		},
		{
			name: "python",
			pkg: Package{
				Name:    "bad-name",
				Version: "bad-v0.1.0",
				Type:    PythonPkg,
				Metadata: PythonPackageMetadata{
					Name:    "name",
					Version: "v0.1.0",
				},
			},
			expected: "pkg:pypi/name@v0.1.0",
		},
		{
			name: "gem",
			pkg: Package{
				Name:    "name",
				Version: "v0.1.0",
				Type:    GemPkg,
			},
			expected: "pkg:gem/name@v0.1.0",
		},
		{
			name: "npm",
			pkg: Package{
				Name:    "name",
				Version: "v0.1.0",
				Type:    NpmPkg,
			},
			expected: "pkg:npm/name@v0.1.0",
		},
		{
			name: "deb",
			distro: &linux.Release{
				ID:        "ubuntu",
				VersionID: "20.04",
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
			expected: "pkg:deb/ubuntu/name@v0.1.0?arch=amd64&distro=ubuntu-20.04",
		},
		{
			name: "rpm",
			distro: &linux.Release{
				ID:        "centos",
				VersionID: "7",
			},
			pkg: Package{
				Name:    "bad-name",
				Version: "bad-v0.1.0",
				Type:    RpmPkg,
				Metadata: RpmdbMetadata{
					Name:    "name",
					Version: "0.1.0",
					Epoch:   intRef(2),
					Arch:    "amd64",
					Release: "3",
				},
			},
			expected: "pkg:rpm/centos/name@0.1.0-3?arch=amd64&epoch=2&distro=centos-7",
		},
		{
			name: "cargo",
			pkg: Package{
				Name:    "name",
				Version: "v0.1.0",
				Type:    RustPkg,
			},
			expected: "pkg:cargo/name@v0.1.0",
		},
		{
			name: "apk",
			distro: &linux.Release{
				ID:        "alpine",
				VersionID: "3.4.6",
			},
			pkg: Package{
				Name:    "bad-name",
				Version: "bad-v0.1.0",
				Type:    ApkPkg,
				Metadata: ApkMetadata{
					Package:      "name",
					Version:      "v0.1.0",
					Architecture: "amd64",
				},
			},
			expected: "pkg:alpine/name@v0.1.0?arch=amd64&distro=alpine-3.4.6",
		},
		{
			name: "php-composer",
			pkg: Package{
				Name:    "bad-name",
				Version: "bad-v0.1.0",
				Type:    PhpComposerPkg,
				Metadata: PhpComposerJSONMetadata{
					Name:    "vendor/name",
					Version: "2.0.1",
				},
			},
			expected: "pkg:composer/vendor/name@2.0.1",
		},
		{
			name: "java",
			pkg: Package{
				Name:    "bad-name",
				Version: "bad-v0.1.0",
				Type:    JavaPkg,
				Metadata: JavaMetadata{
					PomProperties: &PomProperties{},
					PURL:          "pkg:maven/g.id/a@v", // assembled by the java cataloger
				},
			},

			expected: "pkg:maven/g.id/a@v",
		},
		{
			name: "jenkins-plugin",
			pkg: Package{
				Name:    "bad-name",
				Version: "bad-v0.1.0",
				Type:    JenkinsPluginPkg,
				Metadata: JavaMetadata{
					PomProperties: &PomProperties{},
					PURL:          "pkg:maven/g.id/a@v", // assembled by the java cataloger
				},
			},

			expected: "pkg:maven/g.id/a@v",
		},
	}

	var pkgTypes []string
	var expectedTypes = strset.New()
	for _, ty := range AllPkgs {
		expectedTypes.Add(string(ty))
	}

	// testing microsoft packages is not valid for purl at this time
	expectedTypes.Remove(string(KbPkg))

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.pkg.Type != "" {
				pkgTypes = append(pkgTypes, string(test.pkg.Type))
			}
			actual := URL(test.pkg, test.distro)
			if actual != test.expected {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.expected, actual, true)
				t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
			}
		})
	}
	assert.ElementsMatch(t, expectedTypes.List(), pkgTypes, "missing one or more package types to test against (maybe a package type was added?)")
}
