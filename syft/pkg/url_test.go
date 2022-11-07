package pkg

import (
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/linux"
)

func TestPackageURL(t *testing.T) {
	tests := []struct {
		name     string
		pkg      Package
		distro   *linux.Release
		expected string
	}{
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
	expectedTypes.Remove(string(PortagePkg))
	expectedTypes.Remove(string(AlpmPkg))
	expectedTypes.Remove(string(ApkPkg))
	expectedTypes.Remove(string(ConanPkg))
	expectedTypes.Remove(string(DartPubPkg))
	expectedTypes.Remove(string(DotnetPkg))
	expectedTypes.Remove(string(DebPkg))
	expectedTypes.Remove(string(GoModulePkg))
	expectedTypes.Remove(string(HackagePkg))
	expectedTypes.Remove(string(BinaryPkg))
	expectedTypes.Remove(string(PhpComposerPkg))
	expectedTypes.Remove(string(PythonPkg))
	expectedTypes.Remove(string(RpmPkg))
	expectedTypes.Remove(string(GemPkg))
	expectedTypes.Remove(string(NpmPkg))
	expectedTypes.Remove(string(RustPkg))
	expectedTypes.Remove(string(CocoapodsPkg))

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.pkg.Type != "" && !contains(pkgTypes, string(test.pkg.Type)) {
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

func contains(values []string, val string) bool {
	for _, v := range values {
		if val == v {
			return true
		}
	}

	return false
}
