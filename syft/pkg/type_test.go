package pkg

import (
	"testing"

	"github.com/scylladb/go-set/strset"

	"github.com/stretchr/testify/assert"
)

func TestTypeFromPURL(t *testing.T) {

	tests := []struct {
		name     string
		purl     string
		expected Type
	}{
		{
			purl:     "pkg:rpm/fedora/util-linux@2.32.1-27.el8-?arch=amd64",
			expected: RpmPkg,
		},
		{
			purl:     "pkg:alpine/util-linux@2.32.1",
			expected: ApkPkg,
		},
		{
			purl:     "pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie",
			expected: DebPkg,
		},
		{
			purl:     "pkg:npm/util@2.32",
			expected: NpmPkg,
		},
		{
			purl:     "pkg:pypi/util-linux@2.32.1-27.el8",
			expected: PythonPkg,
		},
		{
			purl:     "pkg:gem/ruby-advisory-db-check@0.12.4",
			expected: GemPkg,
		},
		{
			purl:     "pkg:golang/github.com/gorilla/context@234fd47e07d1004f0aed9c",
			expected: GoModulePkg,
		},
		{
			purl:     "pkg:cargo/clap@2.33.0",
			expected: RustPkg,
		},
		{
			purl:     "pkg:pub/util@1.2.34?hosted_url=pub.hosted.org",
			expected: DartPubPkg,
		},

		{
			purl:     "pkg:dotnet/Microsoft.CodeAnalysis.Razor@2.2.0",
			expected: DotnetPkg,
		},
		{
			purl:     "pkg:composer/laravel/laravel@5.5.0",
			expected: PhpComposerPkg,
		},
		{
			purl:     "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?type=zip&classifier=dist",
			expected: JavaPkg,
		},
	}

	var pkgTypes []string
	var expectedTypes = strset.New()
	for _, ty := range AllPkgs {
		expectedTypes.Add(string(ty))
	}

	// testing microsoft packages and jenkins-plugins is not valid for purl at this time
	expectedTypes.Remove(string(KbPkg))
	expectedTypes.Remove(string(JenkinsPluginPkg))

	for _, test := range tests {
		t.Run(string(test.expected), func(t *testing.T) {
			actual := TypeFromPURL(test.purl)

			if actual != "" {
				pkgTypes = append(pkgTypes, string(actual))
			}

			assert.Equal(t, test.expected, actual)
		})
	}

	assert.ElementsMatch(t, expectedTypes.List(), pkgTypes, "missing one or more package types to test against (maybe a package type was added?)")

}
