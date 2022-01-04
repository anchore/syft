package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPackageTypeFromPURL(t *testing.T) {

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
			purl:     "pkg:composer/laravel/laravel@5.5.0",
			expected: PhpComposerPkg,
		},
		{
			purl:     "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?type=zip&classifier=dist",
			expected: JavaPkg,
		},
	}
	for _, test := range tests {
		t.Run(string(test.expected), func(t *testing.T) {
			assert.Equal(t, test.expected, PackageTypeFromPURL(test.purl))
		})
	}
}
