package integration

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func TestWarCatalogedCorrectlyIfRenamed(t *testing.T) {
	// install hudson-war@2.2.1 and renames the file to `/hudson.war`
	sbom, _ := catalogFixtureImage(t, "image-java-virtualpath-regression", source.SquashedScope)

	badPURL := "pkg:maven/hudson/hudson@2.2.1"
	goodPURL := "pkg:maven/org.jvnet.hudson.main/hudson-war@2.2.1"
	foundCorrectPackage := false
	badVirtualPath := "/hudson.war:org.jvnet.hudson.main:hudson-war"
	goodVirtualPath := "/hudson.war"
	for _, p := range sbom.Artifacts.Packages.Sorted() {
		if p.Type == pkg.JavaPkg && strings.Contains(p.Name, "hudson") {
			assert.NotEqual(t, badPURL, p.PURL, "must not find bad purl %q", badPURL)
			virtPath := ""
			if meta, ok := p.Metadata.(pkg.JavaArchive); ok {
				virtPath = meta.VirtualPath
				if p.PURL == goodPURL && virtPath == goodVirtualPath {
					foundCorrectPackage = true
				}
			}
			assert.NotEqual(t, badVirtualPath, virtPath, "must not find bad virtual path %q", badVirtualPath)
		}
	}
	assert.True(t, foundCorrectPackage, "must find correct package, but did not")
}
