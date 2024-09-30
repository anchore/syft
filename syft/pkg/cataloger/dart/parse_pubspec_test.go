package dart

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParsePubspec(t *testing.T) {
	fixture := "test-fixtures/pubspec.yaml"
	fixtureLocationSet := file.NewLocationSet(file.NewLocation(fixture))
	expected := []pkg.Package{
		{
			Name:      "_macros",
			Version:   "0.3.2",
			PURL:      "pkg:pub/_macros@0.3.2",
			Locations: fixtureLocationSet,
			Language:  pkg.Dart,
			Type:      pkg.DartPubPkg,
			Metadata: pkg.DartPubspecEntry{
				Name:    "_macros",
				Version: "0.3.2",
			},
		},
	}

	// TODO: relationships are not under test
	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parsePubspec, expected, expectedRelationships)
}
