package integration

import (
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg/cataloger"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/source"

	"github.com/go-test/deep"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg"
)

func BenchmarkImagePackageCatalogers(b *testing.B) {
	fixtureImageName := "image-pkg-coverage"
	imagetest.GetFixtureImage(b, "docker-archive", fixtureImageName)
	tarPath := imagetest.GetFixtureImageTarPath(b, fixtureImageName)

	var pc *pkg.Catalog
	for _, c := range cataloger.ImageCatalogers() {
		// in case of future alteration where state is persisted, assume no dependency is safe to reuse
		theSource, cleanupSource, err := source.New("docker-archive:"+tarPath, nil)
		b.Cleanup(func() {
			assert.NoError(b, cleanupSource())
		})
		if err != nil {
			b.Fatalf("unable to get source: %+v", err)
		}

		resolver, err := theSource.FileResolver(source.SquashedScope)
		if err != nil {
			b.Fatalf("unable to get resolver: %+v", err)
		}

		theDistro := distro.Identify(resolver)

		b.Run(c.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pc, err = cataloger.Catalog(resolver, theDistro, c)
				if err != nil {
					b.Fatalf("failure during benchmark: %+v", err)
				}
			}
		})

		b.Logf("catalog for %q number of packages: %d", c.Name(), pc.PackageCount())
	}
}

func TestPkgCoverageImage(t *testing.T) {
	catalog, _, _ := catalogFixtureImage(t, "image-pkg-coverage")

	observedLanguages := internal.NewStringSet()
	definedLanguages := internal.NewStringSet()
	for _, l := range pkg.AllLanguages {
		definedLanguages.Add(l.String())
	}

	observedPkgs := internal.NewStringSet()
	definedPkgs := internal.NewStringSet()
	for _, p := range pkg.AllPkgs {
		definedPkgs.Add(string(p))
	}
	definedPkgs.Remove(string(pkg.KbPkg))

	var cases []testCase
	cases = append(cases, commonTestCases...)
	cases = append(cases, imageOnlyTestCases...)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkgCount := 0

			for a := range catalog.Enumerate(c.pkgType) {

				observedLanguages.Add(a.Language.String())
				observedPkgs.Add(string(a.Type))

				expectedVersion, ok := c.pkgInfo[a.Name]
				if !ok {
					t.Errorf("unexpected package found: %s", a.Name)
				}

				if expectedVersion != a.Version {
					t.Errorf("unexpected package version (pkg=%s): %s, expected: %s", a.Name, a.Version, expectedVersion)
				}

				if a.Language != c.pkgLanguage {
					t.Errorf("bad language (pkg=%+v): %+v", a.Name, a.Language)
				}

				if a.Type != c.pkgType {
					t.Errorf("bad package type (pkg=%+v): %+v", a.Name, a.Type)
				}
				pkgCount++
			}

			if pkgCount != len(c.pkgInfo)+c.duplicates {
				t.Logf("Discovered packages of type %+v", c.pkgType)
				for a := range catalog.Enumerate(c.pkgType) {
					t.Log("   ", a)
				}
				t.Fatalf("unexpected package count: %d!=%d", pkgCount, len(c.pkgInfo))
			}

		})
	}

	observedLanguages.Remove(pkg.UnknownLanguage.String())
	definedLanguages.Remove(pkg.UnknownLanguage.String())
	observedPkgs.Remove(string(pkg.UnknownPkg))
	definedPkgs.Remove(string(pkg.UnknownPkg))

	// ensure that integration test cases stay in sync with the available catalogers
	if len(observedLanguages) < len(definedLanguages) {
		t.Errorf("language coverage incomplete (languages=%d, coverage=%d)", len(definedLanguages), len(observedLanguages))
		for _, d := range deep.Equal(observedLanguages, definedLanguages) {
			t.Errorf("diff: %+v", d)
		}
	}

	if len(observedPkgs) < len(definedPkgs) {
		t.Errorf("package coverage incomplete (packages=%d, coverage=%d)", len(definedPkgs), len(observedPkgs))
		for _, d := range deep.Equal(observedPkgs, definedPkgs) {
			t.Errorf("diff: %+v", d)
		}
	}
}

func TestPkgCoverageDirectory(t *testing.T) {
	catalog, _, _ := catalogDirectory(t, "test-fixtures/image-pkg-coverage")

	observedLanguages := internal.NewStringSet()
	definedLanguages := internal.NewStringSet()
	for _, l := range pkg.AllLanguages {
		definedLanguages.Add(l.String())
	}

	observedPkgs := internal.NewStringSet()
	definedPkgs := internal.NewStringSet()
	for _, p := range pkg.AllPkgs {
		definedPkgs.Add(string(p))
	}

	var cases []testCase
	cases = append(cases, commonTestCases...)
	cases = append(cases, dirOnlyTestCases...)

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			actualPkgCount := 0

			for actualPkg := range catalog.Enumerate(test.pkgType) {

				observedLanguages.Add(actualPkg.Language.String())
				observedPkgs.Add(string(actualPkg.Type))

				expectedVersion, ok := test.pkgInfo[actualPkg.Name]
				if !ok {
					t.Errorf("unexpected package found: %s", actualPkg.Name)
				}

				if expectedVersion != actualPkg.Version {
					t.Errorf("unexpected package version (pkg=%s): %s", actualPkg.Name, actualPkg.Version)
				}

				if actualPkg.Language != test.pkgLanguage {
					t.Errorf("bad language (pkg=%+v): %+v", actualPkg.Name, actualPkg.Language)
				}

				if actualPkg.Type != test.pkgType {
					t.Errorf("bad package type (pkg=%+v): %+v", actualPkg.Name, actualPkg.Type)
				}
				actualPkgCount++
			}

			if actualPkgCount != len(test.pkgInfo)+test.duplicates {
				for actualPkg := range catalog.Enumerate(test.pkgType) {
					t.Log("   ", actualPkg)
				}
				t.Fatalf("unexpected package count: %d!=%d", actualPkgCount, len(test.pkgInfo))
			}

		})
	}

	observedLanguages.Remove(pkg.UnknownLanguage.String())
	definedLanguages.Remove(pkg.UnknownLanguage.String())
	observedPkgs.Remove(string(pkg.UnknownPkg))
	definedPkgs.Remove(string(pkg.UnknownPkg))
	definedPkgs.Remove(string(pkg.KbPkg))

	// ensure that integration test commonTestCases stay in sync with the available catalogers
	if len(observedLanguages) < len(definedLanguages) {
		t.Errorf("language coverage incomplete (languages=%d, coverage=%d)", len(definedLanguages), len(observedLanguages))
	}

	if len(observedPkgs) < len(definedPkgs) {
		t.Errorf("package coverage incomplete (packages=%d, coverage=%d)", len(definedPkgs), len(observedPkgs))
	}
}
