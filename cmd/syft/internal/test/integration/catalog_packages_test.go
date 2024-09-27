package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func BenchmarkImagePackageCatalogers(b *testing.B) {
	// get the fixture image tar file
	fixtureImageName := "image-pkg-coverage"
	imagetest.GetFixtureImage(b, "docker-archive", fixtureImageName)
	tarPath := imagetest.GetFixtureImageTarPath(b, fixtureImageName)

	// get the source object for the image
	theSource, err := syft.GetSource(context.Background(), tarPath, syft.DefaultGetSourceConfig().WithSources("docker-archive"))
	require.NoError(b, err)

	b.Cleanup(func() {
		require.NoError(b, theSource.Close())
	})

	// build the SBOM
	s, err := syft.CreateSBOM(context.Background(), theSource, syft.DefaultCreateSBOMConfig())

	// did it work?
	require.NoError(b, err)
	require.NotNil(b, s)
}

func TestPkgCoverageImage(t *testing.T) {
	sbom, _ := catalogFixtureImage(t, "image-pkg-coverage", source.SquashedScope)

	observedLanguages := strset.New()
	definedLanguages := strset.New()
	for _, l := range pkg.AllLanguages {
		definedLanguages.Add(l.String())
	}

	// for image scans we should not expect to see any of the following package types
	definedLanguages.Remove(pkg.Go.String())
	definedLanguages.Remove(pkg.Rust.String())
	definedLanguages.Remove(pkg.Dart.String())
	definedLanguages.Remove(pkg.Swift.String())
	definedLanguages.Remove(pkg.Swipl.String())
	definedLanguages.Remove(pkg.OCaml.String())
	definedLanguages.Remove(pkg.CPP.String())
	definedLanguages.Remove(pkg.Haskell.String())
	definedLanguages.Remove(pkg.Elixir.String())
	definedLanguages.Remove(pkg.Erlang.String())

	observedPkgs := strset.New()
	definedPkgs := strset.New()
	for _, p := range pkg.AllPkgs {
		definedPkgs.Add(string(p))
	}

	// for image scans we should not expect to see any of the following package types
	definedPkgs.Remove(string(pkg.KbPkg))
	definedPkgs.Remove(string(pkg.GoModulePkg))
	definedPkgs.Remove(string(pkg.RustPkg))
	definedPkgs.Remove(string(pkg.DartPubPkg))
	definedPkgs.Remove(string(pkg.ErlangOTPPkg))
	definedPkgs.Remove(string(pkg.CocoapodsPkg))
	definedPkgs.Remove(string(pkg.ConanPkg))
	definedPkgs.Remove(string(pkg.HackagePkg))
	definedPkgs.Remove(string(pkg.BinaryPkg))
	definedPkgs.Remove(string(pkg.HexPkg))
	definedPkgs.Remove(string(pkg.LinuxKernelPkg))
	definedPkgs.Remove(string(pkg.LinuxKernelModulePkg))
	definedPkgs.Remove(string(pkg.SwiftPkg))
	definedPkgs.Remove(string(pkg.SwiplPackPkg))
	definedPkgs.Remove(string(pkg.OpamPkg))
	definedPkgs.Remove(string(pkg.GithubActionPkg))
	definedPkgs.Remove(string(pkg.GithubActionWorkflowPkg))

	var cases []testCase
	cases = append(cases, commonTestCases...)
	cases = append(cases, imageOnlyTestCases...)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkgCount := 0

			for a := range sbom.Artifacts.Packages.Enumerate(c.pkgType) {
				if a.Language.String() != "" {
					observedLanguages.Add(a.Language.String())
				}

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
				for a := range sbom.Artifacts.Packages.Enumerate(c.pkgType) {
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

	missingLang := strset.Difference(definedLanguages, observedLanguages)
	extraLang := strset.Difference(observedLanguages, definedLanguages)

	// ensure that integration test cases stay in sync with the available catalogers
	if missingLang.Size() > 0 || extraLang.Size() > 0 {
		t.Errorf("language coverage incomplete (languages=%d, coverage=%d)", definedLanguages.Size(), observedLanguages.Size())
		t.Errorf("unexpected languages: %s", extraLang.List())
		t.Errorf("missing languages: %s", missingLang.List())
	}

	missingPkgs := strset.Difference(definedPkgs, observedPkgs)
	extraPkgs := strset.Difference(observedPkgs, definedPkgs)

	if missingPkgs.Size() > 0 || extraPkgs.Size() > 0 {
		t.Errorf("package coverage incomplete (packages=%d, coverage=%d)", definedPkgs.Size(), observedPkgs.Size())
		t.Errorf("unexpected packages: %s", extraPkgs.List())
		t.Errorf("missing packages: %s", missingPkgs.List())
	}
}

func TestPkgCoverageDirectory(t *testing.T) {
	sbom, _ := catalogDirectory(t, "test-fixtures/image-pkg-coverage")

	observedLanguages := strset.New()
	definedLanguages := strset.New()
	for _, l := range pkg.AllLanguages {
		definedLanguages.Add(l.String())
	}

	observedPkgs := strset.New()
	definedPkgs := strset.New()
	for _, p := range pkg.AllPkgs {
		definedPkgs.Add(string(p))
	}

	var cases []testCase
	cases = append(cases, commonTestCases...)
	cases = append(cases, dirOnlyTestCases...)

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			actualPkgCount := 0

			for actualPkg := range sbom.Artifacts.Packages.Enumerate(test.pkgType) {
				observedLanguages.Add(actualPkg.Language.String())
				observedPkgs.Add(string(actualPkg.Type))

				expectedVersion, ok := test.pkgInfo[actualPkg.Name]
				if !ok {
					t.Errorf("unexpected package found: %s", actualPkg.Name)
				}

				if expectedVersion != actualPkg.Version {
					t.Errorf("unexpected package version (pkg=%s): %s", actualPkg.Name, actualPkg.Version)
				}

				var foundLang bool
				for _, lang := range strings.Split(test.pkgLanguage.String(), ",") {
					if actualPkg.Language.String() == lang {
						foundLang = true
						break
					}
				}
				if !foundLang {
					t.Errorf("bad language (pkg=%+v): %+v", actualPkg.Name, actualPkg.Language)
				}

				if actualPkg.Type != test.pkgType {
					t.Errorf("bad package type (pkg=%+v): %+v", actualPkg.Name, actualPkg.Type)
				}
				actualPkgCount++
			}

			if actualPkgCount != len(test.pkgInfo)+test.duplicates {
				for actualPkg := range sbom.Artifacts.Packages.Enumerate(test.pkgType) {
					t.Log("   ", actualPkg)
				}
				t.Fatalf("unexpected package count: %d!=%d", actualPkgCount, len(test.pkgInfo))
			}
		})
	}

	observedLanguages.Remove(pkg.UnknownLanguage.String())
	definedLanguages.Remove(pkg.UnknownLanguage.String())
	definedLanguages.Remove(pkg.R.String())
	observedPkgs.Remove(string(pkg.UnknownPkg))
	definedPkgs.Remove(string(pkg.BinaryPkg))
	definedPkgs.Remove(string(pkg.LinuxKernelPkg))
	definedPkgs.Remove(string(pkg.LinuxKernelModulePkg))
	definedPkgs.Remove(string(pkg.Rpkg))
	definedPkgs.Remove(string(pkg.UnknownPkg))

	// for directory scans we should not expect to see any of the following package types
	definedPkgs.Remove(string(pkg.KbPkg))

	// ensure that integration test commonTestCases stay in sync with the available catalogers
	if observedLanguages.Size() < definedLanguages.Size() {
		t.Errorf("language coverage incomplete (languages=%d, coverage=%d)", definedLanguages.Size(), observedLanguages.Size())
	}

	if observedPkgs.Size() < definedPkgs.Size() {
		t.Errorf("package coverage incomplete (packages=%d, coverage=%d)", definedPkgs.Size(), observedPkgs.Size())
	}
}

func TestPkgCoverageImage_HasEvidence(t *testing.T) {
	sbom, _ := catalogFixtureImage(t, "image-pkg-coverage", source.SquashedScope)

	var cases []testCase
	cases = append(cases, commonTestCases...)
	cases = append(cases, imageOnlyTestCases...)

	pkgTypesMissingEvidence := strset.New()

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for a := range sbom.Artifacts.Packages.Enumerate(c.pkgType) {
				assert.NotEmpty(t, a.Locations.ToSlice(), "package %q has no locations (type=%q)", a.Name, a.Type)
				for _, l := range a.Locations.ToSlice() {
					if _, exists := l.Annotations[pkg.EvidenceAnnotationKey]; !exists {
						pkgTypesMissingEvidence.Add(string(a.Type))
						t.Errorf("missing evidence annotation (pkg=%s type=%s)", a.Name, a.Type)
					}
				}
			}
		})
	}

	if pkgTypesMissingEvidence.Size() > 0 {
		t.Log("Package types missing evidence annotations (img resolver): ", pkgTypesMissingEvidence.List())
	}
}

func TestPkgCoverageDirectory_HasEvidence(t *testing.T) {
	sbom, _ := catalogDirectory(t, "test-fixtures/image-pkg-coverage")

	var cases []testCase
	cases = append(cases, commonTestCases...)
	cases = append(cases, imageOnlyTestCases...)

	pkgTypesMissingEvidence := strset.New()

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for a := range sbom.Artifacts.Packages.Enumerate(c.pkgType) {
				assert.NotEmpty(t, a.Locations.ToSlice(), "package %q has no locations (type=%q)", a.Name, a.Type)
				for _, l := range a.Locations.ToSlice() {
					if _, exists := l.Annotations[pkg.EvidenceAnnotationKey]; !exists {
						pkgTypesMissingEvidence.Add(string(a.Type))
						t.Errorf("missing evidence annotation (pkg=%s type=%s)", a.Name, a.Type)
					}
				}
			}
		})
	}

	if pkgTypesMissingEvidence.Size() > 0 {
		t.Log("Package types missing evidence annotations (dir resolver): ", pkgTypesMissingEvidence.List())
	}
}
