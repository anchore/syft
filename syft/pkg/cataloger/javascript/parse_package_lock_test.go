package javascript

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
)

func TestParsePackageLock(t *testing.T) {
	var expectedRelationships []artifact.Relationship
	expectedPkgs := []pkg.Package{
		{
			Name:     "@actions/core",
			Version:  "1.6.0",
			PURL:     "pkg:npm/%40actions/core@1.6.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		{
			Name:     "ansi-regex",
			Version:  "3.0.0",
			PURL:     "pkg:npm/ansi-regex@3.0.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		{
			Name:     "cowsay",
			Version:  "1.4.0",
			PURL:     "pkg:npm/cowsay@1.4.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		{
			Name:     "get-stdin",
			Version:  "5.0.1",
			PURL:     "pkg:npm/get-stdin@5.0.1",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		{
			Name:     "is-fullwidth-code-point",
			Version:  "2.0.0",
			PURL:     "pkg:npm/is-fullwidth-code-point@2.0.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		{
			Name:     "minimist",
			Version:  "0.0.10",
			PURL:     "pkg:npm/minimist@0.0.10",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		{
			Name:     "optimist",
			Version:  "0.6.1",
			PURL:     "pkg:npm/optimist@0.6.1",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		{
			Name:     "string-width",
			Version:  "2.1.1",
			PURL:     "pkg:npm/string-width@2.1.1",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		{
			Name:     "strip-ansi",
			Version:  "4.0.0",
			PURL:     "pkg:npm/strip-ansi@4.0.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		{
			Name:     "strip-eof",
			Version:  "1.0.0",
			PURL:     "pkg:npm/strip-eof@1.0.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		{
			Name:     "wordwrap",
			Version:  "0.0.3",
			PURL:     "pkg:npm/wordwrap@0.0.3",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
	}
	fixture := "test-fixtures/pkg-lock/package-lock.json"
	for i := range expectedPkgs {
		expectedPkgs[i].Locations.Add(source.NewLocation(fixture))
	}

	pkgtest.TestFileParser(t, fixture, parsePackageLock, expectedPkgs, expectedRelationships)
}

func TestParsePackageLockV2(t *testing.T) {
	fixture := "test-fixtures/pkg-lock/package-lock-2.json"
	var expectedRelationships []artifact.Relationship
	expectedPkgs := []pkg.Package{
		{
			Name:     "npm",
			Version:  "6.14.6",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			PURL:     "pkg:npm/npm@6.14.6",
		},
		{
			Name:     "@types/prop-types",
			Version:  "15.7.5",
			PURL:     "pkg:npm/%40types/prop-types@15.7.5",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			Licenses: []string{"MIT"},
		},
		{
			Name:     "@types/react",
			Version:  "18.0.17",
			PURL:     "pkg:npm/%40types/react@18.0.17",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			Licenses: []string{"MIT"},
		},
		{
			Name:     "@types/scheduler",
			Version:  "0.16.2",
			PURL:     "pkg:npm/%40types/scheduler@0.16.2",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			Licenses: []string{"MIT"},
		},
		{
			Name:     "csstype",
			Version:  "3.1.0",
			PURL:     "pkg:npm/csstype@3.1.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			Licenses: []string{"MIT"},
		},
	}
	for i := range expectedPkgs {
		expectedPkgs[i].Locations.Add(source.NewLocation(fixture))
	}
	pkgtest.TestFileParser(t, fixture, parsePackageLock, expectedPkgs, expectedRelationships)
}

func TestParsePackageLockV3(t *testing.T) {
	fixture := "test-fixtures/pkg-lock/package-lock-3.json"
	var expectedRelationships []artifact.Relationship
	expectedPkgs := []pkg.Package{
		{
			Name:     "lock-v3-fixture",
			Version:  "1.0.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			PURL:     "pkg:npm/lock-v3-fixture@1.0.0",
		},
		{
			Name:     "@types/prop-types",
			Version:  "15.7.5",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			PURL:     "pkg:npm/%40types/prop-types@15.7.5",
		},
		{
			Name:     "@types/react",
			Version:  "18.0.20",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			PURL:     "pkg:npm/%40types/react@18.0.20",
		},
		{
			Name:     "@types/scheduler",
			Version:  "0.16.2",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			PURL:     "pkg:npm/%40types/scheduler@0.16.2",
		},
		{
			Name:     "csstype",
			Version:  "3.1.1",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			PURL:     "pkg:npm/csstype@3.1.1",
		},
	}
	for i := range expectedPkgs {
		expectedPkgs[i].Locations.Add(source.NewLocation(fixture))
	}
	pkgtest.TestFileParser(t, fixture, parsePackageLock, expectedPkgs, expectedRelationships)
}

func TestParsePackageLockAlias(t *testing.T) {
	var expectedRelationships []artifact.Relationship
	commonPkgs := []pkg.Package{
		{
			Name:     "case",
			Version:  "1.6.2",
			PURL:     "pkg:npm/case@1.6.2",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		{
			Name:     "case",
			Version:  "1.6.3",
			PURL:     "pkg:npm/case@1.6.3",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
		{
			Name:     "@bundled-es-modules/chai",
			Version:  "4.2.2",
			PURL:     "pkg:npm/%40bundled-es-modules/chai@4.2.2",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		},
	}

	v2Pkg := pkg.Package{
		Name:     "alias-check",
		Version:  "1.0.0",
		PURL:     "pkg:npm/alias-check@1.0.0",
		Language: pkg.JavaScript,
		Type:     pkg.NpmPkg,
		Licenses: []string{"ISC"},
	}

	packageLockV1 := "test-fixtures/pkg-lock/alias-package-lock-1.json"
	packageLockV2 := "test-fixtures/pkg-lock/alias-package-lock-2.json"
	packageLocks := []string{packageLockV1, packageLockV2}

	for _, packageLock := range packageLocks {
		expected := make([]pkg.Package, len(commonPkgs))
		copy(expected, commonPkgs)

		if packageLock == packageLockV2 {
			expected = append(expected, v2Pkg)
		}

		for i := range expected {
			expected[i].Locations.Add(source.NewLocation(packageLock))
		}
		pkgtest.TestFileParser(t, packageLock, parsePackageLock, expected, expectedRelationships)
	}
}
