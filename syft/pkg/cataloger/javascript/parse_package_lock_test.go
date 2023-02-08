package javascript

import (
	"testing"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
)

func TestParsePackageLock(t *testing.T) {
	var expectedRelationships []artifact.Relationship
	expectedPkgs := []pkg.Package{
		{
			Name:         "@actions/core",
			Version:      "1.6.0",
			PURL:         "pkg:npm/%40actions/core@1.6.0",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/@actions/core/-/core-1.6.0.tgz", Integrity: "sha512-NB1UAZomZlCV/LmJqkLhNTqtKfFXJZAUPcfl/zqG7EfsQdeUJtaWO98SGbuQ3pydJ3fHl2CvI/51OKYlCYYcaw=="},
		},
		{
			Name:         "ansi-regex",
			Version:      "3.0.0",
			PURL:         "pkg:npm/ansi-regex@3.0.0",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/ansi-regex/-/ansi-regex-3.0.0.tgz", Integrity: "sha1-7QMXwyIGT3lGbAKWa922Bas32Zg="},
		},
		{
			Name:         "cowsay",
			Version:      "1.4.0",
			PURL:         "pkg:npm/cowsay@1.4.0",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/cowsay/-/cowsay-1.4.0.tgz", Integrity: "sha512-rdg5k5PsHFVJheO/pmE3aDg2rUDDTfPJau6yYkZYlHFktUz+UxbE+IgnUAEyyCyv4noL5ltxXD0gZzmHPCy/9g=="},
		},
		{
			Name:         "get-stdin",
			Version:      "5.0.1",
			PURL:         "pkg:npm/get-stdin@5.0.1",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/get-stdin/-/get-stdin-5.0.1.tgz", Integrity: "sha1-Ei4WFZHiH/TFJTAwVpPyDmOTo5g="},
		},
		{
			Name:         "is-fullwidth-code-point",
			Version:      "2.0.0",
			PURL:         "pkg:npm/is-fullwidth-code-point@2.0.0",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/is-fullwidth-code-point/-/is-fullwidth-code-point-2.0.0.tgz", Integrity: "sha1-o7MKXE8ZkYMWeqq5O+764937ZU8="},
		},
		{
			Name:         "minimist",
			Version:      "0.0.10",
			PURL:         "pkg:npm/minimist@0.0.10",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/minimist/-/minimist-0.0.10.tgz", Integrity: "sha1-3j+YVD2/lggr5IrRoMfNqDYwHc8="},
		},
		{
			Name:         "optimist",
			Version:      "0.6.1",
			PURL:         "pkg:npm/optimist@0.6.1",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/optimist/-/optimist-0.6.1.tgz", Integrity: "sha1-2j6nRob6IaGaERwybpDrFaAZZoY="},
		},
		{
			Name:         "string-width",
			Version:      "2.1.1",
			PURL:         "pkg:npm/string-width@2.1.1",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/string-width/-/string-width-2.1.1.tgz", Integrity: "sha512-nOqH59deCq9SRHlxq1Aw85Jnt4w6KvLKqWVik6oA9ZklXLNIOlqg4F2yrT1MVaTjAqvVwdfeZ7w7aCvJD7ugkw=="},
		},
		{
			Name:         "strip-ansi",
			Version:      "4.0.0",
			PURL:         "pkg:npm/strip-ansi@4.0.0",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/strip-ansi/-/strip-ansi-4.0.0.tgz", Integrity: "sha1-qEeQIusaw2iocTibY1JixQXuNo8="},
		},
		{
			Name:         "strip-eof",
			Version:      "1.0.0",
			PURL:         "pkg:npm/strip-eof@1.0.0",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/strip-eof/-/strip-eof-1.0.0.tgz", Integrity: "sha1-u0P/VZim6wXYm1n80SnJgzE2Br8="},
		},
		{
			Name:         "wordwrap",
			Version:      "0.0.3",
			PURL:         "pkg:npm/wordwrap@0.0.3",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/wordwrap/-/wordwrap-0.0.3.tgz", Integrity: "sha1-o9XabNXAvAAI03I0u68b7WMFkQc="},
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
			Name:         "npm",
			Version:      "6.14.6",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			PURL:         "pkg:npm/npm@6.14.6",
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{},
		},
		{
			Name:         "@types/prop-types",
			Version:      "15.7.5",
			PURL:         "pkg:npm/%40types/prop-types@15.7.5",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			Licenses:     internal.LogicalStrings{Simple: []string{"MIT"}},
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/@types/prop-types/-/prop-types-15.7.5.tgz", Integrity: "sha1-XxnSuFqY6VWANvajysyIGUIPBc8="},
		},
		{
			Name:         "@types/react",
			Version:      "18.0.17",
			PURL:         "pkg:npm/%40types/react@18.0.17",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			Licenses:     internal.LogicalStrings{Simple: []string{"MIT"}},
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/@types/react/-/react-18.0.17.tgz", Integrity: "sha1-RYPZwyLWfv5LOak10iPtzHBQzPQ="},
		},
		{
			Name:         "@types/scheduler",
			Version:      "0.16.2",
			PURL:         "pkg:npm/%40types/scheduler@0.16.2",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			Licenses:     internal.LogicalStrings{Simple: []string{"MIT"}},
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/@types/scheduler/-/scheduler-0.16.2.tgz", Integrity: "sha1-GmL4lSVyPd4kuhsBsJK/XfitTTk="},
		},
		{
			Name:         "csstype",
			Version:      "3.1.0",
			PURL:         "pkg:npm/csstype@3.1.0",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			Licenses:     internal.LogicalStrings{Simple: []string{"MIT"}},
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/csstype/-/csstype-3.1.0.tgz", Integrity: "sha1-TdysNxjXh8+d8NG30VAzklyPKfI="},
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
			Name:         "lock-v3-fixture",
			Version:      "1.0.0",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			PURL:         "pkg:npm/lock-v3-fixture@1.0.0",
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{},
		},
		{
			Name:         "@types/prop-types",
			Version:      "15.7.5",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			PURL:         "pkg:npm/%40types/prop-types@15.7.5",
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/@types/prop-types/-/prop-types-15.7.5.tgz", Integrity: "sha512-JCB8C6SnDoQf0cNycqd/35A7MjcnK+ZTqE7judS6o7utxUCg6imJg3QK2qzHKszlTjcj2cn+NwMB2i96ubpj7w=="},
		},
		{
			Name:         "@types/react",
			Version:      "18.0.20",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			PURL:         "pkg:npm/%40types/react@18.0.20",
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/@types/react/-/react-18.0.20.tgz", Integrity: "sha512-MWul1teSPxujEHVwZl4a5HxQ9vVNsjTchVA+xRqv/VYGCuKGAU6UhfrTdF5aBefwD1BHUD8i/zq+O/vyCm/FrA=="},
		},
		{
			Name:         "@types/scheduler",
			Version:      "0.16.2",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			PURL:         "pkg:npm/%40types/scheduler@0.16.2",
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/@types/scheduler/-/scheduler-0.16.2.tgz", Integrity: "sha512-hppQEBDmlwhFAXKJX2KnWLYu5yMfi91yazPb2l+lbJiwW+wdo1gNeRA+3RgNSO39WYX2euey41KEwnqesU2Jew=="},
		},
		{
			Name:         "csstype",
			Version:      "3.1.1",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			PURL:         "pkg:npm/csstype@3.1.1",
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/csstype/-/csstype-3.1.1.tgz", Integrity: "sha512-DJR/VvkAvSZW9bTouZue2sSxDwdTN92uHjqeKVm+0dAqdfNykRzQ95tay8aXMBAAPpUiq4Qcug2L7neoRh2Egw=="},
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
			Name:         "case",
			Version:      "1.6.2",
			PURL:         "pkg:npm/case@1.6.2",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/case/-/case-1.6.2.tgz", Integrity: "sha512-ll380ZRoraT7mUK2G92UbH+FJVD5AwdVIAYk9xhV1tauh0carDgYByUD1HhjCWsWgxrfQvCeHvtfj7IYR6TKeg=="},
		},
		{
			Name:         "case",
			Version:      "1.6.3",
			PURL:         "pkg:npm/case@1.6.3",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/case/-/case-1.6.3.tgz", Integrity: "sha512-mzDSXIPaFwVDvZAHqZ9VlbyF4yyXRuX6IvB06WvPYkqJVO24kX1PPhv9bfpKNFZyxYFmmgo03HUiD8iklmJYRQ=="},
		},
		{
			Name:         "@bundled-es-modules/chai",
			Version:      "4.2.2",
			PURL:         "pkg:npm/%40bundled-es-modules/chai@4.2.2",
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: "https://registry.npmjs.org/@bundled-es-modules/chai/-/chai-4.2.2.tgz", Integrity: "sha512-iGmVYw2/zJCoqyKTtWEYCtFmMyi8WmACQKtky0lpNyEKWX0YIOpKWGD7saMXL+tPpllss0otilxV0SLwyi3Ytg=="},
		},
	}

	v2Pkg := pkg.Package{
		Name:         "alias-check",
		Version:      "1.0.0",
		PURL:         "pkg:npm/alias-check@1.0.0",
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		Licenses:     internal.LogicalStrings{Simple: []string{"ISC"}},
		MetadataType: "NpmPackageLockJsonMetadata",
		Metadata:     pkg.NpmPackageLockJSONMetadata{},
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

func TestParsePackageLockLicenseWithArray(t *testing.T) {
	fixture := "test-fixtures/pkg-lock/array-license-package-lock.json"
	var expectedRelationships []artifact.Relationship
	expectedPkgs := []pkg.Package{
		{
			Name:         "tmp",
			Version:      "1.0.0",
			Licenses:     internal.LogicalStrings{Simple: []string{"ISC"}},
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			PURL:         "pkg:npm/tmp@1.0.0",
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{},
		},
		{
			Name:         "pause-stream",
			Version:      "0.0.11",
			Licenses:     internal.LogicalStrings{Simple: []string{"MIT", "Apache2"}},
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			PURL:         "pkg:npm/pause-stream@0.0.11",
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{},
		},
		{
			Name:         "through",
			Version:      "2.3.8",
			Licenses:     internal.LogicalStrings{Simple: []string{"MIT"}},
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			PURL:         "pkg:npm/through@2.3.8",
			MetadataType: "NpmPackageLockJsonMetadata",
			Metadata:     pkg.NpmPackageLockJSONMetadata{},
		},
	}
	for i := range expectedPkgs {
		expectedPkgs[i].Locations.Add(source.NewLocation(fixture))
	}
	pkgtest.TestFileParser(t, fixture, parsePackageLock, expectedPkgs, expectedRelationships)
}
