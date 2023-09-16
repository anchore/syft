package javascript

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseYarnBerry(t *testing.T) {
	var expectedRelationships []artifact.Relationship
	fixture := "test-fixtures/yarn-berry/yarn.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkgs := []pkg.Package{
		{
			Name:         "yarn-berry",
			Version:      "0.0.0",
			Locations:    locations,
			PURL:         "pkg:npm/yarn-berry@0.0.0",
			Language:     pkg.JavaScript,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     pkg.NpmPackageLockJSONMetadata{},
			Type:         pkg.NpmPkg,
		},
		{
			Name:         "@babel/code-frame",
			Version:      "7.10.4",
			Locations:    locations,
			PURL:         "pkg:npm/%40babel/code-frame@7.10.4",
			Language:     pkg.JavaScript,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     pkg.NpmPackageLockJSONMetadata{},
			Type:         pkg.NpmPkg,
		},
		{
			Name:         "@types/minimatch",
			Version:      "3.0.3",
			Locations:    locations,
			PURL:         "pkg:npm/%40types/minimatch@3.0.3",
			Language:     pkg.JavaScript,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     pkg.NpmPackageLockJSONMetadata{},
			Type:         pkg.NpmPkg,
		},
		{
			Name:         "@types/qs",
			Version:      "6.9.4",
			Locations:    locations,
			PURL:         "pkg:npm/%40types/qs@6.9.4",
			Language:     pkg.JavaScript,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     pkg.NpmPackageLockJSONMetadata{},
			Type:         pkg.NpmPkg,
		},
		{
			Name:         "ajv",
			Version:      "6.12.3",
			Locations:    locations,
			PURL:         "pkg:npm/ajv@6.12.3",
			Language:     pkg.JavaScript,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     pkg.NpmPackageLockJSONMetadata{},
			Type:         pkg.NpmPkg,
		},
		{
			Name:         "asn1.js",
			Version:      "4.10.1",
			Locations:    locations,
			PURL:         "pkg:npm/asn1.js@4.10.1",
			Language:     pkg.JavaScript,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     pkg.NpmPackageLockJSONMetadata{},
			Type:         pkg.NpmPkg,
		},
		{
			Name:         "atob",
			Version:      "2.1.2",
			Locations:    locations,
			PURL:         "pkg:npm/atob@2.1.2",
			Language:     pkg.JavaScript,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     pkg.NpmPackageLockJSONMetadata{},
			Type:         pkg.NpmPkg,
		},
		{
			Name:         "aws-sdk",
			Version:      "2.706.0",
			PURL:         "pkg:npm/aws-sdk@2.706.0",
			Locations:    locations,
			Language:     pkg.JavaScript,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     pkg.NpmPackageLockJSONMetadata{},
			Type:         pkg.NpmPkg,
		},
		{
			Name:         "c0n-fab_u.laTION",
			Version:      "7.7.7",
			Locations:    locations,
			PURL:         "pkg:npm/c0n-fab_u.laTION@7.7.7",
			Language:     pkg.JavaScript,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     pkg.NpmPackageLockJSONMetadata{},
			Type:         pkg.NpmPkg,
		},
		{
			Name:         "jhipster-core",
			Version:      "7.3.4",
			Locations:    locations,
			PURL:         "pkg:npm/jhipster-core@7.3.4",
			Language:     pkg.JavaScript,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     pkg.NpmPackageLockJSONMetadata{},
			Type:         pkg.NpmPkg,
		},
	}

	pkgtest.TestFileParser(t, fixture, parseYarnLock, expectedPkgs, expectedRelationships)
}

func TestParseYarnLock(t *testing.T) {
	var expectedRelationships []artifact.Relationship
	fixture := "test-fixtures/yarn/yarn.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkgs := []pkg.Package{
		{
			Name:         "yarn",
			Version:      "0.0.0",
			Locations:    locations,
			PURL:         "pkg:npm/yarn@0.0.0",
			Language:     pkg.JavaScript,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata:     pkg.NpmPackageLockJSONMetadata{},
			Type:         pkg.NpmPkg,
		},
		{
			Name:         "@babel/code-frame",
			Version:      "7.10.4",
			Locations:    locations,
			PURL:         "pkg:npm/%40babel/code-frame@7.10.4",
			Language:     pkg.JavaScript,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata: pkg.NpmPackageLockJSONMetadata{
				Resolved:  "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.10.4.tgz#168da1a36e90da68ae8d49c0f1b48c7c6249213a",
				Integrity: "sha512-vG6SvB6oYEhvgisZNFRmRCUkLz11c7rp+tbNTynGqc6mS1d5ATd/sGyV6W0KZZnXRKMTzZDRgQT3Ou9jhpAfUg==",
			},
			Type: pkg.NpmPkg,
		},
		{
			Name:         "@types/minimatch",
			Version:      "3.0.3",
			Locations:    locations,
			PURL:         "pkg:npm/%40types/minimatch@3.0.3",
			Language:     pkg.JavaScript,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata: pkg.NpmPackageLockJSONMetadata{
				Resolved:  "https://registry.yarnpkg.com/@types/minimatch/-/minimatch-3.0.3.tgz#3dca0e3f33b200fc7d1139c0cd96c1268cadfd9d",
				Integrity: "sha512-tHq6qdbT9U1IRSGf14CL0pUlULksvY9OZ+5eEgl1N7t+OA3tGvNpxJCzuKQlsNgCVwbAs670L1vcVQi8j9HjnA==",
			},
			Type: pkg.NpmPkg,
		},
		{
			Name:         "@types/qs",
			Version:      "6.9.4",
			Locations:    locations,
			PURL:         "pkg:npm/%40types/qs@6.9.4",
			Language:     pkg.JavaScript,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata: pkg.NpmPackageLockJSONMetadata{
				Resolved:  "https://registry.yarnpkg.com/@types/qs/-/qs-6.9.4.tgz#a59e851c1ba16c0513ea123830dd639a0a15cb6a",
				Integrity: "sha512-+wYo+L6ZF6BMoEjtf8zB2esQsqdV6WsjRK/GP9WOgLPrq87PbNWgIxS76dS5uvl/QXtHGakZmwTznIfcPXcKlQ==",
			},
			Type: pkg.NpmPkg,
		},
		{
			Name:         "ajv",
			Version:      "6.12.3",
			Locations:    locations,
			PURL:         "pkg:npm/ajv@6.12.3",
			Language:     pkg.JavaScript,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata: pkg.NpmPackageLockJSONMetadata{
				Resolved:  "https://registry.yarnpkg.com/ajv/-/ajv-6.12.3.tgz#18c5af38a111ddeb4f2697bd78d68abc1cabd706",
				Integrity: "sha512-4K0cK3L1hsqk9xIb2z9vs/XU+PGJZ9PNpJRDS9YLzmNdX6jmVPfamLvTJr0aDAusnHyCHO6MjzlkAsgtqp9teA==",
			},
			Type: pkg.NpmPkg,
		},
		{
			Name:         "asn1.js",
			Version:      "4.10.1",
			Locations:    locations,
			PURL:         "pkg:npm/asn1.js@4.10.1",
			Language:     pkg.JavaScript,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata: pkg.NpmPackageLockJSONMetadata{
				Resolved:  "https://registry.yarnpkg.com/asn1.js/-/asn1.js-4.10.1.tgz#b9c2bf5805f1e64aadeed6df3a2bfafb5a73f5a0",
				Integrity: "sha512-p32cOF5q0Zqs9uBiONKYLm6BClCoBCM5O9JfeUSlnQLBTxYdTK+pW+nXflm8UkKd2UYlEbYz5qEi0JuZR9ckSw==",
			},
			Type: pkg.NpmPkg,
		},
		{
			Name:         "atob",
			Version:      "2.1.2",
			Locations:    locations,
			PURL:         "pkg:npm/atob@2.1.2",
			Language:     pkg.JavaScript,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata: pkg.NpmPackageLockJSONMetadata{
				Resolved:  "https://registry.yarnpkg.com/atob/-/atob-2.1.2.tgz#6d9517eb9e030d2436666651e86bd9f6f13533c9",
				Integrity: "sha512-Wm6ukoaOGJi/73p/cl2GvLjTI5JM1k/O14isD73YML8StrH/7/lRFgmg8nICZgD3bZZvjwCGxtMOD3wWNAu8cg==",
			},
			Type: pkg.NpmPkg,
		},
		{
			Name:         "aws-sdk",
			Version:      "2.706.0",
			Locations:    locations,
			PURL:         "pkg:npm/aws-sdk@2.706.0",
			Language:     pkg.JavaScript,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata: pkg.NpmPackageLockJSONMetadata{
				Resolved:  "https://registry.yarnpkg.com/aws-sdk/-/aws-sdk-2.706.0.tgz#09f65e9a91ecac5a635daf934082abae30eca953",
				Integrity: "sha512-7GT+yrB5Wb/zOReRdv/Pzkb2Qt+hz6B/8FGMVaoysX3NryHvQUdz7EQWi5yhg9CxOjKxdw5lFwYSs69YlSp1KA==",
			},
			Type: pkg.NpmPkg,
		},
		{
			Name:         "jhipster-core",
			Version:      "7.3.4",
			Locations:    locations,
			PURL:         "pkg:npm/jhipster-core@7.3.4",
			Language:     pkg.JavaScript,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata: pkg.NpmPackageLockJSONMetadata{
				Resolved:  "https://registry.yarnpkg.com/jhipster-core/-/jhipster-core-7.3.4.tgz#c34b8c97c7f4e8b7518dae015517e2112c73cc80",
				Integrity: "sha512-AUhT69kNkqppaJZVfan/xnKG4Gs9Ggj7YLtTZFVe+xg+THrbMb5Ng7PL07PDlDw4KAEA33GMCwuAf65E8EpC4g==",
			},
			Type: pkg.NpmPkg,
		},
		{
			Name:         "something-i-made-up",
			Version:      "7.7.7",
			Locations:    locations,
			PURL:         "pkg:npm/something-i-made-up@7.7.7",
			Language:     pkg.JavaScript,
			MetadataType: pkg.NpmPackageLockJSONMetadataType,
			Metadata: pkg.NpmPackageLockJSONMetadata{
				Resolved:  "https://registry.yarnpkg.com/something-i-made-up/-/c0n-fab_u.laTION-7.7.7.tgz#b9c2bf5805f1e64aadeed6df3a2bfafb5a73f5a0",
				Integrity: "sha512-p32cOF5q0Zqs9uBiONKYLm6BClCoBCM5O9JfeUSlnQLBTxYdTK+pW+nXflm8UkKd2UYlEbYz5qEi0JuZR9ckSw==",
			},
			Type: pkg.NpmPkg,
		},
	}

	pkgtest.TestFileParser(t, fixture, parseYarnLock, expectedPkgs, expectedRelationships)
}
