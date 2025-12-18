package javascript

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseYarnBerry(t *testing.T) {
	fixture := "test-fixtures/yarn-berry/yarn.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkgs := []pkg.Package{
		{
			Name:      "@babel/code-frame",
			Version:   "7.10.4",
			Locations: locations,
			PURL:      "pkg:npm/%40babel/code-frame@7.10.4",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "@babel/code-frame@npm:7.10.4",
				Integrity: "feb4543c8a509fe30f0f6e8d7aa84f82b41148b963b826cd330e34986f649a85cb63b2f13dd4effdf434ac555d16f14940b8ea5f4433297c2f5ff85486ded019",
				Dependencies: map[string]string{
					"@babel/highlight": "^7.10.4",
				},
			},
		},
		{
			Name:      "@types/minimatch",
			Version:   "3.0.3",
			Locations: locations,
			PURL:      "pkg:npm/%40types/minimatch@3.0.3",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "@types/minimatch@npm:3.0.3",
				Integrity: "b80259d55b96ef24cb3bb961b6dc18b943f2bb8838b4d8e7bead204f3173e551a416ffa49f9aaf1dc431277fffe36214118628eacf4aea20119df8835229901b",
			},
		},
		{
			Name:      "@types/qs",
			Version:   "6.9.4",
			Locations: locations,
			PURL:      "pkg:npm/%40types/qs@6.9.4",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "@types/qs@npm:6.9.4",
				Integrity: "77e509ed213f7694ae35f84a58b88da8744aad019e93556af6aeab4289287abbe71836c051d00649dbac0289ea199e408442590cfb1785009de11c3c8d0cbbea",
			},
		},
		{
			Name:      "ajv",
			Version:   "6.12.3",
			Locations: locations,
			PURL:      "pkg:npm/ajv@6.12.3",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "ajv@npm:6.12.3",
				Integrity: "ca559d34710e6969d33bc1316282e1ece4d4d99ff5fdca4bfe31947740f8f90e7824238cdc2954e499cf75b2432e3e6c56b32814ebe04fccf8abcc3fbf36b348",
				Dependencies: map[string]string{
					"fast-deep-equal":            "^3.1.1",
					"fast-json-stable-stringify": "^2.0.0",
					"json-schema-traverse":       "^0.4.1",
					"uri-js":                     "^4.2.2",
				},
			},
		},
		{
			Name:      "asn1.js",
			Version:   "4.10.1",
			Locations: locations,
			PURL:      "pkg:npm/asn1.js@4.10.1",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "asn1.js@npm:4.10.1",
				Integrity: "9289a1a55401238755e3142511d7b8f6fc32f08c86ff68bd7100da8b6c186179dd6b14234fba2f7f6099afcd6758a816708485efe44bc5b2a6ec87d9ceeddbb5",
				Dependencies: map[string]string{
					"bn.js":               "^4.0.0",
					"inherits":            "^2.0.1",
					"minimalistic-assert": "^1.0.0",
				},
			},
		},
		{
			Name:      "atob",
			Version:   "2.1.2",
			Locations: locations,
			PURL:      "pkg:npm/atob@2.1.2",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "atob@npm:2.1.2",
				Integrity: "dfeeeb70090c5ebea7be4b9f787f866686c645d9f39a0d184c817252d0cf08455ed25267d79c03254d3be1f03ac399992a792edcd5ffb9c91e097ab5ef42833a",
			},
		},
		{
			Name:      "aws-sdk",
			Version:   "2.706.0",
			PURL:      "pkg:npm/aws-sdk@2.706.0",
			Locations: locations,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "aws-sdk@npm:2.706.0",
				Integrity: "bf8ca2fc4f758bdebd04051ec15729affad3eb0e18eed4ae41db5b7d6ff2aed2cf3a12ae082c11b955df0125378c57b8406e1f91006e48f0c162fdbe4ee4e330",
				Dependencies: map[string]string{
					"buffer":      "4.9.2",
					"events":      "1.1.1",
					"ieee754":     "1.1.13",
					"jmespath":    "0.15.0",
					"querystring": "0.2.0",
					"sax":         "1.2.1",
					"url":         "0.10.3",
					"uuid":        "3.3.2",
					"xml2js":      "0.4.19",
				},
			},
		},
		{
			Name:      "c0n-fab_u.laTION",
			Version:   "7.7.7",
			Locations: locations,
			PURL:      "pkg:npm/c0n-fab_u.laTION@7.7.7",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved: "newtest@workspace:.",
				Dependencies: map[string]string{
					"@babel/code-frame": "7.10.4",
					"@types/minimatch":  "3.0.3",
					"@types/qs":         "6.9.4",
					"ajv":               "6.12.3",
					"asn1.js":           "4.10.1",
					"atob":              "2.1.2",
				}},
		},
		{
			Name:      "jhipster-core",
			Version:   "7.3.4",
			Locations: locations,
			PURL:      "pkg:npm/jhipster-core@7.3.4",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "jhipster-core@npm:7.3.4",
				Integrity: "6a97741d574a42a138f98596c668370b41ec8870335bcd758b6b890e279ba30d4d2be447f8cecbf416286f2c53636b406a63a773c7b00709c95af0a9a3f9b397",
				Dependencies: map[string]string{
					"chevrotain": "7.0.1",
					"fs-extra":   "8.1.0",
					"lodash":     "4.17.15",
					"winston":    "3.2.1",
				},
			},
		},
	}
	expectedRelationships := []artifact.Relationship{
		{
			From: expectedPkgs[0],
			To:   expectedPkgs[7],
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: expectedPkgs[1],
			To:   expectedPkgs[7],
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: expectedPkgs[2],
			To:   expectedPkgs[7],
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: expectedPkgs[3],
			To:   expectedPkgs[7],
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: expectedPkgs[4],
			To:   expectedPkgs[7],
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: expectedPkgs[5],
			To:   expectedPkgs[7],
			Type: artifact.DependencyOfRelationship,
		},
	}

	adapter := newGenericYarnLockAdapter(CatalogerConfig{})
	pkgtest.TestFileParser(t, fixture, adapter.parseYarnLock, expectedPkgs, expectedRelationships)
}

func TestParseYarnLock(t *testing.T) {
	var expectedRelationships []artifact.Relationship
	fixture := "test-fixtures/yarn/yarn.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkgs := []pkg.Package{
		{
			Name:      "@babel/code-frame",
			Version:   "7.10.4",
			Locations: locations,
			PURL:      "pkg:npm/%40babel/code-frame@7.10.4",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.10.4.tgz#168da1a36e90da68ae8d49c0f1b48c7c6249213a",
				Integrity: "sha512-vG6SvB6oYEhvgisZNFRmRCUkLz11c7rp+tbNTynGqc6mS1d5ATd/sGyV6W0KZZnXRKMTzZDRgQT3Ou9jhpAfUg==",
				Dependencies: map[string]string{
					"@babel/highlight": "^7.10.4",
				},
			},
		},
		{
			Name:      "@types/minimatch",
			Version:   "3.0.3",
			Locations: locations,
			PURL:      "pkg:npm/%40types/minimatch@3.0.3",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:     "https://registry.yarnpkg.com/@types/minimatch/-/minimatch-3.0.3.tgz#3dca0e3f33b200fc7d1139c0cd96c1268cadfd9d",
				Integrity:    "sha512-tHq6qdbT9U1IRSGf14CL0pUlULksvY9OZ+5eEgl1N7t+OA3tGvNpxJCzuKQlsNgCVwbAs670L1vcVQi8j9HjnA==",
				Dependencies: map[string]string{},
			},
		},
		{
			Name:      "@types/qs",
			Version:   "6.9.4",
			Locations: locations,
			PURL:      "pkg:npm/%40types/qs@6.9.4",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:     "https://registry.yarnpkg.com/@types/qs/-/qs-6.9.4.tgz#a59e851c1ba16c0513ea123830dd639a0a15cb6a",
				Integrity:    "sha512-+wYo+L6ZF6BMoEjtf8zB2esQsqdV6WsjRK/GP9WOgLPrq87PbNWgIxS76dS5uvl/QXtHGakZmwTznIfcPXcKlQ==",
				Dependencies: map[string]string{},
			},
		},
		{
			Name:      "ajv",
			Version:   "6.12.3",
			Locations: locations,
			PURL:      "pkg:npm/ajv@6.12.3",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "https://registry.yarnpkg.com/ajv/-/ajv-6.12.3.tgz#18c5af38a111ddeb4f2697bd78d68abc1cabd706",
				Integrity: "sha512-4K0cK3L1hsqk9xIb2z9vs/XU+PGJZ9PNpJRDS9YLzmNdX6jmVPfamLvTJr0aDAusnHyCHO6MjzlkAsgtqp9teA==",
				Dependencies: map[string]string{
					"fast-deep-equal":            "^3.1.1",
					"fast-json-stable-stringify": "^2.0.0",
					"json-schema-traverse":       "^0.4.1",
					"uri-js":                     "^4.2.2",
				},
			},
		},
		{
			Name:      "asn1.js",
			Version:   "4.10.1",
			Locations: locations,
			PURL:      "pkg:npm/asn1.js@4.10.1",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "https://registry.yarnpkg.com/asn1.js/-/asn1.js-4.10.1.tgz#b9c2bf5805f1e64aadeed6df3a2bfafb5a73f5a0",
				Integrity: "sha512-p32cOF5q0Zqs9uBiONKYLm6BClCoBCM5O9JfeUSlnQLBTxYdTK+pW+nXflm8UkKd2UYlEbYz5qEi0JuZR9ckSw==",
				Dependencies: map[string]string{
					"bn.js":               "^4.0.0",
					"inherits":            "^2.0.1",
					"minimalistic-assert": "^1.0.0",
				},
			},
		},
		{
			Name:      "atob",
			Version:   "2.1.2",
			Locations: locations,

			PURL:     "pkg:npm/atob@2.1.2",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:     "https://registry.yarnpkg.com/atob/-/atob-2.1.2.tgz#6d9517eb9e030d2436666651e86bd9f6f13533c9",
				Integrity:    "sha512-Wm6ukoaOGJi/73p/cl2GvLjTI5JM1k/O14isD73YML8StrH/7/lRFgmg8nICZgD3bZZvjwCGxtMOD3wWNAu8cg==",
				Dependencies: map[string]string{},
			},
		},
		{
			Name:      "aws-sdk",
			Version:   "2.706.0",
			Locations: locations,
			PURL:      "pkg:npm/aws-sdk@2.706.0",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "https://registry.yarnpkg.com/aws-sdk/-/aws-sdk-2.706.0.tgz#09f65e9a91ecac5a635daf934082abae30eca953",
				Integrity: "sha512-7GT+yrB5Wb/zOReRdv/Pzkb2Qt+hz6B/8FGMVaoysX3NryHvQUdz7EQWi5yhg9CxOjKxdw5lFwYSs69YlSp1KA==",
				Dependencies: map[string]string{
					"buffer":      "4.9.2",
					"events":      "1.1.1",
					"ieee754":     "1.1.13",
					"jmespath":    "0.15.0",
					"querystring": "0.2.0",
					"sax":         "1.2.1",
					"url":         "0.10.3",
					"uuid":        "3.3.2",
					"xml2js":      "0.4.19",
				},
			},
		},
		{
			Name:      "jhipster-core",
			Version:   "7.3.4",
			Locations: locations,
			PURL:      "pkg:npm/jhipster-core@7.3.4",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "https://registry.yarnpkg.com/jhipster-core/-/jhipster-core-7.3.4.tgz#c34b8c97c7f4e8b7518dae015517e2112c73cc80",
				Integrity: "sha512-AUhT69kNkqppaJZVfan/xnKG4Gs9Ggj7YLtTZFVe+xg+THrbMb5Ng7PL07PDlDw4KAEA33GMCwuAf65E8EpC4g==",
				Dependencies: map[string]string{
					"chevrotain": "7.0.1",
					"fs-extra":   "8.1.0",
					"lodash":     "4.17.15",
					"winston":    "3.2.1",
				},
			},
		},
		{
			Name:      "something-i-made-up",
			Version:   "7.7.7",
			Locations: locations,
			PURL:      "pkg:npm/something-i-made-up@7.7.7",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:     "https://registry.yarnpkg.com/something-i-made-up/-/c0n-fab_u.laTION-7.7.7.tgz#b9c2bf5805f1e64aadeed6df3a2bfafb5a73f5a0",
				Integrity:    "sha512-p32cOF5q0Zqs9uBiONKYLm6BClCoBCM5O9JfeUSlnQLBTxYdTK+pW+nXflm8UkKd2UYlEbYz5qEi0JuZR9ckSw==",
				Dependencies: map[string]string{},
			},
		},
	}

	adapter := newGenericYarnLockAdapter(CatalogerConfig{})
	pkgtest.TestFileParser(t, fixture, adapter.parseYarnLock, expectedPkgs, expectedRelationships)
}

func TestParseYarnLockWithRelationships(t *testing.T) {
	fixture := "test-fixtures/yarn-v1-deps/yarn.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkgs := []pkg.Package{
		{
			Name:      "@babel/code-frame",
			Version:   "7.10.4",
			Locations: locations,
			PURL:      "pkg:npm/%40babel/code-frame@7.10.4",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.10.4.tgz#168da1a36e90da68ae8d49c0f1b48c7c6249213a",
				Integrity: "sha512-vG6SvB6oYEhvgisZNFRmRCUkLz11c7rp+tbNTynGqc6mS1d5ATd/sGyV6W0KZZnXRKMTzZDRgQT3Ou9jhpAfUg==",
				Dependencies: map[string]string{
					"@babel/highlight": "^7.10.4",
				},
			},
		},
		{
			Name:      "@types/minimatch",
			Version:   "3.0.3",
			Locations: locations,
			PURL:      "pkg:npm/%40types/minimatch@3.0.3",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:     "https://registry.yarnpkg.com/@types/minimatch/-/minimatch-3.0.3.tgz#3dca0e3f33b200fc7d1139c0cd96c1268cadfd9d",
				Integrity:    "sha512-tHq6qdbT9U1IRSGf14CL0pUlULksvY9OZ+5eEgl1N7t+OA3tGvNpxJCzuKQlsNgCVwbAs670L1vcVQi8j9HjnA==",
				Dependencies: map[string]string{},
			},
		},
		{
			Name:      "@types/qs",
			Version:   "6.9.4",
			Locations: locations,
			PURL:      "pkg:npm/%40types/qs@6.9.4",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:     "https://registry.yarnpkg.com/@types/qs/-/qs-6.9.4.tgz#a59e851c1ba16c0513ea123830dd639a0a15cb6a",
				Integrity:    "sha512-+wYo+L6ZF6BMoEjtf8zB2esQsqdV6WsjRK/GP9WOgLPrq87PbNWgIxS76dS5uvl/QXtHGakZmwTznIfcPXcKlQ==",
				Dependencies: map[string]string{},
			},
		},
		{
			Name:      "ajv",
			Version:   "6.12.3",
			Locations: locations,
			PURL:      "pkg:npm/ajv@6.12.3",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "https://registry.yarnpkg.com/ajv/-/ajv-6.12.3.tgz#18c5af38a111ddeb4f2697bd78d68abc1cabd706",
				Integrity: "sha512-4K0cK3L1hsqk9xIb2z9vs/XU+PGJZ9PNpJRDS9YLzmNdX6jmVPfamLvTJr0aDAusnHyCHO6MjzlkAsgtqp9teA==",
				Dependencies: map[string]string{
					"fast-deep-equal":            "^3.1.1",
					"fast-json-stable-stringify": "^2.0.0",
					"json-schema-traverse":       "^0.4.1",
					"uri-js":                     "^4.2.2",
				},
			},
		},
		{
			Name:      "asn1.js",
			Version:   "4.10.1",
			Locations: locations,
			PURL:      "pkg:npm/asn1.js@4.10.1",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "https://registry.yarnpkg.com/asn1.js/-/asn1.js-4.10.1.tgz#b9c2bf5805f1e64aadeed6df3a2bfafb5a73f5a0",
				Integrity: "sha512-p32cOF5q0Zqs9uBiONKYLm6BClCoBCM5O9JfeUSlnQLBTxYdTK+pW+nXflm8UkKd2UYlEbYz5qEi0JuZR9ckSw==",
				Dependencies: map[string]string{
					"atob":                "^2.1.2",
					"bn.js":               "^4.0.0",
					"inherits":            "^2.0.1",
					"minimalistic-assert": "^1.0.0",
				},
			},
		},
		{
			Name:      "atob",
			Version:   "2.1.2",
			Locations: locations,

			PURL:     "pkg:npm/atob@2.1.2",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:     "https://registry.yarnpkg.com/atob/-/atob-2.1.2.tgz#6d9517eb9e030d2436666651e86bd9f6f13533c9",
				Integrity:    "sha512-Wm6ukoaOGJi/73p/cl2GvLjTI5JM1k/O14isD73YML8StrH/7/lRFgmg8nICZgD3bZZvjwCGxtMOD3wWNAu8cg==",
				Dependencies: map[string]string{},
			},
		},
		{
			Name:      "aws-sdk",
			Version:   "2.706.0",
			Locations: locations,
			PURL:      "pkg:npm/aws-sdk@2.706.0",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "https://registry.yarnpkg.com/aws-sdk/-/aws-sdk-2.706.0.tgz#09f65e9a91ecac5a635daf934082abae30eca953",
				Integrity: "sha512-7GT+yrB5Wb/zOReRdv/Pzkb2Qt+hz6B/8FGMVaoysX3NryHvQUdz7EQWi5yhg9CxOjKxdw5lFwYSs69YlSp1KA==",
				Dependencies: map[string]string{
					"asn1.js":     "4.10.1",
					"buffer":      "4.9.2",
					"events":      "1.1.1",
					"ieee754":     "1.1.13",
					"jmespath":    "0.15.0",
					"querystring": "0.2.0",
					"sax":         "1.2.1",
					"url":         "0.10.3",
					"uuid":        "3.3.2",
					"xml2js":      "0.4.19",
				},
			},
		},
		{
			Name:      "jhipster-core",
			Version:   "7.3.4",
			Locations: locations,
			PURL:      "pkg:npm/jhipster-core@7.3.4",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:  "https://registry.yarnpkg.com/jhipster-core/-/jhipster-core-7.3.4.tgz#c34b8c97c7f4e8b7518dae015517e2112c73cc80",
				Integrity: "sha512-AUhT69kNkqppaJZVfan/xnKG4Gs9Ggj7YLtTZFVe+xg+THrbMb5Ng7PL07PDlDw4KAEA33GMCwuAf65E8EpC4g==",
				Dependencies: map[string]string{
					"chevrotain": "7.0.1",
					"fs-extra":   "8.1.0",
					"lodash":     "4.17.15",
					"winston":    "3.2.1",
				},
			},
		},
		{
			Name:      "something-i-made-up",
			Version:   "7.7.7",
			Locations: locations,
			PURL:      "pkg:npm/something-i-made-up@7.7.7",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:     "https://registry.yarnpkg.com/something-i-made-up/-/c0n-fab_u.laTION-7.7.7.tgz#b9c2bf5805f1e64aadeed6df3a2bfafb5a73f5a0",
				Integrity:    "sha512-p32cOF5q0Zqs9uBiONKYLm6BClCoBCM5O9JfeUSlnQLBTxYdTK+pW+nXflm8UkKd2UYlEbYz5qEi0JuZR9ckSw==",
				Dependencies: map[string]string{},
			},
		},
	}

	expectedRelationships := []artifact.Relationship{
		{
			From: expectedPkgs[4],
			To:   expectedPkgs[6],
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: expectedPkgs[5],
			To:   expectedPkgs[4],
			Type: artifact.DependencyOfRelationship,
		},
	}
	adapter := newGenericYarnLockAdapter(CatalogerConfig{})
	pkgtest.TestFileParser(t, fixture, adapter.parseYarnLock, expectedPkgs, expectedRelationships)
}
func TestParseYarnLockWithDuplicates(t *testing.T) {
	var expectedRelationships []artifact.Relationship
	fixture := "test-fixtures/yarn-dups/yarn.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkgs := []pkg.Package{
		{
			Name:      "async",
			Version:   "0.9.2",
			Locations: locations,
			PURL:      "pkg:npm/async@0.9.2",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:     "https://registry.yarnpkg.com/async/-/async-0.9.2.tgz#aea74d5e61c1f899613bf64bda66d4c78f2fd17d",
				Integrity:    "sha1-rqdNXmHB+JlhO/ZL2mbUx48v0X0=",
				Dependencies: map[string]string{},
			},
		},
		{
			Name:      "async",
			Version:   "3.2.3",
			Locations: locations,
			PURL:      "pkg:npm/async@3.2.3",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:     "https://registry.yarnpkg.com/async/-/async-3.2.3.tgz#ac53dafd3f4720ee9e8a160628f18ea91df196c9",
				Integrity:    "sha512-spZRyzKL5l5BZQrr/6m/SqFdBN0q3OCI0f9rjfBzCMBIP4p75P620rR3gTmaksNOhmzgdxcaxdNfMy6anrbM0g==",
				Dependencies: map[string]string{},
			},
		},
		{
			Name:      "merge-objects",
			Version:   "1.0.5",
			Locations: locations,
			PURL:      "pkg:npm/merge-objects@1.0.5",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:     "https://registry.yarnpkg.com/merge-objects/-/merge-objects-1.0.5.tgz#ad923ff3910091acc1438f53eb75b8f37d862a86",
				Integrity:    "sha1-rZI/85EAkazBQ49T63W4832GKoY=",
				Dependencies: map[string]string{},
			},
		},
		{
			Name:      "@4lolo/resize-observer-polyfill",
			Version:   "1.5.2",
			Locations: locations,
			PURL:      "pkg:npm/%404lolo/resize-observer-polyfill@1.5.2",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:     "https://registry.yarnpkg.com/@4lolo/resize-observer-polyfill/-/resize-observer-polyfill-1.5.2.tgz#58868fc7224506236b5550d0c68357f0a874b84b",
				Integrity:    "sha512-HY4JYLITsWBOdeqCF/x3q7Aa2PVl/BmfkPv4H/Qzplc4Lrn9cKmWz6jHyAREH9tFuD0xELjJVgX3JaEmdcXu3g==",
				Dependencies: map[string]string{},
			},
		},
		{
			Name:      "should-type",
			Version:   "1.3.0",
			Locations: locations,
			PURL:      "pkg:npm/should-type@1.3.0",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.YarnLockEntry{
				Resolved:     "https://github.com/shouldjs/type.git#31d26945cb3b4ad21d2308776e4442c461666390",
				Integrity:    "",
				Dependencies: map[string]string{},
			},
		},
	}

	adapter := newGenericYarnLockAdapter(CatalogerConfig{})
	pkgtest.TestFileParser(t, fixture, adapter.parseYarnLock, expectedPkgs, expectedRelationships)
}

type handlerPath struct {
	path    string
	handler func(w http.ResponseWriter, r *http.Request)
}

func TestSearchYarnForLicenses(t *testing.T) {
	ctx := context.TODO()
	fixture := "test-fixtures/yarn-remote/yarn.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	mux, url, teardown := setupYarnRegistry()
	defer teardown()
	tests := []struct {
		name             string
		fixture          string
		config           CatalogerConfig
		requestHandlers  []handlerPath
		expectedPackages []pkg.Package
	}{
		{
			name:   "search remote licenses returns the expected licenses when search is set to true",
			config: CatalogerConfig{SearchRemoteLicenses: true},
			requestHandlers: []handlerPath{
				{
					// https://registry.yarnpkg.com/@babel/code-frame/7.10.4
					path:    "/@babel/code-frame/7.10.4",
					handler: generateMockYarnRegistryHandler("test-fixtures/yarn-remote/registry_response.json"),
				},
			},
			expectedPackages: []pkg.Package{
				{
					Name:      "@babel/code-frame",
					Version:   "7.10.4",
					Locations: locations,
					PURL:      "pkg:npm/%40babel/code-frame@7.10.4",
					Licenses:  pkg.NewLicenseSet(pkg.NewLicenseWithContext(ctx, "MIT")),
					Language:  pkg.JavaScript,
					Type:      pkg.NpmPkg,
					Metadata: pkg.YarnLockEntry{
						Resolved:  "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.10.4.tgz#168da1a36e90da68ae8d49c0f1b48c7c6249213a",
						Integrity: "sha512-vG6SvB6oYEhvgisZNFRmRCUkLz11c7rp+tbNTynGqc6mS1d5ATd/sGyV6W0KZZnXRKMTzZDRgQT3Ou9jhpAfUg==",
						Dependencies: map[string]string{
							"@babel/highlight": "^7.10.4",
						},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// set up the mock server
			for _, handler := range tc.requestHandlers {
				mux.HandleFunc(handler.path, handler.handler)
			}
			tc.config.NPMBaseURL = url
			adapter := newGenericYarnLockAdapter(tc.config)
			pkgtest.NewCatalogTester().
				FromFile(t, fixture).
				Expects(tc.expectedPackages, nil).
				WithoutTestObserver(). // this is an online test, thus not the default configuration
				TestParser(t, adapter.parseYarnLock)
		})
	}
}

func TestParseYarnFindPackageNames(t *testing.T) {
	tests := []struct {
		line     string
		expected string
	}{
		{
			line:     `"@babel/code-frame@npm:7.10.4":`,
			expected: "@babel/code-frame",
		},
		{
			line:     `"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":`,
			expected: "@babel/code-frame",
		},
		{
			line:     "ajv@^6.10.2, ajv@^6.5.5:",
			expected: "ajv",
		},
		{
			line:     "aws-sdk@2.706.0:",
			expected: "aws-sdk",
		},
		{
			line:     "asn1.js@^4.0.0:",
			expected: "asn1.js",
		},
		{
			line:     "c0n-fab_u.laTION@^7.0.0",
			expected: "c0n-fab_u.laTION",
		},
		{
			line:     `"newtest@workspace:.":`,
			expected: "newtest",
		},
		{
			line:     `"color-convert@npm:^1.9.0":`,
			expected: "color-convert",
		},
		{
			line:     `"@npmcorp/code-frame@^7.1.0", "@npmcorp/code-frame@^7.10.4":`,
			expected: "@npmcorp/code-frame",
		},
		{
			line:     `"@npmcorp/code-frame@^7.2.3":`,
			expected: "@npmcorp/code-frame",
		},
		{
			line:     `"@s/odd-name@^7.1.2":`,
			expected: "@s/odd-name",
		},
		{
			line:     `"@/code-frame@^7.3.4":`,
			expected: "",
		},
		{
			line:     `"code-frame":`,
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			t.Parallel()
			actual := findPackageName(test.line)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func generateMockYarnRegistryHandler(responseFixture string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Copy the file's content to the response writer
		file, err := os.Open(responseFixture)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = io.Copy(w, file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

// setup sets up a test HTTP server for mocking requests to a particular registry.
// The returned url is injected into the Config so the client uses the test server.
// Tests should register handlers on mux to simulate the expected request/response structure
func setupYarnRegistry() (mux *http.ServeMux, serverURL string, teardown func()) {
	// mux is the HTTP request multiplexer used with the test server.
	mux = http.NewServeMux()

	// We want to ensure that tests catch mistakes where the endpoint URL is
	// specified as absolute rather than relative. It only makes a difference
	// when there's a non-empty base URL path. So, use that. See issue #752.
	apiHandler := http.NewServeMux()
	apiHandler.Handle("/", mux)
	// server is a test HTTP server used to provide mock API responses.
	server := httptest.NewServer(apiHandler)

	return mux, server.URL, server.Close
}
