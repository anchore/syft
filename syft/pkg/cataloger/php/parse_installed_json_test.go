package php

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseInstalledJsonComposerV1(t *testing.T) {
	fixtures := []string{
		"test-fixtures/vendor/composer_1/installed.json",
		"test-fixtures/vendor/composer_2/installed.json",
	}

	var expectedRelationships []artifact.Relationship
	var expectedPkgs = []pkg.Package{
		{
			Name:     "asm89/stack-cors",
			Version:  "1.3.0",
			PURL:     "pkg:composer/asm89/stack-cors@1.3.0",
			Language: pkg.PHP,
			Type:     pkg.PhpComposerPkg,
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicense("MIT"),
			),
			Metadata: pkg.PhpComposerInstalledEntry{
				Name:    "asm89/stack-cors",
				Version: "1.3.0",
				Source: pkg.PhpComposerExternalReference{
					Type:      "git",
					URL:       "https://github.com/asm89/stack-cors.git",
					Reference: "b9c31def6a83f84b4d4a40d35996d375755f0e08",
				},
				Dist: pkg.PhpComposerExternalReference{
					Type:      "zip",
					URL:       "https://api.github.com/repos/asm89/stack-cors/zipball/b9c31def6a83f84b4d4a40d35996d375755f0e08",
					Reference: "b9c31def6a83f84b4d4a40d35996d375755f0e08",
				},
				Require: map[string]string{
					"php":                     ">=5.5.9",
					"symfony/http-foundation": "~2.7|~3.0|~4.0|~5.0",
					"symfony/http-kernel":     "~2.7|~3.0|~4.0|~5.0",
				},
				RequireDev: map[string]string{
					"phpunit/phpunit":           "^5.0 || ^4.8.10",
					"squizlabs/php_codesniffer": "^2.3",
				},
				Time:            "2019-12-24T22:41:47+00:00",
				Type:            "library",
				NotificationURL: "https://packagist.org/downloads/",
				Authors: []pkg.PhpComposerAuthors{
					{
						Name:  "Alexander",
						Email: "iam.asm89@gmail.com",
					},
				},

				Description: "Cross-origin resource sharing library and stack middleware",
				Homepage:    "https://github.com/asm89/stack-cors",
				Keywords: []string{
					"cors",
					"stack",
				},
			},
		},
		{
			Name:     "behat/mink",
			Version:  "v1.8.1",
			PURL:     "pkg:composer/behat/mink@v1.8.1",
			Language: pkg.PHP,
			Type:     pkg.PhpComposerPkg,
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicense("MIT"),
			),
			Metadata: pkg.PhpComposerInstalledEntry{
				Name:    "behat/mink",
				Version: "v1.8.1",
				Source: pkg.PhpComposerExternalReference{
					Type:      "git",
					URL:       "https://github.com/minkphp/Mink.git",
					Reference: "07c6a9fe3fa98c2de074b25d9ed26c22904e3887",
				},
				Dist: pkg.PhpComposerExternalReference{
					Type:      "zip",
					URL:       "https://api.github.com/repos/minkphp/Mink/zipball/07c6a9fe3fa98c2de074b25d9ed26c22904e3887",
					Reference: "07c6a9fe3fa98c2de074b25d9ed26c22904e3887",
				},
				Require: map[string]string{
					"php":                  ">=5.3.1",
					"symfony/css-selector": "^2.7|^3.0|^4.0|^5.0",
				},
				RequireDev: map[string]string{
					"phpunit/phpunit":        "^4.8.36 || ^5.7.27 || ^6.5.14 || ^7.5.20",
					"symfony/debug":          "^2.7|^3.0|^4.0",
					"symfony/phpunit-bridge": "^3.4.38 || ^5.0.5",
				},
				Suggest: map[string]string{
					"behat/mink-browserkit-driver": "extremely fast headless driver for Symfony\\Kernel-based apps (Sf2, Silex)",
					"behat/mink-goutte-driver":     "fast headless driver for any app without JS emulation",
					"behat/mink-selenium2-driver":  "slow, but JS-enabled driver for any app (requires Selenium2)",
					"behat/mink-zombie-driver":     "fast and JS-enabled headless driver for any app (requires node.js)",
					"dmore/chrome-mink-driver":     "fast and JS-enabled driver for any app (requires chromium or google chrome)",
				},
				Time:            "2020-03-11T15:45:53+00:00",
				Type:            "library",
				NotificationURL: "https://packagist.org/downloads/",
				Authors: []pkg.PhpComposerAuthors{
					{
						Name:     "Konstantin Kudryashov",
						Email:    "ever.zet@gmail.com",
						Homepage: "http://everzet.com",
					},
				},

				Description: "Browser controller/emulator abstraction for PHP",
				Homepage:    "http://mink.behat.org/",
				Keywords: []string{
					"browser",
					"testing",
					"web",
				},
			},
		},
	}

	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			locations := file.NewLocationSet(file.NewLocation(fixture))
			for i := range expectedPkgs {
				expectedPkgs[i].Locations = locations
				locationLicenses := pkg.NewLicenseSet()
				for _, license := range expectedPkgs[i].Licenses.ToSlice() {
					license.Locations = locations
					locationLicenses.Add(license)
				}
				expectedPkgs[i].Licenses = locationLicenses
			}
			pkgtest.TestFileParser(t, fixture, parseInstalledJSON, expectedPkgs, expectedRelationships)
		})
	}
}

func Test_corruptInstalledJSON(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/glob-paths/src/installed.json").
		WithError().
		TestParser(t, parseInstalledJSON)
}
