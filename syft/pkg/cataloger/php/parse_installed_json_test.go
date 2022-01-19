package php

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
)

var expectedInstalledJsonPackages = []*pkg.Package{
	{
		Name:         "asm89/stack-cors",
		Version:      "1.3.0",
		Language:     pkg.PHP,
		Type:         pkg.PhpComposerPkg,
		MetadataType: pkg.PhpComposerJSONMetadataType,
		Metadata: pkg.PhpComposerJSONMetadata{
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
			License: []string{
				"MIT",
			},
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
		Name:         "behat/mink",
		Version:      "v1.8.1",
		Language:     pkg.PHP,
		Type:         pkg.PhpComposerPkg,
		MetadataType: pkg.PhpComposerJSONMetadataType,
		Metadata: pkg.PhpComposerJSONMetadata{
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
			License: []string{
				"MIT",
			},
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

func TestParseInstalledJsonComposerV1(t *testing.T) {

	fixture, err := os.Open("test-fixtures/vendor/composer_1/installed.json")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parseInstalledJSON(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse requirements: %+v", err)
	}
	differences := deep.Equal(expectedInstalledJsonPackages, actual)
	if differences != nil {
		t.Errorf("returned package list differed from expectation: %+v", differences)
	}
}

func TestParseInstalledJsonComposerV2(t *testing.T) {
	fixture, err := os.Open("test-fixtures/vendor/composer_2/installed.json")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parseInstalledJSON(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse requirements: %+v", err)
	}
	differences := deep.Equal(expectedInstalledJsonPackages, actual)
	if differences != nil {
		t.Errorf("returned package list differed from expectation: %+v", differences)
	}

}
