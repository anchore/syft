package php

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
)

func TestParseComposerFileLock(t *testing.T) {
	expected := []*pkg.Package{
		{
			Name:         "adoy/fastcgi-client",
			Version:      "1.0.2",
			Language:     pkg.PHP,
			Type:         pkg.PhpComposerPkg,
			MetadataType: pkg.PhpComposerJSONMetadataType,
			Metadata: pkg.PhpComposerJSONMetadata{
				Name:    "adoy/fastcgi-client",
				Version: "1.0.2",
				Source: pkg.PhpComposerExternalReference{
					Type:      "git",
					URL:       "https://github.com/adoy/PHP-FastCGI-Client.git",
					Reference: "6d9a552f0206a1db7feb442824540aa6c55e5b27",
				},
				Dist: pkg.PhpComposerExternalReference{
					Type:      "zip",
					URL:       "https://api.github.com/repos/adoy/PHP-FastCGI-Client/zipball/6d9a552f0206a1db7feb442824540aa6c55e5b27",
					Reference: "6d9a552f0206a1db7feb442824540aa6c55e5b27",
				},
				Type:            "library",
				NotificationURL: "https://packagist.org/downloads/",
				License: []string{
					"MIT",
				},
				Authors: []pkg.PhpComposerAuthors{
					{
						Name:  "Pierrick Charron",
						Email: "pierrick@adoy.net",
					},
				},
				Description: "Lightweight, single file FastCGI client for PHP.",
				Keywords: []string{
					"fastcgi",
					"fcgi",
				},
				Time: "2019-12-11T13:49:21+00:00",
			},
		},
		{
			Name:         "alcaeus/mongo-php-adapter",
			Version:      "1.1.11",
			Language:     pkg.PHP,
			Type:         pkg.PhpComposerPkg,
			MetadataType: pkg.PhpComposerJSONMetadataType,
			Metadata: pkg.PhpComposerJSONMetadata{
				Name:    "alcaeus/mongo-php-adapter",
				Version: "1.1.11",
				Source: pkg.PhpComposerExternalReference{
					Type:      "git",
					URL:       "https://github.com/alcaeus/mongo-php-adapter.git",
					Reference: "43b6add94c8b4cb9890d662cba4c0defde733dcf",
				},
				Dist: pkg.PhpComposerExternalReference{
					Type:      "zip",
					URL:       "https://api.github.com/repos/alcaeus/mongo-php-adapter/zipball/43b6add94c8b4cb9890d662cba4c0defde733dcf",
					Reference: "43b6add94c8b4cb9890d662cba4c0defde733dcf",
				},
				Require: map[string]string{
					"ext-ctype":       "*",
					"ext-hash":        "*",
					"ext-mongodb":     "^1.2.0",
					"mongodb/mongodb": "^1.0.1",
					"php":             "^5.6 || ^7.0",
				},
				Provide: map[string]string{
					"ext-mongo": "1.6.14",
				},
				RequireDev: map[string]string{
					"phpunit/phpunit":           "^5.7.27 || ^6.0 || ^7.0",
					"squizlabs/php_codesniffer": "^3.2",
				},
				Type:            "library",
				NotificationURL: "https://packagist.org/downloads/",
				License: []string{
					"MIT",
				},
				Authors: []pkg.PhpComposerAuthors{
					{
						Name:  "alcaeus",
						Email: "alcaeus@alcaeus.org",
					},
					{
						Name:  "Olivier Lechevalier",
						Email: "olivier.lechevalier@gmail.com",
					},
				},
				Description: "Adapter to provide ext-mongo interface on top of mongo-php-libary",
				Keywords: []string{
					"database",
					"mongodb",
				},
				Time: "2019-11-11T20:47:32+00:00",
			},
		},
	}
	fixture, err := os.Open("test-fixtures/composer.lock")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parseComposerLock(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse requirements: %+v", err)
	}

	for _, d := range deep.Equal(expected, actual) {
		t.Errorf("diff: %+v", d)
	}
}
