package php

import (
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"testing"

	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_ComposerInstalledCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain composer files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"src/installed.json",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewComposerInstalledCataloger())
		})
	}
}

func Test_ComposerLockCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain composer lock files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"src/composer.lock",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewComposerLockCataloger())
		})
	}
}

func Test_PearCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain pear files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"php/.registry/.channel.pecl.php.net/memcached.reg",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewPearCataloger())
		})
	}
}

func Test_PeclCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain pear files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"php/.registry/.channel.pecl.php.net/memcached.reg",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewPeclCataloger())
		})
	}
}

func Test_ExtensionCataloger(t *testing.T) {
	// TODO: should have a relationship from the installed php package to the extension package
	tests := []struct {
		name     string
		expected []pkg.Package
	}{
		{
			name: "image-extensions",
			expected: []pkg.Package{
				{
					Name:      "bcmath",
					Version:   "8.3.21",
					Type:      pkg.BinaryPkg,
					FoundBy:   "php-extension-cataloger",
					Locations: file.NewLocationSet(file.NewLocation("/usr/local/lib/php/extensions/no-debug-non-zts-20230831/bcmath.so")),
					CPEs: []cpe.CPE{
						cpe.Must("cpe:2.3:a:php-bcmath:php-bcmath:8.3.21:*:*:*:*:*:*:*", cpe.GeneratedSource),
					},
					PURL: "pkg:generic/bcmath@8.3.21",
					Metadata: pkg.BinarySignature{
						Matches: []pkg.ClassifierMatch{
							{
								Classifier: "php-ext-bcmath-binary",
								Location:   file.NewLocation("/usr/local/lib/php/extensions/no-debug-non-zts-20230831/bcmath.so"),
							},
						},
					},
				},
				// TODO: fill in the rest...
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewExtensionCataloger()
			pkgtest.NewCatalogTester().
				WithImageResolver(t, tt.name).
				IgnoreLocationLayer(). // this fixture can be rebuilt, thus the layer ID will change
				Expects(tt.expected, nil).
				TestCataloger(t, c)
		})
	}
}
