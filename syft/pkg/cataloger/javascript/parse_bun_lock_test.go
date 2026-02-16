package javascript

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseBunLock(t *testing.T) {
	fixture := "test-fixtures/bun/bun.lock"

	locationSet := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkgs := []pkg.Package{
		{
			Name:      "@img/sharp-darwin-arm64",
			Version:   "0.33.5",
			PURL:      "pkg:npm/%40img/sharp-darwin-arm64@0.33.5",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Identifier: "@img/sharp-darwin-arm64@0.33.5",
				Integrity:  "sha512-UT4p+iz/2H4twwAoLCqfA9UH5pI6DggwKEGuaPy7nCVQ8ZsiY5PIcrRvD1DzuY3qYL07NtIQcWnBSY/heikIFQ==",
				Dependencies: map[string]pkg.BunLockPackageDependencies{
					"@img/sharp-darwin-arm64": {
						OS:  "darwin",
						CPU: "arm64",
					},
				},
			},
		},
		{
			Name:      "@img/sharp-linux-x64",
			Version:   "0.33.5",
			PURL:      "pkg:npm/%40img/sharp-linux-x64@0.33.5",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Identifier: "@img/sharp-linux-x64@0.33.5",
				Integrity:  "sha512-MmWmQ3iPFZr0Iev+BAgVMb3ZyC4KeFc3jFxnNbEPas60e1cIfevbtuyf9nDGIzOaW9PdnDciJm+wFFaTlj5xYw==",
				Dependencies: map[string]pkg.BunLockPackageDependencies{
					"@img/sharp-linux-x64": {
						OS:  "linux",
						CPU: "x64",
					},
				},
			},
		},
		{
			Name:      "axios",
			Version:   "1.6.0",
			PURL:      "pkg:npm/axios@1.6.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Identifier: "axios@1.6.0",
				Integrity:  "sha512-EZ1DYihju9pwVB+jg67ogm+Tmqc6JmhamRN6I4Zt8DfZu5lbcQGw3ozH9lFejSJgs/ibaef3A9PMXPLeefFGJg==",
				Dependencies: map[string]pkg.BunLockPackageDependencies{
					"axios": {
						Dependencies: map[string]string{
							"follow-redirects": "^1.15.0",
						},
					},
				},
			},
		},
		{
			Name:      "color",
			Version:   "4.2.3",
			PURL:      "pkg:npm/color@4.2.3",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Identifier:   "color@4.2.3",
				Integrity:    "sha512-1rXeuUUiGGrykh+CeBdu5Ie7OJwinCgQY0bc7GCRxy5xVHy+moaqkpL/jqQq0MtQOeYcrqEz4abc5f0KtU7W4A==",
				Dependencies: map[string]pkg.BunLockPackageDependencies{},
			},
		},
		{
			Name:      "eslint",
			Version:   "9.0.0",
			PURL:      "pkg:npm/eslint@9.0.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Identifier: "eslint@9.0.0",
				Integrity:  "sha512-IMryZ5SudxzQvuod6rUdxH8KRx8BKHkTXpHWe3BJ9Qef3PbG9v9vjSB0STcKOVjTvPnG1+9T5e4xfzZ4wKdqiA==",
				Dependencies: map[string]pkg.BunLockPackageDependencies{
					"eslint": {
						Dependencies: map[string]string{
							"eslint-visitor-keys": "^4.0.0",
						},
						Bin: map[string]string{
							"eslint": "bin/eslint.js",
						},
					},
				},
			},
		},
		{
			Name:      "eslint-visitor-keys",
			Version:   "4.0.0",
			PURL:      "pkg:npm/eslint-visitor-keys@4.0.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Identifier:   "eslint-visitor-keys@4.0.0",
				Integrity:    "sha512-OtIRv/2GyiF6o/d8K7MYKKbXrOUBIK6SfkIRM4Z0dY3w+LiQ0vy3F57m0Z71bjbyeiWFiHJ8brqnmE6H6/jEuw==",
				Dependencies: map[string]pkg.BunLockPackageDependencies{},
			},
		},
		{
			Name:      "follow-redirects",
			Version:   "1.15.3",
			PURL:      "pkg:npm/follow-redirects@1.15.3",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Identifier: "follow-redirects@1.15.3",
				Integrity:  "sha512-1VzOtuEM8pC9SFU1E+8KfTjZyMztRsgEfwQl44z8A25uy13jSzTj6dyK2Df52iV0vgHCfBwLhDWevLn95w5v6Q==",
				Dependencies: map[string]pkg.BunLockPackageDependencies{
					"follow-redirects": {
						PeerDependencies: map[string]string{
							"debug": "*",
						},
					},
				},
			},
		},
		{
			Name:      "lodash",
			Version:   "4.17.21",
			PURL:      "pkg:npm/lodash@4.17.21",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Identifier:   "lodash@4.17.21",
				Integrity:    "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==",
				Dependencies: map[string]pkg.BunLockPackageDependencies{},
			},
		},
		{
			Name:      "sharp",
			Version:   "0.33.5",
			PURL:      "pkg:npm/sharp@0.33.5",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Identifier: "sharp@0.33.5",
				Integrity:  "sha512-haPVm1EkS9pgvHrQ/F3Xy+hgxt/HmijnBghFeqCkXp3e+MH2fYF5o6qzrNJJ2k9s4bsZX0QBUCbFjr8VdLAIww==",
				Dependencies: map[string]pkg.BunLockPackageDependencies{
					"sharp": {
						Dependencies: map[string]string{
							"color": "^4.2.3",
						},
						OptionalDependencies: map[string]string{
							"@img/sharp-darwin-arm64": "0.33.5",
							"@img/sharp-linux-x64":    "0.33.5",
						},
					},
				},
			},
		},
		{
			Name:      "typescript",
			Version:   "5.0.0",
			PURL:      "pkg:npm/typescript@5.0.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Identifier: "typescript@5.0.0",
				Integrity:  "sha512-w5c493tkwFQLjKSYw0JvvVbqJ9ZM2SXoWBv/wqHYqWN/jP9bGilMKFbAKkpRHfaLxPn6A3K/fmJ6LD8B0EO9oA==",
				Dependencies: map[string]pkg.BunLockPackageDependencies{
					"typescript": {
						Bin: map[string]string{
							"tsc":      "bin/tsc",
							"tsserver": "bin/tsserver",
						},
					},
				},
			},
		},
	}

	// Relationships are automatically generated by dependency.Resolve
	// We explicitly define expected relationships for packages with dependencies
	expectedRelationships := []artifact.Relationship{
		// sharp depends on color
		{
			From: expectedPkgs[3], // color
			To:   expectedPkgs[8], // sharp
			Type: artifact.DependencyOfRelationship,
		},
		// sharp optionally depends on @img/sharp-darwin-arm64
		{
			From: expectedPkgs[0], // @img/sharp-darwin-arm64
			To:   expectedPkgs[8], // sharp
			Type: artifact.DependencyOfRelationship,
		},
		// sharp optionally depends on @img/sharp-linux-x64
		{
			From: expectedPkgs[1], // @img/sharp-linux-x64
			To:   expectedPkgs[8], // sharp
			Type: artifact.DependencyOfRelationship,
		},
		// axios depends on follow-redirects
		{
			From: expectedPkgs[6], // follow-redirects
			To:   expectedPkgs[2], // axios
			Type: artifact.DependencyOfRelationship,
		},
		// eslint depends on eslint-visitor-keys
		{
			From: expectedPkgs[5], // eslint-visitor-keys
			To:   expectedPkgs[4], // eslint
			Type: artifact.DependencyOfRelationship,
		},
	}

	adapter := newGenericBunLockAdapter(CatalogerConfig{IncludeDevDependencies: true})
	pkgtest.TestFileParser(t, fixture, adapter.parseBunLock, expectedPkgs, expectedRelationships)
}

func TestParseBunLock_ExcludeDevDependencies(t *testing.T) {
	fixture := "test-fixtures/bun/bun.lock"

	locationSet := file.NewLocationSet(file.NewLocation(fixture))

	expectedPkgs := []pkg.Package{
		{
			Name:      "@img/sharp-darwin-arm64",
			Version:   "0.33.5",
			PURL:      "pkg:npm/%40img/sharp-darwin-arm64@0.33.5",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Identifier: "@img/sharp-darwin-arm64@0.33.5",
				Integrity:  "sha512-UT4p+iz/2H4twwAoLCqfA9UH5pI6DggwKEGuaPy7nCVQ8ZsiY5PIcrRvD1DzuY3qYL07NtIQcWnBSY/heikIFQ==",
				Dependencies: map[string]pkg.BunLockPackageDependencies{
					"@img/sharp-darwin-arm64": {
						OS:  "darwin",
						CPU: "arm64",
					},
				},
			},
		},
		{
			Name:      "@img/sharp-linux-x64",
			Version:   "0.33.5",
			PURL:      "pkg:npm/%40img/sharp-linux-x64@0.33.5",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Identifier: "@img/sharp-linux-x64@0.33.5",
				Integrity:  "sha512-MmWmQ3iPFZr0Iev+BAgVMb3ZyC4KeFc3jFxnNbEPas60e1cIfevbtuyf9nDGIzOaW9PdnDciJm+wFFaTlj5xYw==",
				Dependencies: map[string]pkg.BunLockPackageDependencies{
					"@img/sharp-linux-x64": {
						OS:  "linux",
						CPU: "x64",
					},
				},
			},
		},
		{
			Name:      "axios",
			Version:   "1.6.0",
			PURL:      "pkg:npm/axios@1.6.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Identifier: "axios@1.6.0",
				Integrity:  "sha512-EZ1DYihju9pwVB+jg67ogm+Tmqc6JmhamRN6I4Zt8DfZu5lbcQGw3ozH9lFejSJgs/ibaef3A9PMXPLeefFGJg==",
				Dependencies: map[string]pkg.BunLockPackageDependencies{
					"axios": {
						Dependencies: map[string]string{
							"follow-redirects": "^1.15.0",
						},
					},
				},
			},
		},
		{
			Name:      "color",
			Version:   "4.2.3",
			PURL:      "pkg:npm/color@4.2.3",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Identifier:   "color@4.2.3",
				Integrity:    "sha512-1rXeuUUiGGrykh+CeBdu5Ie7OJwinCgQY0bc7GCRxy5xVHy+moaqkpL/jqQq0MtQOeYcrqEz4abc5f0KtU7W4A==",
				Dependencies: map[string]pkg.BunLockPackageDependencies{},
			},
		},
		{
			Name:      "follow-redirects",
			Version:   "1.15.3",
			PURL:      "pkg:npm/follow-redirects@1.15.3",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Identifier: "follow-redirects@1.15.3",
				Integrity:  "sha512-1VzOtuEM8pC9SFU1E+8KfTjZyMztRsgEfwQl44z8A25uy13jSzTj6dyK2Df52iV0vgHCfBwLhDWevLn95w5v6Q==",
				Dependencies: map[string]pkg.BunLockPackageDependencies{
					"follow-redirects": {
						PeerDependencies: map[string]string{
							"debug": "*",
						},
					},
				},
			},
		},
		{
			Name:      "lodash",
			Version:   "4.17.21",
			PURL:      "pkg:npm/lodash@4.17.21",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Identifier:   "lodash@4.17.21",
				Integrity:    "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==",
				Dependencies: map[string]pkg.BunLockPackageDependencies{},
			},
		},
		{
			Name:      "sharp",
			Version:   "0.33.5",
			PURL:      "pkg:npm/sharp@0.33.5",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Identifier: "sharp@0.33.5",
				Integrity:  "sha512-haPVm1EkS9pgvHrQ/F3Xy+hgxt/HmijnBghFeqCkXp3e+MH2fYF5o6qzrNJJ2k9s4bsZX0QBUCbFjr8VdLAIww==",
				Dependencies: map[string]pkg.BunLockPackageDependencies{
					"sharp": {
						Dependencies: map[string]string{
							"color": "^4.2.3",
						},
						OptionalDependencies: map[string]string{
							"@img/sharp-darwin-arm64": "0.33.5",
							"@img/sharp-linux-x64":    "0.33.5",
						},
					},
				},
			},
		},
	}

	// When excluding dev dependencies, we don't have eslint and typescript,
	// so we only have relationships for axios and sharp
	expectedRelationships := []artifact.Relationship{
		// sharp depends on color
		{
			From: expectedPkgs[3], // color
			To:   expectedPkgs[6], // sharp (index 6, not 7)
			Type: artifact.DependencyOfRelationship,
		},
		// sharp optionally depends on @img/sharp-darwin-arm64
		{
			From: expectedPkgs[0], // @img/sharp-darwin-arm64
			To:   expectedPkgs[6], // sharp
			Type: artifact.DependencyOfRelationship,
		},
		// sharp optionally depends on @img/sharp-linux-x64
		{
			From: expectedPkgs[1], // @img/sharp-linux-x64
			To:   expectedPkgs[6], // sharp
			Type: artifact.DependencyOfRelationship,
		},
		// axios depends on follow-redirects
		{
			From: expectedPkgs[4], // follow-redirects
			To:   expectedPkgs[2], // axios
			Type: artifact.DependencyOfRelationship,
		},
	}

	adapter := newGenericBunLockAdapter(CatalogerConfig{IncludeDevDependencies: false})
	pkgtest.TestFileParser(t, fixture, adapter.parseBunLock, expectedPkgs, expectedRelationships)
}

func TestParseBunPackageIdentifier(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		wantName   string
		wantVer    string
		wantOK     bool
	}{
		{
			name:       "simple package",
			identifier: "lodash@4.17.21",
			wantName:   "lodash",
			wantVer:    "4.17.21",
			wantOK:     true,
		},
		{
			name:       "scoped package",
			identifier: "@babel/core@7.24.0",
			wantName:   "@babel/core",
			wantVer:    "7.24.0",
			wantOK:     true,
		},
		{
			name:       "no version",
			identifier: "lodash",
			wantName:   "",
			wantVer:    "",
			wantOK:     false,
		},
		{
			name:       "scoped package with multiple @",
			identifier: "@org/pkg@1.0.0",
			wantName:   "@org/pkg",
			wantVer:    "1.0.0",
			wantOK:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotVer, gotOK := parseBunPackageIdentifier(tt.identifier)
			if gotName != tt.wantName || gotVer != tt.wantVer || gotOK != tt.wantOK {
				t.Errorf("parseBunPackageIdentifier(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tt.identifier, gotName, gotVer, gotOK, tt.wantName, tt.wantVer, tt.wantOK)
			}
		})
	}
}
