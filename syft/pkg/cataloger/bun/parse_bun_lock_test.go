package bun

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseBunLock(t *testing.T) {
	fixture := "test-fixtures/bun-lock/bun.lock"
	locationSet := file.NewLocationSet(file.NewLocation(fixture).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))

	expectedPkgs := []pkg.Package{
		{
			Name:      "lodash",
			Version:   "4.17.21",
			Locations: locationSet,
			PURL:      "pkg:npm/lodash@4.17.21",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Resolved:     "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
				Integrity:    "sha512-v2kDEBM37XMS/prhe0cSBXEHB3cPH5Ni+2hRMKA3lAh1j9l3Y1KMFt0ILd0FYfHYLMaHwZCcNZfT2J0lYLHUDHg==",
				Dependencies: map[string]string{},
			},
		},
		{
			Name:      "express",
			Version:   "4.18.2",
			Locations: locationSet,
			PURL:      "pkg:npm/express@4.18.2",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Resolved:  "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
				Integrity: "sha512-VkTrpA8RXuVBpuMdKZf1u8akqU9VqFvP+D2E3N0JVH5HfK4S0mIq7VgZPnxVL7I4MZJTnxJQZ2XlPvjF8ZyuDg==",
				Dependencies: map[string]string{
					"accepts":       "~1.3.8",
					"array-flatten": "1.1.1",
					"body-parser":   "1.20.1",
				},
			},
		},
		{
			Name:      "typescript",
			Version:   "5.3.3",
			Locations: locationSet,
			PURL:      "pkg:npm/typescript@5.3.3",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Resolved:     "https://registry.npmjs.org/typescript/-/typescript-5.3.3.tgz",
				Integrity:    "sha512-pXWcraxM0uxAS+tN0AG/BF2TyqmHO014Z070UsJ+pFvYuRSq8KH8DmWpnbXe0pEPDHXZV3FcAbJkijJ5oNEnWw==",
				Dependencies: map[string]string{},
			},
		},
		{
			Name:      "accepts",
			Version:   "1.3.8",
			Locations: locationSet,
			PURL:      "pkg:npm/accepts@1.3.8",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Resolved:  "https://registry.npmjs.org/accepts/-/accepts-1.3.8.tgz",
				Integrity: "sha512-PYAthTa2m2VKxuvSD3DPC/Gy+U+sOA1LAuT8mkmRuvw+NACSaeXEQ+NHcVF7rONl6qcaxV3Uuemwawk+7+SJLw==",
				Dependencies: map[string]string{
					"mime-types": "~2.1.34",
					"negotiator": "0.6.3",
				},
			},
		},
		{
			Name:      "@types/node",
			Version:   "20.10.0",
			Locations: locationSet,
			PURL:      "pkg:npm/%40types/node@20.10.0",
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Resolved:  "https://registry.npmjs.org/@types/node/-/node-20.10.0.tgz",
				Integrity: "sha512-D0WfRmU9TQ8I9PFx9Yc+EBHw+vSpIub4IDvQivcp26PtPrdMGAq5SDcpXEo/epqa/DXotVpekHiLNTg3iaKXBQ==",
				Dependencies: map[string]string{
					"undici-types": "~5.26.4",
				},
			},
		},
	}

	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parseBunLock, expectedPkgs, expectedRelationships)
}

func TestParseBunLock_SkipsNodeModules(t *testing.T) {
	if !pathContainsNodeModulesDirectory("/some/path/node_modules/package/bun.lock") {
		t.Error("node_modules not detected")
	}

	if pathContainsNodeModulesDirectory("/some/path/project/bun.lock") {
		t.Error("false positive node_modules")
	}
}

func TestParsePackageKey(t *testing.T) {
	tests := []struct {
		key         string
		wantName    string
		wantVersion string
	}{
		{
			key:         "lodash@4.17.21",
			wantName:    "lodash",
			wantVersion: "4.17.21",
		},
		{
			key:         "@types/node@20.10.0",
			wantName:    "@types/node",
			wantVersion: "20.10.0",
		},
		{
			key:         "@scope/package@1.0.0",
			wantName:    "@scope/package",
			wantVersion: "1.0.0",
		},
		{
			key:         "simple",
			wantName:    "simple",
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			gotName, gotVersion := parsePackageKey(tt.key)
			if gotName != tt.wantName {
				t.Errorf("parsePackageKey() name = %v, want %v", gotName, tt.wantName)
			}
			if gotVersion != tt.wantVersion {
				t.Errorf("parsePackageKey() version = %v, want %v", gotVersion, tt.wantVersion)
			}
		})
	}
}

func TestIsBunLockFile(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name:     "valid bun.lock header",
			content:  "// bun.lock - Bun lockfile v1\n{",
			expected: true,
		},
		{
			name:     "valid bunlock header",
			content:  "// bunlock\n{",
			expected: true,
		},
		{
			name:     "json without header",
			content:  "{\n  \"lockfileVersion\": 1",
			expected: true,
		},
		{
			name:     "empty content",
			content:  "",
			expected: false,
		},
		{
			name:     "random text",
			content:  "not a lockfile",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBunLockFile([]byte(tt.content))
			if got != tt.expected {
				t.Errorf("isBunLockFile() = %v, want %v", got, tt.expected)
			}
		})
	}
}
