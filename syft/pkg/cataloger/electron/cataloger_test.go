package electron

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func TestCataloger_Name(t *testing.T) {
	c := NewCataloger()
	assert.Equal(t, catalogerName, c.Name())
}

func TestParseAsarArchive(t *testing.T) {
	asarPath := filepath.Join("test-fixtures", "app.asar")

	f, err := os.Open(asarPath)
	require.NoError(t, err)
	defer f.Close()

	location := file.NewLocation(asarPath)
	reader := file.NewLocationReadCloser(location, f)

	pkgs, relationships, err := parseAsarArchive(nil, nil, nil, reader)
	require.NoError(t, err)
	assert.Empty(t, relationships)
	require.Len(t, pkgs, 2, "expected 2 packages: test-app and lodash")

	pkgMap := make(map[string]pkg.Package)
	for _, p := range pkgs {
		pkgMap[p.Name] = p
	}

	testApp, ok := pkgMap["test-app"]
	require.True(t, ok, "test-app package not found")
	assert.Equal(t, "1.0.0", testApp.Version)
	assert.Equal(t, pkg.NpmPkg, testApp.Type)
	assert.Equal(t, pkg.JavaScript, testApp.Language)
	assert.Contains(t, testApp.PURL, "pkg:npm/test-app@1.0.0")

	lodash, ok := pkgMap["lodash"]
	require.True(t, ok, "lodash package not found")
	assert.Equal(t, "4.17.21", lodash.Version)
	assert.Equal(t, pkg.NpmPkg, lodash.Type)
	assert.Equal(t, pkg.JavaScript, lodash.Language)
	assert.Contains(t, lodash.PURL, "pkg:npm/lodash@4.17.21")

	for _, p := range pkgs {
		for _, loc := range p.Locations.ToSlice() {
			assert.Contains(t, loc.AccessPath, "app.asar:")
		}
	}
}

func TestParsePackageJSONFromContents(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		expected pkg.Package
	}{
		{
			name: "simple package",
			contents: `{
				"name": "lodash",
				"version": "4.17.21",
				"description": "Lodash modular utilities",
				"license": "MIT"
			}`,
			expected: pkg.Package{
				Name:     "lodash",
				Version:  "4.17.21",
				Type:     pkg.NpmPkg,
				Language: pkg.JavaScript,
			},
		},
		{
			name: "scoped package",
			contents: `{
				"name": "@babel/core",
				"version": "7.23.0",
				"description": "Babel compiler core"
			}`,
			expected: pkg.Package{
				Name:     "@babel/core",
				Version:  "7.23.0",
				Type:     pkg.NpmPkg,
				Language: pkg.JavaScript,
			},
		},
		{
			name: "author as object",
			contents: `{
				"name": "test-pkg",
				"version": "1.0.0",
				"author": {
					"name": "John Doe",
					"email": "john@example.com",
					"url": "https://example.com"
				}
			}`,
			expected: pkg.Package{
				Name:     "test-pkg",
				Version:  "1.0.0",
				Type:     pkg.NpmPkg,
				Language: pkg.JavaScript,
			},
		},
		{
			name: "license as object",
			contents: `{
				"name": "test-pkg",
				"version": "2.0.0",
				"license": {
					"type": "Apache-2.0",
					"url": "https://www.apache.org/licenses/LICENSE-2.0"
				}
			}`,
			expected: pkg.Package{
				Name:     "test-pkg",
				Version:  "2.0.0",
				Type:     pkg.NpmPkg,
				Language: pkg.JavaScript,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			location := file.NewLocation("test/package.json")
			p, err := parsePackageJSONFromContents([]byte(tt.contents), location)
			require.NoError(t, err)

			assert.Equal(t, tt.expected.Name, p.Name)
			assert.Equal(t, tt.expected.Version, p.Version)
			assert.Equal(t, tt.expected.Type, p.Type)
			assert.Equal(t, tt.expected.Language, p.Language)
		})
	}
}

func TestExtractAuthor(t *testing.T) {
	tests := []struct {
		name     string
		author   any
		expected string
	}{
		{
			name:     "nil author",
			author:   nil,
			expected: "",
		},
		{
			name:     "string author",
			author:   "John Doe <john@example.com>",
			expected: "John Doe <john@example.com>",
		},
		{
			name: "object author with all fields",
			author: map[string]any{
				"name":  "John Doe",
				"email": "john@example.com",
				"url":   "https://example.com",
			},
			expected: "John Doe <john@example.com> (https://example.com)",
		},
		{
			name: "object author with name only",
			author: map[string]any{
				"name": "John Doe",
			},
			expected: "John Doe",
		},
		{
			name:     "unsupported type",
			author:   123,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractAuthor(tt.author)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractLicense(t *testing.T) {
	tests := []struct {
		name     string
		license  any
		expected string
	}{
		{
			name:     "nil license",
			license:  nil,
			expected: "",
		},
		{
			name:     "string license",
			license:  "MIT",
			expected: "MIT",
		},
		{
			name: "object license",
			license: map[string]any{
				"type": "Apache-2.0",
				"url":  "https://www.apache.org/licenses/LICENSE-2.0",
			},
			expected: "Apache-2.0",
		},
		{
			name:     "unsupported type",
			license:  []string{"MIT", "Apache-2.0"},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractLicense(tt.license)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractRepositoryURL(t *testing.T) {
	tests := []struct {
		name     string
		repo     any
		expected string
	}{
		{
			name:     "nil repo",
			repo:     nil,
			expected: "",
		},
		{
			name:     "string repo",
			repo:     "https://github.com/user/repo",
			expected: "https://github.com/user/repo",
		},
		{
			name: "object repo",
			repo: map[string]any{
				"type": "git",
				"url":  "git+https://github.com/user/repo.git",
			},
			expected: "git+https://github.com/user/repo.git",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractRepositoryURL(tt.repo)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPackageURL(t *testing.T) {
	tests := []struct {
		name     string
		pkgName  string
		version  string
		expected string
	}{
		{
			name:     "simple package",
			pkgName:  "lodash",
			version:  "4.17.21",
			expected: "pkg:npm/lodash@4.17.21",
		},
		{
			name:     "scoped package",
			pkgName:  "@babel/core",
			version:  "7.23.0",
			expected: "pkg:npm/%40babel/core@7.23.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := packageURL(tt.pkgName, tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseAsarArchive_InvalidASAR(t *testing.T) {
	location := file.NewLocation("invalid.asar")

	tmpPath := filepath.Join(t.TempDir(), "invalid.asar")
	require.NoError(t, os.WriteFile(tmpPath, []byte("invalid asar content"), 0644))

	f, err := os.Open(tmpPath)
	require.NoError(t, err)

	reader := file.NewLocationReadCloser(location, f)

	pkgs, _, err := parseAsarArchive(nil, nil, nil, reader)
	assert.Error(t, err)
	assert.Nil(t, pkgs)
}

func TestParsePackageJSONFromContents_InvalidJSON(t *testing.T) {
	location := file.NewLocation("test/package.json")

	_, err := parsePackageJSONFromContents([]byte("not valid json"), location)
	assert.Error(t, err)

	p, err := parsePackageJSONFromContents([]byte("{}"), location)
	assert.NoError(t, err)
	assert.Empty(t, p.Name)
	assert.Empty(t, p.Version)
}

func TestFindPackageJSONFilesFromHeader_NoPackages(t *testing.T) {
	header := &asarHeader{
		Files: map[string]asarEntry{},
	}
	paths := findPackageJSONFilesFromHeader(header)
	assert.Empty(t, paths)
}

func TestFindPackageJSONFilesFromHeader_WithPackages(t *testing.T) {
	header := &asarHeader{
		Files: map[string]asarEntry{
			"package.json": {Size: 100, Offset: "0"},
			"node_modules": {
				Files: map[string]asarEntry{
					"lodash": {
						Files: map[string]asarEntry{
							"package.json": {Size: 50, Offset: "100"},
						},
					},
				},
			},
		},
	}
	paths := findPackageJSONFilesFromHeader(header)
	assert.Len(t, paths, 2)
	assert.Contains(t, paths, "package.json")
	assert.Contains(t, paths, "node_modules/lodash/package.json")
}

func TestParseAsarHeader(t *testing.T) {
	asarPath := filepath.Join("test-fixtures", "app.asar")
	data, err := os.ReadFile(asarPath)
	require.NoError(t, err)

	header, headerSize, err := parseAsarHeader(data)
	require.NoError(t, err)
	assert.NotNil(t, header)
	assert.True(t, headerSize > 0)

	_, hasRootPkg := header.Files["package.json"]
	assert.True(t, hasRootPkg, "should have root package.json")

	_, hasNodeModules := header.Files["node_modules"]
	assert.True(t, hasNodeModules, "should have node_modules")
}

func TestFindEntry(t *testing.T) {
	header := &asarHeader{
		Files: map[string]asarEntry{
			"package.json": {Size: 100, Offset: "0"},
			"node_modules": {
				Files: map[string]asarEntry{
					"lodash": {
						Files: map[string]asarEntry{
							"package.json": {Size: 50, Offset: "100"},
						},
					},
				},
			},
		},
	}

	entry, found := findEntry(header, "package.json")
	assert.True(t, found)
	assert.NotNil(t, entry)
	assert.Equal(t, int64(100), entry.Size)

	entry, found = findEntry(header, "node_modules/lodash/package.json")
	assert.True(t, found)
	assert.NotNil(t, entry)
	assert.Equal(t, int64(50), entry.Size)

	_, found = findEntry(header, "nonexistent.json")
	assert.False(t, found)
}
