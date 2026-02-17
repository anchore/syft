package snap

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

func gzipContent(t *testing.T, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func locationReadCloser(t *testing.T, data []byte) file.LocationReadCloser {
	t.Helper()
	return file.LocationReadCloser{
		Location:   file.NewLocation("test-fixtures/changelog.Debian.gz"),
		ReadCloser: io.NopCloser(bytes.NewReader(data)),
	}
}

func TestExtractKernelVersion(t *testing.T) {
	tests := []struct {
		name        string
		firstLine   string
		expected    *kernelVersionInfo
		expectError string
	}{
		{
			name:      "standard focal kernel",
			firstLine: "linux (5.4.0-195.215) focal; urgency=medium",
			expected: &kernelVersionInfo{
				baseVersion:    "5.4.0-195",
				releaseVersion: "215",
				fullVersion:    "5.4.0-195.215",
				majorVersion:   "5.4",
			},
		},
		{
			name:      "noble kernel 6.x",
			firstLine: "linux (6.8.0-50.51) noble; urgency=medium",
			expected: &kernelVersionInfo{
				baseVersion:    "6.8.0-50",
				releaseVersion: "51",
				fullVersion:    "6.8.0-50.51",
				majorVersion:   "6.8",
			},
		},
		{
			name:      "jammy kernel",
			firstLine: "linux (5.15.0-130.140) jammy; urgency=medium",
			expected: &kernelVersionInfo{
				baseVersion:    "5.15.0-130",
				releaseVersion: "140",
				fullVersion:    "5.15.0-130.140",
				majorVersion:   "5.15",
			},
		},
		{
			name:        "empty string",
			firstLine:   "",
			expectError: "could not parse kernel version from changelog",
		},
		{
			name:        "no version match",
			firstLine:   "not a valid changelog line",
			expectError: "could not parse kernel version from changelog",
		},
		{
			name:        "missing release version",
			firstLine:   "linux (5.4.0-195) focal; urgency=medium",
			expectError: "could not parse kernel version from changelog",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := extractKernelVersion(tt.firstLine)
			if tt.expectError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected.baseVersion, result.baseVersion)
			assert.Equal(t, tt.expected.releaseVersion, result.releaseVersion)
			assert.Equal(t, tt.expected.fullVersion, result.fullVersion)
			assert.Equal(t, tt.expected.majorVersion, result.majorVersion)
		})
	}
}

func TestCreateMainKernelPackage(t *testing.T) {
	location := file.NewLocation("test-fixtures/changelog.Debian.gz")
	versionInfo := &kernelVersionInfo{
		baseVersion:    "5.4.0-195",
		releaseVersion: "215",
		fullVersion:    "5.4.0-195.215",
		majorVersion:   "5.4",
	}
	snapMetadata := pkg.SnapEntry{
		SnapType: pkg.SnapTypeKernel,
	}

	packages := createMainKernelPackage(versionInfo, snapMetadata, location)

	require.Len(t, packages, 1)
	p := packages[0]
	assert.Equal(t, "linux-image-5.4.0-195-generic", p.Name)
	assert.Equal(t, "5.4.0-195.215", p.Version)
	assert.Equal(t, pkg.DebPkg, p.Type)

	metadata, ok := p.Metadata.(pkg.SnapEntry)
	require.True(t, ok)
	assert.Equal(t, pkg.SnapTypeKernel, metadata.SnapType)
}

func TestParseBaseKernelLine(t *testing.T) {
	location := file.NewLocation("test-fixtures/changelog.Debian.gz")
	snapMetadata := pkg.SnapEntry{
		SnapType: pkg.SnapTypeKernel,
	}

	tests := []struct {
		name         string
		line         string
		majorVersion string
		expectNil    bool
		expectedName string
		expectedVer  string
	}{
		{
			name:         "standard base kernel entry",
			line:         "    [ Ubuntu: 5.4-100.200 ]",
			majorVersion: "5.4",
			expectedName: "linux-image-5.4-100-generic",
			expectedVer:  "5.4-100.200",
		},
		{
			name:         "6.x base kernel entry",
			line:         "    [ Ubuntu: 6.8-40.41 ]",
			majorVersion: "6.8",
			expectedName: "linux-image-6.8-40-generic",
			expectedVer:  "6.8-40.41",
		},
		{
			name:         "no matching version",
			line:         "  * some random changelog text here",
			majorVersion: "5.4",
			expectNil:    true,
		},
		{
			name:         "empty line",
			line:         "",
			majorVersion: "5.4",
			expectNil:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseBaseKernelLine(tt.line, tt.majorVersion, snapMetadata, location)
			if tt.expectNil {
				assert.Nil(t, result)
				return
			}
			require.NotNil(t, result)
			assert.Equal(t, tt.expectedName, result.Name)
			assert.Equal(t, tt.expectedVer, result.Version)
			assert.Equal(t, pkg.DebPkg, result.Type)

			metadata, ok := result.Metadata.(pkg.SnapEntry)
			require.True(t, ok)
			assert.Equal(t, pkg.SnapTypeKernel, metadata.SnapType)
		})
	}
}

func TestParseKernelChangelog(t *testing.T) {
	// Realistic changelog content modeled on Ubuntu kernel changelogs.
	// The first line declares the patched kernel version.
	// Somewhere later a line references the base upstream kernel.
	fullChangelog := strings.Join([]string{
		"linux (5.4.0-195.215) focal; urgency=medium",
		"",
		"  * focal/linux: 5.4.0-195.215 -proposed tracker (LP: #2083390)",
		"",
		"  [ Ubuntu: 5.4-100.200 ]",
		"",
		"  * Some other entry",
		"",
		" -- Ubuntu Kernel Team <kernel-team@lists.ubuntu.com>  Mon, 01 Jan 2024 00:00:00 +0000",
		"",
	}, "\n")

	// Changelog where the base kernel entry line uses the release version pattern
	// The code builds: fmt.Sprintf("%s/linux:", releaseVersion) → "215/linux:"
	changelogWithBaseEntry := strings.Join([]string{
		"linux (5.4.0-195.215) focal; urgency=medium",
		"",
		"  * focal/linux: 5.4.0-195.215 -proposed tracker",
		"",
		"  215/linux: 5.4-100.200 base entry",
		"",
		" -- Ubuntu Kernel Team <kernel-team@lists.ubuntu.com>  Mon, 01 Jan 2024 00:00:00 +0000",
		"",
	}, "\n")

	// Changelog with only the header line and no base kernel match
	minimalChangelog := "linux (6.8.0-50.51) noble; urgency=medium\n"

	tests := []struct {
		name          string
		input         []byte
		expectedCount int
		expectedNames []string
		expectedVers  []string
		expectError   bool
		errorContains string
	}{
		{
			name:          "full changelog with base kernel via release version pattern",
			input:         gzipContent(t, changelogWithBaseEntry),
			expectedCount: 2,
			expectedNames: []string{"linux-image-5.4.0-195-generic", "linux-image-5.4-100-generic"},
			expectedVers:  []string{"5.4.0-195.215", "5.4-100.200"},
		},
		{
			name:          "changelog without base kernel match returns only main package",
			input:         gzipContent(t, minimalChangelog),
			expectedCount: 1,
			expectedNames: []string{"linux-image-6.8.0-50-generic"},
			expectedVers:  []string{"6.8.0-50.51"},
		},
		{
			name:          "full changelog without matching release version pattern returns only main package",
			input:         gzipContent(t, fullChangelog),
			expectedCount: 1,
			expectedNames: []string{"linux-image-5.4.0-195-generic"},
			expectedVers:  []string{"5.4.0-195.215"},
		},
		{
			name:          "invalid gzip data",
			input:         []byte("not gzip data"),
			expectError:   true,
			errorContains: "failed to create gzip reader",
		},
		{
			// The old (slurp) implementation produces "could not parse kernel version"
			// because strings.Split("", "\n") yields [""], not an empty slice.
			// The new (streaming) implementation produces "changelog file is empty"
			// because bufio.Scanner.Scan() returns false immediately.
			// Both correctly reject empty content; only the message differs.
			name:        "empty gzip content",
			input:       gzipContent(t, ""),
			expectError: true,
		},
		{
			name:          "gzip content with unparseable first line",
			input:         gzipContent(t, "this is not a valid kernel changelog\n"),
			expectError:   true,
			errorContains: "could not parse kernel version from changelog",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := locationReadCloser(t, tt.input)

			packages, relationships, err := parseKernelChangelog(
				context.Background(), nil, &generic.Environment{}, reader,
			)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				return
			}

			require.NoError(t, err)
			assert.Nil(t, relationships)
			require.Len(t, packages, tt.expectedCount)

			for i, p := range packages {
				assert.Equal(t, tt.expectedNames[i], p.Name, "package %d name", i)
				assert.Equal(t, tt.expectedVers[i], p.Version, "package %d version", i)
				assert.Equal(t, pkg.DebPkg, p.Type, "package %d type", i)

				metadata, ok := p.Metadata.(pkg.SnapEntry)
				require.True(t, ok, "package %d metadata type", i)
				assert.Equal(t, pkg.SnapTypeKernel, metadata.SnapType, "package %d snap type", i)
			}
		})
	}
}
