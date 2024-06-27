package python

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/go-test/deep"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/cmptest"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func TestParseWheelEggMetadata(t *testing.T) {
	tests := []struct {
		Fixture          string
		ExpectedMetadata parsedData
	}{
		{
			Fixture: "test-fixtures/egg-info/PKG-INFO",
			ExpectedMetadata: parsedData{
				"Apache 2.0",
				"",
				"",
				file.NewLocation("test-fixtures/egg-info/PKG-INFO"),
				pkg.PythonPackage{
					Name:                 "requests",
					Version:              "2.22.0",
					Platform:             "UNKNOWN",
					Author:               "Kenneth Reitz",
					AuthorEmail:          "me@kennethreitz.org",
					SitePackagesRootPath: "test-fixtures",
					RequiresPython:       ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*",
					ProvidesExtra:        []string{"security", "socks"},
				},
			},
		},
		{
			Fixture: "test-fixtures/dist-info/METADATA",
			ExpectedMetadata: parsedData{
				"BSD License",
				"",
				"",
				file.NewLocation("test-fixtures/dist-info/METADATA"),
				pkg.PythonPackage{
					Name:                 "Pygments",
					Version:              "2.6.1",
					Platform:             "any",
					Author:               "Georg Brandl",
					AuthorEmail:          "georg@python.org",
					SitePackagesRootPath: "test-fixtures",
					RequiresPython:       ">=3.5",
					RequiresDist:         []string{"soupsieve (>1.2)", "html5lib ; extra == 'html5lib'", "lxml ; extra == 'lxml'"},
					ProvidesExtra:        []string{"html5lib", "lxml"},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Fixture, func(t *testing.T) {
			fixture, err := os.Open(test.Fixture)
			if err != nil {
				t.Fatalf("failed to open fixture: %+v", err)
			}

			l := file.NewLocationReadCloser(file.NewLocation(test.Fixture), fixture)

			actual, err := parseWheelOrEggMetadata(l)
			if err != nil {
				t.Fatalf("failed to parse: %+v", err)
			}

			if d := cmp.Diff(test.ExpectedMetadata, actual, cmptest.DefaultCommonOptions()...); d != "" {
				t.Errorf("metadata mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func TestIsRegularEggFile(t *testing.T) {
	cases := []struct {
		path     string
		expected bool
	}{
		{
			"/usr/lib64/python2.6/site-packages/M2Crypto-0.20.2-py2.6.egg-info",
			true,
		},
		{
			"/usr/lib64/python2.6/site-packages/M2Crypto-0.20.2-py2.6.egg-info/PKG-INFO",
			false,
		},
		{
			"/usr/lib64/python2.6/site-packages/M2Crypto-0.20.2-py2.6.dist-info/METADATA",
			false,
		},
	}

	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			actual := isEggRegularFile(c.path)

			if actual != c.expected {
				t.Errorf("expected %t but got %t", c.expected, actual)
			}
		})
	}
}

func TestDetermineSitePackagesRootPath(t *testing.T) {
	cases := []struct {
		inputPath string
		expected  string
	}{
		{
			inputPath: "/usr/lib64/python2.6/site-packages/ethtool-0.6-py2.6.egg-info",
			expected:  "/usr/lib64/python2.6/site-packages",
		},
		{
			inputPath: "/usr/lib/python2.7/dist-packages/configobj-5.0.6.egg-info/top_level.txt",
			expected:  "/usr/lib/python2.7/dist-packages",
		},
		{
			inputPath: "/usr/lib/python2.7/dist-packages/six-1.10.0.egg-info/PKG-INFO",
			expected:  "/usr/lib/python2.7/dist-packages",
		},
	}

	for _, c := range cases {
		t.Run(c.inputPath, func(t *testing.T) {
			actual := determineSitePackagesRootPath(c.inputPath)

			if actual != c.expected {
				t.Errorf("expected %s but got %s", c.expected, actual)
			}
		})
	}
}

func TestParseWheelEggMetadataInvalid(t *testing.T) {
	tests := []struct {
		Fixture          string
		ExpectedMetadata parsedData
	}{
		{
			Fixture: "test-fixtures/egg-info/PKG-INFO-INVALID",
			ExpectedMetadata: parsedData{
				"",
				"",
				"",
				file.Location{},
				pkg.PythonPackage{
					Name:                 "mxnet",
					Version:              "1.8.0",
					SitePackagesRootPath: "test-fixtures",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Fixture, func(t *testing.T) {
			fixture, err := os.Open(test.Fixture)
			if err != nil {
				t.Fatalf("failed to open fixture: %+v", err)
			}

			l := file.NewLocationReadCloser(file.NewLocation(test.Fixture), fixture)

			actual, err := parseWheelOrEggMetadata(l)
			if err != nil {
				t.Fatalf("failed to parse: %+v", err)
			}

			for _, d := range deep.Equal(actual, test.ExpectedMetadata) {
				t.Errorf("diff: %+v", d)
			}
		})
	}
}

func Test_extractRFC5322Fields(t *testing.T) {

	tests := []struct {
		name    string
		input   string
		want    map[string]any
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "with valid plural fields",
			input: `
Name: mxnet
Version: 1.8.0
Requires-Dist: numpy (>=1.16.6)
Requires-Dist: requests (>=2.22.0)
ProvidesExtra: cryptoutils ; extra == 'secure'
ProvidesExtra: socks ; extra == 'secure'
`,
			want: map[string]any{
				"Name":          "mxnet",
				"Version":       "1.8.0",
				"RequiresDist":  []string{"numpy (>=1.16.6)", "requests (>=2.22.0)"},
				"ProvidesExtra": []string{"cryptoutils ; extra == 'secure'", "socks ; extra == 'secure'"},
			},
		},
		{
			name: "with invalid plural fields (overwrite)",
			input: `
Name: mxnet
Version: 1.8.0
Version: 1.9.0
`,
			want: map[string]any{
				"Name":    "mxnet",
				"Version": "1.9.0",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			reader := file.NewLocationReadCloser(
				file.NewLocation("/made/up"),
				io.NopCloser(strings.NewReader(tt.input)),
			)

			got, err := extractRFC5322Fields(reader)
			tt.wantErr(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
