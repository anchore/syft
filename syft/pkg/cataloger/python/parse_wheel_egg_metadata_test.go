package python

import (
	"os"
	"testing"

	"github.com/go-test/deep"

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
				file.NewLocation("test-fixtures/egg-info/PKG-INFO"),
				pkg.PythonPackageMetadata{
					Name:                 "requests",
					Version:              "2.22.0",
					Platform:             "UNKNOWN",
					Author:               "Kenneth Reitz",
					AuthorEmail:          "me@kennethreitz.org",
					SitePackagesRootPath: "test-fixtures",
				},
			},
		},
		{
			Fixture: "test-fixtures/dist-info/METADATA",
			ExpectedMetadata: parsedData{
				"BSD License",
				file.NewLocation("test-fixtures/dist-info/METADATA"),
				pkg.PythonPackageMetadata{
					Name:                 "Pygments",
					Version:              "2.6.1",
					Platform:             "any",
					Author:               "Georg Brandl",
					AuthorEmail:          "georg@python.org",
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

			actual, err := parseWheelOrEggMetadata(test.Fixture, fixture)
			if err != nil {
				t.Fatalf("failed to parse: %+v", err)
			}

			for _, d := range deep.Equal(actual, test.ExpectedMetadata) {
				t.Errorf("diff: %+v", d)
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
				file.Location{},
				pkg.PythonPackageMetadata{
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

			actual, err := parseWheelOrEggMetadata(test.Fixture, fixture)
			if err != nil {
				t.Fatalf("failed to parse: %+v", err)
			}

			for _, d := range deep.Equal(actual, test.ExpectedMetadata) {
				t.Errorf("diff: %+v", d)
			}
		})
	}
}
