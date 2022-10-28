package python

import (
	"os"
	"testing"

	"github.com/go-test/deep"

	"github.com/anchore/syft/syft/pkg"
)

func TestParseWheelEggRecord(t *testing.T) {
	tests := []struct {
		Fixture          string
		ExpectedMetadata []pkg.PythonFileRecord
	}{
		{
			Fixture: "test-fixtures/egg-info/RECORD",
			ExpectedMetadata: []pkg.PythonFileRecord{
				{Path: "requests-2.22.0.dist-info/INSTALLER", Digest: &pkg.PythonFileDigest{"sha256", "zuuue4knoyJ-UwPPXg8fezS7VCrXJQrAP7zeNuwvFQg"}, Size: "4"},
				{Path: "requests/__init__.py", Digest: &pkg.PythonFileDigest{"sha256", "PnKCgjcTq44LaAMzB-7--B2FdewRrE8F_vjZeaG9NhA"}, Size: "3921"},
				{Path: "requests/__pycache__/__version__.cpython-38.pyc"},
				{Path: "requests/__pycache__/utils.cpython-38.pyc"},
				{Path: "requests/__version__.py", Digest: &pkg.PythonFileDigest{"sha256", "Bm-GFstQaFezsFlnmEMrJDe8JNROz9n2XXYtODdvjjc"}, Size: "436"},
				{Path: "requests/utils.py", Digest: &pkg.PythonFileDigest{"sha256", "LtPJ1db6mJff2TJSJWKi7rBpzjPS3mSOrjC9zRhoD3A"}, Size: "30049"},
			},
		},
		{
			Fixture: "test-fixtures/dist-info/RECORD",
			ExpectedMetadata: []pkg.PythonFileRecord{
				{Path: "../../../bin/pygmentize", Digest: &pkg.PythonFileDigest{"sha256", "dDhv_U2jiCpmFQwIRHpFRLAHUO4R1jIJPEvT_QYTFp8"}, Size: "220"},
				{Path: "Pygments-2.6.1.dist-info/AUTHORS", Digest: &pkg.PythonFileDigest{"sha256", "PVpa2_Oku6BGuiUvutvuPnWGpzxqFy2I8-NIrqCvqUY"}, Size: "8449"},
				{Path: "Pygments-2.6.1.dist-info/RECORD"},
				{Path: "pygments/__pycache__/__init__.cpython-38.pyc"},
				{Path: "pygments/util.py", Digest: &pkg.PythonFileDigest{"sha256", "586xXHiJGGZxqk5PMBu3vBhE68DLuAe5MBARWrSPGxA"}, Size: "10778"},
				{Path: "pygments/x_util.py", Digest: &pkg.PythonFileDigest{"sha256", "qpzzsOW31KT955agi-7NS--90I0iNiJCyLJQnRCHgKI="}, Size: "10778"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Fixture, func(t *testing.T) {
			fixture, err := os.Open(test.Fixture)
			if err != nil {
				t.Fatalf("failed to open fixture: %+v", err)
			}

			actual := parseWheelOrEggRecord(fixture)

			for _, d := range deep.Equal(actual, test.ExpectedMetadata) {
				t.Errorf("diff: %+v", d)
			}
		})
	}
}

func TestParseInstalledFiles(t *testing.T) {
	tests := []struct {
		Fixture          string
		ExpectedMetadata []pkg.PythonFileRecord
	}{
		{
			Fixture: "test-fixtures/installed-files/installed-files.txt",
			ExpectedMetadata: []pkg.PythonFileRecord{
				{Path: "../__pycache__/dicttoxml.cpython-36.pyc"},
				{Path: "../dicttoxml.py"},
				{Path: "PKG-INFO"},
				{Path: "SOURCES.txt"},
				{Path: "dependency_links.txt"},
				{Path: "top_level.txt"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Fixture, func(t *testing.T) {
			fixture, err := os.Open(test.Fixture)
			if err != nil {
				t.Fatalf("failed to open fixture: %+v", err)
			}

			actual, err := parseInstalledFiles(fixture, "", "")
			if err != nil {
				t.Fatalf("failed to parse: %+v", err)
			}

			for _, d := range deep.Equal(actual, test.ExpectedMetadata) {
				t.Errorf("diff: %+v", d)
			}

		})
	}
}
