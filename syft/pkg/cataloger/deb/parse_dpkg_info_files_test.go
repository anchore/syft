package deb

import (
	"os"
	"testing"

	"github.com/go-test/deep"

	"github.com/anchore/syft/syft/pkg"
)

func TestMD5SumInfoParsing(t *testing.T) {
	tests := []struct {
		fixture  string
		expected []pkg.DpkgFileRecord
	}{
		{
			fixture: "test-fixtures/info/zlib1g.md5sums",
			expected: []pkg.DpkgFileRecord{
				{Path: "/lib/x86_64-linux-gnu/libz.so.1.2.11", MD5: "55f905631797551d4d936a34c7e73474"},
				{Path: "/usr/share/doc/zlib1g/changelog.Debian.gz", MD5: "cede84bda30d2380217f97753c8ccf3a"},
				{Path: "/usr/share/doc/zlib1g/changelog.gz", MD5: "f3c9dafa6da7992c47328b4464f6d122"},
				{Path: "/usr/share/doc/zlib1g/copyright", MD5: "a4fae96070439a5209a62ae5b8017ab2"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			file, err := os.Open(test.fixture)
			if err != nil {
				t.Fatal("Unable to read: ", err)
			}
			defer func() {
				err := file.Close()
				if err != nil {
					t.Fatal("closing file failed:", err)
				}
			}()

			actual := parseDpkgMD5Info(file)

			if len(actual) != len(test.expected) {
				for _, a := range actual {
					t.Logf("   %+v", a)
				}
				t.Fatalf("unexpected package count: %d!=%d", len(actual), len(test.expected))
			}

			diffs := deep.Equal(actual, test.expected)
			for _, d := range diffs {
				t.Errorf("diff: %+v", d)
			}

		})
	}
}
