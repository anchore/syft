package deb

import (
	"bufio"
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
)

func compareEntries(t *testing.T, left, right pkg.DpkgMetadata) {
	t.Helper()
	if diff := deep.Equal(left, right); diff != nil {
		t.Error(diff)
	}
}

func TestSinglePackage(t *testing.T) {
	tests := []struct {
		name     string
		expected pkg.DpkgMetadata
	}{
		{
			name: "Test Single Package",
			expected: pkg.DpkgMetadata{
				Package:       "apt",
				Source:        "apt-dev",
				Version:       "1.8.2",
				Architecture:  "amd64",
				InstalledSize: 4064,
				Maintainer:    "APT Development Team <deity@lists.debian.org>",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, err := os.Open("test-fixtures/status/single")
			if err != nil {
				t.Fatal("Unable to read test_fixtures/single: ", err)
			}
			defer func() {
				err := file.Close()
				if err != nil {
					t.Fatal("closing file failed:", err)
				}
			}()

			reader := bufio.NewReader(file)

			entry, err := parseDpkgStatusEntry(reader)
			if err != nil {
				t.Fatal("Unable to read file contents: ", err)
			}

			compareEntries(t, entry, test.expected)
		})
	}
}

func TestMultiplePackages(t *testing.T) {
	tests := []struct {
		name     string
		expected []pkg.DpkgMetadata
	}{
		{
			name: "Test Multiple Package",
			expected: []pkg.DpkgMetadata{
				{
					Package:       "tzdata",
					Version:       "2020a-0+deb10u1",
					Source:        "tzdata-dev",
					Architecture:  "all",
					InstalledSize: 3036,
					Maintainer:    "GNU Libc Maintainers <debian-glibc@lists.debian.org>",
				},
				{
					Package:       "util-linux",
					Version:       "2.33.1-0.1",
					Architecture:  "amd64",
					InstalledSize: 4327,
					Maintainer:    "LaMont Jones <lamont@debian.org>",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, err := os.Open("test-fixtures/status/multiple")
			if err != nil {
				t.Fatal("Unable to read: ", err)
			}
			defer func() {
				err := file.Close()
				if err != nil {
					t.Fatal("closing file failed:", err)
				}
			}()

			pkgs, err := parseDpkgStatus(file)
			if err != nil {
				t.Fatal("Unable to read file contents: ", err)
			}

			if len(pkgs) != 2 {
				t.Fatalf("unexpected number of entries: %d", len(pkgs))
			}

			for idx, entry := range pkgs {
				compareEntries(t, entry.Metadata.(pkg.DpkgMetadata), test.expected[idx])
			}

		})
	}
}

func TestSourceVersionExtract(t *testing.T) {

	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "name and version",
			input:    "test (1.2.3)",
			expected: []string{"test", "1.2.3"},
		},
		{
			name:     "only name",
			input:    "test",
			expected: []string{"test", ""},
		},
		{
			name:     "empty",
			input:    "",
			expected: []string{"", ""},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name, version := extractSourceVersion(test.input)

			if name != test.expected[0] {
				t.Errorf("mismatch name for %q : %q!=%q", test.input, name, test.expected[0])
			}

			if version != test.expected[1] {
				t.Errorf("mismatch version for %q : %q!=%q", test.input, version, test.expected[1])
			}

		})
	}
}
