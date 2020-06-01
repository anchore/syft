package dpkg

import (
	"bufio"
	"os"
	"testing"

	"github.com/anchore/imgbom/imgbom/pkg"
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
				Package: "apt",
				Source:  "apt-dev",
				Version: "1.8.2",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, err := os.Open("test-fixtures/single")
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

			entry, err := parseEntry(reader)
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
					Package: "tzdata",
					Version: "2020a-0+deb10u1",
					Source:  "tzdata-dev",
				},
				{
					Package: "util-linux",
					Version: "2.33.1-0.1",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, err := os.Open("test-fixtures/multiple")
			if err != nil {
				t.Fatal("Unable to read: ", err)
			}
			defer func() {
				err := file.Close()
				if err != nil {
					t.Fatal("closing file failed:", err)
				}
			}()

			entries, err := ParseEntries(file)
			if err != nil {
				t.Fatal("Unable to read file contents: ", err)
			}

			if len(entries) != 2 {
				t.Fatalf("unexpected number of entries: %d", len(entries))
			}

			for idx, entry := range entries {
				compareEntries(t, entry, test.expected[idx])
			}

		})
	}
}
