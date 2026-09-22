package debian

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func TestMD5SumInfoParsing(t *testing.T) {
	tests := []struct {
		fixture  string
		expected []pkg.DpkgFileRecord
	}{
		{
			fixture: "testdata/info/zlib1g.md5sums",
			expected: []pkg.DpkgFileRecord{
				{Path: "/lib/x86_64-linux-gnu/libz.so.1.2.11", Digest: &file.Digest{
					Algorithm: "md5",
					Value:     "55f905631797551d4d936a34c7e73474",
				}},
				{Path: "/usr/share/doc/zlib1g/changelog.Debian.gz", Digest: &file.Digest{
					Algorithm: "md5",
					Value:     "cede84bda30d2380217f97753c8ccf3a",
				}},
				{Path: "/usr/share/doc/zlib1g/changelog.gz", Digest: &file.Digest{
					Algorithm: "md5",
					Value:     "f3c9dafa6da7992c47328b4464f6d122",
				}},
				{Path: "/usr/share/doc/zlib1g/copyright", Digest: &file.Digest{
					Algorithm: "md5",
					Value:     "a4fae96070439a5209a62ae5b8017ab2",
				}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			f, err := os.Open(test.fixture)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, f.Close()) })

			actual, err := parseDpkgMD5Info(f)
			require.NoError(t, err)

			if diff := cmp.Diff(test.expected, actual); diff != "" {
				t.Errorf("unexpected md5 files (-want +got):\n%s", diff)
			}

		})
	}
}

func TestConffileInfoParsing(t *testing.T) {
	tests := []struct {
		fixture  string
		expected []pkg.DpkgFileRecord
	}{
		{
			fixture: "testdata/info/util-linux.conffiles",
			expected: []pkg.DpkgFileRecord{
				{Path: "/etc/default/hwclock", IsConfigFile: true},
				{Path: "/etc/init.d/hwclock.sh", IsConfigFile: true},
				{Path: "/etc/pam.d/runuser", IsConfigFile: true},
				{Path: "/etc/pam.d/runuser-l", IsConfigFile: true},
				{Path: "/etc/pam.d/su", IsConfigFile: true},
				{Path: "/etc/pam.d/su-l", IsConfigFile: true},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			f, err := os.Open(test.fixture)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, f.Close()) })

			actual, err := parseDpkgConffileInfo(f)
			require.NoError(t, err)

			if diff := cmp.Diff(test.expected, actual); diff != "" {
				t.Errorf("unexpected md5 files (-want +got):\n%s", diff)
			}

		})
	}
}

func Test_parseDpkgInfoFiles_boundRecordCount(t *testing.T) {
	// a byte cap on the enclosing stream cannot bound these on its own, since the shortest line that
	// still yields a record is a few bytes. exercises the real maxDpkgFileRecords const directly, since
	// the limit is no longer injectable.
	t.Run("md5sums stops at the record bound", func(t *testing.T) {
		buf := strings.Repeat("d41d8cd98f00b204e9800998ecf8427e  usr/bin/x\n", maxDpkgFileRecords+10)

		got, err := parseDpkgMD5Info(strings.NewReader(buf))

		assert.Len(t, got, maxDpkgFileRecords)
		require.ErrorIs(t, err, errClippedFileListing)
	})

	t.Run("conffiles stops at the record bound", func(t *testing.T) {
		buf := strings.Repeat("/etc/x.conf\n", maxDpkgFileRecords+10)

		got, err := parseDpkgConffileInfo(strings.NewReader(buf))

		assert.Len(t, got, maxDpkgFileRecords)
		require.ErrorIs(t, err, errClippedFileListing)
	})

	t.Run("a listing under the bound is returned whole", func(t *testing.T) {
		// guards against the bound clipping legitimate input
		got, err := parseDpkgMD5Info(strings.NewReader(
			"d41d8cd98f00b204e9800998ecf8427e  usr/bin/a\n" +
				"d41d8cd98f00b204e9800998ecf8427e  usr/bin/b\n"))

		require.NoError(t, err)
		require.Len(t, got, 2)
		assert.Equal(t, "/usr/bin/a", got[0].Path)
		assert.Equal(t, "/usr/bin/b", got[1].Path)
	})
}

func Test_parseDpkgMD5Info_scannerError(t *testing.T) {
	// a single line longer than bufio.MaxScanTokenSize with no trailing newline trips the scanner's
	// internal error rather than yielding a clean (and silently incomplete) empty list
	line := strings.Repeat("a", bufio.MaxScanTokenSize+1)

	got, err := parseDpkgMD5Info(strings.NewReader(line))

	assert.Empty(t, got)
	require.Error(t, err)
}
