package alpm

import (
	"bufio"
	"os"
	"testing"
	"time"

	"github.com/go-test/deep"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func TestDatabaseParser(t *testing.T) {
	tests := []struct {
		name     string
		expected pkg.AlpmMetadata
	}{
		{
			name: "test alpm database parsing",
			expected: pkg.AlpmMetadata{
				Backup: []pkg.AlpmFileRecord{
					{
						Path: "/etc/pacman.conf",
						Digests: []file.Digest{{
							Algorithm: "md5",
							Value:     "de541390e52468165b96511c4665bff4",
						}},
					},
					{
						Path: "/etc/makepkg.conf",
						Digests: []file.Digest{{
							Algorithm: "md5",
							Value:     "79fce043df7dfc676ae5ecb903762d8b",
						}},
					},
				},
				Files: []pkg.AlpmFileRecord{
					{
						Path: "/etc/",
					},
					{
						Path: "/etc/makepkg.conf",
					},
					{
						Path: "/etc/pacman.conf",
					},
					{
						Path: "/usr/",
					},
					{
						Path: "/usr/bin/",
					},
					{
						Path: "/usr/bin/makepkg",
					},
					{
						Path: "/usr/bin/makepkg-template",
					},
					{
						Path: "/usr/bin/pacman",
					},
					{
						Path: "/usr/bin/pacman-conf",
					},
					{
						Path: "/var/",
					},
					{
						Path: "/var/cache/",
					},
					{
						Path: "/var/cache/pacman/",
					},
					{
						Path: "/var/cache/pacman/pkg/",
					},
					{
						Path: "/var/lib/",
					},
					{
						Path: "/var/lib/pacman/",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, err := os.Open("test-fixtures/files")
			if err != nil {
				t.Fatal("Unable to read test-fixtures/file: ", err)
			}
			defer func() {
				err := file.Close()
				if err != nil {
					t.Fatal("closing file failed:", err)
				}
			}()

			reader := bufio.NewReader(file)

			entry, err := parseAlpmDBEntry(reader)
			if err != nil {
				t.Fatal("Unable to read file contents: ", err)
			}

			if diff := deep.Equal(entry.Files, test.expected.Files); diff != nil {
				for _, d := range diff {
					t.Errorf("files diff: %+v", d)
				}
			}
			if diff := deep.Equal(entry.Backup, test.expected.Backup); diff != nil {
				for _, d := range diff {
					t.Errorf("backup diff: %+v", d)
				}
			}
		})
	}
}

func parseTime(stime string) time.Time {
	t, _ := time.Parse(time.RFC3339, stime)
	return t
}

func TestMtreeParse(t *testing.T) {
	tests := []struct {
		name     string
		expected []pkg.AlpmFileRecord
	}{
		{
			name: "test mtree parsing",
			expected: []pkg.AlpmFileRecord{
				{
					Path:    "/etc",
					Type:    "dir",
					Time:    parseTime("2022-04-10T14:59:52+02:00"),
					Digests: make([]file.Digest, 0),
				},
				{
					Path:    "/etc/pacman.d",
					Type:    "dir",
					Time:    parseTime("2022-04-10T14:59:52+02:00"),
					Digests: make([]file.Digest, 0),
				},
				{
					Path: "/etc/pacman.d/mirrorlist",
					Size: "44683",
					Time: parseTime("2022-04-10T14:59:52+02:00"),
					Digests: []file.Digest{
						{
							Algorithm: "md5digest",
							Value:     "81c39827e38c759d7e847f05db62c233",
						},
						{
							Algorithm: "sha256",
							Value:     "fc135ab26f2a227b9599b66a2f1ba325c445acb914d60e7ecf6e5997a87abe1e",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, err := os.Open("test-fixtures/mtree")
			if err != nil {
				t.Fatal("Unable to read test-fixtures/mtree: ", err)
			}
			defer func() {
				err := file.Close()
				if err != nil {
					t.Fatal("closing file failed:", err)
				}
			}()

			reader := bufio.NewReader(file)

			entry, err := parseMtree(reader)
			if err != nil {
				t.Fatal("Unable to read file contents: ", err)
			}

			if diff := deep.Equal(entry, test.expected); diff != nil {
				for _, d := range diff {
					t.Errorf("files diff: %+v", d)
				}
			}
		})
	}

}
