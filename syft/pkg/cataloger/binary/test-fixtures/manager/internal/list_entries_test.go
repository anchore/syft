package internal

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg/cataloger/binary/test-fixtures/manager/internal/config"
)

func TestSortingLogicalEntryKeys(t *testing.T) {
	keys := LogicalEntryKeys{
		{OrgName: "Org1", Version: "1.0", Platform: "Linux", Filename: "fileB"},
		{OrgName: "Org1", Version: "1.0", Platform: "Linux", Filename: "fileA"},
		{OrgName: "Org2", Version: "1.0", Platform: "Linux", Filename: "fileA"},
		{OrgName: "Org1", Version: "1.1", Platform: "Linux", Filename: "fileA"},
	}

	expected := LogicalEntryKeys{
		{OrgName: "Org1", Version: "1.0", Platform: "Linux", Filename: "fileA"},
		{OrgName: "Org1", Version: "1.0", Platform: "Linux", Filename: "fileB"},
		{OrgName: "Org1", Version: "1.1", Platform: "Linux", Filename: "fileA"},
		{OrgName: "Org2", Version: "1.0", Platform: "Linux", Filename: "fileA"},
	}

	sort.Sort(keys)

	assert.Equal(t, expected, keys)
}

func TestListAllBinaries(t *testing.T) {

	appConfig := config.Application{
		DownloadPath: filepath.Join("testdata", "bin"),
		SnippetPath:  filepath.Join("testdata", "snippets"),
		FromImages: []config.BinaryFromImage{
			{
				Version: "1.3.6",
				Images: []config.Image{
					{
						Reference: "ref-1",
						Platform:  "linux/amd64",
					},
					// this makes it not configured
					//{
					//	Reference: "ref-2",
					//	Platform:  "linux/arm64",
					//},
				},
				PathsInImage: []string{
					"/usr/local/bin/busybox",
				},
			},
		},
	}

	entries, err := ListAllBinaries(appConfig)

	require.NoError(t, err)
	require.Len(t, entries, 2)

	assert.Equal(t,
		Entries{
			LogicalEntryKey{OrgName: "busybox", Version: "1.3.6", Platform: "linux-amd64", Filename: "busybox"}: EntryInfo{IsConfigured: true, BinaryPath: "testdata/bin/busybox/1.3.6/linux-amd64/busybox", SnippetPath: ""},
			LogicalEntryKey{OrgName: "busybox", Version: "1.3.6", Platform: "linux-arm64", Filename: "busybox"}: EntryInfo{IsConfigured: false, BinaryPath: "testdata/bin/busybox/1.3.6/linux-arm64/busybox", SnippetPath: ""},
		},
		entries,
	)

}

func TestListAllEntries(t *testing.T) {

	appConfig := config.Application{
		DownloadPath: filepath.Join("testdata", "bin"),
		SnippetPath:  filepath.Join("testdata", "snippets"),
		FromImages: []config.BinaryFromImage{
			{
				Version: "1.3.6",
				Images: []config.Image{
					{
						Reference: "ref-1",
						Platform:  "linux/amd64",
					},
					// this makes it not configured
					//{
					//	Reference: "ref-2",
					//	Platform:  "linux/arm64",
					//},
				},
				PathsInImage: []string{
					"/usr/local/bin/busybox",
				},
			},
		},
	}

	entries, err := ListAllEntries(appConfig)

	require.NoError(t, err)
	require.Len(t, entries, 3)

	assert.Equal(t,
		Entries{
			LogicalEntryKey{OrgName: "busybox", Version: "1.3.6", Platform: "linux-amd64", Filename: "busybox"}: EntryInfo{IsConfigured: true, BinaryPath: "testdata/bin/busybox/1.3.6/linux-amd64/busybox", SnippetPath: "testdata/snippets/busybox/1.3.6/linux-amd64/busybox"},
			LogicalEntryKey{OrgName: "busybox", Version: "1.3.6", Platform: "linux-arm64", Filename: "busybox"}: EntryInfo{IsConfigured: false, BinaryPath: "testdata/bin/busybox/1.3.6/linux-arm64/busybox", SnippetPath: "testdata/snippets/busybox/1.3.6/linux-arm64/busybox"},
			// note the standalone snippet!
			LogicalEntryKey{OrgName: "postgres", Version: "9.6.10", Platform: "linux-amd64", Filename: "postgres"}: EntryInfo{IsConfigured: false, BinaryPath: "", SnippetPath: "testdata/snippets/postgres/9.6.10/linux-amd64/postgres"},
		},
		entries,
	)

}
