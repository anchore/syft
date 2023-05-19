package java

import (
	"testing"

	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_ArchiveCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain java archive files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"java-archives/example.jar",
				"java-archives/example.war",
				"java-archives/example.ear",
				"java-archives/example.par",
				"java-archives/example.sar",
				"java-archives/example.nar",
				"java-archives/example.jpi",
				"java-archives/example.hpi",
				"java-archives/example.lpkg",
				"archives/example.zip",
				"archives/example.tar",
				"archives/example.tar.gz",
				"archives/example.tgz",
				"archives/example.tar.bz",
				"archives/example.tar.bz2",
				"archives/example.tbz",
				"archives/example.tbz2",
				"archives/example.tar.br",
				"archives/example.tbr",
				"archives/example.tar.lz4",
				"archives/example.tlz4",
				"archives/example.tar.sz",
				"archives/example.tsz",
				"archives/example.tar.xz",
				"archives/example.txz",
				"archives/example.tar.zst",
				"archives/example.tzst",
				"archives/example.tar.zstd",
				"archives/example.tzstd",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewJavaCataloger(Config{
					SearchUnindexedArchives: true,
					SearchIndexedArchives:   true,
				}))
		})
	}
}

func Test_POMCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain java pom files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"src/pom.xml",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewJavaPomCataloger())
		})
	}
}
