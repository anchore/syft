package archive

import (
	"fmt"
	"testing"
)

// every pattern but the last two is one syft's own catalogers register
func BenchmarkIndex_FilesByGlob(b *testing.B) {
	r := benchArchive(b)

	patterns := map[string]string{
		"exact-name":           "**/go",
		"extension":            "**/*.jar",
		"alternation":          "**/{go,go.exe}",
		"question-marks":       "**/libstd-????????????????.so",
		"alternation-suffix":   "**/*.{jar,war}",
		"alternation-with-sep": "**/var/lib/dpkg/{status,status.d/**}",
		"alternation-both-ends": "**/{var/lib,usr/share,usr/lib/sysimage}/rpm/" +
			"{Packages,Packages.db,rpmdb.sqlite}",
		"alternation-mid-segment": "**/{java,jvm}/*/release",
		"alternation-mid-path":    "/{usr,opt}/**/*.jar",
		"class-in-extension":      "**/*.[jw]ar",
		"many-matches":            "**/[lm]*",
	}

	for name, pattern := range patterns {
		b.Run(name, func(b *testing.B) {
			for b.Loop() {
				if _, err := r.FilesByGlob(pattern); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// benchArchive is shaped like a fat application image layer: thousands of entries with distinct base
// names, plus decoys sharing the prefixes and suffixes the patterns fix, so no lookup looks free.
func benchArchive(tb testing.TB) *Index {
	tb.Helper()
	entries := map[string]string{
		"usr/local/go/bin/go":                        "binary",
		"usr/lib/rustlib/libstd-0123456789abcdef.so": "binary",
		"usr/bin/mariadb":                            "binary",
		"opt/app/lib/app.jar":                        "PK\x03\x04",
		"opt/app/lib/dep.war":                        "PK\x03\x04",
		"var/lib/dpkg/status":                        "dpkg",
		"var/lib/dpkg/status.d/base":                 "dpkg",
		"var/lib/rpm/Packages":                       "rpm",
		"usr/lib/jvm/java-21/release":                "jvm",
	}
	for i := range 1500 {
		entries[fmt.Sprintf("var/cache/archive%04d.tar", i)] = "data"
		entries[fmt.Sprintf("var/cache/bundle%04d.rar", i)] = "data"
		entries[fmt.Sprintf("usr/share/cal%04dendar", i)] = "data"
		entries[fmt.Sprintf("usr/share/gopher%04d.md", i)] = "docs"
		entries[fmt.Sprintf("usr/lib/libstd-%04d.a", i)] = "archive"
		entries[fmt.Sprintf("usr/lib/mod%04d.py", i)] = "code"
		entries[fmt.Sprintf("usr/share/doc/pkg%04d/NOTES%04d.md", i, i)] = "docs"
	}
	return indexOver(tb, 1<<26, entries)
}
