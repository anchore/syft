package fileresolver

import (
	"fmt"
	"testing"
)

// BenchmarkArchiveIndex_FilesByGlob covers the shapes a cataloger asks for: the ones the name index
// answers outright, the ones reducing to a finite set of lookups, and the ones reaching doublestar
// over whatever the literal bounds narrow them to.
//
// Every pattern but the last two is one syft's own catalogers register, verbatim. That matters because
// a benchmark of invented patterns measures the wrong thing: no cataloger glob uses a character class,
// so `class-in-extension` is kept for coverage rather than as a cost anyone pays, and `many-matches`
// is a control - it matches thousands of files, so it measures building and sorting locations rather
// than finding them, and is expected to stay flat while the others improve.
func BenchmarkArchiveIndex_FilesByGlob(b *testing.B) {
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

// benchArchive is shaped like a fat application image layer: thousands of entries with thousands of
// distinct base names, spread over nested directories.
//
// The names must be distinct: an archive whose files are all called README.md puts two keys in the
// name index and makes every lookup look free. The decoys serve the same purpose - names ending "ar"
// that are not archives, names beginning "go" that are not the go binary - separating a lookup keyed
// on a whole extension from one keyed on the two characters a weak bound fixes.
func benchArchive(tb testing.TB) *ArchiveIndex {
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
		// decoys for the weak tail bound "ar" that `*.[jw]ar` and `*.{jar,war}` would share
		entries[fmt.Sprintf("var/cache/archive%04d.tar", i)] = "data"
		entries[fmt.Sprintf("var/cache/bundle%04d.rar", i)] = "data"
		entries[fmt.Sprintf("usr/share/cal%04dendar", i)] = "data"
		// decoys for the head bound "go"
		entries[fmt.Sprintf("usr/share/gopher%04d.md", i)] = "docs"
		// decoys for the head bounds "l" and "m", and for "libstd-"
		entries[fmt.Sprintf("usr/lib/libstd-%04d.a", i)] = "archive"
		entries[fmt.Sprintf("usr/lib/mod%04d.py", i)] = "code"
		// ordinary bulk, with distinct names
		entries[fmt.Sprintf("usr/share/doc/pkg%04d/NOTES%04d.md", i, i)] = "docs"
	}
	return indexOver(tb, 1<<26, entries)
}
