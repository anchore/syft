package fileresolver

import (
	"sort"
	"testing"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_FilesByGlob_agreesWithBruteForce is the safety net under every index shortcut.
//
// Each shortcut - the exact-name lookup, the prefix and suffix lookups, and the literal bounds that
// narrow what doublestar is shown - answers a pattern from the index rather than the archive. A
// shortcut that is too eager fails silently, returning fewer files, so every shape is checked against
// matching every path the slow way.
func Test_FilesByGlob_agreesWithBruteForce(t *testing.T) {
	paths := []string{
		"LICENSE",
		"go",
		"go.exe",
		"gopher.txt",
		"opt/a.jar",
		"opt/b.war",
		"opt/c.rar",
		"opt/notes.txt",
		"opt/app/lib/inner.jar",
		"usr/local/go/bin/go",
		"usr/lib/libstd-0123456789abcdef.so",
		"usr/lib/libstd-short.so",
		"usr/lib/libz.so",
		"usr/bin/mariadb",
		"usr/bin/mysql",
		"usr/bin/postgres",
		"var/lib/dpkg/status",
		"var/lib/dpkg/status.d/base",
		"var/lib/dpkg/status.d/nested/deep",
		"var/lib/rpm/Packages",
		"usr/lib/sysimage/rpm/rpmdb.sqlite",
		"usr/lib/firefox/firefox",
		"META-INF/MANIFEST.MF",
		"META-INF/maven/com.example/lib/pom.xml",
		"META-INF/maven/com.example/lib/pom.properties",
		"WEB-INF/lib/dep.jar",
		".hidden.jar",
		"xyz",
		"xaz",
		"lib.so",
		"log.txt",
		"mn.txt",
	}

	entries := make(map[string]string, len(paths))
	for _, p := range paths {
		entries[p] = "body of " + p
	}
	r := indexOver(t, 1<<20, entries)

	patterns := []string{
		// the shapes the index answers outright
		"**/pom.xml", "**/*.jar", "**/pom*", "**/*", "/*", "/opt/*",
		// the shapes that reach doublestar, with and without usable bounds
		"**/{go,go.exe}",
		"**/libstd-????????????????.so",
		"**/*.[jw]ar",
		"**/libstd-*.so",
		"**/*.?ar",
		"**/*o*",
		"**/?o",
		"**/{a,b}.{jar,war}",
		// segments that reduce to a finite set of names, answered by exact lookups
		"**/{mariadb,mysql}",
		"**/[lm]*",
		"**/*.{jar,war}",
		"**/pom.{xml,properties}",
		"**/{lib,libz}.so",
		"**/[a-c]*",
		"**/libstd-[s0]*.so",
		"**/x[!y]z",
		// alternations where only some branches reduce to a lookup: dropping the rest would silently
		// lose every file those branches match
		"**/{go,*}",
		"**/{lib,l}*",
		"**/{lo,m}*",
		"**/{*.jar,pom.xml}",
		// metacharacters in a middle segment, where only the leading bound is usable
		"/{META-INF,WEB-INF}/**/*.xml",
		"/usr/{bin,lib}/*",
		"/opt/*/lib/*.jar",
		"/us?/lib/libstd-*.so",
		"**/lib/**/*.jar",
		// a `**` below a selected directory, where the name it looks up also exists outside that
		// directory - the lookup is archive-wide, so only the subtree filter keeps the stranger out
		"/opt/**/*.jar",
		"/opt/**/lib/*.jar",
		"/usr/**/go",
		"/{opt,WEB-INF}/**/*.jar",
		"/META-INF/**/pom.*",
		"/usr/**/lib*.so",
		// the alternations syft's catalogers actually write, whose branches carry separators of their
		// own - splitting the pattern into segments before expanding these cuts a group in half
		"**/var/lib/dpkg/{status,status.d/**}",
		"**/var/lib/dpkg/{status,status.d/*}",
		"**/{var/lib,usr/share,usr/lib/sysimage}/rpm/{Packages,Packages.db,rpmdb.sqlite}",
		"**/{firefox,firefox.exe}",
		"**/{java,jvm}/*/release",
		// and the degenerate ones
		"**", "**/**", "/**/*.so",
	}

	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			locations, err := r.FilesByGlob(pattern)
			require.NoError(t, err)

			var got []string
			for _, loc := range locations {
				got = append(got, loc.RealPath)
			}
			sort.Strings(got)

			assert.Equal(t, bruteForceMatches(t, pattern, paths), got)
		})
	}
}

// bruteForceMatches is what the index computes faster: every path in the archive, matched one at a
// time. Patterns and paths are both archive-relative, so the leading slash is dropped from both.
func bruteForceMatches(t *testing.T, pattern string, paths []string) []string {
	t.Helper()
	trimmed := trimArchiveRoot(pattern)
	var out []string
	for _, p := range paths {
		matched, err := doublestar.Match(trimmed, p)
		require.NoError(t, err)
		if matched {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func trimArchiveRoot(pattern string) string {
	for len(pattern) > 0 && pattern[0] == '/' {
		pattern = pattern[1:]
	}
	return pattern
}
