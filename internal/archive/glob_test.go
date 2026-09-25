package archive

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var globFixture = map[string]string{
	"one/two/athing":                    "a",
	"one/two/deep/er/zthing":            "z",
	"one/two/Athing":                    "A",
	"two/athing":                        "not under one",
	"x/one/two/bthing":                  "b",
	"onefoo/bartwo/deep/something":      "s",
	"onefoo/bartwo/nothing":             "n",
	"one/bartwo/something":              "no one* dir",
	"usr/local/go/bin/go":               "bin",
	"usr/local/go/bin/go.exe":           "bin",
	"usr/lib/rustlib/libstd-0123.so":    "lib",
	"usr/lib/libstd-0123.a":             "lib",
	"var/lib/dpkg/status":               "dpkg",
	"var/lib/dpkg/status.d/base":        "dpkg",
	"var/lib/dpkg/status.d/deep/thing":  "dpkg",
	"opt/a.jar":                         "PK",
	"opt/b.war":                         "PK",
	"opt/c.ear":                         "PK",
	"opt/notes.txt":                     "prose",
	"LICENSE":                           "root file",
	".hidden/secret.jar":                "dotdir",
	"META-INF/maven/g/a/pom.xml":        "pom",
	"META-INF/maven/g/a/pom.properties": "pom",
	"weird/a]b/x":                       "class edge",
	"weird/a-b/x":                       "class edge",
	"java/openjdk-21/release":           "jvm",
	"jvm/zulu-17/release":               "jvm",
	"go":                                "root binary",
	"gopher.txt":                        "prose",
	"opt/c.rar":                         "not a jar",
	"opt/app/lib/inner.jar":             "PK",
	"usr/lib/libstd-short.so":           "lib",
	"usr/lib/libz.so":                   "lib",
	"usr/bin/mariadb":                   "bin",
	"usr/bin/mysql":                     "bin",
	"usr/bin/postgres":                  "bin",
	"var/lib/rpm/Packages":              "rpm",
	"usr/lib/sysimage/rpm/rpmdb.sqlite": "rpm",
	"usr/lib/firefox/firefox":           "bin",
	"META-INF/MANIFEST.MF":              "manifest",
	"WEB-INF/lib/dep.jar":               "PK",
	".hidden.jar":                       "dotfile",
	"xyz":                               "class edge",
	"xaz":                               "class edge",
	"lib.so":                            "root lib",
	"log.txt":                           "prose",
	"mn.txt":                            "prose",
}

// every shape the catalogers use, plus the ones that exercise narrowing and its edges
var globPatterns = []string{
	"**/one/two/**/[a-z]thing",
	"**/one*/*two/**/[s]omething",
	"**/one/two/*",
	"**/one/two/**",
	"**/two/**",
	"/one/**",
	"one/two/athing",
	"/*",
	"*",
	"**/*",
	"**",
	"**/{go,go.exe}",
	"**/*.{jar,war}",
	"**/{opt,usr}/**/*.{jar,so}",
	"**/var/lib/dpkg/{status,status.d/**}",
	"**/{a,{b,c}}.{jar,war,ear}",
	"**/g{o,o.exe}",
	"**/{[a]b,cd}",
	"**/*{,.exe}",
	"**/{one,x/one}/two/*thing",
	"**/*.[jw]ar",
	"**/[!a]thing",
	"**/[^a]thing",
	"**/libstd-????.so",
	"**/libstd-*",
	"**/*thing",
	"**/pom.*",
	"**/maven/*/*/pom.xml",
	"**/{java,jvm}/*/release",
	"**/*-17/release",
	"**/a]b/x",
	"**/.hidden/*.jar",
	"**/*.jar",
	"**/status",
	"**/status.d/**",
	"**/deep/**/*thing",
	"**/nothing/**",
	"nope/**",
	"",
	"/",
	"**/one//two/athing",
	"**/a\\]b/x",
	"**/pom*",
	"/opt/*",
	"/META-INF/*",
	"**/*.?ar",
	"**/*o*",
	"**/?o",
	"**/{mariadb,mysql}",
	"**/[lm]*",
	"**/pom.{xml,properties}",
	"**/{lib,libz}.so",
	"**/[a-c]*",
	"**/libstd-[s0]*.so",
	"**/x[!y]z",
	"**/{go,*}",
	"**/{lib,l}*",
	"**/{lo,m}*",
	"**/{*.jar,pom.xml}",
	"/{META-INF,WEB-INF}/**/*.xml",
	"/usr/{bin,lib}/*",
	"/opt/*/lib/*.jar",
	"/us?/lib/libstd-*.so",
	"**/lib/**/*.jar",
	// the name looked up also exists outside the selected directory
	"/opt/**/*.jar",
	"/opt/**/lib/*.jar",
	"/usr/**/go",
	"/{opt,WEB-INF}/**/*.jar",
	"/META-INF/**/pom.*",
	"/usr/**/lib*.so",
	// alternations whose branches carry separators, as syft's catalogers write them
	"**/var/lib/dpkg/{status,status.d/*}",
	"**/{var/lib,usr/share,usr/lib/sysimage}/rpm/{Packages,Packages.db,rpmdb.sqlite}",
	"**/{firefox,firefox.exe}",
	"**/**",
	"/**/*.so",
}

// every pattern shape is checked against matching every path the slow way, since a name-index
// shortcut that is too eager fails silently by returning fewer files
func TestGlob_agreesWithDoublestar(t *testing.T) {
	r := resolverOver(t, 1<<20, globFixture)
	var all []string
	for _, n := range r.files {
		all = append(all, reportedPath(n.path))
	}

	for _, pattern := range globPatterns {
		t.Run(pattern, func(t *testing.T) {
			// paths are archive-relative, so a leading slash anchors at the archive root
			var want []string
			for _, p := range all {
				ok, err := doublestar.Match(strings.TrimLeft(pattern, "/"), p)
				require.NoError(t, err)
				if ok {
					want = append(want, p)
				}
			}
			sort.Strings(want)

			locations, err := r.FilesByGlob(pattern)
			require.NoError(t, err)
			assert.Equal(t, want, realPaths(locations))
		})
	}
}

func TestGlob_narrowsByDirectory(t *testing.T) {
	// enough files share the last segment's suffix that the directories in the pattern narrow better
	entries := map[string]string{}
	for k, v := range globFixture {
		entries[k] = v
	}
	for i := range 100 {
		entries[fmt.Sprintf("noise/f%03dthing", i)] = "x"
		entries[fmt.Sprintf("noise/d%03d/something", i)] = "x"
	}
	r := resolverOver(t, 1<<20, entries)

	tests := []struct {
		pattern string
		want    int // candidates considered
	}{
		{"**/one/two/**/[a-z]thing", 5}, // everything under a directory named `one`
		{"**/one*/*two/**/[s]omething", 7},
		{"**/dpkg/**", 3},
		{"**/[a-z]thing", 209}, // the file-name suffix alone
		{"**/[lm]*", len(r.files)},
		{"**/*", len(r.files)},
		{"**/g{o,o.exe}", 3},
		{"**/{d00*,f00*}/**", 10}, // ten directories d000-d009 narrow; f00* names no directory
		{"**/{*,cd}", len(r.files)},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			candidates, _ := r.globCandidates(parseGlob(tt.pattern)[0])
			assert.Len(t, candidates, tt.want)
		})
	}
}

func TestGlob_exactLookupsSkipVerification(t *testing.T) {
	r := resolverOver(t, 1<<20, globFixture)
	for pattern, exact := range map[string]bool{
		"**/pom.xml":       true,
		"**/*.jar":         true,
		"**/libstd-*":      true,
		"**/pom.*":         true,
		"**/p*m.xml":       false, // narrowed by an end, but the middle still has to be checked
		"**/g{o,o.exe}":    true,
		"**/*.{jar,war}":   true,
		"**/{[a]b,cd}":     false,
		"**/{*,cd}":        false,
		"**/*thing":        true,
		"**/[a-z]thing":    false,
		"/opt/*.jar":       false,
		"**/maven/pom.xml": false,
	} {
		_, got := r.globCandidates(parseGlob(pattern)[0])
		assert.Equal(t, exact, got, pattern)
	}
}

func Test_expandBraces(t *testing.T) {
	tests := []struct {
		pattern string
		want    []string
	}{
		{"**/*.jar", []string{"**/*.jar"}},
		{"**/{go,go.exe}", []string{"**/go", "**/go.exe"}},
		{"**/{a,{b,c}}.{jar,war}", []string{"**/a.jar", "**/a.war", "**/b.jar", "**/b.war", "**/c.jar", "**/c.war"}},
		{"**/dpkg/{status,status.d/**}", []string{"**/dpkg/status", "**/dpkg/status.d/**"}},
		{"**/{lone", []string{"**/{lone"}},
		{"**/lone}", []string{"**/lone}"}},
		{"**/\\{not,a,group\\}", []string{"**/\\{not,a,group\\}"}},
		{"{,a}", []string{"", "a"}},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, expandBraces(tt.pattern), tt.pattern)
	}
}

func Test_literalEnds(t *testing.T) {
	tests := []struct {
		seg            string
		prefix, suffix string
		plain          bool
	}{
		{"pom.xml", "pom.xml", "", true},
		{"*.jar", "", ".jar", false},
		{"libstd-*", "libstd-", "", false},
		{"[a-z]thing", "", "thing", false},
		{"libstd-????.so", "libstd-", ".so", false},
		{"a*b*c", "a", "c", false},
		{"*", "", "", false},
		{"a]b", "a]b", "", true},
		{"a[]-]b", "a", "b", false},
		{"a[^]]b", "a", "b", false},
		{"a\\*b", "a", "b", false},
		{"a\\", "a", "", false},
		{"a[b", "a", "", false},
	}
	for _, tt := range tests {
		prefix, suffix, plain := literalEnds(tt.seg)
		assert.Equal(t, []any{tt.prefix, tt.suffix, tt.plain}, []any{prefix, suffix, plain}, tt.seg)
	}
}

// every pattern but the last two is one syft's own catalogers register
func BenchmarkResolver_FilesByGlob(b *testing.B) {
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
func benchArchive(tb testing.TB) *Resolver {
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
	return resolverOver(tb, 1<<26, entries)
}
