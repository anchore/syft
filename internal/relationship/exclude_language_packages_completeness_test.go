package relationship

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/syft/pkg"
)

// binaryExtractedLanguageTypes are language types whose packages are components extracted from a single
// OS-owned binary or fat archive (cataloger tagged "binary", or a native-image/archive extractor). They
// are deliberately excluded from languageCatalogerTypes: deleting them on OS file ownership would drop
// distinct components the OS package does not actually replace. The exclusion is verified against
// cataloger capabilities by Test_languageCatalogerTypes_matchesLanguageTag.
var binaryExtractedLanguageTypes = []pkg.Type{
	pkg.GoModulePkg,           // go-module-binary-cataloger: modules built into a binary
	pkg.RustPkg,               // cargo-auditable-binary-cataloger: crates built into a binary
	pkg.DotnetPkg,             // dotnet-deps-binary-cataloger: deps of a .NET binary
	pkg.GraalVMNativeImagePkg, // graalvm-native-image-cataloger: SBOM embedded in a native image
	pkg.JavaPkg,               // java-archive-cataloger: (nested) JARs inside an OS-owned archive
}

// capCataloger is the slice of a cataloger capability file we care about here.
type capCataloger struct {
	Name         string   `yaml:"name"`
	Selectors    []string `yaml:"selectors"`
	PackageTypes []string `yaml:"package_types"`
	Parsers      []struct {
		PackageTypes []string `yaml:"package_types"`
	} `yaml:"parsers"`
}

// loadLanguageCatalogers reads syft's own cataloger capability files and returns the "language"-tagged
// catalogers. It reads the YAMLs directly rather than importing internal/capabilities, because that
// package pulls in internal/task, which imports this package (import cycle).
func loadLanguageCatalogers(t *testing.T) []capCataloger {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "syft", "pkg", "cataloger", "*", "capabilities.yaml"))
	require.NoError(t, err)
	require.NotEmpty(t, files, "no cataloger capability files found; fix the relative path")

	var out []capCataloger
	for _, f := range files {
		data, err := os.ReadFile(f)
		require.NoError(t, err)
		var doc struct {
			Catalogers []capCataloger `yaml:"catalogers"`
		}
		require.NoError(t, yaml.Unmarshal(data, &doc), "parsing %s", f)
		for _, c := range doc.Catalogers {
			if slices.Contains(c.Selectors, "language") {
				out = append(out, c)
			}
		}
	}
	require.NotEmpty(t, out, "found zero language-tagged catalogers; capability schema may have changed")
	return out
}

func (c capCataloger) types() []string {
	pts := append([]string{}, c.PackageTypes...)
	for _, p := range c.Parsers {
		pts = append(pts, p.PackageTypes...)
	}
	return pts
}

// isBinaryExtractor reports whether a cataloger extracts components from a single binary/archive
// artifact (so OS ownership of that artifact does not subsume the components).
func (c capCataloger) isBinaryExtractor() bool {
	if slices.Contains(c.Selectors, "binary") {
		return true
	}
	// some extractors are not tagged with the "binary" selector (e.g. dotnet-deps-binary-cataloger),
	// so also match the cataloger name shape.
	for _, frag := range []string{"binary", "native-image", "archive"} {
		if strings.Contains(c.Name, frag) {
			return true
		}
	}
	return false
}

// Test_languageCatalogerTypes_matchesLanguageTag enforces the inclusion rule documented on
// languageCatalogerTypes:
//
//	languageCatalogerTypes == {types of "language"-tagged catalogers} \ osCatalogerTypes
//	                          \ binaryExtractedLanguageTypes  (+ documented exceptions)
//
// The expectation is derived from syft's own cataloger capability files, so a new language cataloger
// (or a new pkg.Type on one) fails this test until the lists are updated — an omission can no longer
// slip through silently (the original hand-maintained list missed 9 such installed-package types).
func Test_languageCatalogerTypes_matchesLanguageTag(t *testing.T) {
	// types intentionally present in languageCatalogerTypes even though no language-tagged cataloger
	// emits them in the capability files. Keep this tiny and explained.
	exceptions := map[pkg.Type]string{
		// php-pecl is emitted only by the deprecated (DeprecatedTag, not language-tagged) pecl cataloger;
		// its packages still overlap OS packages until the cataloger is removed in syft v2.0.
		pkg.PhpPeclPkg: "deprecated php-pecl cataloger (not language-tagged)",
	}

	cats := loadLanguageCatalogers(t)

	osTypes := map[string]struct{}{}
	for _, ty := range osCatalogerTypes {
		osTypes[string(ty)] = struct{}{}
	}
	excluded := map[string]struct{}{}
	for _, ty := range binaryExtractedLanguageTypes {
		excluded[string(ty)] = struct{}{}
	}

	// every excluded type must actually be (a) emitted by a language-tagged cataloger and (b) emitted by
	// a binary/archive extractor — otherwise the exclusion is stale or unjustified.
	emittedByExtractor := map[string]bool{}
	languageTagged := map[string]struct{}{}
	for _, c := range cats {
		for _, pt := range c.types() {
			languageTagged[pt] = struct{}{}
			if c.isBinaryExtractor() {
				emittedByExtractor[pt] = true
			}
		}
	}
	for _, ty := range binaryExtractedLanguageTypes {
		s := string(ty)
		_, isLang := languageTagged[s]
		require.True(t, isLang, "binaryExtractedLanguageTypes lists %q but no language-tagged cataloger emits it", s)
		require.True(t, emittedByExtractor[s], "binaryExtractedLanguageTypes lists %q but no binary/archive extractor emits it; exclusion unjustified", s)
	}

	// derive expected: language-tagged, minus OS types, minus binary-extracted types
	want := map[string]struct{}{}
	for s := range languageTagged {
		if _, isOS := osTypes[s]; isOS {
			continue
		}
		if _, isExcluded := excluded[s]; isExcluded {
			continue
		}
		want[s] = struct{}{}
	}

	// every documented exception must actually be present in the production list (else the exception is dead
	// and the list silently lost a type) — this guards the false-pass codex flagged.
	listed := map[pkg.Type]struct{}{}
	for _, ty := range languageCatalogerTypes {
		listed[ty] = struct{}{}
	}
	for ty, reason := range exceptions {
		_, ok := listed[ty]
		require.True(t, ok, "exception %q (%s) is documented but missing from languageCatalogerTypes", ty, reason)
	}

	got := map[string]struct{}{}
	for _, ty := range languageCatalogerTypes {
		if _, ok := exceptions[ty]; ok {
			continue // exceptions are allowed to be absent from the derived set
		}
		got[string(ty)] = struct{}{}
	}

	var missing, extra []string
	for s := range want {
		if _, ok := got[s]; !ok {
			missing = append(missing, s)
		}
	}
	for s := range got {
		if _, ok := want[s]; !ok {
			extra = append(extra, s)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)

	require.Empty(t, missing, "installed-package language types missing from languageCatalogerTypes (add them, or document an exception): %v", missing)
	require.Empty(t, extra, "types in languageCatalogerTypes that are not installed-package language types (remove them, exclude as binary-extracted, or add to exceptions): %v", extra)
}
