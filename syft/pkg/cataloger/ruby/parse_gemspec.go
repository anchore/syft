package ruby

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-viper/mapstructure/v2"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseGemFileLockEntries

type postProcessor func(string) []string

type gemData struct {
	Licenses        []string `mapstructure:"licenses" json:"licenses,omitempty"`
	pkg.RubyGemspec `mapstructure:",squash" json:",inline"`
}

// match example:      Al\u003Ex   --->   003E
var unicodePattern = regexp.MustCompile(`\\u(?P<unicode>[0-9A-F]{4})`)

var patterns = map[string]*regexp.Regexp{
	// match example:       name = "railties".freeze   --->   railties
	"name": regexp.MustCompile(`.*\.name\s*=\s*["']{1}(?P<name>.*)["']{1} *`),

	// match example:       version = "1.0.4".freeze   --->   1.0.4
	"version": regexp.MustCompile(`.*\.version\s*=\s*["']{1}(?P<version>.*)["']{1} *`),

	// match example:
	// homepage = "https://github.com/anchore/syft".freeze   --->   https://github.com/anchore/syft
	"homepage": regexp.MustCompile(`.*\.homepage\s*=\s*["']{1}(?P<homepage>.*)["']{1} *`),

	// match example:       files = ["exe/bundle".freeze, "exe/bundler".freeze]    --->    "exe/bundle".freeze, "exe/bundler".freeze
	"files": regexp.MustCompile(`.*\.files\s*=\s*\[(?P<files>.*)] *`),

	// match example:       authors = ["Andr\u00E9 Arko".freeze, "Samuel Giddins".freeze, "Colby Swandale".freeze,
	//								   "Hiroshi Shibata".freeze, "David Rodr\u00EDguez".freeze, "Grey Baker".freeze...]
	"authors": regexp.MustCompile(`.*\.authors\s*=\s*\[(?P<authors>.*)] *`),

	// match example:	    licenses = ["MIT".freeze]   ----> "MIT".freeze
	"licenses": regexp.MustCompile(`.*\.licenses\s*=\s*\[(?P<licenses>.*)] *`),
}

var postProcessors = map[string]postProcessor{
	"files":    processList,
	"authors":  processList,
	"licenses": processList,
}

func processList(s string) []string {
	var results []string
	for _, item := range strings.Split(s, ",") {
		results = append(results, strings.Trim(item, "\" "))
	}
	return results
}

// parseGemSpecEntries parses the gemspec file and returns the packages and relationships found.
func parseGemSpecEntries(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	var fields = make(map[string]any)
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()

		sanitizedLine := strings.TrimSpace(line)
		sanitizedLine = strings.ReplaceAll(sanitizedLine, ".freeze", "")
		sanitizedLine = renderUtf8(sanitizedLine)

		if sanitizedLine == "" {
			continue
		}

		for field, pattern := range patterns {
			matchMap := internal.MatchNamedCaptureGroups(pattern, sanitizedLine)
			if value := matchMap[field]; value != "" {
				if pp := postProcessors[field]; pp != nil {
					fields[field] = pp(value)
				} else {
					fields[field] = value
				}
				// TODO: know that a line could actually match on multiple patterns, this is unlikely though
				break
			}
		}
	}

	resolveRubyInterpolationsInFields(fields)

	if fields["name"] != "" && fields["version"] != "" {
		var metadata gemData
		if err := mapstructure.Decode(fields, &metadata); err != nil {
			return nil, nil, fmt.Errorf("unable to decode gem metadata: %w", err)
		}

		pkgs = append(
			pkgs,
			newGemspecPackage(
				ctx,
				resolver,
				metadata,
				reader.Location,
			),
		)
	}

	return pkgs, nil, nil
}

// resolveRubyInterpolationsInFields substitutes a handful of well-known
// Ruby string interpolation placeholders (#{s.name}, #{s.version}, and
// the equivalent #{gem.*} forms) in captured gemspec string fields using
// values already captured from the same file. Gemspec authors routinely
// write things like
//
//	s.homepage = "https://github.com/foo/#{s.name}"
//
// which Ruby evaluates before loading the gem. Syft reads the gemspec as
// plain text, so without this pass the literal #{s.name} would leak into
// the SBOM and in particular break CycloneDX schema validation because
// '{' and '}' are not valid IRI characters (see anchore/syft#4720).
//
// We only resolve fields for which syft has already captured a concrete
// value, and only the simple interpolation forms pointing at those same
// fields. Any remaining unresolved interpolation in a URL-like field
// (homepage) is dropped so the output BOM is always schema-valid.
func resolveRubyInterpolationsInFields(fields map[string]any) {
	replaceIn := func(key string, placeholders []string, with string) {
		v, ok := fields[key].(string)
		if !ok || v == "" || with == "" {
			return
		}
		for _, p := range placeholders {
			v = strings.ReplaceAll(v, p, with)
		}
		fields[key] = v
	}

	// Expand known placeholders in every captured string field. We could
	// restrict this to URL-like fields, but the substitution is
	// well-scoped and any future addition of a new string field gets the
	// same behaviour for free.
	stringFields := []string{"homepage"}
	if name, ok := fields["name"].(string); ok {
		for _, k := range stringFields {
			replaceIn(k, []string{"#{s.name}", "#{gem.name}", "#{name}"}, name)
		}
	}
	if version, ok := fields["version"].(string); ok {
		for _, k := range stringFields {
			replaceIn(k, []string{"#{s.version}", "#{gem.version}", "#{version}"}, version)
		}
	}

	// Anything still containing a '#{' after best-effort substitution is
	// an unresolvable Ruby expression. Dropping URL-like fields keeps
	// the SBOM schema-valid; we would rather lose the homepage URL than
	// emit one that breaks downstream consumers.
	if v, ok := fields["homepage"].(string); ok && strings.Contains(v, "#{") {
		delete(fields, "homepage")
	}
}

// renderUtf8 takes any string escaped string subsections from the ruby string and replaces those sections with the UTF8 runes.
func renderUtf8(s string) string {
	fullReplacement := unicodePattern.ReplaceAllStringFunc(s, func(unicodeSection string) string {
		var replacement string
		// note: the json parser already has support for interpreting hex-representations of unicode escaped strings as unicode runes.
		// we can do this ourselves with strconv.Atoi, or leverage the existing json package.
		if err := json.Unmarshal([]byte(`"`+unicodeSection+`"`), &replacement); err != nil {
			return unicodeSection
		}
		return replacement
	})
	return fullReplacement
}
