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

// match the common Ruby string-interpolation forms gemspec authors use to build
// fields from the gem's own name/version: #{s.name}, #{gem.name}, #{spec.version},
// bare #{name}, and the same with surrounding whitespace. The optional receiver
// (s./gem./spec./...) is discarded; only the trailing attribute is captured.
var rubyInterpolationPattern = regexp.MustCompile(`#\{\s*(?:\w+\.)?(name|version)\s*\}`)

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
// We only resolve interpolations pointing at name/version (the values syft has
// already captured from the same file). Both the substitution and the drop
// below are driven by the same field list, so adding a URL-like field here
// keeps it protected from leaking unresolved interpolation.
func resolveRubyInterpolationsInFields(fields map[string]any) {
	name, _ := fields["name"].(string)
	version, _ := fields["version"].(string)

	// homepage is currently the only captured string field that flows into a
	// schema-validated URL slot (CycloneDX externalReferences, SPDX homepage).
	for _, key := range []string{"homepage"} {
		v, ok := fields[key].(string)
		if !ok || v == "" {
			continue
		}

		v = rubyInterpolationPattern.ReplaceAllStringFunc(v, func(match string) string {
			switch rubyInterpolationPattern.FindStringSubmatch(match)[1] {
			case "name":
				if name != "" {
					return name
				}
			case "version":
				if version != "" {
					return version
				}
			}
			return match // leave unresolved; the field is dropped below
		})

		// anything still containing a '#{' is an unresolvable Ruby expression.
		// Drop the field rather than emit a URL with '{'/'}', which fails
		// CycloneDX IRI validation (see anchore/syft#4720); a missing homepage
		// is preferable to a BOM downstream tools reject.
		if strings.Contains(v, "#{") {
			delete(fields, key)
			continue
		}
		fields[key] = v
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
