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
func parseGemSpecEntries(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	var fields = make(map[string]interface{})
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

	if fields["name"] != "" && fields["version"] != "" {
		var metadata gemData
		if err := mapstructure.Decode(fields, &metadata); err != nil {
			return nil, nil, fmt.Errorf("unable to decode gem metadata: %w", err)
		}

		pkgs = append(
			pkgs,
			newGemspecPackage(
				ctx,
				metadata,
				reader.Location,
			),
		)
	}

	return pkgs, nil, nil
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
