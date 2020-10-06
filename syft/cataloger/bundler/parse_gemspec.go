package bundler

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/mitchellh/mapstructure"

	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
)

// integrity check
var _ common.ParserFn = parseGemFileLockEntries

type postProcessor func(string) []string

var patterns = map[string]*regexp.Regexp{
	// match example:       name = "railties".freeze   --->   railties
	"name": regexp.MustCompile(`.*\.name\s*=\s*["']{1}(?P<name>.*)["']{1} *`),

	// match example:       version = "1.0.4".freeze   --->   1.0.4
	"version": regexp.MustCompile(`.*\.version\s*=\s*["']{1}(?P<version>.*)["']{1} *`),

	// match example:
	// homepage = "https://github.com/anchore/syft".freeze   --->   https://github.com/anchore/syft
	"homepage": regexp.MustCompile(`.*\.homepage\s*=\s*["']{1}(?P<homepage>.*)["']{1} *`),

	// match example:       files = ["exe/bundle".freeze, "exe/bundler".freeze]    --->    "exe/bundle".freeze, "exe/bundler".freeze
	"files": regexp.MustCompile(`.*\.files\s*=\s*\[(?P<files>.*)\] *`),

	// match example:       authors = ["Andr\u00E9 Arko".freeze, "Samuel Giddins".freeze, "Colby Swandale".freeze,
	//								   "Hiroshi Shibata".freeze, "David Rodr\u00EDguez".freeze, "Grey Baker".freeze...]
	"authors": regexp.MustCompile(`.*\.authors\s*=\s*\[(?P<authors>.*)\] *`),

	// match example:	    licenses = ["MIT".freeze]   ----> "MIT".freeze
	"licenses": regexp.MustCompile(`.*\.licenses\s*=\s*\[(?P<licenses>.*)\] *`),
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

func parseGemSpecEntries(_ string, reader io.Reader) ([]pkg.Package, error) {
	var pkgs []pkg.Package
	var fields = make(map[string]interface{})
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()

		// TODO: sanitize unicode? (see engine code)
		sanitizedLine := strings.TrimSpace(line)
		sanitizedLine = strings.ReplaceAll(sanitizedLine, ".freeze", "")

		if sanitizedLine == "" {
			continue
		}

		for field, pattern := range patterns {
			if strings.Contains(sanitizedLine, "licenses") {
				println("Found it.")
			}
			matchMap := matchCaptureGroups(pattern, sanitizedLine)
			if value := matchMap[field]; value != "" {
				if postProcessor := postProcessors[field]; postProcessor != nil {
					fields[field] = postProcessor(value)
				} else {
					fields[field] = value
				}
				// TODO: know that a line could actually match on multiple patterns, this is unlikely though
				break
			}
		}
	}

	if fields["name"] != "" && fields["version"] != "" {
		var metadata pkg.GemMetadata
		if err := mapstructure.Decode(fields, &metadata); err != nil {
			return nil, fmt.Errorf("unable to decode gem metadata: %w", err)
		}

		pkgs = append(pkgs, pkg.Package{
			Name:     metadata.Name,
			Version:  metadata.Version,
			Licenses: metadata.Licenses,
			Language: pkg.Ruby,
			Type:     pkg.GemPkg,
			Metadata: metadata,
		})
	}

	return pkgs, nil
}

// matchCaptureGroups takes a regular expression and string and returns all of the named capture group results in a map.
func matchCaptureGroups(regEx *regexp.Regexp, str string) map[string]string {
	match := regEx.FindStringSubmatch(str)
	results := make(map[string]string)
	for i, name := range regEx.SubexpNames() {
		if i > 0 && i <= len(match) {
			results[name] = match[i]
		}
	}
	return results
}
