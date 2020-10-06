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

// for line in gem.splitlines():
// line = line.strip()
// line = re.sub(r"\.freeze", "", line)

// # look for the unicode \u{} format and try to convert to something python can use
// patt = re.match(r".*\.homepage *= *(.*) *", line)
// if patt:
// 	sourcepkg = json.loads(patt.group(1))

// patt = re.match(r".*\.licenses *= *(.*) *", line)
// if patt:
// 	lstr = re.sub(r"^\[|\]$", "", patt.group(1)).split(',')
// 	for thestr in lstr:
// 		thestr = re.sub(' *" *', "", thestr)
// 		lics.append(thestr)

// patt = re.match(r".*\.authors *= *(.*) *", line)
// if patt:
// 	lstr = re.sub(r"^\[|\]$", "", patt.group(1)).split(',')
// 	for thestr in lstr:
// 		thestr = re.sub(' *" *', "", thestr)
// 		origins.append(thestr)

// patt = re.match(r".*\.files *= *(.*) *", line)
// if patt:
// 	lstr = re.sub(r"^\[|\]$", "", patt.group(1)).split(',')
// 	for thestr in lstr:
// 		thestr = re.sub(' *" *', "", thestr)
// 		rfiles.append(thestr)

type listProcessor func(string) []string

var patterns = map[string]*regexp.Regexp{
	// match example:       name = "railties".freeze   --->   railties
	"name": regexp.MustCompile(`.*\.name\s*=\s*["']{1}(?P<name>.*)["']{1} *`),
	// match example:       version = "1.0.4".freeze   --->   1.0.4
	"version": regexp.MustCompile(`.*\.version\s*=\s*["']{1}(?P<version>.*)["']{1} *`),
	// match example:       homepage = "https://github.com/anchore/syft".freeze   --->   https://github.com/anchore/syft
	"homepage": regexp.MustCompile(`.*\.homepage\s*=\s*["']{1}(?P<homepage>.*)["']{1} *`),
	// TODO: add more fields
}

// TODO: use post processors for lists
var postProcessors = map[string]listProcessor{
	//"files": func(s string) []string {
	//
	//},
}

func parseGemSpecEntries(_ string, reader io.Reader) ([]pkg.Package, error) {
	var pkgs []pkg.Package
	var fields = make(map[string]interface{})
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()

		// TODO: sanitize unicode? (see engine code)
		sanitizedLine := strings.TrimSpace(line)

		if sanitizedLine == "" {
			continue
		}

		for field, pattern := range patterns {
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
