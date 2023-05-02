package r

import (
	"bufio"
	"io"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
)

/* some examples of license strings found in DESCRIPTION files:
find /usr/local/lib/R -name DESCRIPTION | xargs cat | grep 'License:' | sort | uniq
License: GPL
License: GPL (>= 2)
License: GPL (>=2)
License: GPL(>=2)
License: GPL (>= 2) | file LICENCE
License: GPL-2 | GPL-3
License: GPL-3
License: LGPL (>= 2)
License: LGPL (>= 2.1)
License: MIT + file LICENSE
License: Part of R 4.3.0
License: Unlimited
*/

func parseDescriptionFile(_ source.FileResolver, _ *generic.Environment, reader source.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	values := extractFieldsFromDescriptionFile(reader)
	m := parseDataFromDescriptionMap(values)
	return []pkg.Package{newPackage(m, []source.Location{reader.Location}...)}, nil, nil
}

type parseData struct {
	Package string
	Version string
	License string
	pkg.RDescriptionFileMetadata
}

func parseDataFromDescriptionMap(values map[string]string) parseData {
	return parseData{
		License: values["License"],
		Package: values["Package"],
		Version: values["Version"],
		RDescriptionFileMetadata: pkg.RDescriptionFileMetadata{
			Title:            values["Title"],
			Description:      cleanMultiLineValue(values["Description"]),
			Maintainer:       values["Maintainer"],
			URL:              commaSeparatedList(values["URL"]),
			Depends:          commaSeparatedList(values["Depends"]),
			Imports:          commaSeparatedList(values["Imports"]),
			Suggests:         commaSeparatedList(values["Suggests"]),
			NeedsCompilation: yesNoToBool(values["NeedsCompilation"]),
			Author:           values["Author"],
			Repository:       values["Repository"],
			Built:            values["Built"],
		},
	}
}

func yesNoToBool(s string) bool {
	return strings.EqualFold(s, "yes")
}

func commaSeparatedList(s string) []string {
	var result []string
	split := strings.Split(s, ",")
	for _, piece := range split {
		value := strings.TrimSpace(piece)
		if value == "" {
			continue
		}
		result = append(result, value)
	}
	return result
}

var space = regexp.MustCompile(`\s+`)

func cleanMultiLineValue(s string) string {
	return space.ReplaceAllString(s, " ")
}

func extractFieldsFromDescriptionFile(reader io.Reader) map[string]string {
	result := make(map[string]string)
	key := ""
	var valueFragment strings.Builder
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()
		// line is like Key: Value -> start capturing value; close out previous value
		// line is like \t\t continued value -> append to existing value
		if len(line) == 0 {
			continue
		}
		if startsWithWhitespace(line) {
			// we're continuing a value
			if key == "" {
				continue
			}
			valueFragment.WriteByte('\n')
			valueFragment.WriteString(strings.TrimSpace(line))
		} else {
			if key != "" {
				// capture previous value
				result[key] = valueFragment.String()
				key = ""
				valueFragment = strings.Builder{}
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key = parts[0]
			valueFragment.WriteString(strings.TrimSpace(parts[1]))
		}
	}
	if key != "" {
		result[key] = valueFragment.String()
	}
	return result
}

func startsWithWhitespace(s string) bool {
	if s == "" {
		return false
	}
	return s[0] == ' ' || s[0] == '\t'
}
