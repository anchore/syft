package gentoo

import (
	"bufio"
	"io"
	"strings"

	"github.com/scylladb/go-set/strset"
)

// the licenses files seems to conform to a custom format that is common to gentoo packages.
// see more details:
//  - https://www.gentoo.org/glep/glep-0023.html#id9
//  - https://devmanual.gentoo.org/general-concepts/licenses/index.html
//
// in short, the format is:
//
//   mandatory-license
//      || ( choosable-licence1 chooseable-license-2 )
//      useflag? ( optional-component-license )
//
//   "License names may contain [a-zA-Z0-9] (english alphanumeric characters), _ (underscore), - (hyphen), .
//   (dot) and + (plus sign). They must not begin with a hyphen, a dot or a plus sign."
//
// this does not conform to SPDX license expressions, which would be a great enhancement in the future.

// extractLicenses attempts to parse the license field into a valid SPDX license expression
func extractLicenses(reader io.Reader) string {
	findings := strset.New()
	scanner := bufio.NewScanner(reader)
	scanner.Split(bufio.ScanWords)
	var (
		mandatoryLicenses, conditionalLicenses, useflagLicenses []string
		pipe                                                    bool
		useflag                                                 bool
	)

	for scanner.Scan() {
		token := scanner.Text()
		if token == "||" {
			pipe = true
			continue
		}
		// useflag
		if strings.Contains(token, "?") {
			useflag = true
			continue
		}
		if !strings.ContainsAny(token, "()|?") {
			switch {
			case useflag:
				useflagLicenses = append(useflagLicenses, token)
			case pipe:
				conditionalLicenses = append(conditionalLicenses, token)
			default:
				mandatoryLicenses = append(mandatoryLicenses, token)
			}
		}
	}

	findings.Add(mandatoryLicenses...)
	findings.Add(conditionalLicenses...)
	findings.Add(useflagLicenses...)

	var mandatoryStatement, conditionalStatement string
	// attempt to build valid SPDX license expression
	if len(mandatoryLicenses) > 0 {
		mandatoryStatement = strings.Join(mandatoryLicenses, " AND ")
	}
	if len(conditionalLicenses) > 0 {
		conditionalStatement = strings.Join(conditionalLicenses, " OR ")
	}

	if mandatoryStatement != "" && conditionalStatement != "" {
		return mandatoryStatement + " AND (" + conditionalStatement + ")"
	}

	if mandatoryStatement != "" {
		return mandatoryStatement
	}

	if conditionalStatement != "" {
		return conditionalStatement
	}

	return ""
}
