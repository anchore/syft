package portage

import (
	"bufio"
	"io"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/license"
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
// if the expression cannot be parsed, the extract licenses will be returned as a slice of string
func extractLicenses(reader io.Reader) (spdxExpression string, licenses []string) {
	findings := internal.NewStringSet()
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
		spdxExpression = mandatoryStatement + " AND (" + conditionalStatement + ")"
	} else if mandatoryStatement != "" {
		spdxExpression = mandatoryStatement
	} else if conditionalStatement != "" {
		spdxExpression = conditionalStatement
	}

	if _, err := license.ParseExpression(spdxExpression); err != nil {
		// the expression could not be parsed, return the licenses as a slice of strings
		licenses = findings.ToSlice()
		return
	}
	return spdxExpression, nil
}
