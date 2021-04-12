package deb

import (
	"bufio"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/anchore/syft/internal"
)

// For more information see: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/#license-syntax

var licensePattern = regexp.MustCompile(`^License: (?P<license>\S*)`)

func parseLicensesFromCopyright(reader io.Reader) []string {
	findings := internal.NewStringSet()
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()

		matchesByGroup := internal.MatchNamedCaptureGroups(licensePattern, line)
		if len(matchesByGroup) > 0 {
			candidate, ok := matchesByGroup["license"]
			if !ok {
				continue
			}

			candidate = strings.TrimSpace(candidate)
			if strings.Contains(candidate, " or ") || strings.Contains(candidate, " and ") {
				// this is a multi-license summary, ignore this as other recurrent license lines should cover this
				continue
			}
			if candidate != "" && strings.ToLower(candidate) != "none" {
				findings.Add(candidate)
			}
		}
	}

	results := findings.ToSlice()

	sort.Strings(results)

	return results
}
