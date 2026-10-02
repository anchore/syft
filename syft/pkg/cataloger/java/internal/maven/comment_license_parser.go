package maven

import (
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/spdxlicense"
)

var (
	xmlCommentPattern = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	licenseURLPattern = regexp.MustCompile(`https?://[^\s<>"')]+`)
	spdxIDPattern     = regexp.MustCompile(`(?i)\b(?:Apache-2\.0|MIT|BSD-2-Clause|BSD-3-Clause|BSD-4-Clause|ISC|MPL-2\.0|EPL-1\.0|EPL-2\.0|CDDL-1\.0|Unlicense|GPL-2\.0(?:-only|-or-later|\+)?|GPL-3\.0(?:-only|-or-later|\+)?|LGPL-2\.1(?:-only|-or-later|\+)?|LGPL-3\.0(?:-only|-or-later|\+)?|AGPL-3\.0(?:-only|-or-later|\+)?)\b`)
)

var commentLicenseMatchers = []struct {
	pattern *regexp.Regexp
	spdxID  string
}{
	{pattern: regexp.MustCompile(`(?i)\bapache(?: software)? license(?:,\s*version|\s+version)?\s+2(?:\.0)?\b`), spdxID: "Apache-2.0"},
	{pattern: regexp.MustCompile(`(?i)\bmit license\b`), spdxID: "MIT"},
	{pattern: regexp.MustCompile(`(?i)\bisc license\b`), spdxID: "ISC"},
	{pattern: regexp.MustCompile(`(?i)\bunlicense\b`), spdxID: "Unlicense"},
	{pattern: regexp.MustCompile(`(?i)\bbsd[\s-]+2[\s-]+clause license\b`), spdxID: "BSD-2-Clause"},
	{pattern: regexp.MustCompile(`(?i)\bbsd[\s-]+3[\s-]+clause license\b`), spdxID: "BSD-3-Clause"},
	{pattern: regexp.MustCompile(`(?i)\bbsd[\s-]+4[\s-]+clause license\b`), spdxID: "BSD-4-Clause"},
	{pattern: regexp.MustCompile(`(?i)\bmozilla public license(?:,\s*version|\s+version)?\s+2(?:\.0)?\b`), spdxID: "MPL-2.0"},
	{pattern: regexp.MustCompile(`(?i)\beclipse public license(?:,\s*version|\s+version)?\s+1(?:\.0)?\b`), spdxID: "EPL-1.0"},
	{pattern: regexp.MustCompile(`(?i)\beclipse public license(?:,\s*version|\s+version)?\s+2(?:\.0)?\b`), spdxID: "EPL-2.0"},
	{pattern: regexp.MustCompile(`(?i)\bcommon development and distribution license(?:,\s*version|\s+version)?\s+1(?:\.0)?\b`), spdxID: "CDDL-1.0"},
	{pattern: regexp.MustCompile(`(?i)\bgnu general public license(?:,\s*version|\s+version)?\s+2(?:\.0)?\s+or later\b`), spdxID: "GPL-2.0-or-later"},
	{pattern: regexp.MustCompile(`(?i)\bgnu general public license(?:,\s*version|\s+version)?\s+2(?:\.0)?\b`), spdxID: "GPL-2.0-only"},
	{pattern: regexp.MustCompile(`(?i)\bgnu general public license(?:,\s*version|\s+version)?\s+3(?:\.0)?\s+or later\b`), spdxID: "GPL-3.0-or-later"},
	{pattern: regexp.MustCompile(`(?i)\bgnu general public license(?:,\s*version|\s+version)?\s+3(?:\.0)?\b`), spdxID: "GPL-3.0-only"},
	{pattern: regexp.MustCompile(`(?i)\bgnu lesser general public license(?:,\s*version|\s+version)?\s+2\.1\s+or later\b`), spdxID: "LGPL-2.1-or-later"},
	{pattern: regexp.MustCompile(`(?i)\bgnu lesser general public license(?:,\s*version|\s+version)?\s+2\.1\b`), spdxID: "LGPL-2.1-only"},
	{pattern: regexp.MustCompile(`(?i)\bgnu lesser general public license(?:,\s*version|\s+version)?\s+3(?:\.0)?\s+or later\b`), spdxID: "LGPL-3.0-or-later"},
	{pattern: regexp.MustCompile(`(?i)\bgnu lesser general public license(?:,\s*version|\s+version)?\s+3(?:\.0)?\b`), spdxID: "LGPL-3.0-only"},
	{pattern: regexp.MustCompile(`(?i)\bgnu affero general public license(?:,\s*version|\s+version)?\s+3(?:\.0)?\s+or later\b`), spdxID: "AGPL-3.0-or-later"},
	{pattern: regexp.MustCompile(`(?i)\bgnu affero general public license(?:,\s*version|\s+version)?\s+3(?:\.0)?\b`), spdxID: "AGPL-3.0-only"},
}

func ExtractLicensesFromComments(rawXML string) []License {
	type detectedLicense struct {
		name string
		url  string
	}

	if rawXML == "" {
		return nil
	}

	comments := xmlCommentPattern.FindAllStringSubmatch(rawXML, -1)
	if len(comments) == 0 {
		return nil
	}

	detected := make(map[string]*detectedLicense)
	var order []string
	add := func(key, name, url string) {
		if key == "" {
			return
		}
		license, exists := detected[key]
		if !exists {
			license = &detectedLicense{}
			detected[key] = license
			order = append(order, key)
		}
		if license.name == "" {
			license.name = name
		}
		if license.url == "" {
			license.url = url
		}
	}

	for _, match := range comments {
		if len(match) < 2 {
			continue
		}
		comment := match[1]

		for _, url := range licenseURLPattern.FindAllString(comment, -1) {
			url = strings.TrimRight(strings.TrimSpace(url), ".,:;)")
			if info, found := spdxlicense.LicenseByURL(url); found {
				add(info.ID, info.ID, url)
			}
		}

		for _, matcher := range commentLicenseMatchers {
			if matcher.pattern.MatchString(comment) {
				if canonicalID, ok := spdxlicense.ID(matcher.spdxID); ok {
					add(canonicalID, canonicalID, "")
				}
			}
		}

		for _, spdxID := range spdxIDPattern.FindAllString(comment, -1) {
			if canonicalID, ok := spdxlicense.ID(spdxID); ok {
				add(canonicalID, canonicalID, "")
			}
		}
	}

	var out []License
	for _, key := range order {
		license := detected[key]
		if license == nil || (license.name == "" && license.url == "") {
			continue
		}

		var name, url *string
		if license.name != "" {
			name = &license.name
		}
		if license.url != "" {
			url = &license.url
		}
		out = append(out, License{
			Name: name,
			URL:  url,
		})
	}

	return out
}
