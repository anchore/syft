package gentoo

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
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
func extractLicenses(resolver file.Resolver, closestLocation *file.Location, reader io.Reader) (string, string) {
	findings := strset.New()
	contentsWriter := bytes.Buffer{}
	scanner := bufio.NewScanner(io.TeeReader(reader, &contentsWriter))
	scanner.Split(bufio.ScanWords)
	var (
		mandatoryLicenses, conditionalLicenses, useflagLicenses []string
		usesGroups                                              bool
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
			if strings.HasPrefix(token, "@") {
				usesGroups = true
			}
		}
	}

	var licenseGroups map[string][]string
	if usesGroups {
		licenseGroups = readLicenseGroups(resolver, closestLocation)
	}
	mandatoryLicenses = replaceLicenseGroups(mandatoryLicenses, licenseGroups)
	conditionalLicenses = replaceLicenseGroups(conditionalLicenses, licenseGroups)
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

	contents := strings.TrimSpace(contentsWriter.String())

	if mandatoryStatement != "" && conditionalStatement != "" {
		return contents, mandatoryStatement + " AND (" + conditionalStatement + ")"
	}

	if mandatoryStatement != "" {
		return contents, mandatoryStatement
	}

	if conditionalStatement != "" {
		return contents, conditionalStatement
	}

	return contents, ""
}

func readLicenseGroups(resolver file.Resolver, closestLocation *file.Location) map[string][]string {
	if resolver == nil || closestLocation == nil {
		return nil
	}
	var licenseGroups map[string][]string
	groupLocation := resolver.RelativeFileByPath(*closestLocation, "/etc/portage/license_groups")
	if groupLocation == nil {
		return nil
	}

	groupReader, err := resolver.FileContentsByLocation(*groupLocation)
	defer internal.CloseAndLogError(groupReader, groupLocation.RealPath)
	if err != nil {
		log.WithFields("path", groupLocation.RealPath, "error", err).Debug("failed to fetch portage LICENSE")
		return nil
	}

	if groupReader == nil {
		return nil
	}

	licenseGroups, err = parseLicenseGroups(groupReader)
	if err != nil {
		log.WithFields("path", groupLocation.RealPath, "error", err).Debug("failed to parse portage LICENSE")
	}

	return licenseGroups
}

func replaceLicenseGroups(licenses []string, groups map[string][]string) []string {
	if groups == nil {
		return licenses
	}

	result := make([]string, 0, len(licenses))
	for _, license := range licenses {
		if strings.HasPrefix(license, "@") {
			// this is a license group...
			name := strings.TrimPrefix(license, "@")
			if expandedLicenses, ok := groups[name]; ok {
				result = append(result, expandedLicenses...)
			} else {
				// unable to expand, use the original license group value (including the '@')
				result = append(result, license)
			}
		} else {
			// this is a license...
			result = append(result, license)
		}
	}
	return result
}

func parseLicenseGroups(reader io.Reader) (map[string][]string, error) {
	result := make(map[string][]string)
	rawGroups := make(map[string][]string)

	scanner := bufio.NewScanner(reader)

	// first collect all raw groups
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			// skip empty lines and comments
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid line format: %s", line)
		}

		groupName := parts[0]
		licenses := parts[1:]

		rawGroups[groupName] = licenses
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// next process each group to expand nested references
	for groupName, licenses := range rawGroups {
		expanded, err := expandLicenses(groupName, licenses, rawGroups, make(map[string]bool))
		if err != nil {
			return nil, err
		}
		result[groupName] = expanded
	}

	return result, nil
}

// expandLicenses handles the recursive expansion of license groups, 'visited' is used to detect cycles. We are always
// in terms of slices instead of sets to ensure original ordering is preserved.
func expandLicenses(currentGroup string, licenses []string, rawGroups map[string][]string, visited map[string]bool) ([]string, error) {
	if visited[currentGroup] {
		return nil, fmt.Errorf("cycle detected in license group definitions for group: %s", currentGroup)
	}

	visited[currentGroup] = true

	result := make([]string, 0)

	for _, item := range licenses {
		if strings.HasPrefix(item, "@") {
			// this is a reference to another group
			refGroupName := item[1:] // remove '@' prefix

			refLicenses, exists := rawGroups[refGroupName]
			if !exists {
				return nil, fmt.Errorf("referenced group not found: %s", refGroupName)
			}

			newVisited := make(map[string]bool)
			for k, v := range visited {
				newVisited[k] = v
			}

			expanded, err := expandLicenses(refGroupName, refLicenses, rawGroups, newVisited)
			if err != nil {
				return nil, err
			}

			for _, license := range expanded {
				if !slices.Contains(result, license) {
					result = append(result, license)
				}
			}
		} else if !slices.Contains(result, item) {
			// ...this is a regular license
			result = append(result, item)
		}
	}

	return result, nil
}
