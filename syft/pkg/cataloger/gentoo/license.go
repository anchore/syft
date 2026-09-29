package gentoo

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
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
	scanner := internal.NewLineScanner(io.TeeReader(reader, &contentsWriter))
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
	if err := scanner.Err(); err != nil {
		fields := []any{"error", err}
		if closestLocation != nil {
			fields = append(fields, "path", closestLocation.RealPath)
		}
		log.WithFields(fields...).Debug("failed to fully read portage LICENSE")
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

	return strings.TrimSpace(contentsWriter.String()), licenseExpression(mandatoryLicenses, conditionalLicenses)
}

// licenseExpression attempts to build a valid SPDX license expression
func licenseExpression(mandatoryLicenses, conditionalLicenses []string) string {
	mandatoryStatement := strings.Join(mandatoryLicenses, " AND ")
	conditionalStatement := strings.Join(conditionalLicenses, " OR ")

	switch {
	case mandatoryStatement != "" && conditionalStatement != "":
		return mandatoryStatement + " AND (" + conditionalStatement + ")"
	case mandatoryStatement != "":
		return mandatoryStatement
	default:
		return conditionalStatement
	}
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
		if after, ok := strings.CutPrefix(license, "@"); ok {
			// this is a license group...
			name := after
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
	rawGroups := make(map[string][]string)

	scanner := internal.NewLineScanner(reader)

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
	expanded := make(map[string][]string)
	for groupName := range rawGroups {
		if _, err := expandLicenses(groupName, rawGroups, expanded, make(map[string]bool)); err != nil {
			return nil, err
		}
	}

	return expanded, nil
}

// expandLicenses handles the recursive expansion of license groups. Each group is expanded once and memoized in
// 'expanded' (the file is untrusted, so re-expanding on every reference would be exponential), and 'visiting' holds
// the groups on the current path to detect cycles. We are always in terms of slices instead of sets to ensure
// original ordering is preserved.
func expandLicenses(currentGroup string, rawGroups, expanded map[string][]string, visiting map[string]bool) ([]string, error) {
	if result, ok := expanded[currentGroup]; ok {
		return result, nil
	}
	if visiting[currentGroup] {
		return nil, fmt.Errorf("cycle detected in license group definitions for group: %s", currentGroup)
	}
	visiting[currentGroup] = true
	defer delete(visiting, currentGroup)

	result := make([]string, 0)
	// sets keep dedup linear, since a single group line can hold hundreds of thousands of tokens
	seen := strset.New()
	seenRefs := strset.New()

	for _, item := range rawGroups[currentGroup] {
		refGroupName, isRef := strings.CutPrefix(item, "@")
		if !isRef {
			// this is a regular license
			if !seen.Has(item) {
				seen.Add(item)
				result = append(result, item)
			}
			continue
		}

		// this is a reference to another group
		if seenRefs.Has(refGroupName) {
			continue
		}
		seenRefs.Add(refGroupName)

		if _, exists := rawGroups[refGroupName]; !exists {
			return nil, fmt.Errorf("referenced group not found: %s", refGroupName)
		}

		refLicenses, err := expandLicenses(refGroupName, rawGroups, expanded, visiting)
		if err != nil {
			return nil, err
		}

		for _, license := range refLicenses {
			if !seen.Has(license) {
				seen.Add(license)
				result = append(result, license)
			}
		}
	}

	expanded[currentGroup] = result
	return result, nil
}
