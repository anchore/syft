package internal

import "regexp"

// MatchNamedCaptureGroups takes a regular expression and string and returns all of the named capture group results in a map.
// Note: this is only for the first match in the regex.
func MatchNamedCaptureGroups(regEx *regexp.Regexp, content string) map[string]string {
	// note: we are looking across all matches and stopping on the first non-empty match. Why? Take the following example:
	// input: "cool something to match against" pattern: `((?P<name>match) (?P<version>against))?`. Since the pattern is
	// encapsulated in an optional capture group, there will be results for each character, but the results will match
	// on nothing. The only "true" match will be at the end ("match against").
	allMatches := regEx.FindAllStringSubmatch(content, -1)
	for matchIdx, match := range allMatches {
		// fill a candidate results map with named capture group results, accepting empty values, but not groups with
		// no names
		results := make(map[string]string)
		for nameIdx, name := range regEx.SubexpNames() {
			if nameIdx <= len(match) && len(name) > 0 {
				results[name] = match[nameIdx]
			}
		}
		// note: since we are looking for the first best potential match we should stop when we find the first one
		// with non-empty results.
		if len(results) > 0 {
			foundNonEmptyValue := false
			for _, value := range results {
				if value != "" {
					foundNonEmptyValue = true
					break
				}
			}
			// return the first non-empty result, or if this is the last match, the results that were found.
			if foundNonEmptyValue || matchIdx == len(allMatches)-1 {
				return results
			}
		}
	}
	return nil
}
