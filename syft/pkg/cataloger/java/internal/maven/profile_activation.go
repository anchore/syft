package maven

import (
	"strconv"
	"strings"
)

// maxKnownJDKMajorVersion is the highest major version of a released JDK at the time of writing. It is used
// to detect <jdk> activation requirements that no released JDK can satisfy (e.g. "[99,)"). This is
// deliberately conservative: as newer JDKs ship, this bound only becomes more permissive (never drops
// profiles it previously kept), and profiles keyed on unreleased JDKs are rare in practice.
const maxKnownJDKMajorVersion = 26

// jdkProbeVersions is the set of released JDK versions, in both legacy ("1.8") and modern ("17") notation,
// used to test whether a <jdk> activation requirement is satisfiable by any build.
var jdkProbeVersions = func() [][]int {
	var probes [][]int
	for major := 1; major <= 8; major++ {
		probes = append(probes, []int{1, major}) // legacy notation: JDK 8 == "1.8"
	}
	for major := 1; major <= maxKnownJDKMajorVersion; major++ {
		probes = append(probes, []int{major}) // modern notation (also matches legacy for 1-8)
	}
	return probes
}()

// profileCanBeActive indicates whether a pom profile could be active in some build, judging only from the
// pom itself (a minimal subset of Maven profile activation semantics):
//
//   - a profile with no <activation> element can still be selected manually (e.g. with -P);
//   - a profile whose only activation configuration is <activeByDefault>false</activeByDefault> is
//     explicitly switched off in the pom;
//   - a profile with a <jdk> requirement no released JDK can satisfy can never activate.
//
// <os>, <property>, and <file> activators are not evaluated against the scan environment: they are
// environment-dependent, so such profiles are treated as potentially active.
func profileCanBeActive(profile Profile) bool {
	activation := profile.Activation
	if activation == nil {
		return true
	}

	hasOtherActivator := activation.JDK != nil ||
		activation.OS != nil ||
		activation.Property != nil ||
		activation.File != nil

	if !hasOtherActivator &&
		activation.ActiveByDefault != nil && !*activation.ActiveByDefault {
		// explicitly off unless requested by -P; the pom itself documents this profile as inactive
		return false
	}

	if activation.JDK != nil && !jdkRequirementSatisfiable(*activation.JDK) {
		return false
	}

	return true
}

// jdkRequirementSatisfiable indicates whether any released JDK could satisfy the requirement. Maven accepts
// either a version range (e.g. "[9,)") or a bare version acting as a minimum (e.g. "1.8"; see
// https://maven.apache.org/guides/introduction/introduction-to-profiles.html).
func jdkRequirementSatisfiable(requirement string) bool {
	requirement = strings.TrimSpace(requirement)
	if requirement == "" {
		return true
	}

	if !strings.ContainsAny(requirement, "[]()") {
		// bare version: treated as a minimum, satisfiable if any released JDK is at or above it
		minimum, ok := parseVersionParts(requirement)
		if !ok {
			return true // unparseable: assume satisfiable rather than dropping dependencies
		}
		return anyProbeMatches(func(probe []int) bool {
			return compareVersionParts(probe, minimum) >= 0
		})
	}

	// version range: probe the set of released JDKs against it
	r := parseRangeSet(requirement)
	if r == nil {
		return true // unparseable: assume satisfiable rather than dropping dependencies
	}
	return anyProbeMatches(r.matches)
}

func anyProbeMatches(matches func(probe []int) bool) bool {
	for _, probe := range jdkProbeVersions {
		if matches(probe) {
			return true
		}
	}
	return false
}

// rangeSet is a single Maven version range set, e.g. "[1.5,)" or "(,1.0]".
type rangeSet struct {
	lower          []int
	upper          []int
	lowerInclusive bool
	upperInclusive bool
}

func (r rangeSet) matches(probe []int) bool {
	if r.lower != nil {
		cmp := compareVersionParts(probe, r.lower)
		if cmp < 0 || (cmp == 0 && !r.lowerInclusive) {
			return false
		}
	}
	if r.upper != nil {
		cmp := compareVersionParts(probe, r.upper)
		if cmp > 0 || (cmp == 0 && !r.upperInclusive) {
			return false
		}
	}
	return true
}

// parseRangeSet parses the first Maven version range set from a requirement such as "[1.0,2.0)",
// "(,1.0]", "[1.5,)", or an exact-match "[1.5]". It returns nil if the input does not parse.
func parseRangeSet(requirement string) *rangeSet {
	s := strings.TrimSpace(requirement)

	var r rangeSet
	switch {
	case strings.HasPrefix(s, "["):
		r.lowerInclusive = true
	case strings.HasPrefix(s, "("):
		r.lowerInclusive = false
	default:
		return nil
	}
	s = s[1:]

	var upperDelim string
	switch {
	case strings.HasSuffix(s, "]"):
		r.upperInclusive = true
		upperDelim = "]"
	case strings.HasSuffix(s, ")"):
		r.upperInclusive = false
		upperDelim = ")"
	default:
		return nil
	}
	s = strings.TrimSuffix(s, upperDelim)

	comma := strings.Index(s, ",")
	if comma == -1 {
		// exact version match, e.g. "[1.5]"
		exact, ok := parseVersionParts(s)
		if !ok {
			return nil
		}
		r.lower, r.upper = exact, exact
		r.lowerInclusive, r.upperInclusive = true, true
		return &r
	}

	lowerStr := strings.TrimSpace(s[:comma])
	upperStr := strings.TrimSpace(s[comma+1:])

	if lowerStr != "" {
		lower, ok := parseVersionParts(lowerStr)
		if !ok {
			return nil
		}
		r.lower = lower
	}
	if upperStr != "" {
		upper, ok := parseVersionParts(upperStr)
		if !ok {
			return nil
		}
		r.upper = upper
	}
	return &r
}

// parseVersionParts splits a dotted version string into numeric parts, e.g. "1.8.0_25" -> [1, 8, 0, 25].
// Non-numeric input returns ok=false.
func parseVersionParts(version string) ([]int, bool) {
	version = strings.TrimSpace(version)
	version = strings.ReplaceAll(version, "_", ".")
	if version == "" {
		return nil, false
	}
	var parts []int
	for _, part := range strings.Split(version, ".") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return nil, false
		}
		parts = append(parts, n)
	}
	return parts, true
}

// compareVersionParts compares two dotted versions numerically, padding the shorter with zeros, so that
// e.g. "9" == "9.0" and "1.8" < "9".
func compareVersionParts(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var av, bv int
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}
