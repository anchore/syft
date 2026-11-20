package rust

import (
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
)

var cargoComparatorPattern = regexp.MustCompile(`^(\^|~|>=|<=|=|>|<)?[ \t]*(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*|\*))?(?:\.(0|[1-9][0-9]*|\*))?(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

type cargoVersionRequirement struct {
	comparators []cargoVersionComparator
}

type cargoVersionComparator struct {
	op        string
	version   *semver.Version
	precision int
}

// Cargo requirements are intersections of comparators with a separate
// prerelease opt-in rule. The semver library supplies version ordering only;
// its constraint language has different tilde and prerelease semantics.
func cargoVersionConstraint(version string) (*cargoVersionRequirement, bool) {
	if version == "" {
		return nil, true // git and path dependencies need not specify a version
	}
	requirement := &cargoVersionRequirement{}
	for _, part := range strings.Split(version, ",") {
		comparator, ok := parseCargoComparator(strings.TrimSpace(part))
		if !ok {
			return nil, false
		}
		requirement.comparators = append(requirement.comparators, comparator)
	}
	return requirement, true
}

func parseCargoComparator(text string) (cargoVersionComparator, bool) {
	if text == "*" {
		return cargoVersionComparator{op: "*"}, true
	}
	match := cargoComparatorPattern.FindStringSubmatch(text)
	if match == nil {
		return cargoVersionComparator{}, false
	}
	comparator := cargoVersionComparator{op: match[1], precision: 1}
	numbers := []string{match[2], "0", "0"}
	for i := 1; i < 3; i++ {
		part := match[i+2]
		if part == "" || part == "*" {
			break
		}
		numbers[i] = part
		comparator.precision++
	}
	if strings.Contains(text, "*") {
		if (comparator.op != "" && comparator.op != "=") || (match[3] == "*" && match[4] != "") {
			return cargoVersionComparator{}, false
		}
		comparator.op = "="
	}
	if comparator.op == "" {
		comparator.op = "^"
	}
	if comparator.precision < 3 && (match[5] != "" || match[6] != "") {
		return cargoVersionComparator{}, false
	}
	version, err := semver.StrictNewVersion(strings.Join(numbers, ".") + match[5] + match[6])
	if err != nil {
		return cargoVersionComparator{}, false
	}
	comparator.version = version
	return comparator, true
}

func (r cargoVersionRequirement) matches(version *semver.Version) bool {
	for _, comparator := range r.comparators {
		if !comparator.matches(version) {
			return false
		}
	}
	if version.Prerelease() == "" {
		return true
	}
	for _, comparator := range r.comparators {
		if comparator.precision == 3 && comparator.version.Prerelease() != "" &&
			comparator.version.Major() == version.Major() && comparator.version.Minor() == version.Minor() && comparator.version.Patch() == version.Patch() {
			return true
		}
	}
	return false
}

func (c cargoVersionComparator) matches(version *semver.Version) bool {
	switch c.op {
	case "*":
		return true
	case "=":
		return c.exact(version)
	case ">":
		return c.compare(version) > 0
	case "<":
		return c.compare(version) < 0
	case ">=":
		return c.exact(version) || c.compare(version) > 0
	case "<=":
		return c.exact(version) || c.compare(version) < 0
	case "~":
		return c.tilde(version)
	case "^":
		return c.caret(version)
	}
	return false
}

// compare ignores unspecified components, as Cargo's partial comparison
// operators do. Prerelease ordering participates only at full precision.
func (c cargoVersionComparator) compare(version *semver.Version) int {
	left := []uint64{version.Major(), version.Minor(), version.Patch()}
	right := []uint64{c.version.Major(), c.version.Minor(), c.version.Patch()}
	for i := 0; i < c.precision; i++ {
		if left[i] < right[i] {
			return -1
		}
		if left[i] > right[i] {
			return 1
		}
	}
	if c.precision == 3 {
		return version.Compare(c.version)
	}
	return 0
}

func (c cargoVersionComparator) exact(version *semver.Version) bool {
	return c.compare(version) == 0 && version.Prerelease() == c.version.Prerelease()
}

func (c cargoVersionComparator) tilde(version *semver.Version) bool {
	if version.Major() != c.version.Major() || (c.precision >= 2 && version.Minor() != c.version.Minor()) {
		return false
	}
	if c.precision == 3 && version.Patch() != c.version.Patch() {
		return version.Patch() > c.version.Patch()
	}
	return semver.New(0, 0, 0, version.Prerelease(), "").Compare(semver.New(0, 0, 0, c.version.Prerelease(), "")) >= 0
}

func (c cargoVersionComparator) caret(version *semver.Version) bool {
	if version.Major() != c.version.Major() {
		return false
	}
	if c.precision == 1 {
		return true
	}
	if c.precision == 2 {
		if c.version.Major() > 0 {
			return version.Minor() >= c.version.Minor()
		}
		return version.Minor() == c.version.Minor()
	}
	if c.version.Major() == 0 && version.Minor() != c.version.Minor() {
		return false
	}
	if c.version.Major() == 0 && c.version.Minor() == 0 && version.Patch() != c.version.Patch() {
		return false
	}
	return version.Compare(c.version) >= 0
}
