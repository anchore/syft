package licenses

import (
	"math"
	"regexp"
	"slices"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/licenses"
)

var licenseRegexp = regexp.MustCompile(`^(?i)(?:(?:UN|MIT-)?LICEN[S|C]E|COPYING|NOTICE).*$`)

// lowerFileNames is a strset.Set of lowercased filenames
var lowerFileNames = func() *strset.Set {
	lowerNames := strset.New()
	for _, fileName := range licenses.FileNames() {
		lowerNames.Add(strings.ToLower(fileName))
	}
	return lowerNames
}()

// lowerFileNamesSorted is a sorted slice of lowercased filenames
var lowerFileNamesSorted = func() []string {
	out := lowerFileNames.List()
	slices.Sort(out)
	return out
}()

// remove duplicate names that match the regex, keep any extras to test after regex check
var minLength, extraFileNames = func() (int, []string) {
	minSize := math.MaxInt
	var extras []string
	for _, name := range lowerFileNamesSorted {
		if len(name) < minSize {
			minSize = len(name)
		}
		if licenseRegexp.MatchString(name) {
			continue
		}
		extras = append(extras, name)
	}
	return minSize, extras
}()

// IsLicenseFile returns true if the name matches known license file name patterns
func IsLicenseFile(name string) bool {
	if len(name) < minLength {
		return false
	}
	if licenseRegexp.MatchString(name) {
		return true
	}
	for _, licenseFile := range extraFileNames {
		if strings.EqualFold(licenseFile, name) {
			return true
		}
	}
	return false
}
