package secrets

import (
	"fmt"
	"regexp"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/hashicorp/go-multierror"
)

// GenerateSearchPatterns takes a set of named base patterns, a set of additional named patterns and an name exclusion list and generates a final
// set of regular expressions (indexed by name). The sets are aggregated roughly as such: (base - excluded) + additional.
func GenerateSearchPatterns(basePatterns map[string]string, additionalPatterns map[string]string, excludePatternNames []string) (map[string]*regexp.Regexp, error) {
	var regexObjs = make(map[string]*regexp.Regexp)
	var errs error

	addFn := func(name, pattern string) {
		// always enable multiline search option for extracting secrets with multiline values
		obj, err := regexp.Compile(`(?m)` + pattern)
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("unable to parse %q regular expression: %w", name, err))
		}
		regexObjs[name] = obj
	}

	// add all base cases... unless that base case was asked to be excluded
	for name, pattern := range basePatterns {
		if !matchesExclusion(excludePatternNames, name) {
			addFn(name, pattern)
		}
	}

	// add all additional cases
	for name, pattern := range additionalPatterns {
		addFn(name, pattern)
	}

	if errs != nil {
		return nil, errs
	}

	return regexObjs, nil
}

func matchesExclusion(excludePatternNames []string, name string) bool {
	for _, exclude := range excludePatternNames {
		matches, err := doublestar.Match(exclude, name)
		if err != nil {
			return false
		}
		if matches {
			return true
		}
	}
	return false
}
