// Copyright (c) Facebook, Inc. and its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wfn

// Matcher knows whether it matches some attributes
type Matcher interface {
	// Match returns attributes which match it
	// if require version, then Matcher which matches all versions should return false
	Match(attrs []*Attributes, requireVersion bool) (matches []*Attributes)
	// Config returns all attributes that are used by in the matching process
	Config() []*Attributes
}

// Attrs is part of the Matcher interface
func (a *Attributes) Config() []*Attributes {
	return []*Attributes{a}
}

// MatchOnlyVersion checks whether version matches
func (a *Attributes) MatchOnlyVersion(attr *Attributes) bool {
	if a == nil || attr == nil {
		return a == attr // both are nil
	}
	return matchAttr(a.Version, attr.Version)
}

// MatchWithoutVersion checks whether everything else besides the version matches
func (a *Attributes) MatchWithoutVersion(attr *Attributes) bool {
	if a == nil || attr == nil {
		return a == attr // both are nil
	}
	return matchAttr(a.Product, attr.Product) &&
		matchAttr(a.Vendor, attr.Vendor) && matchAttr(a.Part, attr.Part) &&
		matchAttr(a.Update, attr.Update) && matchAttr(a.Edition, attr.Edition) &&
		matchAttr(a.Language, attr.Language) && matchAttr(a.SWEdition, attr.SWEdition) &&
		matchAttr(a.TargetHW, attr.TargetHW) && matchAttr(a.TargetSW, attr.TargetSW) &&
		matchAttr(a.Other, attr.Other)
}

// MatchAll returns a Matcher which matches only if all matchers match
func MatchAll(ms ...Matcher) Matcher {
	return &multiMatcher{ms, true}
}

// MatchAll returns a Matcher which matches if any of the matchers match
func MatchAny(ms ...Matcher) Matcher {
	return &multiMatcher{ms, false}
}

// DontMatch returns a Matcher which matches if the given matchers doesn't
func DontMatch(m Matcher) Matcher {
	return notMatcher{m}
}

type multiMatcher struct {
	matchers []Matcher
	// if true, match will only return something if all matchers matched at least something
	allMatch bool
}

// Match is part of the Matcher interface
func (mm *multiMatcher) Match(attrs []*Attributes, requireVersion bool) []*Attributes {
	matched := make(map[*Attributes]bool)
	for _, matcher := range mm.matchers {
		matches := matcher.Match(attrs, requireVersion)
		if mm.allMatch && len(matches) == 0 {
			// all matchers need to match at least one attr
			return nil
		}
		for _, m := range matches {
			matched[m] = true
		}
	}

	matches := make([]*Attributes, 0, len(matched))
	for m := range matched {
		matches = append(matches, m)
	}
	return matches
}

// Attrs is part of the Matcher interface
func (mm *multiMatcher) Config() []*Attributes {
	var attrs []*Attributes
	for _, matcher := range mm.matchers {
		attrs = append(attrs, matcher.Config()...)
	}
	return attrs
}

type notMatcher struct {
	Matcher
}

// Match is part of the Matcher interface
func (nm notMatcher) Match(attrs []*Attributes, requireVersion bool) (matches []*Attributes) {
	matched := make(map[*Attributes]bool)
	for _, m := range nm.Matcher.Match(attrs, requireVersion) {
		matched[m] = true
	}

	for _, a := range attrs {
		if !matched[a] {
			matches = append(matches, a)
		}
	}
	return matches
}
