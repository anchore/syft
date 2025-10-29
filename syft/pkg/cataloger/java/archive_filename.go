package java

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

// nameAndVersionPattern finds the package name and version (as named capture
// groups) in a string. The pattern's strategy is to start at the beginning of
// the string, and for every next dash-delimited group, consider the group to be
// a continuation of the package name, unless the group begins with a number or
// matches any of a specified set of "version-indicating" patterns. When a given
// group meets this criterion, consider the group and the remainder of the
// string to be the package version.
//
// Regex components of note:
//
// (?Ui)													...	Sets the "U" and the "i" options for this Regex —— (ungreedy,
// and case-insensitive, respectively). "Ungreedy" is important so that the '*' that trails the package name
// component doesn't consume the rest of the string.
//
// [[:alpha:]][[:word:].]*									...	Matches any word, and the word can include "word" characters (
// which includes numbers and underscores), and periods, but the first character of the word MUST be a letter.
//
// (?:\.[[:alpha:]][[:word:].]*)* 							... This looks redundant, but it's not. It
// extends the previous pattern such that the net effect of both components is
// that words can also include a period and more words (thus, when combined, not
// only is "something" matched, but so is "com.prefix.thing"
//
// (?:\d.*|(?:build\d*.*)|(?:rc?\d+(?:^[[:alpha:]].*)?))	...
// This match group covers the "version-indicating" patterns mentioned in the above description. Given the pipes (
// '|'), this functions as a series of 'OR'-joined conditions:
//
//	\d.*						...	"If it starts with a numeric digit, this is a version, no matter what follows."
//	build\d*.*					...	"If it starts with "build" and then a numeric digit immediately after, this is a version."
//	rc?\d+(?:^[[:alpha:]].*)?	...	"If it starts with "r" or "rc" and then one or more numeric digits immediately
//									after, but no alpha characters right after that (in the same word), this is a version."
//
// Match examples:
//
//	some-package-4.0.1		--> name="some-package", version="4.0.1"
//	prefix.thing-4			-->	name="prefix.thing", version="4"
//	my-http2-server-5		-->	name="my-http2-server", version="5"
//	jetpack-build235-rc5	-->	name="jetpack", version="build2.0-rc5"
//	ironman-r4-2009			--> name="ironman", version="r4-2009"
var nameAndVersionPattern = regexp.MustCompile(`(?Ui)^(?P<name>(?:[[:alpha:]][[:word:].]*(?:\.[[:alpha:]][[:word:].]*)*-?)+)(?:-(?P<version>(\d.*|(build\d+.*)|(rc?\d+(?:^[[:alpha:]].*)?))))?$`)
var secondaryVersionPattern = regexp.MustCompile(`(?:[._-](?P<version>(\d.*|(build\d+.*)|(rc?\d+(?:^[[:alpha:]].*)?))))?$`)

type archiveFilename struct {
	raw     string
	name    string
	version string
}

func getSubexp(matches []string, subexpName string, re *regexp.Regexp, raw string) string {
	if len(matches) < 1 {
		log.Tracef("unexpectedly empty matches for Java archive '%s'", raw)
		return ""
	}

	index := re.SubexpIndex(subexpName)
	if index < 1 {
		log.Tracef("unexpected index of '%s' capture group for Java archive '%s'", subexpName, raw)
		return ""
	}

	// Prevent out-of-range panic
	if len(matches) < index+1 {
		log.Tracef("no match found for '%s' in '%s' for Java archive", subexpName, matches[0])
		return ""
	}

	return matches[index]
}

func newJavaArchiveFilename(raw string) archiveFilename {
	// trim the file extension and remove any path prefixes
	cleanedFileName := strings.TrimSuffix(filepath.Base(raw), filepath.Ext(raw))

	matches := nameAndVersionPattern.FindStringSubmatch(cleanedFileName)

	name := getSubexp(matches, "name", nameAndVersionPattern, raw)
	version := getSubexp(matches, "version", nameAndVersionPattern, raw)

	// some jars get named with different conventions, like `_<version>` or `.<version>`
	if version == "" {
		matches = secondaryVersionPattern.FindStringSubmatch(name)
		version = getSubexp(matches, "version", secondaryVersionPattern, raw)
		if version != "" {
			name = name[0 : len(name)-len(version)-1]
		}
	}

	return archiveFilename{
		raw:     raw,
		name:    name,
		version: version,
	}
}

func (a archiveFilename) extension() string {
	return strings.TrimPrefix(filepath.Ext(a.raw), ".")
}

func (a archiveFilename) pkgType() pkg.Type {
	switch strings.ToLower(a.extension()) {
	case "jar", "war", "ear", "lpkg", "par", "sar", "nar", "kar", "rar":
		return pkg.JavaPkg
	case "jpi", "hpi":
		return pkg.JenkinsPluginPkg
	default:
		return pkg.UnknownPkg
	}
}
