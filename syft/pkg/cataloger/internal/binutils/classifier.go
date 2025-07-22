package binutils

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
	"github.com/anchore/syft/syft/pkg"
)

// Classifier is a generic package classifier that can be used to match a package definition
// to a file that meets the given content criteria of the EvidenceMatcher.
type Classifier struct {
	Class string `json:"class"`

	// FileGlob is a selector to narrow down file inspection using the **/glob* syntax
	FileGlob string `json:"fileGlob"`

	// EvidenceMatcher is what will be used to match against the file in the source
	// location. If the matcher returns a package, the file will be considered a candidate.
	EvidenceMatcher EvidenceMatcher `json:"-"`

	// The information below is used to specify the Package information when returned

	// Package is the name to use for the package
	Package string `json:"package"`

	// PURL is the Package URL to use when generating a package
	PURL packageurl.PackageURL `json:"purl"`

	// CPEs are the specific CPEs we want to include for this binary with updated version information
	CPEs []cpe.CPE `json:"cpes"`
}

func (cfg Classifier) MarshalJSON() ([]byte, error) {
	type marshalled struct {
		Class    string   `json:"class"`
		FileGlob string   `json:"fileGlob"`
		Package  string   `json:"package"`
		PURL     string   `json:"purl"`
		CPEs     []string `json:"cpes"`
	}

	var marshalledCPEs []string
	for _, c := range cfg.CPEs {
		marshalledCPEs = append(marshalledCPEs, c.Attributes.BindToFmtString())
	}

	m := marshalled{
		Class:    cfg.Class,
		FileGlob: cfg.FileGlob,
		Package:  cfg.Package,
		PURL:     cfg.PURL.String(),
		CPEs:     marshalledCPEs,
	}

	return json.Marshal(m)
}

// EvidenceMatcher is a function called to identify based on some sort of evidence in the filesystem contents.
// A non-nil return value indicates a successful match, regardless of packages being returned.
type EvidenceMatcher func(classifier Classifier, context MatcherContext) ([]pkg.Package, error)

type MatcherContext struct {
	Resolver  file.Resolver
	Location  file.Location
	GetReader func(resolver MatcherContext) (unionreader.UnionReader, error)
}

// MatchAny returns a combined evidence matcher that returns results from the first
// matcher that returns results
func MatchAny(matchers ...EvidenceMatcher) EvidenceMatcher {
	return func(classifier Classifier, context MatcherContext) ([]pkg.Package, error) {
		for _, matcher := range matchers {
			match, err := matcher(classifier, context)
			if err != nil {
				return nil, err
			}
			// only return when results
			if match != nil {
				return match, nil
			}
		}
		return nil, nil
	}
}

// MatchAll executes all matchers until one returns nil results, only returning the final results
func MatchAll(matchers ...EvidenceMatcher) EvidenceMatcher {
	return func(classifier Classifier, context MatcherContext) ([]pkg.Package, error) {
		var out []pkg.Package
		for _, matcher := range matchers {
			match, err := matcher(classifier, context)
			if match == nil || err != nil {
				return nil, err
			}
			if len(match) > 0 {
				out = match
			}
		}
		return out, nil
	}
}

type ContextualEvidenceMatchers struct {
	CatalogerName string
}

func (c ContextualEvidenceMatchers) FileNameTemplateVersionMatcher(fileNamePattern string, contentTemplate string) EvidenceMatcher {
	return FileNameTemplateVersionMatcher(fileNamePattern, contentTemplate, c.CatalogerName)
}

func (c ContextualEvidenceMatchers) FileContentsVersionMatcher(patterns ...string) EvidenceMatcher {
	return FileContentsVersionMatcher(c.CatalogerName, patterns...)
}

func FileNameTemplateVersionMatcher(fileNamePattern, contentTemplate, catalogerName string) EvidenceMatcher {
	pat := regexp.MustCompile(fileNamePattern)
	return func(classifier Classifier, context MatcherContext) ([]pkg.Package, error) {
		if !pat.MatchString(context.Location.RealPath) {
			return nil, nil
		}

		filepathNamedGroupValues := internal.MatchNamedCaptureGroups(pat, context.Location.RealPath)

		// versions like 3.5 should not match any character, but explicit dot
		for k, v := range filepathNamedGroupValues {
			filepathNamedGroupValues[k] = strings.ReplaceAll(v, ".", "\\.")
		}

		tmpl, err := template.New("").Parse(contentTemplate)
		if err != nil {
			return nil, fmt.Errorf("unable to parse classifier template=%q : %w", contentTemplate, err)
		}

		patternBuf := &bytes.Buffer{}
		err = tmpl.Execute(patternBuf, filepathNamedGroupValues)
		if err != nil {
			return nil, fmt.Errorf("unable to render template: %w", err)
		}

		tmplPattern, err := regexp.Compile(patternBuf.String())
		if err != nil {
			return nil, fmt.Errorf("unable to compile rendered regex=%q: %w", patternBuf.String(), err)
		}

		contents, err := getReader(context)
		if err != nil {
			return nil, fmt.Errorf("unable to get read contents for file: %w", err)
		}

		matchMetadata, err := internal.MatchNamedCaptureGroupsFromReader(tmplPattern, contents)
		if err != nil {
			return nil, fmt.Errorf("unable to match version: %w", err)
		}

		p := NewClassifierPackage(classifier, context.Location, matchMetadata, catalogerName)
		if p == nil {
			return nil, nil
		}

		return []pkg.Package{*p}, nil
	}
}

// FileContentsVersionMatcher will match all provided patterns, extracting named capture groups from each pattern, overwriting earlier results
func FileContentsVersionMatcher(catalogerName string, patterns ...string) EvidenceMatcher {
	if len(patterns) == 0 {
		panic("must specify at least one pattern")
	}
	var pats []*regexp.Regexp
	for _, pattern := range patterns {
		pats = append(pats, regexp.MustCompile(pattern))
	}
	return func(classifier Classifier, context MatcherContext) ([]pkg.Package, error) {
		var matchMetadata map[string]string

		for _, pat := range pats {
			contents, err := getReader(context)
			if err != nil {
				return nil, fmt.Errorf("unable to get read contents for file: %w", err)
			}

			match, err := internal.MatchNamedCaptureGroupsFromReader(pat, contents)
			if err != nil {
				return nil, fmt.Errorf("unable to match version: %w", err)
			}
			if match == nil {
				return nil, nil
			}
			if matchMetadata == nil {
				matchMetadata = match
			} else {
				maps.Copy(matchMetadata, match)
			}
		}

		// Convert {major: 1, minor: 2, patch: 3} to "1.2.3"
		_, versionOk := matchMetadata["version"]
		majorStr, majorOk := matchMetadata["major"]
		minorStr, minorOk := matchMetadata["minor"]
		patchStr, patchOk := matchMetadata["patch"]

		if !versionOk && majorOk && minorOk && patchOk {
			major, majorErr := strconv.Atoi(majorStr)
			minor, minorErr := strconv.Atoi(minorStr)
			patch, patchErr := strconv.Atoi(patchStr)

			if majorErr == nil && minorErr == nil && patchErr == nil {
				matchMetadata["version"] = fmt.Sprintf("%d.%d.%d", major, minor, patch)
			}
		}

		p := NewClassifierPackage(classifier, context.Location, matchMetadata, catalogerName)
		if p == nil {
			if matchMetadata != nil {
				// if we had a successful metadata match, but no packages, return a successful match result
				return []pkg.Package{}, nil
			}
			return nil, nil
		}

		return []pkg.Package{*p}, nil
	}
}

func SharedLibraryLookup(sharedLibraryPattern string, sharedLibraryMatcher EvidenceMatcher) EvidenceMatcher {
	pat := regexp.MustCompile(sharedLibraryPattern)
	return func(classifier Classifier, context MatcherContext) (packages []pkg.Package, _ error) {
		libs, err := sharedLibraries(context)
		if err != nil {
			return nil, err
		}
		for _, lib := range libs {
			if !pat.MatchString(lib) {
				continue
			}

			locations, err := context.Resolver.FilesByGlob("**/" + lib)
			if err != nil {
				return nil, err
			}
			for _, libraryLocation := range locations {
				// create a new resolver without the cached context lookup -- this is decidedly a different file
				newResolver := MatcherContext{
					Resolver: context.Resolver,
					Location: libraryLocation,
				}
				pkgs, err := sharedLibraryMatcher(classifier, newResolver)
				if err != nil {
					return nil, err
				}
				// not a successful match
				if pkgs == nil {
					continue
				}
				for _, p := range pkgs {
					// set the source binary as the first location
					locationSet := file.NewLocationSet(context.Location)
					locationSet.Add(p.Locations.ToSlice()...)
					p.Locations = locationSet
					meta, _ := p.Metadata.(pkg.BinarySignature)
					p.Metadata = pkg.BinarySignature{
						Matches: append([]pkg.ClassifierMatch{
							{
								Classifier: classifier.Class,
								Location:   context.Location,
							},
						}, meta.Matches...),
					}
					packages = append(packages, p)
				}
				// return non-nil package results as a successful match indication if the evidence matcher returned a successful match indication
				if packages == nil {
					packages = pkgs
				}
			}
		}
		return packages, nil
	}
}

func MatchPath(path string) EvidenceMatcher {
	if !doublestar.ValidatePattern(path) {
		panic("invalid pattern")
	}
	return func(_ Classifier, context MatcherContext) ([]pkg.Package, error) {
		if doublestar.MatchUnvalidated(path, context.Location.RealPath) {
			return []pkg.Package{}, nil // return non-nil
		}
		return nil, nil
	}
}

func getReader(context MatcherContext) (unionreader.UnionReader, error) {
	if context.GetReader != nil {
		return context.GetReader(context)
	}
	reader, err := context.Resolver.FileContentsByLocation(context.Location) //nolint:gocritic
	if err != nil {
		return nil, err
	}

	return unionreader.GetUnionReader(reader)
}

// sharedLibraries returns a list of all shared libraries found within a binary, currently
// supporting: elf, macho, and windows pe
func sharedLibraries(context MatcherContext) ([]string, error) {
	contents, err := getReader(context)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogError(contents, context.Location.RealPath)

	e, _ := elf.NewFile(contents)
	if e != nil {
		symbols, err := e.ImportedLibraries()
		if err != nil {
			log.Debugf("unable to read elf binary at: %s -- %s", context.Location.RealPath, err)
		}
		return symbols, nil
	}
	if _, err := contents.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("unable to seek to beginning of file: %w", err)
	}

	m, _ := macho.NewFile(contents)
	if m != nil {
		symbols, err := m.ImportedLibraries()
		if err != nil {
			log.Debugf("unable to read macho binary at: %s -- %s", context.Location.RealPath, err)
		}
		return symbols, nil
	}
	if _, err := contents.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("unable to seek to beginning of file: %w", err)
	}

	p, _ := pe.NewFile(contents)
	if p != nil {
		symbols, err := p.ImportedLibraries()
		if err != nil {
			log.Debugf("unable to read pe binary at: %s -- %s", context.Location.RealPath, err)
		}
		return symbols, nil
	}
	if _, err := contents.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("unable to seek to beginning of file: %w", err)
	}

	return nil, nil
}
