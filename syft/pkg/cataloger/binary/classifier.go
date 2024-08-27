package binary

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
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

	// Information below is used to specify the Package information when returned

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

// EvidenceMatcher is a function called to catalog Packages that match some sort of evidence
type EvidenceMatcher func(classifier Classifier, context matcherContext) ([]pkg.Package, error)

type matcherContext struct {
	resolver    file.Resolver
	location    file.Location
	getContents func(resolver matcherContext) ([]byte, error)
}

func evidenceMatchers(matchers ...EvidenceMatcher) EvidenceMatcher {
	return func(classifier Classifier, context matcherContext) ([]pkg.Package, error) {
		for _, matcher := range matchers {
			match, err := matcher(classifier, context)
			if err != nil {
				return nil, err
			}
			if match != nil {
				return match, nil
			}
		}
		return nil, nil
	}
}

func fileNameTemplateVersionMatcher(fileNamePattern string, contentTemplate string) EvidenceMatcher {
	pat := regexp.MustCompile(fileNamePattern)
	return func(classifier Classifier, context matcherContext) ([]pkg.Package, error) {
		if !pat.MatchString(context.location.RealPath) {
			return nil, nil
		}

		filepathNamedGroupValues := internal.MatchNamedCaptureGroups(pat, context.location.RealPath)

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

		contents, err := getContents(context)
		if err != nil {
			return nil, fmt.Errorf("unable to get read contents for file: %w", err)
		}

		matchMetadata := internal.MatchNamedCaptureGroups(tmplPattern, string(contents))

		p := newClassifierPackage(classifier, context.location, matchMetadata)
		if p == nil {
			return nil, nil
		}

		return []pkg.Package{*p}, nil
	}
}

func FileContentsVersionMatcher(pattern string) EvidenceMatcher {
	pat := regexp.MustCompile(pattern)
	return func(classifier Classifier, context matcherContext) ([]pkg.Package, error) {
		contents, err := getContents(context)
		if err != nil {
			return nil, fmt.Errorf("unable to get read contents for file: %w", err)
		}

		matchMetadata := internal.MatchNamedCaptureGroups(pat, string(contents))

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

		p := newClassifierPackage(classifier, context.location, matchMetadata)
		if p == nil {
			return nil, nil
		}

		return []pkg.Package{*p}, nil
	}
}

// matchExcluding tests the provided regular expressions against the file, and if matched, DOES NOT return
// anything that the matcher would otherwise return
func matchExcluding(matcher EvidenceMatcher, contentPatternsToExclude ...string) EvidenceMatcher {
	var nonMatchPatterns []*regexp.Regexp
	for _, p := range contentPatternsToExclude {
		nonMatchPatterns = append(nonMatchPatterns, regexp.MustCompile(p))
	}
	return func(classifier Classifier, context matcherContext) ([]pkg.Package, error) {
		contents, err := getContents(context)
		if err != nil {
			return nil, fmt.Errorf("unable to get read contents for file: %w", err)
		}
		for _, nonMatch := range nonMatchPatterns {
			if nonMatch.Match(contents) {
				return nil, nil
			}
		}
		return matcher(classifier, context)
	}
}

func sharedLibraryLookup(sharedLibraryPattern string, sharedLibraryMatcher EvidenceMatcher) EvidenceMatcher {
	pat := regexp.MustCompile(sharedLibraryPattern)
	return func(classifier Classifier, context matcherContext) (packages []pkg.Package, _ error) {
		libs, err := sharedLibraries(context)
		if err != nil {
			return nil, err
		}
		for _, lib := range libs {
			if !pat.MatchString(lib) {
				continue
			}

			locations, err := context.resolver.FilesByGlob("**/" + lib)
			if err != nil {
				return nil, err
			}
			for _, libraryLocation := range locations {
				newResolver := matcherContext{
					resolver:    context.resolver,
					location:    libraryLocation,
					getContents: context.getContents,
				}
				newResolver.location = libraryLocation
				pkgs, err := sharedLibraryMatcher(classifier, newResolver)
				if err != nil {
					return nil, err
				}
				for _, p := range pkgs {
					// set the source binary as the first location
					locationSet := file.NewLocationSet(context.location)
					locationSet.Add(p.Locations.ToSlice()...)
					p.Locations = locationSet
					meta, _ := p.Metadata.(pkg.BinarySignature)
					p.Metadata = pkg.BinarySignature{
						Matches: append([]pkg.ClassifierMatch{
							{
								Classifier: classifier.Class,
								Location:   context.location,
							},
						}, meta.Matches...),
					}
					packages = append(packages, p)
				}
			}
		}
		return packages, nil
	}
}

func mustPURL(purl string) packageurl.PackageURL {
	p, err := packageurl.FromString(purl)
	if err != nil {
		panic(fmt.Sprintf("invalid PURL: %s", p))
	}
	return p
}

func getContents(context matcherContext) ([]byte, error) {
	if context.getContents != nil {
		return context.getContents(context)
	}
	reader, err := context.resolver.FileContentsByLocation(context.location)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogError(reader, context.location.AccessPath)

	// TODO: there may be room for improvement here, as this may use an excessive amount of memory. Alternate approach is to leverage a RuneReader.
	contents, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to get contents for file: %w", err)
	}

	return contents, nil
}

// singleCPE returns a []cpe.CPE with Source: Generated based on the cpe string or panics if the
// cpe string cannot be parsed into valid CPE Attributes
func singleCPE(cpeString string, source ...cpe.Source) []cpe.CPE {
	src := cpe.GeneratedSource
	if len(source) > 0 {
		src = source[0]
	}
	return []cpe.CPE{
		cpe.Must(cpeString, src),
	}
}

// sharedLibraries returns a list of all shared libraries found within a binary, currently
// supporting: elf, macho, and windows pe
func sharedLibraries(context matcherContext) ([]string, error) {
	contents, err := getContents(context)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(contents)

	e, _ := elf.NewFile(r)
	if e != nil {
		symbols, err := e.ImportedLibraries()
		if err != nil {
			log.Debugf("unable to read elf binary at: %s -- %s", context.location.RealPath, err)
		}
		return symbols, nil
	}

	m, _ := macho.NewFile(r)
	if m != nil {
		symbols, err := m.ImportedLibraries()
		if err != nil {
			log.Debugf("unable to read macho binary at: %s -- %s", context.location.RealPath, err)
		}
		return symbols, nil
	}

	p, _ := pe.NewFile(r)
	if p != nil {
		symbols, err := p.ImportedLibraries()
		if err != nil {
			log.Debugf("unable to read pe binary at: %s -- %s", context.location.RealPath, err)
		}
		return symbols, nil
	}

	return nil, nil
}
