package binary

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"text/template"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/unionreader"
	"github.com/anchore/syft/syft/source"
)

var emptyPURL = packageurl.PackageURL{}

// classifier is a generic package classifier that can be used to match a package definition
// to a file that meets the given content criteria of the evidenceMatcher.
type classifier struct {
	Class string

	// FileGlob is a selector to narrow down file inspection using the **/glob* syntax
	FileGlob string

	// EvidenceMatcher is what will be used to match against the file in the source
	// location. If the matcher returns a package, the file will be considered a candidate.
	EvidenceMatcher evidenceMatcher

	// Information below is used to specify the Package information when returned

	// Package is the name to use for the package
	Package string

	// Language is the language to classify this package as
	Language pkg.Language

	// Type is the package type to use for the package
	Type pkg.Type

	// PURL is the Package URL to use when generating a package
	PURL packageurl.PackageURL

	// CPEs are the specific CPEs we want to include for this binary with updated version information
	CPEs []cpe.CPE
}

// evidenceMatcher is a function called to catalog Packages that match some sort of evidence
type evidenceMatcher func(resolver source.FileResolver, classifier classifier, reader source.LocationReadCloser) ([]pkg.Package, error)

func evidenceMatchers(matchers ...evidenceMatcher) evidenceMatcher {
	return func(resolver source.FileResolver, classifier classifier, reader source.LocationReadCloser) ([]pkg.Package, error) {
		for i, matcher := range matchers {
			if i > 0 {
				readCloser, err := resolver.FileContentsByLocation(reader.Location)
				if err != nil {
					return nil, err
				}
				reader = source.NewLocationReadCloser(reader.Location, readCloser)
			}
			match, err := matcher(resolver, classifier, reader)
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

func fileNameTemplateVersionMatcher(fileNamePattern string, contentTemplate string) evidenceMatcher {
	pat := regexp.MustCompile(fileNamePattern)
	return func(_ source.FileResolver, classifier classifier, reader source.LocationReadCloser) ([]pkg.Package, error) {
		if !pat.MatchString(reader.RealPath) {
			return nil, nil
		}

		filepathNamedGroupValues := internal.MatchNamedCaptureGroups(pat, reader.RealPath)

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

		contents, err := getContents(reader)
		if err != nil {
			return nil, fmt.Errorf("unable to get read contents for file: %w", err)
		}

		matchMetadata := internal.MatchNamedCaptureGroups(tmplPattern, string(contents))
		return singlePackage(classifier, reader, matchMetadata), nil
	}
}

func fileContentsVersionMatcher(pattern string) evidenceMatcher {
	pat := regexp.MustCompile(pattern)
	return func(_ source.FileResolver, classifier classifier, reader source.LocationReadCloser) ([]pkg.Package, error) {
		contents, err := getContents(reader)
		if err != nil {
			return nil, fmt.Errorf("unable to get read contents for file: %w", err)
		}

		matchMetadata := internal.MatchNamedCaptureGroups(pat, string(contents))
		return singlePackage(classifier, reader, matchMetadata), nil
	}
}

func isExecutable(mode os.FileMode) bool {
	return mode&0111 != 0
}

//nolint:gocognit
func sharedLibraryLookup(sharedLibraryPattern string, sharedLibraryMatcher evidenceMatcher) evidenceMatcher {
	pat := regexp.MustCompile(sharedLibraryPattern)
	return func(resolver source.FileResolver, classifier classifier, reader source.LocationReadCloser) (packages []pkg.Package, _ error) {
		meta, err := resolver.FileMetadataByLocation(reader.Location)
		if err != nil {
			return nil, err
		}

		if !isExecutable(meta.Mode) {
			return nil, nil
		}

		libs, err := sharedLibraries(reader)
		if err != nil {
			return nil, err
		}
		for _, lib := range libs {
			if pat.MatchString(lib) {
				locations, err := resolver.FilesByGlob("**/" + lib)
				if err != nil {
					return nil, err
				}
				for _, location := range locations {
					readCloser, err := resolver.FileContentsByLocation(location)
					if err != nil {
						return nil, err
					}
					if readCloser == nil {
						log.Debug("unable to get reader for location: %+v", location)
						continue
					}
					locationReader := source.NewLocationReadCloser(location, readCloser)
					pkgs, err := sharedLibraryMatcher(resolver, classifier, locationReader)
					if err != nil {
						return nil, err
					}
					for _, p := range pkgs {
						// set the source binary as the first location
						locationSet := source.NewLocationSet(reader.Location)
						locationSet.Add(p.Locations.ToSlice()...)
						p.Locations = locationSet
						packages = append(packages, p)
					}
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

func singlePackage(classifier classifier, reader source.LocationReadCloser, matchMetadata map[string]string) []pkg.Package {
	version, ok := matchMetadata["version"]
	if !ok {
		return nil
	}

	update := matchMetadata["update"]

	var cpes []cpe.CPE
	for _, c := range classifier.CPEs {
		c.Version = version
		c.Update = update
		cpes = append(cpes, c)
	}

	p := pkg.Package{
		Name:         classifier.Package,
		Version:      version,
		Locations:    source.NewLocationSet(reader.Location),
		Type:         pkg.BinaryPkg,
		CPEs:         cpes,
		FoundBy:      catalogerName,
		MetadataType: pkg.BinaryMetadataType,
		Metadata: pkg.BinaryMetadata{
			Matches: []pkg.ClassifierMatch{
				{
					Classifier: classifier.Class,
					Location:   reader.Location,
				},
			},
		},
	}

	if classifier.Type != "" {
		p.Type = classifier.Type
	}

	if !reflect.DeepEqual(classifier.PURL, emptyPURL) {
		purl := classifier.PURL
		purl.Version = version
		p.PURL = purl.ToString()
	}

	if classifier.Language != "" {
		p.Language = classifier.Language
	}

	p.SetID()

	return []pkg.Package{p}
}

func getContents(reader source.LocationReadCloser) ([]byte, error) {
	unionReader, err := unionreader.GetUnionReader(reader.ReadCloser)
	if err != nil {
		return nil, fmt.Errorf("unable to get union reader for file: %w", err)
	}

	// TODO: there may be room for improvement here, as this may use an excessive amount of memory. Alternate approach is to leverage a RuneReader.
	contents, err := io.ReadAll(unionReader)
	if err != nil {
		return nil, fmt.Errorf("unable to get contents for file: %w", err)
	}

	return contents, nil
}

// singleCPE returns a []pkg.CPE based on the cpe string or panics if the CPE is invalid
func singleCPE(cpeString string) []cpe.CPE {
	return []cpe.CPE{
		cpe.Must(cpeString),
	}
}

// sharedLibraries returns a list of all shared libraries found within a binary, currently
// supporting: elf, macho, and windows pe
func sharedLibraries(reader source.LocationReadCloser) ([]string, error) {
	contents, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(contents)

	e, err := elf.NewFile(r)
	if err != nil {
		log.Debug(err)
	}
	if e != nil {
		symbols, err := e.ImportedLibraries()
		if err != nil {
			log.Debug(err)
		}
		return symbols, nil
	}

	m, err := macho.NewFile(r)
	if err != nil {
		log.Debug(err)
	}
	if m != nil {
		symbols, err := m.ImportedLibraries()
		if err != nil {
			log.Debug(err)
		}
		return symbols, nil
	}

	p, err := pe.NewFile(r)
	if err != nil {
		log.Debug(err)
	}
	if p != nil {
		symbols, err := p.ImportedLibraries()
		if err != nil {
			log.Debug(err)
		}
		return symbols, nil
	}

	return nil, nil
}
