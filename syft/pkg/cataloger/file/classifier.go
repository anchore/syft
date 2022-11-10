package file

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"text/template"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/unionreader"
	"github.com/anchore/syft/syft/source"
)

var emptyPURL = packageurl.PackageURL{}

// Classifier is a generic package classifier that can be used to match a package definition
// to a file that meets the given content criteria of the EvidenceMatcher.
type Classifier struct {
	Class string

	// FileGlob is a selector to narrow down file inspection using the **/glob* syntax
	FileGlob string

	// EvidenceMatcher is what will be used to match against the file in the source
	// location. If the matcher returns a package, the file will be considered a candidate.
	EvidenceMatcher EvidenceMatcher

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
	CPEs []pkg.CPE
}

// EvidenceMatcher is a function called to catalog Packages that match some sort of evidence
type EvidenceMatcher func(classifier Classifier, reader source.LocationReadCloser) ([]pkg.Package, error)

func MultiMatcher(matchers ...EvidenceMatcher) EvidenceMatcher {
	return func(classifier Classifier, reader source.LocationReadCloser) ([]pkg.Package, error) {
		for _, matcher := range matchers {
			p, err := matcher(classifier, reader)
			if err != nil {
				return nil, err
			}
			if p != nil {
				return p, nil
			}
		}
		return nil, nil
	}
}

func fileNameTemplateVersionMatcher(fileNamePattern string, contentTemplate string) EvidenceMatcher {
	pat := regexp.MustCompile(fileNamePattern)
	return func(classifier Classifier, reader source.LocationReadCloser) ([]pkg.Package, error) {
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
			return nil, fmt.Errorf("unable to get read contents for file: %+v", err)
		}

		matchMetadata := internal.MatchNamedCaptureGroups(tmplPattern, string(contents))

		version, ok := matchMetadata["version"]
		if ok {
			return singlePackage(classifier, reader, version), nil
		}

		return nil, nil
	}
}

func fileContentsVersionMatcher(pattern string) EvidenceMatcher {
	pat := regexp.MustCompile(pattern)
	return func(classifier Classifier, reader source.LocationReadCloser) ([]pkg.Package, error) {
		contents, err := getContents(reader)
		if err != nil {
			return nil, fmt.Errorf("unable to get read contents for file: %+v", err)
		}

		matchMetadata := internal.MatchNamedCaptureGroups(pat, string(contents))
		version, ok := matchMetadata["version"]
		if ok {
			return singlePackage(classifier, reader, version), nil
		}
		return nil, nil
	}
}

func mustPURL(purl string) packageurl.PackageURL {
	p, err := packageurl.FromString(purl)
	if err != nil {
		panic(fmt.Sprintf("invalid PURL: %s", p))
	}
	return p
}

func singlePackage(classifier Classifier, reader source.LocationReadCloser, version string) []pkg.Package {
	var cpes []pkg.CPE
	for _, cpe := range classifier.CPEs {
		cpe.Version = version
		cpes = append(cpes, cpe)
	}

	p := pkg.Package{
		Name:         classifier.Package,
		Version:      version,
		Language:     pkg.Binary,
		Locations:    source.NewLocationSet(reader.Location),
		Type:         pkg.BinaryPkg,
		CPEs:         cpes,
		MetadataType: pkg.BinaryMetadataType,
		Metadata: pkg.BinaryMetadata{
			Classifier:  classifier.Class,
			RealPath:    reader.RealPath,
			VirtualPath: reader.VirtualPath,
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
		return nil, fmt.Errorf("unable to get union reader for file: %+v", err)
	}

	// TODO: there may be room for improvement here, as this may use an excessive amount of memory. Alternate approach is to leverage a RuneReader.
	contents, err := io.ReadAll(unionReader)
	if err != nil {
		return nil, fmt.Errorf("unable to get contents for file: %+v", err)
	}

	return contents, nil
}

// singleCPE returns a []pkg.CPE based on the cpe string or panics if the CPE is invalid
func singleCPE(cpe string) []pkg.CPE {
	return []pkg.CPE{
		pkg.MustCPE(cpe),
	}
}
