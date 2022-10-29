package generic

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"text/template"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/unionreader"
	"github.com/anchore/syft/syft/source"
)

// Lookup is a generic package lookup that can be used to match a package definition
// To a file that meets the given content criteria of the EvidencePatternTemplates.
type Lookup struct {
	Package string
	// FilepathPatterns is a list of regular expressions that will be used to match against the file path of a given
	// source location. If any of the patterns match, the file will be considered a candidate for parsing.
	FilepathPatterns []*regexp.Regexp
	// EvidencePatternTemplates is a list of regular expressions that will be used to match against the file contents of a
	// given file in the source location. If any of the patterns match, the file will be considered a candidate for parsing.
	EvidencePatternTemplates []string
}

func (l Lookup) Find(reader source.LocationReadCloser) (p *pkg.Package, r *artifact.Relationship, err error) {
	doesFilepathMatch, filepathNamedGroupValues := file.FilepathMatches(l.FilepathPatterns, reader.Location)
	if !doesFilepathMatch {
		return nil, nil, fmt.Errorf("location: %s did not match any patterns for package=%q", reader.Location, l.Package)
	}

	unionReader, err := unionreader.GetUnionReader(reader.ReadCloser)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get union reader for file: %+v", err)
	}

	contents, err := io.ReadAll(unionReader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get read contents for file: %+v", err)
	}

	var lookupPkg *pkg.Package
	for _, patternTemplate := range l.EvidencePatternTemplates {
		tmpl, err := template.New("").Parse(patternTemplate)
		if err != nil {
			log.Debugf("unable to parse template: %+v", err)
			continue
		}

		patternBuf := &bytes.Buffer{}
		err = tmpl.Execute(patternBuf, filepathNamedGroupValues)
		if err != nil {
			log.Debugf("unable to execute template: %+v", err)
			continue
		}

		pattern, err := regexp.Compile(patternBuf.String())
		if err != nil {
			log.Debugf("unable to compile pattern: %+v", err)
			continue
		}

		if !pattern.Match(contents) {
			continue
		}

		matchMetadata := internal.MatchNamedCaptureGroups(pattern, string(contents))
		if lookupPkg == nil {
			lookupPkg = &pkg.Package{
				Name:      l.Package,
				Version:   matchMetadata["version"],
				Language:  pkg.UnknownLanguage,
				Locations: source.NewLocationSet(reader.Location),
				Type:      pkg.BinaryPkg,
			}
			lookupPkg.SetID()
		}
	}
	return lookupPkg, nil, nil
}
