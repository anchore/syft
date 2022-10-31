package generic

import (
	"fmt"
	"io"
	"path"
	"regexp"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/unionreader"
	"github.com/anchore/syft/syft/source"
)

// Classifier is a generic package classifier that can be used to match a package definition
// to a file that meets the given content criteria of the EvidencePatternTemplates.
type Classifier struct {
	Package string
	// FilepathPatterns is a list of regular expressions that will be used to match against the file path of a given
	// source location. If any of the patterns match, the file will be considered a candidate for parsing.
	// If no patterns are provided, the reader is automatically considered a candidate.
	FilepathPatterns []*regexp.Regexp
	// EvidencePattern is a list of regular expressions that will be used to match against the file contents of a
	// given file in the source location. If any of the patterns match, the file will be considered a candidate for parsing.
	EvidencePatterns []*regexp.Regexp
	// CPE is the CPE we want to match against
	CPEs []pkg.CPE
}

func (c Classifier) Examine(reader source.LocationReadCloser) (p *pkg.Package, r *artifact.Relationship, err error) {
	doesFilepathMatch := true
	if len(c.FilepathPatterns) > 0 {
		doesFilepathMatch, _ = file.FilepathMatches(c.FilepathPatterns, reader.Location)
	}

	if !doesFilepathMatch {
		return nil, nil, fmt.Errorf("location: %s did not match any patterns for package=%q", reader.Location, c.Package)
	}

	contents, err := getContents(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get read contents for file: %+v", err)
	}

	var classifiedPackage *pkg.Package
	for _, patternTemplate := range c.EvidencePatterns {
		if !patternTemplate.Match(contents) {
			continue
		}

		matchMetadata := internal.MatchNamedCaptureGroups(patternTemplate, string(contents))
		if classifiedPackage == nil {
			classifiedPackage = &pkg.Package{
				Name:         path.Base(reader.VirtualPath),
				Version:      matchMetadata["version"],
				Language:     pkg.Binary,
				Locations:    source.NewLocationSet(reader.Location),
				Type:         pkg.BinaryPkg,
				CPEs:         c.CPEs,
				MetadataType: pkg.BinaryMetadataType,
				Metadata: pkg.BinaryMetadata{
					Classifier:  c.Package,
					RealPath:    reader.RealPath,
					VirtualPath: reader.VirtualPath,
				},
			}
			break
		}
	}
	return classifiedPackage, nil, nil
}

func getContents(reader source.LocationReadCloser) ([]byte, error) {
	unionReader, err := unionreader.GetUnionReader(reader.ReadCloser)
	if err != nil {
		return nil, fmt.Errorf("unable to get union reader for file: %+v", err)
	}

	contents, err := io.ReadAll(unionReader)
	if err != nil {
		return nil, fmt.Errorf("unable to get contents for file: %+v", err)
	}

	return contents, nil
}
