package binary

import (
	"bytes"
	"io"
	"regexp"
	"text/template"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/unionreader"
	"github.com/anchore/syft/syft/source"
)

var binaryParsers = []binaryParser{
	{
		Package: "node.js", // Note: this purposely matches the "node.js" string to aid nvd vuln matching
		FilepathPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(.*/|^)node$`),
		},
		EvidencePatternTemplates: []string{
			// regex that matches node.js/vx.y.z
			`(?m)node\.js\/v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`,
		},
	},
	{
		Package: "busybox-binary",
		FilepathPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(.*/|^)busybox$`),
		},
		EvidencePatternTemplates: []string{
			`(?m)BusyBox\s+v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`,
		},
	},
}

type binaryParser struct {
	Package                  string
	FilepathPatterns         []*regexp.Regexp
	EvidencePatternTemplates []string
}

func parseBinary(_ source.FileResolver, _ *generic.Environment, reader source.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	packages := make([]pkg.Package, 0)
	for _, binParser := range binaryParsers {
		doesFilepathMatch, filepathNamedGroupValues := file.FilepathMatches(binParser.FilepathPatterns, reader.Location)
		if !doesFilepathMatch {
			continue
		}

		unionReader, err := unionreader.GetUnionReader(reader.ReadCloser)
		if err != nil {
			log.Debugf("unable to get union reader for binary: %+v", err)
			continue
		}

		contents, err := io.ReadAll(unionReader)
		if err != nil {
			log.Debugf("unable to get union reader for binary: %+v", err)
			continue
		}

		var binPkg *pkg.Package
		for _, patternTemplate := range binParser.EvidencePatternTemplates {
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
			if binPkg == nil {
				binPkg = &pkg.Package{
					Name:         binParser.Package,
					Version:      matchMetadata["version"],
					Language:     pkg.UnknownLanguage,
					Locations:    source.NewLocationSet(reader.Location),
					Type:         pkg.UnknownPkg,
					MetadataType: pkg.UnknownMetadataType,
				}
				binPkg.SetID()
				packages = append(packages, *binPkg)
			}
		}
	}
	return packages, nil, nil
}
