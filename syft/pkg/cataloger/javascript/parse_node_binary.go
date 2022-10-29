package javascript

import (
	"github.com/anchore/syft/internal/log"
	"regexp"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
)

var nodeLookup = generic.Lookup{
	Package: "node.js", // Note: this purposely matches the "node.js" string to aid nvd vuln matching
	FilepathPatterns: []*regexp.Regexp{
		// note: should we just parse all files resolved with executable mimetypes
		// regexp that matches node binary
		regexp.MustCompile(`(.*/|^)node$`),
	},
	EvidencePatternTemplates: []string{
		// regex that matches node.js/vx.y.z
		`(?m)node\.js\/v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`,
	},
}

func parseNodeBinary(_ source.FileResolver, _ *generic.Environment, reader source.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	p, _, err := nodeLookup.Find(reader)
	if err != nil {
		log.Debugf("unable to find node.js package for file:%s; err: %+v", reader.VirtualPath, err)
		return nil, nil, err
	}
	// TODO add node specific metadata to the packages
	if p != nil {
		return []pkg.Package{*p}, nil, nil
	}
	return nil, nil, nil
}
