package javascript

import (
	"regexp"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
)

var nodeClassifier = generic.Classifier{
	Package: "node.js", // Note: this purposely matches the "node.js" string to aid nvd vuln matching
	FilepathPatterns: []*regexp.Regexp{
		// note: should we just parse all files resolved with executable mimetypes
		// regexp that matches node binary
		regexp.MustCompile(`(.*/|^)node$`),
	},
	EvidencePatterns: []*regexp.Regexp{
		// regex that matches node.js/vx.y.z
		regexp.MustCompile(`(?m)node\.js\/v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
	},
	CPEs: []pkg.CPE{
		pkg.MustCPE("cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*"),
	},
}

func parseNodeBinary(_ source.FileResolver, _ *generic.Environment, reader source.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	p, _, err := nodeClassifier.Examine(reader)
	if err != nil {
		log.Trace("failed to find node.js package: %+v", err)
		return nil, nil, nil // we can silently fail here to reduce warning noise
	}

	// TODO add node specific metadata to the packages to help with vulnerability matching
	if p != nil {
		p.Language = pkg.JavaScript
        p.SetID()
		return []pkg.Package{*p}, nil, nil
	}
	return nil, nil, nil
}
