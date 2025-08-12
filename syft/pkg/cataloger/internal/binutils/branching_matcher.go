package binutils

import (
	"io"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/internal/unionreader"
	"github.com/anchore/syft/syft/pkg"
)

// BranchingEvidenceMatcher loads the contents of the reader into memory, assuming that all
// classifier matchers are going to be reading the same file, e.g. a "java" binary, continuing to
// try classifier EvidenceMatcher until the first set of packages is found
func BranchingEvidenceMatcher(classifiers ...Classifier) EvidenceMatcher {
	return func(_ Classifier, context MatcherContext) ([]pkg.Package, error) {
		// we are scanning the same contents multiple times, so read it into memory for a reader that can reset
		rdr, err := getReader(context)
		if err != nil {
			return nil, err
		}
		defer internal.CloseAndLogError(rdr, context.Location.RealPath)
		if err != nil {
			return nil, err
		}
		for _, c := range classifiers {
			pkgs, err := c.EvidenceMatcher(c, MatcherContext{
				Resolver: context.Resolver,
				Location: context.Location,
				GetReader: func(_ MatcherContext) (unionreader.UnionReader, error) {
					_, err := rdr.Seek(0, io.SeekStart)
					if err != nil {
						return nil, err
					}
					return &nonClosingUnionReader{rdr}, nil
				},
			})
			if len(pkgs) > 0 || err != nil {
				return pkgs, err
			}
		}
		return nil, nil
	}
}

type nonClosingUnionReader struct {
	unionreader.UnionReader
}

func (c *nonClosingUnionReader) Close() error {
	return nil
}
