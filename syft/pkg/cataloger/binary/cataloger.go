package binary

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const catalogerName = "binary-cataloger"

func NewCataloger() *Cataloger {
	return &Cataloger{}
}

// Cataloger is the cataloger responsible for surfacing evidence of a very limited set of binary files,
// which have been identified by the classifiers. The Cataloger is _NOT_ a place to catalog any and every
// binary, but rather the specific set that has been curated to be important, predominantly related to toolchain-
// related runtimes like Python, Go, Java, or Node. Some exceptions can be made for widely-used binaries such
// as busybox.
type Cataloger struct{}

// Name returns a string that uniquely describes the Cataloger
func (c Cataloger) Name() string {
	return catalogerName
}

// Catalog is given an object to resolve file references and content, this function returns any discovered Packages
// after analyzing the catalog source.
func (c Cataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package
	var relationships []artifact.Relationship

	for _, classifier := range defaultClassifiers {
		locations, err := resolver.FilesByGlob(classifier.FileGlob)
		if err != nil {
			return nil, nil, err
		}
		for _, location := range locations {
			reader, err := resolver.FileContentsByLocation(location)
			if err != nil {
				return nil, nil, err
			}
			locationReader := source.NewLocationReadCloser(location, reader)
			newPkgs, err := classifier.EvidenceMatcher(classifier, locationReader)
			if err != nil {
				return nil, nil, err
			}
		newPackages:
			for i := range newPkgs {
				newPkg := &newPkgs[i]
				for j := range packages {
					p := &packages[j]
					// consolidate identical packages found in different locations,
					// but continue to track each location
					if packagesMatch(p, newPkg) {
						p.Locations.Add(newPkg.Locations.ToSlice()...)
						continue newPackages
					}
				}
				packages = append(packages, *newPkg)
			}
		}
	}

	return packages, relationships, nil
}

// packagesMatch returns true if the binary packages "match" based on basic criteria
func packagesMatch(p1 *pkg.Package, p2 *pkg.Package) bool {
	if p1.Name != p2.Name ||
		p1.Version != p2.Version ||
		p1.Language != p2.Language ||
		p1.Type != p2.Type {
		return false
	}

	return true
}
