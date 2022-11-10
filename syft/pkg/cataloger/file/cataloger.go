package file

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const catalogerName = "file-cataloger"

func NewFileCataloger() pkg.Cataloger {
	return &fileCataloger{}
}

// fileCataloger is the cataloger responsible for cataloging files classified by the classifiers into packages
type fileCataloger struct{}

// Name returns a string that uniquely describes a cataloger
func (c fileCataloger) Name() string {
	return catalogerName
}

// Catalog is given an object to resolve file references and content, this function returns any discovered Packages
// after analyzing the catalog source.
func (c fileCataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package
	var relationships []artifact.Relationship

	for _, classifier := range DefaultClassifiers {
		locations, err := resolver.FilesByGlob(classifier.FileGlob)
		if err != nil {
			return nil, nil, err
		}
		for _, location := range locations {
			reader, err := resolver.FileContentsByLocation(location)
			if err != nil {
				return nil, nil, err
			}
			locationReader := source.LocationReadCloser{
				Location:   location,
				ReadCloser: reader,
			}
			newPkgs, err := classifier.EvidenceMatcher(classifier, locationReader)
			if err != nil {
				return nil, nil, err
			}
		newPackages:
			for _, newPkg := range newPkgs {
				for i := range packages {
					p := &packages[i]
					if packagesMatch(p, &newPkg) {
						p.Locations.Add(newPkg.Locations.ToSlice()...)
						continue newPackages
					}
				}
				packages = append(packages, newPkg)
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
