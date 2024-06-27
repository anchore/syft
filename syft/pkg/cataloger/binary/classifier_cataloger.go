/*
Package binary provides a concrete cataloger implementations for surfacing possible packages based on signatures found within binary files.
*/
package binary

import (
	"context"
	"encoding/json"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

const catalogerName = "binary-classifier-cataloger"

type ClassifierCatalogerConfig struct {
	Classifiers []Classifier `yaml:"classifiers" json:"classifiers" mapstructure:"classifiers"`
}

func DefaultClassifierCatalogerConfig() ClassifierCatalogerConfig {
	return ClassifierCatalogerConfig{
		Classifiers: DefaultClassifiers(),
	}
}

func NewClassifierCataloger(cfg ClassifierCatalogerConfig) pkg.Cataloger {
	return &cataloger{
		classifiers: cfg.Classifiers,
	}
}

func (cfg ClassifierCatalogerConfig) MarshalJSON() ([]byte, error) {
	// only keep the class names
	var names []string
	for _, cls := range cfg.Classifiers {
		names = append(names, cls.Class)
	}
	return json.Marshal(names)
}

// cataloger is the cataloger responsible for surfacing evidence of a very limited set of binary files,
// which have been identified by the classifiers. The cataloger is _NOT_ a place to catalog any and every
// binary, but rather the specific set that has been curated to be important, predominantly related to toolchain-
// related runtimes like Python, Go, Java, or Node. Some exceptions can be made for widely-used binaries such
// as busybox.
type cataloger struct {
	classifiers []Classifier
}

// Name returns a string that uniquely describes the cataloger
func (c cataloger) Name() string {
	return catalogerName
}

// Catalog is given an object to resolve file references and content, this function returns any discovered Packages
// after analyzing the catalog source.
func (c cataloger) Catalog(_ context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package
	var relationships []artifact.Relationship

	for _, cls := range c.classifiers {
		log.WithFields("classifier", cls.Class).Trace("cataloging binaries")
		newPkgs, err := catalog(resolver, cls)
		if err != nil {
			log.WithFields("error", err, "classifier", cls.Class).Warn("unable to catalog binary package: %w", err)
			continue
		}
	newPackages:
		for i := range newPkgs {
			newPkg := &newPkgs[i]
			for j := range packages {
				p := &packages[j]
				// consolidate identical packages found in different locations or by different classifiers
				if packagesMatch(p, newPkg) {
					mergePackages(p, newPkg)
					continue newPackages
				}
			}
			packages = append(packages, *newPkg)
		}
	}

	return packages, relationships, nil
}

// mergePackages merges information from the extra package into the target package
func mergePackages(target *pkg.Package, extra *pkg.Package) {
	// add the locations
	target.Locations.Add(extra.Locations.ToSlice()...)
	// update the metadata to indicate which classifiers were used
	meta, _ := target.Metadata.(pkg.BinarySignature)
	if m, ok := extra.Metadata.(pkg.BinarySignature); ok {
		meta.Matches = append(meta.Matches, m.Matches...)
	}
	target.Metadata = meta
}

func catalog(resolver file.Resolver, cls Classifier) (packages []pkg.Package, err error) {
	locations, err := resolver.FilesByGlob(cls.FileGlob)
	if err != nil {
		return nil, err
	}
	for _, location := range locations {
		pkgs, err := cls.EvidenceMatcher(cls, matcherContext{resolver: resolver, location: location})
		if err != nil {
			return nil, err
		}
		packages = append(packages, pkgs...)
	}
	return packages, nil
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
