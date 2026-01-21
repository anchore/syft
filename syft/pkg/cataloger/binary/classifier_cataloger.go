/*
Package binary provides a concrete cataloger implementations for surfacing possible packages based on signatures found within binary files.
*/
package binary

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/binutils"
)

const catalogerName = "binary-classifier-cataloger"

type ClassifierCatalogerConfig struct {
	Classifiers []binutils.Classifier `yaml:"classifiers" json:"classifiers" mapstructure:"classifiers"`
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
	classifiers []binutils.Classifier
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
	var errs error

	for _, cls := range c.classifiers {
		log.WithFields("classifier", cls.Class).Trace("cataloging binaries")
		newPkgs, err := catalog(resolver, cls)
		if err != nil {
			log.WithFields("error", err, "classifier", cls.Class).Debugf("unable to catalog binary package: %v", err)
			errs = unknown.Join(errs, fmt.Errorf("%s: %w", cls.Class, err))
			continue
		}
	newPackages:
		for i := range newPkgs {
			newPkg := &newPkgs[i]
			purlType := pkg.TypeFromPURL(newPkg.PURL)
			// for certain results, such as hashicorp vault we are returning a golang PURL, so we can use Golang package type,
			// despite not having the known metadata, this should result in downstream grype matching to use the golang matcher
			if purlType != pkg.UnknownPkg {
				newPkg.Type = purlType
			}
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

	return packages, relationships, errs
}

// mergePackages merges information from the extra package into the target package
func mergePackages(target *pkg.Package, extra *pkg.Package) {
	if extra.Type != pkg.BinaryPkg && target.Type == pkg.BinaryPkg {
		target.Type = extra.Type
	}
	// add the locations
	target.Locations.Add(extra.Locations.ToSlice()...)
	// update the metadata to indicate which classifiers were used
	meta, _ := target.Metadata.(pkg.BinarySignature)
	if m, ok := extra.Metadata.(pkg.BinarySignature); ok {
		meta.Matches = append(meta.Matches, m.Matches...)
	}
	target.Metadata = meta
}

func catalog(resolver file.Resolver, cls binutils.Classifier) (packages []pkg.Package, err error) {
	var errs error
	locations, err := resolver.FilesByGlob(cls.FileGlob)
	if err != nil {
		err = unknown.ProcessPathErrors(err) // convert any file.Resolver path errors to unknowns with locations
		return nil, err
	}
	for _, location := range locations {
		pkgs, err := cls.EvidenceMatcher(cls, binutils.MatcherContext{Resolver: resolver, Location: location})
		if err != nil {
			errs = unknown.Append(errs, location, err)
			continue
		}
		packages = append(packages, pkgs...)
	}
	return packages, errs
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
