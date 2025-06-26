package task

import (
	"context"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/mholt/archives"
)

const unknownsLabelerTaskName = "unknowns-labeler"

func NewUnknownsLabelerTask(cfg cataloging.UnknownsConfig) Task {
	return NewTask(unknownsLabelerTaskName, unknownsLabelerTask{cfg}.processUnknowns)
}

type unknownsLabelerTask struct {
	cataloging.UnknownsConfig
}

// processUnknowns removes unknown entries that have valid packages reported for the locations
func (c unknownsLabelerTask) processUnknowns(_ context.Context, resolver file.Resolver, builder sbomsync.Builder) error {
	accessor := builder.(sbomsync.Accessor)
	accessor.WriteToSBOM(func(s *sbom.SBOM) {
		c.finalize(resolver, s)
	})
	return nil
}

func (c unknownsLabelerTask) finalize(resolver file.Resolver, s *sbom.SBOM) {
	hasPackageReference := coordinateReferenceLookup(resolver, s)

	if c.RemoveWhenPackagesDefined {
		for coords := range s.Artifacts.Unknowns {
			if !hasPackageReference(coords) {
				continue
			}
			delete(s.Artifacts.Unknowns, coords)
		}
	}

	if s.Artifacts.Unknowns == nil {
		s.Artifacts.Unknowns = map[file.Coordinates][]string{}
	}

	if c.IncludeExecutablesWithoutPackages {
		for coords := range s.Artifacts.Executables {
			if !hasPackageReference(coords) {
				s.Artifacts.Unknowns[coords] = append(s.Artifacts.Unknowns[coords], formatUnknown("no package identified in executable file", unknownsLabelerTaskName))
			}
		}
	}

	if c.IncludeUnexpandedArchives {
		ctx := context.Background()
		for coords := range s.Artifacts.FileMetadata {
			format, _, notArchiveErr := archives.Identify(ctx, coords.RealPath, nil)
			if format != nil && notArchiveErr == nil && !hasPackageReference(coords) {
				s.Artifacts.Unknowns[coords] = append(s.Artifacts.Unknowns[coords], "archive not cataloged")
			}
		}
	}
}

func formatUnknown(err string, task ...string) string {
	return strings.Join(task, "/") + ": " + err
}

func coordinateReferenceLookup(resolver file.Resolver, s *sbom.SBOM) func(coords file.Coordinates) bool {
	allPackageCoords := file.NewCoordinateSet()

	// include all directly included locations that result in packages
	for p := range s.Artifacts.Packages.Enumerate() {
		allPackageCoords.Add(p.Locations.CoordinateSet().ToSlice()...)
	}

	// include owned files, for example specified by package managers.
	// relationships for these owned files may be disabled, but we always want to include them
	for p := range s.Artifacts.Packages.Enumerate() {
		if f, ok := p.Metadata.(pkg.FileOwner); ok {
			for _, ownedFilePath := range f.OwnedFiles() {
				// resolve these owned files, as they may have symlinks
				// but coordinates we will test against are always absolute paths
				locations, err := resolver.FilesByPath(ownedFilePath)
				if err != nil {
					log.Debugf("unable to resolve owned file '%s': %v", ownedFilePath, err)
				}
				for _, loc := range locations {
					allPackageCoords.Add(loc.Coordinates)
				}
			}
		}
	}

	// include relationships
	for _, r := range s.Relationships {
		_, fromPkgOk := r.From.(pkg.Package)
		fromFile, fromFileOk := r.From.(file.Coordinates)
		_, toPkgOk := r.To.(pkg.Package)
		toFile, toFileOk := r.To.(file.Coordinates)
		if fromPkgOk && toFileOk {
			allPackageCoords.Add(toFile)
		} else if fromFileOk && toPkgOk {
			allPackageCoords.Add(fromFile)
		}
	}

	return allPackageCoords.Contains
}
