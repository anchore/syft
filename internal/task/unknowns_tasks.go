package task

import (
	"context"

	"github.com/mholt/archiver/v3"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
)

type UnknownsConfig struct {
	IncludeExecutablesWithoutPackages bool
	IncludeUnexpandedArchives         bool
}

func DefaultUnknownsConfig() UnknownsConfig {
	return UnknownsConfig{
		IncludeExecutablesWithoutPackages: true,
		IncludeUnexpandedArchives:         true,
	}
}

func NewUnknownsFinalizeTask(cfg UnknownsConfig) Task {
	return NewTask("unknowns-finalize", cfg.processUnknowns)
}

// processUnknowns removes unknown entries that have valid packages reported for the locations
func (c UnknownsConfig) processUnknowns(_ context.Context, _ file.Resolver, builder sbomsync.Builder) error {
	accessor := builder.(sbomsync.Accessor)
	accessor.WriteToSBOM(func(s *sbom.SBOM) {
		allPackageCoords := file.NewCoordinateSet()
		for p := range s.Artifacts.Packages.Enumerate() {
			allPackageCoords.Add(p.Locations.CoordinateSet().ToSlice()...)
		}

		for coords := range s.Artifacts.Unknowns {
			if !allPackageCoords.Contains(coords) {
				continue
			}
			delete(s.Artifacts.Unknowns, coords)
		}

		if s.Artifacts.Unknowns == nil {
			s.Artifacts.Unknowns = map[file.Coordinates][]string{}
		}

		if c.IncludeExecutablesWithoutPackages {
			for coords := range s.Artifacts.Executables {
				if !allPackageCoords.Contains(coords) {
					s.Artifacts.Unknowns[coords] = append(s.Artifacts.Unknowns[coords], "no package identified in executable file")
				}
			}
		}

		if c.IncludeUnexpandedArchives {
			for coords := range s.Artifacts.FileMetadata {
				unarchiver, notArchiveErr := archiver.ByExtension(coords.RealPath)
				if unarchiver != nil && notArchiveErr == nil && !allPackageCoords.Contains(coords) {
					s.Artifacts.Unknowns[coords] = append(s.Artifacts.Unknowns[coords], "archive not cataloged")
				}
			}
		}
	})
	return nil
}
