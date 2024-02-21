package task

import (
	"context"
	"crypto"
	"fmt"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/file/cataloger/executable"
	"github.com/anchore/syft/syft/file/cataloger/filecontent"
	"github.com/anchore/syft/syft/file/cataloger/filedigest"
	"github.com/anchore/syft/syft/file/cataloger/filemetadata"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func NewFileDigestCatalogerTask(selection file.Selection, hashers ...crypto.Hash) Task {
	if selection == file.NoFilesSelection || len(hashers) == 0 {
		return nil
	}

	digestsCataloger := filedigest.NewCataloger(hashers)

	fn := func(ctx context.Context, resolver file.Resolver, builder sbomsync.Builder) error {
		accessor := builder.(sbomsync.Accessor)

		coordinates, ok := coordinatesForSelection(selection, builder.(sbomsync.Accessor))
		if !ok {
			return nil
		}

		result, err := digestsCataloger.Catalog(ctx, resolver, coordinates...)
		if err != nil {
			return fmt.Errorf("unable to catalog file digests: %w", err)
		}

		accessor.WriteToSBOM(func(sbom *sbom.SBOM) {
			sbom.Artifacts.FileDigests = result
		})

		return nil
	}

	return NewTask("file-digest-cataloger", fn)
}

func NewFileMetadataCatalogerTask(selection file.Selection) Task {
	if selection == file.NoFilesSelection {
		return nil
	}

	metadataCataloger := filemetadata.NewCataloger()

	fn := func(ctx context.Context, resolver file.Resolver, builder sbomsync.Builder) error {
		accessor := builder.(sbomsync.Accessor)

		coordinates, ok := coordinatesForSelection(selection, builder.(sbomsync.Accessor))
		if !ok {
			return nil
		}

		result, err := metadataCataloger.Catalog(ctx, resolver, coordinates...)
		if err != nil {
			return err
		}

		accessor.WriteToSBOM(func(sbom *sbom.SBOM) {
			sbom.Artifacts.FileMetadata = result
		})

		return nil
	}

	return NewTask("file-metadata-cataloger", fn)
}

func NewFileContentCatalogerTask(cfg filecontent.Config) Task {
	if len(cfg.Globs) == 0 {
		return nil
	}

	cat := filecontent.NewCataloger(cfg)

	fn := func(ctx context.Context, resolver file.Resolver, builder sbomsync.Builder) error {
		accessor := builder.(sbomsync.Accessor)

		result, err := cat.Catalog(ctx, resolver)
		if err != nil {
			return err
		}

		accessor.WriteToSBOM(func(sbom *sbom.SBOM) {
			sbom.Artifacts.FileContents = result
		})

		return nil
	}

	return NewTask("file-content-cataloger", fn)
}

func NewExecutableCatalogerTask(selection file.Selection, cfg executable.Config) Task {
	if selection == file.NoFilesSelection {
		return nil
	}

	cat := executable.NewCataloger(cfg)

	fn := func(_ context.Context, resolver file.Resolver, builder sbomsync.Builder) error {
		accessor := builder.(sbomsync.Accessor)

		result, err := cat.Catalog(resolver)
		if err != nil {
			return err
		}

		accessor.WriteToSBOM(func(sbom *sbom.SBOM) {
			sbom.Artifacts.Executables = result
		})

		return nil
	}

	return NewTask("file-executable-cataloger", fn)
}

// TODO: this should be replaced with a fix that allows passing a coordinate or location iterator to the cataloger
// Today internal to both cataloger this functions differently: a slice of coordinates vs a channel of locations
func coordinatesForSelection(selection file.Selection, accessor sbomsync.Accessor) ([]file.Coordinates, bool) {
	if selection == file.AllFilesSelection {
		return nil, true
	}

	if selection == file.FilesOwnedByPackageSelection {
		var coordinates []file.Coordinates

		accessor.ReadFromSBOM(func(sbom *sbom.SBOM) {
			for _, r := range sbom.Relationships {
				if r.Type != artifact.ContainsRelationship {
					continue
				}
				if _, ok := r.From.(pkg.Package); !ok {
					continue
				}
				if c, ok := r.To.(file.Coordinates); ok {
					coordinates = append(coordinates, c)
				}
			}
		})

		if len(coordinates) == 0 {
			return nil, false
		}

		return coordinates, true
	}

	return nil, false
}
