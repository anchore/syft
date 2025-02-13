package task

import (
	"context"
	"crypto"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/file/cataloger/executable"
	"github.com/anchore/syft/syft/file/cataloger/filecontent"
	"github.com/anchore/syft/syft/file/cataloger/filedigest"
	"github.com/anchore/syft/syft/file/cataloger/filemetadata"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func DefaultFileTaskFactories() Factories {
	return Factories{
		newFileDigestCatalogerTaskFactory("digest"),
		newFileMetadataCatalogerTaskFactory("file-metadata"),
		newFileContentCatalogerTaskFactory("content"),
		newExecutableCatalogerTaskFactory("binary-metadata"),
	}
}

func newFileDigestCatalogerTaskFactory(tags ...string) factory {
	return func(cfg CatalogingFactoryConfig) Task {
		return newFileDigestCatalogerTask(cfg.FilesConfig.Selection, cfg.FilesConfig.Hashers, tags...)
	}
}

func newFileDigestCatalogerTask(selection file.Selection, hashers []crypto.Hash, tags ...string) Task {
	fn := func(ctx context.Context, resolver file.Resolver, builder sbomsync.Builder) error {
		if selection == file.NoFilesSelection || len(hashers) == 0 {
			return nil
		}

		accessor := builder.(sbomsync.Accessor)

		coordinates, ok := coordinatesForSelection(selection, builder.(sbomsync.Accessor))
		if !ok {
			return nil
		}

		result, err := filedigest.NewCataloger(hashers).Catalog(ctx, resolver, coordinates...)

		accessor.WriteToSBOM(func(sbom *sbom.SBOM) {
			sbom.Artifacts.FileDigests = result
		})

		return err
	}

	return NewTask("file-digest-cataloger", fn, commonFileTags(tags)...)
}

func newFileMetadataCatalogerTaskFactory(tags ...string) factory {
	return func(cfg CatalogingFactoryConfig) Task {
		return newFileMetadataCatalogerTask(cfg.FilesConfig.Selection, tags...)
	}
}

func newFileMetadataCatalogerTask(selection file.Selection, tags ...string) Task {
	fn := func(ctx context.Context, resolver file.Resolver, builder sbomsync.Builder) error {
		if selection == file.NoFilesSelection {
			return nil
		}

		accessor := builder.(sbomsync.Accessor)

		coordinates, ok := coordinatesForSelection(selection, builder.(sbomsync.Accessor))
		if !ok {
			return nil
		}

		result, err := filemetadata.NewCataloger().Catalog(ctx, resolver, coordinates...)

		accessor.WriteToSBOM(func(sbom *sbom.SBOM) {
			sbom.Artifacts.FileMetadata = result
		})

		return err
	}

	return NewTask("file-metadata-cataloger", fn, commonFileTags(tags)...)
}

func newFileContentCatalogerTaskFactory(tags ...string) factory {
	return func(cfg CatalogingFactoryConfig) Task {
		return newFileContentCatalogerTask(cfg.FilesConfig.Content, tags...)
	}
}

func newFileContentCatalogerTask(cfg filecontent.Config, tags ...string) Task {
	fn := func(ctx context.Context, resolver file.Resolver, builder sbomsync.Builder) error {
		if len(cfg.Globs) == 0 {
			return nil
		}

		accessor := builder.(sbomsync.Accessor)

		result, err := filecontent.NewCataloger(cfg).Catalog(ctx, resolver)

		accessor.WriteToSBOM(func(sbom *sbom.SBOM) {
			sbom.Artifacts.FileContents = result
		})

		return err
	}

	return NewTask("file-content-cataloger", fn, commonFileTags(tags)...)
}

func newExecutableCatalogerTaskFactory(tags ...string) factory {
	return func(cfg CatalogingFactoryConfig) Task {
		return newExecutableCatalogerTask(cfg.FilesConfig.Selection, cfg.FilesConfig.Executable, tags...)
	}
}

func newExecutableCatalogerTask(selection file.Selection, cfg executable.Config, tags ...string) Task {
	fn := func(ctx context.Context, resolver file.Resolver, builder sbomsync.Builder) error {
		if selection == file.NoFilesSelection {
			return nil
		}

		accessor := builder.(sbomsync.Accessor)

		result, err := executable.NewCataloger(cfg).CatalogCtx(ctx, resolver)

		accessor.WriteToSBOM(func(sbom *sbom.SBOM) {
			sbom.Artifacts.Executables = result
		})

		return err
	}

	return NewTask("file-executable-cataloger", fn, commonFileTags(tags)...)
}

// TODO: this should be replaced with a fix that allows passing a coordinate or location iterator to the cataloger
// Today internal to both cataloger this functions differently: a slice of coordinates vs a channel of locations
func coordinatesForSelection(selection file.Selection, accessor sbomsync.Accessor) ([]file.Coordinates, bool) {
	if selection == file.AllFilesSelection {
		return nil, true
	}

	if selection == file.FilesOwnedByPackageSelection {
		var coordinates file.CoordinateSet

		accessor.ReadFromSBOM(func(sbom *sbom.SBOM) {
			// get any file coordinates that are owned by a package
			for _, r := range sbom.Relationships {
				if r.Type != artifact.ContainsRelationship {
					continue
				}
				if _, ok := r.From.(pkg.Package); !ok {
					continue
				}
				if c, ok := r.To.(file.Coordinates); ok {
					coordinates.Add(c)
				}
			}

			// get any file coordinates referenced by a package directly
			for p := range sbom.Artifacts.Packages.Enumerate() {
				coordinates.Add(p.Locations.CoordinateSet().ToSlice()...)
			}
		})

		coords := coordinates.ToSlice()

		if len(coords) == 0 {
			return nil, false
		}

		return coords, true
	}

	return nil, false
}

func commonFileTags(tags []string) []string {
	tags = append(tags, filecataloging.FileTag)
	return tags
}
