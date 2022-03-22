package syft

import (
	"fmt"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file/cataloger/fileclassifier"
	"github.com/anchore/syft/syft/file/cataloger/filecontents"
	"github.com/anchore/syft/syft/file/cataloger/filedigests"
	"github.com/anchore/syft/syft/file/cataloger/filemetadata"
	"github.com/anchore/syft/syft/file/cataloger/secrets"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg/cataloger/packages"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

type task func(*sbom.Artifacts, *source.Source) ([]artifact.Relationship, error)
type taskGenerator func(CatalogingConfig) (task, error)

func generatePackagesCatalogingTask(config CatalogingConfig) (task, error) {
	if len(config.PackageCatalogers) == 0 {
		return nil, nil
	}

	return func(artifacts *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(config.Scope)
		if err != nil {
			return nil, fmt.Errorf("unable to determine resolver while cataloging packages: %w", err)
		}

		// find the distro
		artifacts.LinuxDistribution = linux.IdentifyRelease(resolver)

		// catalog packages
		catalog, relationships, err := packages.Catalog(resolver, artifacts.LinuxDistribution, config.PackageCatalogers...)
		if err != nil {
			return nil, err
		}
		artifacts.PackageCatalog = catalog

		return relationships, nil
	}, nil
}

func generateFileMetadataCatalogingTask(config CatalogingConfig) (task, error) {
	if !config.CaptureFileMetadata {
		return nil, nil
	}

	cataloger := filemetadata.NewCataloger()

	return func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(config.Scope)
		if err != nil {
			return nil, err
		}

		result, err := cataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.FileMetadata = result
		return nil, nil
	}, nil
}

func generateFileDigestsCatalogingTask(config CatalogingConfig) (task, error) {
	if len(config.DigestHashes) == 0 {
		return nil, nil
	}

	cataloger, err := filedigests.NewCataloger(config.DigestHashes)
	if err != nil {
		return nil, err
	}

	return func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(config.Scope)
		if err != nil {
			return nil, err
		}

		result, err := cataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.FileDigests = result
		return nil, nil
	}, nil
}

func generateContentsCatalogingTask(config CatalogingConfig) (task, error) {
	if len(config.ContentsConfig.Globs) == 0 {
		return nil, nil
	}

	cataloger, err := filecontents.NewCataloger(config.ContentsConfig)
	if err != nil {
		return nil, err
	}

	return func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(config.Scope)
		if err != nil {
			return nil, err
		}

		result, err := cataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.FileContents = result
		return nil, nil
	}, nil
}

func generateSecretsCatalogingTask(config CatalogingConfig) (task, error) {
	if !config.CaptureSecrets {
		return nil, nil
	}

	cataloger, err := secrets.NewCataloger(config.SecretsConfig)
	if err != nil {
		return nil, err
	}

	return func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(config.SecretsScope)
		if err != nil {
			return nil, err
		}

		result, err := cataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.Secrets = result
		return nil, nil
	}, nil
}

func generateFileClassifierTask(config CatalogingConfig) (task, error) {
	if !config.ClassifyFiles {
		return nil, nil
	}

	cataloger, err := fileclassifier.NewCataloger(config.FileClassifiers)
	if err != nil {
		return nil, err
	}

	return func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(config.Scope)
		if err != nil {
			return nil, err
		}

		result, err := cataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.FileClassifications = result
		return nil, nil
	}, nil
}
