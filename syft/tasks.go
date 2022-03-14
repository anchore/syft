package syft

import (
	"fmt"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg/cataloger/packages"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

type task func(*sbom.Artifacts, *source.Source) ([]artifact.Relationship, error)
type taskGenerator func(CatalogingConfig) (task, error)

func generateCatalogPackagesTask(config CatalogingConfig) (task, error) {
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

func generateCatalogFileMetadataTask(config CatalogingConfig) (task, error) {
	if !config.CaptureFileMetadata {
		return nil, nil
	}

	metadataCataloger := file.NewMetadataCataloger()

	return func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(config.Scope)
		if err != nil {
			return nil, err
		}

		result, err := metadataCataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.FileMetadata = result
		return nil, nil
	}, nil

}

func generateCatalogFileDigestsTask(config CatalogingConfig) (task, error) {
	if len(config.DigestHashes) == 0 {
		return nil, nil
	}

	digestsCataloger, err := file.NewDigestsCataloger(config.DigestHashes)
	if err != nil {
		return nil, err
	}

	return func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(config.Scope)
		if err != nil {
			return nil, err
		}

		result, err := digestsCataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.FileDigests = result
		return nil, nil
	}, nil

}

func generateCatalogContentsTask(config CatalogingConfig) (task, error) {
	if len(config.ContentsConfig.Globs) > 0 {
		return nil, nil
	}

	contentsCataloger, err := file.NewContentsCataloger(config.ContentsConfig)
	if err != nil {
		return nil, err
	}

	return func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(config.Scope)
		if err != nil {
			return nil, err
		}

		result, err := contentsCataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.FileContents = result
		return nil, nil
	}, nil
}

func generateCatalogSecretsTask(config CatalogingConfig) (task, error) {
	if !config.CaptureSecrets {
		return nil, nil
	}

	secretsCataloger, err := file.NewSecretsCataloger(config.SecretsConfig)
	if err != nil {
		return nil, err
	}

	return func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(config.SecretsScope)
		if err != nil {
			return nil, err
		}

		result, err := secretsCataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.Secrets = result
		return nil, nil
	}, nil

}

func generateCatalogFileClassificationsTask(config CatalogingConfig) (task, error) {
	if !config.ClassifyFiles {
		return nil, nil
	}

	classifierCataloger, err := file.NewClassificationCataloger(config.FileClassifiers)
	if err != nil {
		return nil, err
	}

	return func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(config.Scope)
		if err != nil {
			return nil, err
		}

		result, err := classifierCataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.FileClassifications = result
		return nil, nil
	}, nil
}
