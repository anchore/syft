package cmd

import (
	"crypto"
	"fmt"

	"github.com/anchore/syft/syft/artifact"

	"github.com/anchore/syft/syft/sbom"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

type powerUserTask func(*sbom.Artifacts, *source.Source) ([]artifact.Relationship, error)

func powerUserTasks() ([]powerUserTask, error) {
	var tasks []powerUserTask

	generators := []func() (powerUserTask, error){
		catalogPackagesTask,
		catalogFileMetadataTask,
		catalogFileDigestsTask,
		catalogSecretsTask,
		catalogFileClassificationsTask,
		catalogContentsTask,
	}

	for _, generator := range generators {
		task, err := generator()
		if err != nil {
			return nil, err
		}
		if task != nil {
			tasks = append(tasks, task)
		}
	}

	return tasks, nil
}

func catalogPackagesTask() (powerUserTask, error) {
	if !appConfig.Package.Cataloger.Enabled {
		return nil, nil
	}

	task := func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		packageCatalog, relationships, theDistro, err := syft.CatalogPackages(src, appConfig.Package.Cataloger.ScopeOpt)
		if err != nil {
			return nil, err
		}

		results.PackageCatalog = packageCatalog
		results.Distro = theDistro

		return relationships, nil
	}

	return task, nil
}

func catalogFileMetadataTask() (powerUserTask, error) {
	if !appConfig.FileMetadata.Cataloger.Enabled {
		return nil, nil
	}

	metadataCataloger := file.NewMetadataCataloger()

	task := func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(appConfig.FileMetadata.Cataloger.ScopeOpt)
		if err != nil {
			return nil, err
		}

		result, err := metadataCataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.FileMetadata = result
		return nil, nil
	}

	return task, nil
}

func catalogFileDigestsTask() (powerUserTask, error) {
	if !appConfig.FileMetadata.Cataloger.Enabled {
		return nil, nil
	}

	supportedHashAlgorithms := make(map[string]crypto.Hash)
	for _, h := range []crypto.Hash{
		crypto.MD5,
		crypto.SHA1,
		crypto.SHA256,
	} {
		supportedHashAlgorithms[file.DigestAlgorithmName(h)] = h
	}

	var hashes []crypto.Hash
	for _, hashStr := range appConfig.FileMetadata.Digests {
		name := file.CleanDigestAlgorithmName(hashStr)
		hashObj, ok := supportedHashAlgorithms[name]
		if !ok {
			return nil, fmt.Errorf("unsupported hash algorithm: %s", hashStr)
		}
		hashes = append(hashes, hashObj)
	}

	digestsCataloger, err := file.NewDigestsCataloger(hashes)
	if err != nil {
		return nil, err
	}

	task := func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(appConfig.FileMetadata.Cataloger.ScopeOpt)
		if err != nil {
			return nil, err
		}

		result, err := digestsCataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.FileDigests = result
		return nil, nil
	}

	return task, nil
}

func catalogSecretsTask() (powerUserTask, error) {
	if !appConfig.Secrets.Cataloger.Enabled {
		return nil, nil
	}

	patterns, err := file.GenerateSearchPatterns(file.DefaultSecretsPatterns, appConfig.Secrets.AdditionalPatterns, appConfig.Secrets.ExcludePatternNames)
	if err != nil {
		return nil, err
	}

	secretsCataloger, err := file.NewSecretsCataloger(patterns, appConfig.Secrets.RevealValues, appConfig.Secrets.SkipFilesAboveSize)
	if err != nil {
		return nil, err
	}

	task := func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(appConfig.Secrets.Cataloger.ScopeOpt)
		if err != nil {
			return nil, err
		}

		result, err := secretsCataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.Secrets = result
		return nil, nil
	}

	return task, nil
}

func catalogFileClassificationsTask() (powerUserTask, error) {
	if !appConfig.FileClassification.Cataloger.Enabled {
		return nil, nil
	}

	// TODO: in the future we could expose out the classifiers via configuration
	classifierCataloger, err := file.NewClassificationCataloger(file.DefaultClassifiers)
	if err != nil {
		return nil, err
	}

	task := func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(appConfig.FileClassification.Cataloger.ScopeOpt)
		if err != nil {
			return nil, err
		}

		result, err := classifierCataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.FileClassifications = result
		return nil, nil
	}

	return task, nil
}

func catalogContentsTask() (powerUserTask, error) {
	if !appConfig.FileContents.Cataloger.Enabled {
		return nil, nil
	}

	contentsCataloger, err := file.NewContentsCataloger(appConfig.FileContents.Globs, appConfig.FileContents.SkipFilesAboveSize)
	if err != nil {
		return nil, err
	}

	task := func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(appConfig.FileContents.Cataloger.ScopeOpt)
		if err != nil {
			return nil, err
		}

		result, err := contentsCataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.FileContents = result
		return nil, nil
	}

	return task, nil
}
