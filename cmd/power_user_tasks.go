package cmd

import (
	"github.com/anchore/syft/internal/presenter/poweruser"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

type powerUserTask func(*poweruser.JSONDocumentConfig) error

func powerUserTasks(src source.Source) ([]powerUserTask, error) {
	var tasks []powerUserTask
	var err error
	var task powerUserTask

	task = catalogPackagesTask(src)
	if task != nil {
		tasks = append(tasks, task)
	}

	task, err = catalogFileMetadataTask(src)
	if err != nil {
		return nil, err
	} else if task != nil {
		tasks = append(tasks, task)
	}

	task, err = catalogFileDigestTask(src)
	if err != nil {
		return nil, err
	} else if task != nil {
		tasks = append(tasks, task)
	}

	return tasks, nil
}

func catalogPackagesTask(src source.Source) powerUserTask {
	if !appConfig.Packages.CatalogingEnabled {
		return nil
	}

	task := func(results *poweruser.JSONDocumentConfig) error {
		packageCatalog, theDistro, err := syft.CatalogPackages(src, appConfig.Packages.ScopeOpt)
		if err != nil {
			return err
		}

		results.PackageCatalog = packageCatalog
		results.Distro = theDistro

		return nil
	}

	return task
}

func catalogFileMetadataTask(src source.Source) (powerUserTask, error) {
	if !appConfig.FileMetadata.CatalogingEnabled {
		return nil, nil
	}

	resolver, err := src.FileResolver(appConfig.FileMetadata.ScopeOpt)
	if err != nil {
		return nil, err
	}

	task := func(results *poweruser.JSONDocumentConfig) error {
		result, err := file.NewMetadataCataloger(resolver).Catalog()
		if err != nil {
			return err
		}
		results.FileMetadata = result
		return nil
	}

	return task, nil
}

func catalogFileDigestTask(src source.Source) (powerUserTask, error) {
	if !appConfig.FileMetadata.CatalogingEnabled {
		return nil, nil
	}

	resolver, err := src.FileResolver(appConfig.FileMetadata.ScopeOpt)
	if err != nil {
		return nil, err
	}

	cataloger, err := file.NewDigestsCataloger(resolver, appConfig.FileMetadata.Digests)
	if err != nil {
		return nil, err
	}

	task := func(results *poweruser.JSONDocumentConfig) error {
		result, err := cataloger.Catalog()
		if err != nil {
			return err
		}
		results.FileDigests = result
		return nil
	}

	return task, nil
}
