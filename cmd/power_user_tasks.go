package cmd

import (
	"github.com/anchore/syft/internal/presenter/poweruser"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

type powerUserTask func(*poweruser.JSONDocumentConfig, source.Source) error

func powerUserTasks() ([]powerUserTask, error) {
	var tasks []powerUserTask

	generators := []func() (powerUserTask, error){
		catalogPackagesTask,
		catalogFileMetadataTask,
		catalogFileDigestTask,
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

	task := func(results *poweruser.JSONDocumentConfig, src source.Source) error {
		packageCatalog, theDistro, err := syft.CatalogPackages(src, appConfig.Package.Cataloger.ScopeOpt)
		if err != nil {
			return err
		}

		results.PackageCatalog = packageCatalog
		results.Distro = theDistro

		return nil
	}

	return task, nil
}

func catalogFileMetadataTask() (powerUserTask, error) {
	if !appConfig.FileMetadata.Cataloger.Enabled {
		return nil, nil
	}

	metadataCataloger := file.NewMetadataCataloger()

	task := func(results *poweruser.JSONDocumentConfig, src source.Source) error {
		resolver, err := src.FileResolver(appConfig.FileMetadata.Cataloger.ScopeOpt)
		if err != nil {
			return err
		}

		result, err := metadataCataloger.Catalog(resolver)
		if err != nil {
			return err
		}
		results.FileMetadata = result
		return nil
	}

	return task, nil
}

func catalogFileDigestTask() (powerUserTask, error) {
	if !appConfig.FileMetadata.Cataloger.Enabled {
		return nil, nil
	}

	digestsCataloger, err := file.NewDigestsCataloger(appConfig.FileMetadata.Digests)
	if err != nil {
		return nil, err
	}

	task := func(results *poweruser.JSONDocumentConfig, src source.Source) error {
		resolver, err := src.FileResolver(appConfig.FileMetadata.Cataloger.ScopeOpt)
		if err != nil {
			return err
		}

		result, err := digestsCataloger.Catalog(resolver)
		if err != nil {
			return err
		}
		results.FileDigests = result
		return nil
	}

	return task, nil
}
