package eventloop

import (
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file/cataloger/filecontent"
	"github.com/anchore/syft/syft/file/cataloger/filedigest"
	"github.com/anchore/syft/syft/file/cataloger/filemetadata"
	"github.com/anchore/syft/syft/file/cataloger/secrets"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

type Task func(*sbom.Artifacts, source.Source) ([]artifact.Relationship, error)

func Tasks(opts *options.Packages) ([]Task, error) {
	var tasks []Task

	generators := []func(opts *options.Packages) (Task, error){
		generateCatalogPackagesTask,
		generateCatalogFileMetadataTask,
		generateCatalogFileDigestsTask,
		generateCatalogSecretsTask,
		generateCatalogContentsTask,
	}

	for _, generator := range generators {
		task, err := generator(opts)
		if err != nil {
			return nil, err
		}

		if task != nil {
			tasks = append(tasks, task)
		}
	}

	return tasks, nil
}

func generateCatalogPackagesTask(opts *options.Packages) (Task, error) {
	if !opts.Package.Cataloger.Enabled {
		return nil, nil
	}

	task := func(results *sbom.Artifacts, src source.Source) ([]artifact.Relationship, error) {
		packageCatalog, relationships, theDistro, err := syft.CatalogPackages(src, opts.ToCatalogerConfig())

		results.Packages = packageCatalog
		results.LinuxDistribution = theDistro

		return relationships, err
	}

	return task, nil
}

func generateCatalogFileMetadataTask(app *options.Packages) (Task, error) {
	if !app.FileMetadata.Cataloger.Enabled {
		return nil, nil
	}

	metadataCataloger := filemetadata.NewCataloger()

	task := func(results *sbom.Artifacts, src source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(app.FileMetadata.Cataloger.SourceScope())
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

func generateCatalogFileDigestsTask(app *options.Packages) (Task, error) {
	if !app.FileMetadata.Cataloger.Enabled {
		return nil, nil
	}

	hashes, err := file.Hashers(app.FileMetadata.Digests...)
	if err != nil {
		return nil, err
	}

	digestsCataloger := filedigest.NewCataloger(hashes)

	task := func(results *sbom.Artifacts, src source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(app.FileMetadata.Cataloger.SourceScope())
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

func generateCatalogSecretsTask(app *options.Packages) (Task, error) {
	if !app.Secrets.Cataloger.Enabled {
		return nil, nil
	}

	patterns, err := secrets.GenerateSearchPatterns(secrets.DefaultSecretsPatterns, app.Secrets.AdditionalPatterns, app.Secrets.ExcludePatternNames)
	if err != nil {
		return nil, err
	}

	secretsCataloger, err := secrets.NewCataloger(patterns, app.Secrets.RevealValues, app.Secrets.SkipFilesAboveSize) //nolint:staticcheck
	if err != nil {
		return nil, err
	}

	task := func(results *sbom.Artifacts, src source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(app.Secrets.Cataloger.SourceScope())
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

func generateCatalogContentsTask(app *options.Packages) (Task, error) {
	if !app.FileContents.Cataloger.Enabled {
		return nil, nil
	}

	contentsCataloger, err := filecontent.NewCataloger(app.FileContents.Globs, app.FileContents.SkipFilesAboveSize) //nolint:staticcheck
	if err != nil {
		return nil, err
	}

	task := func(results *sbom.Artifacts, src source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(app.FileContents.Cataloger.SourceScope())
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

func RunTask(t Task, a *sbom.Artifacts, src source.Source, c chan<- artifact.Relationship) error {
	defer close(c)

	relationships, err := t(a, src)
	if err != nil {
		return err
	}

	for _, relationship := range relationships {
		c <- relationship
	}

	return nil
}
