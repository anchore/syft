package syft

import (
	"fmt"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cataloger"
	"github.com/anchore/syft/syft/cataloger/files/fileclassifier"
	"github.com/anchore/syft/syft/cataloger/files/filecontents"
	"github.com/anchore/syft/syft/cataloger/files/filedigests"
	"github.com/anchore/syft/syft/cataloger/files/filemetadata"
	"github.com/anchore/syft/syft/cataloger/files/secrets"
	"github.com/anchore/syft/syft/cataloger/packages/apkdb"
	"github.com/anchore/syft/syft/cataloger/packages/deb"
	"github.com/anchore/syft/syft/cataloger/packages/golang"
	"github.com/anchore/syft/syft/cataloger/packages/java"
	"github.com/anchore/syft/syft/cataloger/packages/javascript"
	"github.com/anchore/syft/syft/cataloger/packages/php"
	"github.com/anchore/syft/syft/cataloger/packages/python"
	"github.com/anchore/syft/syft/cataloger/packages/rpmdb"
	"github.com/anchore/syft/syft/cataloger/packages/ruby"
	"github.com/anchore/syft/syft/cataloger/packages/rust"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/speculate"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloger/packages"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

type taskGenerator func(cataloger.ID, CatalogingConfig) (task, error)

type task interface {
	Run(*sbom.Artifacts, *source.Source) ([]artifact.Relationship, error)
}

type genericTask struct {
	run func(*sbom.Artifacts, *source.Source) ([]artifact.Relationship, error)
}

func (t genericTask) Run(artifacts *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
	return t.run(artifacts, src)
}

type catalogerTask struct {
	id cataloger.ID
	genericTask
}

type pkgCatalogerTask struct {
	id        cataloger.ID
	cataloger pkg.Cataloger
	config    CatalogingConfig
}

func newPkgCatalogerTask(id cataloger.ID, config CatalogingConfig, c pkg.Cataloger) pkgCatalogerTask {
	return pkgCatalogerTask{
		id:        id,
		cataloger: c,
		config:    config,
	}
}

func (t pkgCatalogerTask) Run(artifacts *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
	resolver, err := src.FileResolver(t.config.DefaultScope)
	if err != nil {
		return nil, fmt.Errorf("unable to determine resolver while cataloging packages: %w", err)
	}

	// catalog packages
	pkgs, relationships, err := t.cataloger.Catalog(resolver)
	if err != nil {
		return nil, err
	}

	for _, p := range pkgs {
		p.FoundBy = string(t.id)
		speculate.Identifiers(&p, artifacts.LinuxDistribution)
		p.SetID()
		artifacts.Packages.Add(p)
	}

	return relationships, nil
}

func newIdentifyDistroTask(config CatalogingConfig) (task, error) {
	return genericTask{
		run: func(artifacts *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
			resolver, err := src.FileResolver(config.DefaultScope)
			if err != nil {
				return nil, fmt.Errorf("unable to determine resolver while determining linux distro: %w", err)
			}

			artifacts.LinuxDistribution = linux.IdentifyRelease(resolver)

			return nil, nil
		},
	}, nil
}

func newAPKDBCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	return newPkgCatalogerTask(id, config, apkdb.NewApkdbCataloger()), nil
}

func newDPKGCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	return newPkgCatalogerTask(id, config, deb.NewDpkgdbCataloger()), nil
}

func newGolangBinaryCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	return newPkgCatalogerTask(id, config, golang.NewGoModuleBinaryCataloger()), nil
}

func newGolangModuleCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	return newPkgCatalogerTask(id, config, golang.NewGoModFileCataloger()), nil
}

func newJavaCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	return newPkgCatalogerTask(
		id,
		config,
		java.NewJavaCataloger(
			java.CatalogerConfig{
				SearchUnindexedArchives: config.PackageSearch.IncludeUnindexedArchives,
				SearchIndexedArchives:   config.PackageSearch.IncludeIndexedArchives,
			},
		),
	), nil
}

func newJavascriptPackageJSONCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	return newPkgCatalogerTask(id, config, javascript.NewJavascriptPackageCataloger()), nil
}

func newJavascriptPackageLockCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	return newPkgCatalogerTask(id, config, javascript.NewJavascriptPackageLockCataloger()), nil
}

func newJavascriptYarnLockCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	return newPkgCatalogerTask(id, config, javascript.NewJavascriptYarnLockCataloger()), nil
}

func newPHPComposerLockCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	return newPkgCatalogerTask(id, config, php.NewPHPComposerLockCataloger()), nil
}

func newPHPInstalledCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	return newPkgCatalogerTask(id, config, php.NewPHPComposerInstalledCataloger()), nil
}

func newPythonPackageCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	return newPkgCatalogerTask(id, config, python.NewPythonPackageCataloger()), nil
}

func newPythonRequirementsCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	return newPkgCatalogerTask(id, config, python.NewPythonRequirementsCataloger()), nil
}

func newPythonPoetryCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	return newPkgCatalogerTask(id, config, python.NewPythonPoetryCataloger()), nil
}

func newPythonPipfileCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	return newPkgCatalogerTask(id, config, python.NewPythonPipfileCataloger()), nil
}

func newPythonSetupCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	return newPkgCatalogerTask(id, config, python.NewPythonSetupCataloger()), nil
}

func newRPMDBCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	return newPkgCatalogerTask(id, config, rpmdb.NewRpmdbCataloger()), nil
}

func newRubyGemFileLockCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	return newPkgCatalogerTask(id, config, ruby.NewGemFileLockCataloger()), nil
}

func newRubyGemSpecCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	return newPkgCatalogerTask(id, config, ruby.NewGemSpecCataloger()), nil
}

func newRustCargoLockCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	return newPkgCatalogerTask(id, config, rust.NewCargoLockCataloger()), nil
}

func newFileMetadataCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	c := filemetadata.NewCataloger()

	return catalogerTask{
		id: id,
		genericTask: genericTask{
			run: func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
				resolver, err := src.FileResolver(config.DefaultScope)
				if err != nil {
					return nil, err
				}

				result, err := c.Catalog(resolver)
				if err != nil {
					return nil, err
				}
				results.FileMetadata = result
				return nil, nil
			},
		},
	}, nil
}

func newFileDigestsCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	if len(config.DigestHashes) == 0 {
		log.Warn("using file-digest cataloger with no file digest algorithms configured")
		return nil, nil
	}

	c, err := filedigests.NewCataloger(config.DigestHashes)
	if err != nil {
		return nil, err
	}

	return catalogerTask{
		id: id,
		genericTask: genericTask{
			run: func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
				resolver, err := src.FileResolver(config.DefaultScope)
				if err != nil {
					return nil, err
				}

				result, err := c.Catalog(resolver)
				if err != nil {
					return nil, err
				}
				results.FileDigests = result
				return nil, nil
			},
		},
	}, nil
}

func newFileContentsCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	if len(config.ContentsSearch.Globs) == 0 {
		log.Warn("using file-content cataloger with no content file paths/globs configured")
		return nil, nil
	}

	c, err := filecontents.NewCataloger(config.ContentsSearch)
	if err != nil {
		return nil, err
	}

	return catalogerTask{
		id: id,
		genericTask: genericTask{
			run: func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
				resolver, err := src.FileResolver(config.DefaultScope)
				if err != nil {
					return nil, err
				}

				result, err := c.Catalog(resolver)
				if err != nil {
					return nil, err
				}
				results.FileContents = result
				return nil, nil
			},
		},
	}, nil
}

func newSecretsCatalogingTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	c, err := secrets.NewCataloger(config.SecretsSearch)
	if err != nil {
		return nil, err
	}

	return catalogerTask{
		id: id,
		genericTask: genericTask{
			run: func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
				resolver, err := src.FileResolver(config.SecretsScope)
				if err != nil {
					return nil, err
				}

				result, err := c.Catalog(resolver)
				if err != nil {
					return nil, err
				}
				results.Secrets = result
				return nil, nil
			},
		},
	}, nil
}

func newFileClassifierTask(id cataloger.ID, config CatalogingConfig) (task, error) {
	c, err := fileclassifier.NewCataloger(config.FileClassifiers)
	if err != nil {
		return nil, err
	}

	return catalogerTask{
		id: id,
		genericTask: genericTask{
			run: func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
				resolver, err := src.FileResolver(config.DefaultScope)
				if err != nil {
					return nil, err
				}

				result, err := c.Catalog(resolver)
				if err != nil {
					return nil, err
				}
				results.FileClassifications = result
				return nil, nil
			},
		},
	}, nil
}

func newSynthesizePackageRelationshipsTasks(config CatalogingConfig) (task, error) {
	return genericTask{
		run: func(artifacts *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
			resolver, err := src.FileResolver(config.DefaultScope)
			if err != nil {
				return nil, err
			}

			return packages.FindRelationships(artifacts.Packages, resolver), nil
		},
	}, nil
}
