package syft

import (
	"fmt"
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

type taskGenerator func(CatalogingConfig) (task, error)

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

func newAPKDBCatalogingTask(config CatalogingConfig) (task, error) {
	return pkgCatalogerTask{
		id:        cataloger.ApkDBID,
		cataloger: apkdb.NewApkdbCataloger(),
		config:    config,
	}, nil
}

func newDPKGCatalogingTask(config CatalogingConfig) (task, error) {
	return pkgCatalogerTask{
		id:        cataloger.DpkgID,
		cataloger: deb.NewDpkgdbCataloger(),
		config:    config,
	}, nil
}

func newGolangBinaryCatalogingTask(config CatalogingConfig) (task, error) {
	return pkgCatalogerTask{
		id:        cataloger.GoBinaryID,
		cataloger: golang.NewGoModuleBinaryCataloger(),
		config:    config,
	}, nil
}

func newGolangModuleCatalogingTask(config CatalogingConfig) (task, error) {
	return pkgCatalogerTask{
		id:        cataloger.GoModID,
		cataloger: golang.NewGoModFileCataloger(),
		config:    config,
	}, nil
}

func newJavaCatalogingTask(config CatalogingConfig) (task, error) {
	return pkgCatalogerTask{
		id: cataloger.JavaArchiveID,
		cataloger: java.NewJavaCataloger(java.CatalogerConfig{
			SearchUnindexedArchives: config.PackageSearch.IncludeUnindexedArchives,
			SearchIndexedArchives:   config.PackageSearch.IncludeIndexedArchives,
		}),
		config: config,
	}, nil
}

func newJavascriptPackageJSONCatalogingTask(config CatalogingConfig) (task, error) {
	return pkgCatalogerTask{
		id:        cataloger.JavascriptPackageJSONID,
		cataloger: javascript.NewJavascriptPackageCataloger(),
		config:    config,
	}, nil
}

func newJavascriptPackageLockCatalogingTask(config CatalogingConfig) (task, error) {
	return pkgCatalogerTask{
		id:        cataloger.JavascriptPackageLockID,
		cataloger: javascript.NewJavascriptPackageLockCataloger(),
		config:    config,
	}, nil
}

func newJavascriptYarnLockCatalogingTask(config CatalogingConfig) (task, error) {
	return pkgCatalogerTask{
		id:        cataloger.JavaScriptYarnLockID,
		cataloger: javascript.NewJavascriptYarnLockCataloger(),
		config:    config,
	}, nil
}

func newPHPComposerLockCatalogingTask(config CatalogingConfig) (task, error) {
	return pkgCatalogerTask{
		id:        cataloger.PHPComposerLockID,
		cataloger: php.NewPHPComposerLockCataloger(),
		config:    config,
	}, nil
}

func newPHPInstalledCatalogingTask(config CatalogingConfig) (task, error) {
	return pkgCatalogerTask{
		id:        cataloger.PHPInstalledJSONID,
		cataloger: php.NewPHPComposerInstalledCataloger(),
		config:    config,
	}, nil
}

func newPythonPackageCatalogingTask(config CatalogingConfig) (task, error) {
	return pkgCatalogerTask{
		id:        cataloger.PythonPackageID,
		cataloger: python.NewPythonPackageCataloger(),
		config:    config,
	}, nil
}

func newPythonRequirementsCatalogingTask(config CatalogingConfig) (task, error) {
	return pkgCatalogerTask{
		id:        cataloger.PythonRequirementsID,
		cataloger: python.NewPythonRequirementsCataloger(),
		config:    config,
	}, nil
}

func newPythonPoetryCatalogingTask(config CatalogingConfig) (task, error) {
	return pkgCatalogerTask{
		id:        cataloger.PythonPoetryID,
		cataloger: python.NewPythonPoetryCataloger(),
		config:    config,
	}, nil
}

func newPythonPipfileCatalogingTask(config CatalogingConfig) (task, error) {
	return pkgCatalogerTask{
		id:        cataloger.PythonPipFileID,
		cataloger: python.NewPythonPipfileCataloger(),
		config:    config,
	}, nil
}

func newPythonSetupCatalogingTask(config CatalogingConfig) (task, error) {
	return pkgCatalogerTask{
		id:        cataloger.PythonSetupID,
		cataloger: python.NewPythonSetupCataloger(),
		config:    config,
	}, nil
}

func newRPMDBCatalogingTask(config CatalogingConfig) (task, error) {
	return pkgCatalogerTask{
		id:        cataloger.RpmDBID,
		cataloger: rpmdb.NewRpmdbCataloger(),
		config:    config,
	}, nil
}

func newRubyGemFileLockCatalogingTask(config CatalogingConfig) (task, error) {
	return pkgCatalogerTask{
		id:        cataloger.RubyGemfileLockID,
		cataloger: ruby.NewGemFileLockCataloger(),
		config:    config,
	}, nil
}

func newRubyGemSpecCatalogingTask(config CatalogingConfig) (task, error) {
	return pkgCatalogerTask{
		id:        cataloger.RubyGemspecID,
		cataloger: ruby.NewGemSpecCataloger(),
		config:    config,
	}, nil
}

func newRustCargoLockCatalogingTask(config CatalogingConfig) (task, error) {
	return pkgCatalogerTask{
		id:        cataloger.RustCargoLockID,
		cataloger: rust.NewCargoLockCataloger(),
		config:    config,
	}, nil
}

func newFileMetadataCatalogingTask(config CatalogingConfig) (task, error) {
	c := filemetadata.NewCataloger()

	return catalogerTask{
		id: cataloger.FileMetadataID,
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

func newFileDigestsCatalogingTask(config CatalogingConfig) (task, error) {
	if len(config.DigestHashes) == 0 {
		return nil, nil
	}

	c, err := filedigests.NewCataloger(config.DigestHashes)
	if err != nil {
		return nil, err
	}

	return catalogerTask{
		id: cataloger.FileDigestsID,
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

func newFileContentsCatalogingTask(config CatalogingConfig) (task, error) {
	if len(config.ContentsSearch.Globs) == 0 {
		return nil, nil
	}

	c, err := filecontents.NewCataloger(config.ContentsSearch)
	if err != nil {
		return nil, err
	}

	return catalogerTask{
		id: cataloger.FileContentsID,
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

func newSecretsCatalogingTask(config CatalogingConfig) (task, error) {

	c, err := secrets.NewCataloger(config.SecretsSearch)
	if err != nil {
		return nil, err
	}

	return catalogerTask{
		id: cataloger.SecretsID,
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

func newFileClassifierTask(config CatalogingConfig) (task, error) {

	c, err := fileclassifier.NewCataloger(config.FileClassifiers)
	if err != nil {
		return nil, err
	}

	return catalogerTask{
		id: cataloger.FileClassifierID,
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
