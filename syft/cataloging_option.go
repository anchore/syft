package syft

import (
	"crypto"
	"fmt"
	"github.com/anchore/syft/syft/cataloger"
	"github.com/anchore/syft/syft/cataloger/files/fileclassifier"
	"github.com/anchore/syft/syft/cataloger/files/secrets"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"strings"
)

type CatalogingOption func(*source.Source, *CatalogingConfig) error

func WithConfig(override CatalogingConfig) CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		*config = override
		return nil
	}
}

func WithoutConcurrency() CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		config.ProcessTasksInSerial = true
		return nil
	}
}

func WithScope(scope source.Scope) CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		config.DefaultScope = scope
		return nil
	}
}

func WithToolIdentification(name, version string) CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		config.ToolName = name
		config.ToolVersion = version
		return nil
	}
}

func WithToolConfiguration(c interface{}) CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		config.ToolConfiguration = c
		return nil
	}
}

func WithPackageCataloger(id cataloger.ID, c pkg.Cataloger) CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		if config.availableTasks == nil {
			var err error
			config.availableTasks, err = newTaskCollection()
			if err != nil {
				return err
			}
		}

		gen := func(id cataloger.ID, cfg CatalogingConfig) (task, error) {
			return newPkgCatalogerTask(id, cfg, c), nil
		}
		config.EnabledCatalogers = append(config.EnabledCatalogers, id)

		return config.availableTasks.add(string(id), gen)
	}
}

func WithDefaultCatalogers() CatalogingOption {
	return func(src *source.Source, config *CatalogingConfig) error {
		if config.availableTasks == nil {
			var err error
			config.availableTasks, err = newTaskCollection()
			if err != nil {
				return err
			}
		}

		// override any previously added catalogers
		tc := config.availableTasks
		if len(config.EnabledCatalogers) == 0 {
			switch src.Metadata.Scheme {
			case source.ImageType:
				config.EnabledCatalogers = tc.withLabels(packageTaskLabel, installedTaskLabel)
			case source.FileType:
				config.EnabledCatalogers = tc.all()
			case source.DirectoryType:
				// TODO: it looks like gemspec was left out on main, is this intentional? if so it's not accounted for here...
				config.EnabledCatalogers = tc.withLabels(packageTaskLabel)
			}
		}

		return nil
	}
}

func WithCatalogers(catalogers ...string) CatalogingOption {
	return func(src *source.Source, config *CatalogingConfig) error {
		if config.availableTasks == nil {
			var err error
			config.availableTasks, err = newTaskCollection()
			if err != nil {
				return err
			}
		}

		// override any previously added catalogers
		for _, q := range catalogers {
			var ids []cataloger.ID
			isAdditive := strings.HasPrefix(q, "+")
			if isAdditive {
				ids = config.availableTasks.query(strings.TrimPrefix(q, "+"))
			} else {
				ids = config.availableTasks.query(q)
			}

			if len(ids) == 0 {
				return fmt.Errorf("cataloger selection invalid: %q", q)
			}

			if isAdditive && len(config.EnabledCatalogers) == 0 {
				// stick in the default set of catalogers first
				if err := WithDefaultCatalogers()(src, config); err != nil {
					return fmt.Errorf("unable to set default catalogers: %w", err)
				}

			}
			
			config.EnabledCatalogers = append(config.EnabledCatalogers, ids...)
		}
		return nil
	}
}

func WithFileMetadata() CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		config.EnabledCatalogers = append(config.EnabledCatalogers, cataloger.FileMetadataID)
		return nil
	}
}

func WithFileDigests(hashes ...crypto.Hash) CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		config.EnabledCatalogers = append(config.EnabledCatalogers, cataloger.FileDigestsID)
		config.DigestHashes = hashes

		return nil
	}
}

func WithSecrets(secretConfig *secrets.Config) CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		config.EnabledCatalogers = append(config.EnabledCatalogers, cataloger.SecretsID)
		if secretConfig != nil {
			config.SecretsSearch = *secretConfig
		}
		return nil
	}
}

func WithFileClassification() CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		if len(config.FileClassifiers) > 0 {
			config.EnabledCatalogers = append(config.EnabledCatalogers, cataloger.FileClassifierID)
		}
		return nil
	}
}

func WithFileClassifiers(classifiers ...fileclassifier.Classifier) CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		config.FileClassifiers = classifiers
		if len(config.FileClassifiers) > 0 {
			config.EnabledCatalogers = append(config.EnabledCatalogers, cataloger.FileClassifierID)
		}
		return nil
	}
}

func WithFileContents(globs ...string) CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		config.EnabledCatalogers = append(config.EnabledCatalogers, cataloger.FileContentsID)
		config.ContentsSearch.Globs = globs
		return nil
	}
}

func WithFileSizeLimit(byteLimit int64) CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		config.ContentsSearch.SkipFilesAboveSizeInBytes = byteLimit
		config.SecretsSearch.MaxFileSize = byteLimit
		return nil
	}
}
