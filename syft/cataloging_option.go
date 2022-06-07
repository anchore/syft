package syft

import (
	"crypto"
	"github.com/anchore/syft/syft/cataloger"
	"github.com/anchore/syft/syft/cataloger/files/fileclassifier"
	"github.com/anchore/syft/syft/cataloger/files/secrets"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
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

func WithCataloger(id cataloger.ID, c pkg.Cataloger) CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		if config.availableTasks == nil {
			config.availableTasks = newTaskCollection()
		}

		var cfg CatalogingConfig
		if config != nil {
			cfg = *config
		}

		return config.availableTasks.add(pkgCatalogerTask{
			id:        id,
			cataloger: c,
			config:    cfg,
		})
	}
}

func WithDefaultCatalogers() CatalogingOption {
	return func(src *source.Source, config *CatalogingConfig) error {
		// override any previously added catalogers
		config.availableTasks = newTaskCollection()
		config.EnabledCatalogers = nil
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
