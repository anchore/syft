package syft

import (
	"crypto"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/packages"
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
		config.Scope = scope
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

func WithPackageCatalogers(catalogers ...pkg.Cataloger) CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		config.PackageCatalogers = catalogers
		return nil
	}
}

func WithDefaultPackageCatalogers(cfg packages.SearchConfig) CatalogingOption {
	return func(src *source.Source, config *CatalogingConfig) error {
		config.PackageCatalogers = packages.CatalogersBySourceScheme(src.Metadata.Scheme, cfg)
		return nil
	}
}

func WithFileMetadata() CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		config.CaptureFileMetadata = true
		return nil
	}
}

func WithFileDigests(hashes ...crypto.Hash) CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		config.DigestHashes = hashes

		return nil
	}
}

func WithSecrets(secretConfig *file.SecretsCatalogerConfig) CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		config.CaptureSecrets = true
		if secretConfig != nil {
			config.SecretsConfig = *secretConfig
		}
		return nil
	}
}

func WithFileClassification() CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		config.ClassifyFiles = true
		return nil
	}
}

func WithFileClassifiers(classifiers ...file.Classifier) CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		config.ClassifyFiles = !(len(classifiers) > 0)
		config.FileClassifiers = classifiers
		return nil
	}
}

func WithFileContents(globs ...string) CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		config.ContentsConfig.Globs = globs
		return nil
	}
}

func WithFileSizeLimit(byteLimit int64) CatalogingOption {
	return func(_ *source.Source, config *CatalogingConfig) error {
		config.ContentsConfig.SkipFilesAboveSizeInBytes = byteLimit
		config.SecretsConfig.MaxFileSize = byteLimit
		return nil
	}
}
