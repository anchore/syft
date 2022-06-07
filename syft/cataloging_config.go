package syft

import (
	"crypto"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/cataloger"
	"github.com/anchore/syft/syft/cataloger/files/fileclassifier"
	"github.com/anchore/syft/syft/cataloger/files/filecontents"
	"github.com/anchore/syft/syft/cataloger/files/secrets"
	"github.com/anchore/syft/syft/cataloger/packages"
	"github.com/anchore/syft/syft/source"
)

type CatalogingConfig struct {
	// tool-specific information
	ToolName          string
	ToolVersion       string
	ToolConfiguration interface{}
	// applies to all catalogers
	DefaultScope         source.Scope // TODO: shouldn't this be in the package.SearchConfig?
	ProcessTasksInSerial bool         // TODO: this seems a little odd, if this should be an option is this the right spot?
	EnabledCatalogers    []cataloger.ID
	availableTasks       *taskCollection
	// package
	PackageSearch packages.SearchConfig
	// file metadata
	DigestHashes []crypto.Hash
	// secrets
	SecretsSearch secrets.Config
	SecretsScope  source.Scope
	// file classification
	FileClassifiers []fileclassifier.Classifier
	// file contents
	ContentsSearch filecontents.Config
}

func DefaultCatalogingConfig() CatalogingConfig {
	return CatalogingConfig{
		DefaultScope:    source.SquashedScope,
		ToolName:        internal.ApplicationName,
		ToolVersion:     version.Guess(),
		SecretsScope:    source.AllLayersScope,
		SecretsSearch:   secrets.DefaultConfig(),
		FileClassifiers: fileclassifier.DefaultClassifiers(),
		ContentsSearch:  filecontents.DefaultConfig(),
		PackageSearch:   packages.DefaultSearchConfig(),
	}
}
