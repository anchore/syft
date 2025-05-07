package cataloging

import "github.com/anchore/syft/internal/licenses"

type LicenseContent string

const (
	//IncludeAllLicenseContent         LicenseContent = "all" // added later... not now
	IncludeOnlyUnknownLicenseContent LicenseContent = "unknown"
	IncludeNoLicenseContent          LicenseContent = "none"

	defaultIncludeLicenseContent = IncludeOnlyUnknownLicenseContent
)

// - hash ignore the contents (so anyone can drop content without changing the hash)
// - when missing value/expression, put in "LicenseRef-sha256:xxxx..." as the value
// - have a post-processor (outside of the catalogers at a single point in the package cataloging task) that enforces having content or not
// - smell: there is no content constructor... so add one!
// - deprecate all existing constructors.... add new constructors that always take context

type LicenseConfig struct {
	Content  LicenseContent `json:"content" yaml:"content" mapstructure:"content"`
	Coverage float64        `json:"coverage" yaml:"coverage" mapstructure:"coverage"`
}

func DefaultLicenseConfig() LicenseConfig {
	return LicenseConfig{
		Content:  defaultIncludeLicenseContent,
		Coverage: licenses.DefaultCoverageThreshold,
	}
}
