package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/pkg/cataloger/dotnet"
)

type dotnetConfig struct {
	DepPackagesMustHaveDLL bool `mapstructure:"dep-packages-must-have-dll" json:"dep-packages-must-have-dll" yaml:"dep-packages-must-have-dll"`

	DepPackagesMustClaimDLL bool `mapstructure:"dep-packages-must-claim-dll" json:"dep-packages-must-claim-dll" yaml:"dep-packages-must-claim-dll"`

	PropagateDLLClaimsToParents bool `mapstructure:"propagate-dll-claims-to-parents" json:"propagate-dll-claims-to-parents" yaml:"propagate-dll-claims-to-parents"`

	RelaxDLLClaimsWhenBundlingDetected bool `mapstructure:"relax-dll-claims-when-bundling-detected" json:"relax-dll-claims-when-bundling-detected" yaml:"relax-dll-claims-when-bundling-detected"`
}

var _ interface {
	clio.FieldDescriber
} = (*dotnetConfig)(nil)

func (o *dotnetConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.DepPackagesMustHaveDLL, `only keep dep.json packages which an executable on disk is found. The package is also included if a DLL is found for any child package, even if the package itself does not have a DLL.`)
	descriptions.Add(&o.DepPackagesMustClaimDLL, `only keep dep.json packages which have a runtime/resource DLL claimed in the deps.json targets section (but not necessarily found on disk). The package is also included if any child package claims a DLL, even if the package itself does not claim a DLL.`)
	descriptions.Add(&o.PropagateDLLClaimsToParents, `treat DLL claims or on-disk evidence for child packages as DLL claims or on-disk evidence for any parent package`)
	descriptions.Add(&o.RelaxDLLClaimsWhenBundlingDetected, `show all packages from the deps.json if bundling tooling is present as a dependency (e.g. ILRepack)`)
}

func defaultDotnetConfig() dotnetConfig {
	def := dotnet.DefaultCatalogerConfig()
	return dotnetConfig{
		DepPackagesMustHaveDLL:             def.DepPackagesMustHaveDLL,
		DepPackagesMustClaimDLL:            def.DepPackagesMustClaimDLL,
		PropagateDLLClaimsToParents:        def.PropagateDLLClaimsToParents,
		RelaxDLLClaimsWhenBundlingDetected: def.RelaxDLLClaimsWhenBundlingDetected,
	}
}
