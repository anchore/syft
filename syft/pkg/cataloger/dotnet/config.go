package dotnet

type CatalogerConfig struct {
	// DepPackagesMustHaveDLL allows for deps.json packages to be included only if there is a DLL on disk for that package.
	// app-config: dotnet.dep-packages-must-have-dll
	DepPackagesMustHaveDLL bool `mapstructure:"dep-packages-must-have-dll" json:"dep-packages-must-have-dll" yaml:"dep-packages-must-have-dll"`

	// DepPackagesMustClaimDLL allows for deps.json packages to be included only if there is a runtime/resource DLL claimed in the deps.json targets section.
	// This does not require such claimed DLLs to exist on disk. The behavior of this
	// app-config: dotnet.dep-packages-must-claim-dll
	DepPackagesMustClaimDLL bool `mapstructure:"dep-packages-must-claim-dll" json:"dep-packages-must-claim-dll" yaml:"dep-packages-must-claim-dll"`

	// PropagateDLLClaimsToParents allows for deps.json packages to be included if any child (transitive) package claims a DLL. This applies to both the claims configuration and evidence-on-disk configurations.
	// app-config: dotnet.propagate-dll-claims-to-parents
	PropagateDLLClaimsToParents bool `mapstructure:"propagate-dll-claims-to-parents" json:"propagate-dll-claims-to-parents" yaml:"propagate-dll-claims-to-parents"`

	// RelaxDLLClaimsWhenBundlingDetected will look for indications of IL bundle tooling via deps.json package names
	// and, if found (and this config option is enabled), will relax the DepPackagesMustClaimDLL value to `false` only in those cases.
	// app-config: dotnet.relax-dll-claims-when-bundling-detected
	RelaxDLLClaimsWhenBundlingDetected bool `mapstructure:"relax-dll-claims-when-bundling-detected" json:"relax-dll-claims-when-bundling-detected" yaml:"relax-dll-claims-when-bundling-detected"`

	// ExcludeProjectReferences excludes packages with type "project" from deps.json output.
	// These are internal project references, not external NuGet packages.
	// app-config: dotnet.exclude-project-references
	ExcludeProjectReferences bool `mapstructure:"exclude-project-references" json:"exclude-project-references" yaml:"exclude-project-references"`
}

func (c CatalogerConfig) WithDepPackagesMustHaveDLL(requireDlls bool) CatalogerConfig {
	c.DepPackagesMustHaveDLL = requireDlls
	return c
}

func (c CatalogerConfig) WithDepPackagesMustClaimDLL(requireDlls bool) CatalogerConfig {
	c.DepPackagesMustClaimDLL = requireDlls
	return c
}

func (c CatalogerConfig) WithRelaxDLLClaimsWhenBundlingDetected(relax bool) CatalogerConfig {
	c.RelaxDLLClaimsWhenBundlingDetected = relax
	return c
}

func (c CatalogerConfig) WithPropagateDLLClaimsToParents(propagate bool) CatalogerConfig {
	c.PropagateDLLClaimsToParents = propagate
	return c
}

func (c CatalogerConfig) WithExcludeProjectReferences(exclude bool) CatalogerConfig {
	c.ExcludeProjectReferences = exclude
	return c
}

func DefaultCatalogerConfig() CatalogerConfig {
	return CatalogerConfig{
		DepPackagesMustHaveDLL:             false,
		DepPackagesMustClaimDLL:            true,
		PropagateDLLClaimsToParents:        true,
		RelaxDLLClaimsWhenBundlingDetected: true,
		ExcludeProjectReferences:           true,
	}
}
