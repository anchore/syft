package cataloging

type UnknownsConfig struct {
	RemoveWhenPackagesDefined         bool
	IncludeExecutablesWithoutPackages bool
	IncludeUnexpandedArchives         bool
}

func DefaultUnknownsConfig() UnknownsConfig {
	return UnknownsConfig{
		RemoveWhenPackagesDefined:         true,
		IncludeExecutablesWithoutPackages: true,
		IncludeUnexpandedArchives:         true,
	}
}
