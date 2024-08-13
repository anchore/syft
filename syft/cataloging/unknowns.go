package cataloging

type UnknownsConfig struct {
	IncludeExecutablesWithoutPackages bool
	IncludeUnexpandedArchives         bool
}

func DefaultUnknownsConfig() UnknownsConfig {
	return UnknownsConfig{
		IncludeExecutablesWithoutPackages: true,
		IncludeUnexpandedArchives:         true,
	}
}
