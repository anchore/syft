package pkg

type PythonRequirementsMetadata struct {
	Name              string            `json:"name" mapstruct:"Name"`
	Extras            []string          `json:"extras" mapstruct:"Extras"`
	VersionConstraint string            `json:"versionConstraint" mapstruct:"VersionConstraint"`
	URL               string            `json:"url" mapstruct:"URL"`
	Markers           map[string]string `json:"markers" mapstruct:"Markers"`
}
