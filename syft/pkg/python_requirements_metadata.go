package pkg

type PythonRequirementsMetadata struct {
	Name              string   `json:"name" mapstruct:"Name"`
	Extras            []string `json:"extras,omitempty" mapstruct:"Extras"`
	VersionConstraint string   `json:"versionConstraint" mapstruct:"VersionConstraint"`
	URL               string   `json:"url,omitempty" mapstruct:"URL"`
	Markers           string   `json:"markers,omitempty" mapstruct:"Markers"`
}
