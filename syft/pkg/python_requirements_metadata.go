package pkg

type PythonRequirementsMetadata struct {
	Name              string   `json:"name"`
	Extras            []string `json:"extras"`
	VersionConstraint string   `json:"versionConstraint"`
	URL               string   `json:"url"`
	Markers           string   `json:"markers"`
}
