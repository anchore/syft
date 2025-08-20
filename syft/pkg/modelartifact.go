package pkg

// ModelArtifact represents a machine learning model artifact
type ModelArtifact struct {
	Name          string   `json:"name" mapstructure:"name"`
	ModelType     string   `json:"modelType" mapstructure:"modelType"`
	Architectures []string `json:"architecture" mapstructure:"architecture"`
	ConfigPath    string   `json:"configPath" mapstructure:"configPath"`
	ReadmePath    string   `json:"readmePath" mapstructure:"readmePath"`
	Artifactory   string   `json:"artifactory" mapstructure:"artifactory"`
}
