package source

// UnknownMetadata represents the CycloneComponentType that Syft can't handle at present
type UnknownMetadata struct {
	UserInput string `json:"name" yaml:"name"`
	ID        string `json:"bom-ref" yaml:"bom-ref"`
	Version   string `json:"version" yaml:"version"`
}
