package model

type Relationship struct {
	Parent string `json:"parent"`
	Child  string `json:"child"`
	Type   string `json:"type"`
	// FIXME should be TryComparable, but isn't due to artifact.Relationship
	Metadata interface{} `json:"metadata,omitempty"`
}
