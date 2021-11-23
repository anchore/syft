package model

type Relationship struct {
	Parent   string      `json:"parent"`
	Child    string      `json:"child"`
	Type     string      `json:"type"`
	Metadata interface{} `json:"metadata,omitempty"`
}
