package model

import "github.com/anchore/syft/syft/sort"

type Relationship struct {
	Parent   string             `json:"parent"`
	Child    string             `json:"child"`
	Type     string             `json:"type"`
	Metadata sort.TryComparable `json:"metadata,omitempty"`
}
