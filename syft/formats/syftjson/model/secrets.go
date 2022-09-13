package model

import (
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

type Secrets struct {
	Location source.Coordinates  `json:"location"`
	Secrets  []file.SearchResult `json:"secrets"`
}
