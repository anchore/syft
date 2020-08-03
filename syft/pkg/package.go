package pkg

import (
	"fmt"

	"github.com/anchore/stereoscope/pkg/file"
)

type ID int64

// TODO: add field to trace which cataloger detected this

// Package represents an application or library that has been bundled into a distributable format
type Package struct {
	id       ID               // this is set when a package is added to the catalog
	Name     string           `json:"manifest"`
	Version  string           `json:"version"`
	FoundBy  string           `json:"found-by"`
	Source   []file.Reference `json:"sources"`
	Licenses []string         `json:"licenses"` // TODO: should we move this into metadata?
	Language Language         `json:"language"` // TODO: should this support multiple languages as a slice?
	Type     Type             `json:"type"`
	Metadata interface{}      `json:"metadata,omitempty"`
}

func (p Package) ID() ID {
	return p.id
}

func (p Package) String() string {
	return fmt.Sprintf("Pkg(type=%s, name=%s, version=%s)", p.Type, p.Name, p.Version)
}
