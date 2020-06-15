package pkg

import (
	"fmt"

	"github.com/anchore/stereoscope/pkg/file"
)

type ID int64

// TODO: add field to trace which cataloger detected this
type Package struct {
	id       ID
	Name     string
	Version  string
	FoundBy  string
	Source   []file.Reference
	Licenses []string
	Language Language // TODO: should this support multiple languages as a slice?
	Type     Type
	Metadata interface{}
}

func (p Package) ID() ID {
	return p.id
}

func (p Package) String() string {
	return fmt.Sprintf("Pkg(type=%s, name=%s, version=%s)", p.Type, p.Name, p.Version)
}
