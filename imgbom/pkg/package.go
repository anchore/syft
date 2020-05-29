package pkg

import (
	"fmt"

	"github.com/anchore/stereoscope/pkg/file"
)

type ID int64

// TODO: add field to trace which analyzer detected this
type Package struct {
	id       ID
	Name     string
	Version  string
	Source   []file.Reference
	Licenses []string
	Type     Type
	Metadata interface{}
}

func (p Package) ID() ID {
	return p.id
}

func (p Package) String() string {
	return fmt.Sprintf("Pkg(type=%s, name=%s, version=%s)", p.Type, p.Name, p.Version)
}
