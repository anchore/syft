package pkg

import "github.com/anchore/stereoscope/pkg/file"

// TODO: add package ID (random/incremental)

// TODO: add field to trace which analyzer detected this
type Package struct {
	Name     string
	Version  string
	Source   []file.Reference
	Licenses []string
	Type     Type
	Metadata interface{}
}

// TODO: stringer...
