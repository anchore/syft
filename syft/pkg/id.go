package pkg

import (
	"fmt"

	"github.com/mitchellh/hashstructure"
)

// ID represents a unique value for each package added to a package catalog.
type ID string

func newID(p Package) ID {
	hash, err := hashstructure.Hash(p, nil)
	if err != nil {
		panic(err)
	}

	return ID(fmt.Sprint(hash))
}
