package pkg

import (
	"github.com/google/uuid"
)

// ID represents a unique value for each package added to a package catalog.
type ID string

func newID() ID {
	return ID(uuid.New().String())
}
