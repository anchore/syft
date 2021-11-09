package artifact

// ID represents a unique value for each package added to a package catalog.
type ID string

type Identifiable interface {
	ID() ID
}
