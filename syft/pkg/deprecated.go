package pkg

// Deprecated: use Collection instead
type Catalog = Collection

// Deprecated: use NewCollection() instead
func NewCatalog(pkgs ...Package) *Catalog {
	return NewCollection(pkgs...)
}
