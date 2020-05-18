package pkg

// TODO: add reader methods (by type, id, fuzzy search, etc)

type Catalog struct {
	// TODO: catalog by package ID for potential indexing
	Packages map[Type][]Package
}

func NewCatalog() Catalog {
	return Catalog{
		Packages: make(map[Type][]Package),
	}
}

func (c *Catalog) Add(p Package) {
	_, ok := c.Packages[p.Type]
	if !ok {
		c.Packages[p.Type] = make([]Package, 0)
	}
	c.Packages[p.Type] = append(c.Packages[p.Type], p)
}
