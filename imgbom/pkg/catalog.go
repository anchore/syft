package pkg

type Catalog struct {
	// TODO: catalog by package ID for potential indexing
	catalog map[Type][]Package
}

type CatalogWriter interface {
	Add(Package) error
}

func (c *Catalog) Add(p Package) {
	_, ok := c.catalog[p.Type]
	if !ok {
		c.catalog[p.Type] = make([]Package, 0)
	}
	c.catalog[p.Type] = append(c.catalog[p.Type], p)
}