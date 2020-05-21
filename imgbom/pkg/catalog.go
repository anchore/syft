package pkg

// TODO: add reader methods (by type, id, fuzzy search, etc)

type Catalog struct {
	// TODO: catalog by package ID for potential indexing
	packages map[Type][]Package
}

func NewCatalog() Catalog {
	return Catalog{
		packages: make(map[Type][]Package),
	}
}

func (c *Catalog) Add(p Package) {
	_, ok := c.packages[p.Type]
	if !ok {
		c.packages[p.Type] = make([]Package, 0)
	}
	c.packages[p.Type] = append(c.packages[p.Type], p)
}

func (c *Catalog) Enumerate(types ...Type) <-chan Package {
	channel := make(chan Package)
	go func() {
		defer close(channel)
		for ty, packages := range c.packages {
			if len(types) != 0 {
				found := false
			typeCheck:
				for _, t := range types {
					if t == ty {
						found = true
						break typeCheck
					}
				}
				if !found {
					continue
				}
			}
			for _, p := range packages {
				channel <- p
			}
		}
	}()
	return channel
}
