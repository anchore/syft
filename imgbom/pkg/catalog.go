package pkg

import (
	"sync"

	"github.com/anchore/imgbom/internal/log"
	"github.com/anchore/stereoscope/pkg/file"
)

// TODO: add reader methods (by type, id, fuzzy search, etc)

var nextPackageID int64

type Catalog struct {
	byID   map[ID]*Package
	byType map[Type][]*Package
	byFile map[file.Reference][]*Package
	lock   sync.RWMutex
}

func NewCatalog() Catalog {
	return Catalog{
		byID:   make(map[ID]*Package),
		byType: make(map[Type][]*Package),
		byFile: make(map[file.Reference][]*Package),
	}
}

func (c *Catalog) Package(id ID) *Package {
	return c.byID[id]
}

func (c *Catalog) PackagesByFile(ref file.Reference) []*Package {
	return c.byFile[ref]
}

func (c *Catalog) Add(p Package) {
	if p.id != 0 {
		log.Errorf("package already added to catalog: %s", p)
		return
	}
	c.lock.Lock()
	defer c.lock.Unlock()

	p.id = ID(nextPackageID)
	nextPackageID++

	// store by package ID
	c.byID[p.id] = &p

	// store by package type
	_, ok := c.byType[p.Type]
	if !ok {
		c.byType[p.Type] = make([]*Package, 0)
	}
	c.byType[p.Type] = append(c.byType[p.Type], &p)

	// store by file references
	for _, s := range p.Source {
		_, ok := c.byFile[s]
		if !ok {
			c.byFile[s] = make([]*Package, 0)
		}
		c.byFile[s] = append(c.byFile[s], &p)
	}
}

func (c *Catalog) Enumerate(types ...Type) <-chan *Package {
	channel := make(chan *Package)
	go func() {
		defer close(channel)
		for ty, packages := range c.byType {
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
