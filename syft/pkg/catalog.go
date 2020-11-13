package pkg

import (
	"sort"
	"sync"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal/log"
)

var nextPackageID int64

// Catalog represents a collection of Packages.
type Catalog struct {
	byID   map[ID]*Package
	byType map[Type][]*Package
	byFile map[file.Reference][]*Package
	lock   sync.RWMutex
}

// NewCatalog returns a new empty Catalog
func NewCatalog(pkgs ...Package) *Catalog {
	catalog := Catalog{
		byID:   make(map[ID]*Package),
		byType: make(map[Type][]*Package),
		byFile: make(map[file.Reference][]*Package),
	}

	for _, p := range pkgs {
		catalog.Add(p)
	}

	return &catalog
}

// PackageCount returns the total number of packages that have been added.
func (c *Catalog) PackageCount() int {
	return len(c.byID)
}

// Package returns the package with the given ID.
func (c *Catalog) Package(id ID) *Package {
	return c.byID[id]
}

// PackagesByFile returns all packages that were discovered from the given source file reference.
func (c *Catalog) PackagesByFile(ref file.Reference) []*Package {
	return c.byFile[ref]
}

// Add a package to the Catalog.
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

// Enumerate all packages for the given type(s), enumerating all packages if no type is specified.
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

// Sorted enumerates all packages for the given types sorted by package name. Enumerates all packages if no type
// is specified.
func (c *Catalog) Sorted(types ...Type) []*Package {
	pkgs := make([]*Package, 0)
	for p := range c.Enumerate(types...) {
		pkgs = append(pkgs, p)
	}

	sort.SliceStable(pkgs, func(i, j int) bool {
		if pkgs[i].Name == pkgs[j].Name {
			if pkgs[i].Version == pkgs[j].Version {
				return pkgs[i].Type < pkgs[j].Type
			}
			return pkgs[i].Version < pkgs[j].Version
		}
		return pkgs[i].Name < pkgs[j].Name
	})

	return pkgs
}
