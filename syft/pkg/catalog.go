package pkg

import (
	"sort"
	"sync"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
)

// Catalog represents a collection of Packages.
type Catalog struct {
	byID      map[ID]*Package
	idsByType map[Type][]ID
	idsByPath map[string][]ID // note: this is real path or virtual path
	lock      sync.RWMutex
}

// NewCatalog returns a new empty Catalog
func NewCatalog(pkgs ...Package) *Catalog {
	catalog := Catalog{
		byID:      make(map[ID]*Package),
		idsByType: make(map[Type][]ID),
		idsByPath: make(map[string][]ID),
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
	v, exists := c.byID[id]
	if !exists {
		return nil
	}
	return v
}

// PackagesByPath returns all packages that were discovered from the given path.
func (c *Catalog) PackagesByPath(path string) []*Package {
	return c.Packages(c.idsByPath[path])
}

// Packages returns all packages for the given ID.
func (c *Catalog) Packages(ids []ID) (result []*Package) {
	for _, i := range ids {
		p, exists := c.byID[i]
		if exists {
			result = append(result, p)
		}
	}
	return result
}

// Add a package to the Catalog.
func (c *Catalog) Add(p Package) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if _, exists := c.byID[p.ID]; exists {
		log.Errorf("package ID already exists in the catalog : id=%+v %+v", p.ID, p)
		return
	}

	if p.ID == "" {
		p.ID = newID()
	}

	// store by package ID
	c.byID[p.ID] = &p

	// store by package type
	c.idsByType[p.Type] = append(c.idsByType[p.Type], p.ID)

	// store by file location paths
	observedPaths := internal.NewStringSet()
	for _, l := range p.Locations {
		if l.RealPath != "" && !observedPaths.Contains(l.RealPath) {
			c.idsByPath[l.RealPath] = append(c.idsByPath[l.RealPath], p.ID)
			observedPaths.Add(l.RealPath)
		}
		if l.VirtualPath != "" && l.RealPath != l.VirtualPath && !observedPaths.Contains(l.VirtualPath) {
			c.idsByPath[l.VirtualPath] = append(c.idsByPath[l.VirtualPath], p.ID)
			observedPaths.Add(l.VirtualPath)
		}
	}
}

func (c *Catalog) Remove(id ID) {
	c.lock.Lock()
	defer c.lock.Unlock()

	_, exists := c.byID[id]
	if !exists {
		log.Errorf("package ID does not exist in the catalog : id=%+v", id)
		return
	}

	// Remove all index references to this package ID
	for t, ids := range c.idsByType {
		c.idsByType[t] = removeID(id, ids)
		if len(c.idsByType[t]) == 0 {
			delete(c.idsByType, t)
		}
	}

	for p, ids := range c.idsByPath {
		c.idsByPath[p] = removeID(id, ids)
		if len(c.idsByPath[p]) == 0 {
			delete(c.idsByPath, p)
		}
	}

	// Remove package
	delete(c.byID, id)
}

// Enumerate all packages for the given type(s), enumerating all packages if no type is specified.
func (c *Catalog) Enumerate(types ...Type) <-chan *Package {
	channel := make(chan *Package)
	go func() {
		defer close(channel)
		for ty, ids := range c.idsByType {
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
			for _, id := range ids {
				channel <- c.Package(id)
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
				if pkgs[i].Type == pkgs[j].Type {
					return pkgs[i].Locations[0].String() < pkgs[j].Locations[0].String()
				}
				return pkgs[i].Type < pkgs[j].Type
			}
			return pkgs[i].Version < pkgs[j].Version
		}
		return pkgs[i].Name < pkgs[j].Name
	})

	return pkgs
}

func removeID(id ID, target []ID) (result []ID) {
	for _, value := range target {
		if value != id {
			result = append(result, value)
		}
	}
	return result
}
