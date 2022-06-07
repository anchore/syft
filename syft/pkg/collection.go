package pkg

import (
	"sort"
	"sync"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/jinzhu/copier"
)

// Collection represents a collection of Packages.
type Collection interface {
	Size() int
	Package(id artifact.ID) *Package
	PackagesByPath(path string) []Package
	Packages(ids []artifact.ID) (result []Package)
	Add(p Package)
	Enumerate(types ...Type) <-chan Package
	Sorted(types ...Type) (pkgs []Package)
}

type collection struct {
	byID      map[artifact.ID]Package
	idsByType map[Type][]artifact.ID
	idsByPath map[string][]artifact.ID // note: this is real path or virtual path
	lock      sync.RWMutex
}

// NewCollection returns a new empty Collection
func NewCollection(pkgs ...Package) Collection {
	catalog := &collection{
		byID:      make(map[artifact.ID]Package),
		idsByType: make(map[Type][]artifact.ID),
		idsByPath: make(map[string][]artifact.ID),
	}

	for _, p := range pkgs {
		catalog.Add(p)
	}

	return catalog
}

// Size returns the total number of packages that have been added.
func (c *collection) Size() int {
	return len(c.byID)
}

// Package returns the package with the given ID.
func (c *collection) Package(id artifact.ID) *Package {
	v, exists := c.byID[id]
	if !exists {
		return nil
	}
	var p Package
	if err := copier.Copy(&p, &v); err != nil {
		log.Warnf("unable to copy package id=%q name=%q: %+v", id, v.Name, err)
		return nil
	}
	p.id = v.id
	return &p
}

// PackagesByPath returns all packages that were discovered from the given path.
func (c *collection) PackagesByPath(path string) []Package {
	return c.Packages(c.idsByPath[path])
}

// Packages returns all packages for the given ID.
func (c *collection) Packages(ids []artifact.ID) (result []Package) {
	for _, i := range ids {
		p, exists := c.byID[i]
		if exists {
			result = append(result, p)
		}
	}
	return result
}

// Add a package to the Collection.
func (c *collection) Add(p Package) {
	c.lock.Lock()
	defer c.lock.Unlock()

	id := p.ID()
	if id == "" {
		log.Warnf("found package with empty ID while adding to the catalog: %+v", p)
		p.SetID()
		id = p.ID()
	}

	// store by package ID
	c.byID[id] = p

	// store by package type
	c.idsByType[p.Type] = append(c.idsByType[p.Type], id)

	// store by file location paths
	observedPaths := internal.NewStringSet()
	for _, l := range p.Locations {
		if l.RealPath != "" && !observedPaths.Contains(l.RealPath) {
			c.idsByPath[l.RealPath] = append(c.idsByPath[l.RealPath], id)
			observedPaths.Add(l.RealPath)
		}
		if l.AccessPath != "" && l.RealPath != l.AccessPath && !observedPaths.Contains(l.AccessPath) {
			c.idsByPath[l.AccessPath] = append(c.idsByPath[l.AccessPath], id)
			observedPaths.Add(l.AccessPath)
		}
	}
}

// Enumerate all packages for the given type(s), enumerating all packages if no type is specified.
func (c *collection) Enumerate(types ...Type) <-chan Package {
	channel := make(chan Package)
	go func() {
		defer close(channel)
		if c == nil {
			// we should allow enumerating from a catalog that was never created (which will result in no packages enumerated)
			return
		}
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
				p := c.Package(id)
				if p != nil {
					channel <- *p
				}
			}
		}
	}()
	return channel
}

// Sorted enumerates all packages for the given types sorted by package name. Enumerates all packages if no type is specified.
func (c *collection) Sorted(types ...Type) (pkgs []Package) {
	for p := range c.Enumerate(types...) {
		pkgs = append(pkgs, p)
	}

	sort.SliceStable(pkgs, func(i, j int) bool {
		if pkgs[i].Name == pkgs[j].Name {
			if pkgs[i].Version == pkgs[j].Version {
				if pkgs[i].Type == pkgs[j].Type && len(pkgs[i].Locations) > 0 && len(pkgs[j].Locations) > 0 {
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
