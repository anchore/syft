package pkg

import (
	"sort"
	"sync"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/jinzhu/copier"
)

type orderedIDSet struct {
	slice []artifact.ID
}

func (s *orderedIDSet) add(ids ...artifact.ID) {
loopNewIDs:
	for _, newID := range ids {
		for _, existingID := range s.slice {
			if existingID == newID {
				continue loopNewIDs
			}
		}
		s.slice = append(s.slice, newID)
	}
}

// Catalog represents a collection of Packages.
type Catalog struct {
	byID      map[artifact.ID]Package
	idsByName map[string]orderedIDSet
	idsByType map[Type]orderedIDSet
	idsByPath map[string]orderedIDSet // note: this is real path or virtual path
	lock      sync.RWMutex
}

// NewCatalog returns a new empty Catalog
func NewCatalog(pkgs ...Package) *Catalog {
	catalog := Catalog{
		byID:      make(map[artifact.ID]Package),
		idsByName: make(map[string]orderedIDSet),
		idsByType: make(map[Type]orderedIDSet),
		idsByPath: make(map[string]orderedIDSet),
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
func (c *Catalog) Package(id artifact.ID) *Package {
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
func (c *Catalog) PackagesByPath(path string) []Package {
	return c.Packages(c.idsByPath[path].slice)
}

// PackagesByName returns all packages that were discovered with a matching name.
func (c *Catalog) PackagesByName(name string) []Package {
	return c.Packages(c.idsByName[name].slice)
}

// Packages returns all packages for the given ID.
func (c *Catalog) Packages(ids []artifact.ID) (result []Package) {
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

	id := p.ID()
	if id == "" {
		log.Warnf("found package with empty ID while adding to the catalog: %+v", p)
		p.SetID()
		id = p.ID()
	}

	if existing, exists := c.byID[id]; exists {
		// there is already a package with this fingerprint merge the existing record with the new one
		if err := existing.merge(p); err != nil {
			log.Warnf("failed to merge packages: %+v", err)
		} else {
			c.addPathsToIndex(p)
		}
		return
	}

	c.addToIndex(p)
}

func (c *Catalog) addToIndex(p Package) {
	c.byID[p.id] = p
	c.addNameToIndex(p)
	c.addTypeToIndex(p)
	c.addPathsToIndex(p)
}

func (c *Catalog) addNameToIndex(p Package) {
	nameIndex := c.idsByName[p.Name]
	nameIndex.add(p.id)
	c.idsByName[p.Name] = nameIndex
}

func (c *Catalog) addTypeToIndex(p Package) {
	typeIndex := c.idsByType[p.Type]
	typeIndex.add(p.id)
	c.idsByType[p.Type] = typeIndex
}

func (c *Catalog) addPathsToIndex(p Package) {
	observedPaths := internal.NewStringSet()
	for _, l := range p.Locations.ToSlice() {
		if l.RealPath != "" && !observedPaths.Contains(l.RealPath) {
			c.addPathToIndex(p.id, l.RealPath)
			observedPaths.Add(l.RealPath)
		}
		if l.VirtualPath != "" && l.RealPath != l.VirtualPath && !observedPaths.Contains(l.VirtualPath) {
			c.addPathToIndex(p.id, l.VirtualPath)
			observedPaths.Add(l.VirtualPath)
		}
	}
}

func (c *Catalog) addPathToIndex(id artifact.ID, path string) {
	pathIndex := c.idsByPath[path]
	pathIndex.add(id)
	c.idsByPath[path] = pathIndex
}

// Enumerate all packages for the given type(s), enumerating all packages if no type is specified.
func (c *Catalog) Enumerate(types ...Type) <-chan Package {
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
			for _, id := range ids.slice {
				p := c.Package(id)
				if p != nil {
					channel <- *p
				}
			}
		}
	}()
	return channel
}

// Sorted enumerates all packages for the given types sorted by package name. Enumerates all packages if no type
// is specified.
func (c *Catalog) Sorted(types ...Type) (pkgs []Package) {
	for p := range c.Enumerate(types...) {
		pkgs = append(pkgs, p)
	}

	sort.SliceStable(pkgs, func(i, j int) bool {
		if pkgs[i].Name == pkgs[j].Name {
			if pkgs[i].Version == pkgs[j].Version {
				iLocations := pkgs[i].Locations.ToSlice()
				jLocations := pkgs[j].Locations.ToSlice()
				if pkgs[i].Type == pkgs[j].Type && len(iLocations) > 0 && len(jLocations) > 0 {
					return iLocations[0].String() < jLocations[0].String()
				}
				return pkgs[i].Type < pkgs[j].Type
			}
			return pkgs[i].Version < pkgs[j].Version
		}
		return pkgs[i].Name < pkgs[j].Name
	})

	return pkgs
}
