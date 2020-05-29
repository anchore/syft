package pkg

import (
	"fmt"
	"sync"

	"github.com/anchore/imgbom/internal/log"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/blevesearch/bleve"
	"github.com/blevesearch/bleve/mapping"
)

// TODO: add reader methods (by type, id, fuzzy search, etc)

var nextPackageID int64

type Catalog struct {
	byID                map[ID]*Package
	byType              map[Type][]*Package
	byFile              map[file.Reference][]*Package
	searchSpace         mapping.IndexMapping
	nameSearchIndex     bleve.Index
	metadataSearchIndex bleve.Index
	lock                sync.RWMutex
}

func NewCatalog() Catalog {
	searchMap := bleve.NewIndexMapping()
	nameIndex, err := bleve.NewMemOnly(searchMap)
	if err != nil {
		// TODO: log
		panic(err)
	}
	metadataIndex, err := bleve.NewMemOnly(searchMap)
	if err != nil {
		// TODO: log
		panic(err)
	}
	return Catalog{
		byID:                make(map[ID]*Package),
		byType:              make(map[Type][]*Package),
		byFile:              make(map[file.Reference][]*Package),
		searchSpace:         searchMap,
		nameSearchIndex:     nameIndex,
		metadataSearchIndex: metadataIndex,
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

	// index the package findings
	err := c.nameSearchIndex.Index(fmt.Sprintf("%d", p.id), p.Name)
	if err != nil {
		// TODO: just no...
		panic(err)
	}
	err = c.metadataSearchIndex.Index(fmt.Sprintf("%d", p.id), p.Metadata)
	if err != nil {
		// TODO: just no...
		panic(err)
	}
}

func (c *Catalog) SearchMetadata(query string) *bleve.SearchResult {
	request := bleve.NewSearchRequest(bleve.NewMatchQuery(query))
	result, err := c.metadataSearchIndex.Search(request)
	if err != nil {
		// TODO: just no...
		panic(err)
	}
	return result
}

func (c *Catalog) SearchName(query string) *bleve.SearchResult {
	request := bleve.NewSearchRequest(bleve.NewMatchQuery(query))
	result, err := c.nameSearchIndex.Search(request)
	if err != nil {
		// TODO: just no...
		panic(err)
	}
	return result
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
