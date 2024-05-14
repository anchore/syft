package sbomsync

import (
	"sync"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

var _ interface {
	Accessor
	Builder
} = (*sbomBuilder)(nil) // integrity check

// Builder provides a simple facade for simple additions to the SBOM
type Builder interface {
	// nodes

	AddPackages(...pkg.Package)

	DeletePackages(...artifact.ID)

	// edges

	AddRelationships(...artifact.Relationship)

	// other

	SetLinuxDistribution(linux.Release)
}

// Accessor allows for low-level access to the SBOM
type Accessor interface {
	WriteToSBOM(func(*sbom.SBOM))
	ReadFromSBOM(func(*sbom.SBOM))
}

type sbomBuilder struct {
	sbom    *sbom.SBOM
	lock    *sync.RWMutex
	onWrite []func(*sbom.SBOM)
}

func NewBuilder(s *sbom.SBOM, onWrite ...func(*sbom.SBOM)) Builder {
	return &sbomBuilder{
		sbom:    s,
		lock:    &sync.RWMutex{},
		onWrite: onWrite,
	}
}

func (b sbomBuilder) onWriteEvent() {
	for _, fn := range b.onWrite {
		fn(b.sbom)
	}
}

func (b sbomBuilder) WriteToSBOM(fn func(*sbom.SBOM)) {
	b.lock.Lock()
	defer b.lock.Unlock()

	fn(b.sbom)
	b.onWriteEvent()
}

func (b sbomBuilder) ReadFromSBOM(fn func(*sbom.SBOM)) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	fn(b.sbom)
}

func (b sbomBuilder) AddPackages(p ...pkg.Package) {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.sbom.Artifacts.Packages.Add(p...)
	b.onWriteEvent()
}

func (b sbomBuilder) DeletePackages(ids ...artifact.ID) {
	b.lock.Lock()
	defer b.lock.Unlock()

	deleted := make(map[artifact.ID]struct{})
	for _, id := range ids {
		b.sbom.Artifacts.Packages.Delete(id)
		deleted[id] = struct{}{}
	}

	// remove any relationships that reference the deleted packages
	var relationships []artifact.Relationship
	for _, rel := range b.sbom.Relationships {
		if _, ok := deleted[rel.From.ID()]; ok {
			continue
		}
		if _, ok := deleted[rel.To.ID()]; ok {
			continue
		}

		// only keep relationships that don't reference the deleted packages
		relationships = append(relationships, rel)
	}

	b.sbom.Relationships = relationships
	b.onWriteEvent()
}

func (b sbomBuilder) AddRelationships(relationship ...artifact.Relationship) {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.sbom.Relationships = append(b.sbom.Relationships, relationship...)
	b.onWriteEvent()
}

func (b sbomBuilder) SetLinuxDistribution(release linux.Release) {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.sbom.Artifacts.LinuxDistribution = &release
	b.onWriteEvent()
}
