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
	sbom *sbom.SBOM
	lock *sync.RWMutex
}

func NewBuilder(s *sbom.SBOM) Builder {
	return &sbomBuilder{
		sbom: s,
		lock: &sync.RWMutex{},
	}
}

func (b sbomBuilder) WriteToSBOM(fn func(*sbom.SBOM)) {
	b.lock.Lock()
	defer b.lock.Unlock()

	fn(b.sbom)
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
}

func (b sbomBuilder) AddRelationships(relationship ...artifact.Relationship) {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.sbom.Relationships = append(b.sbom.Relationships, relationship...)
}

func (b sbomBuilder) SetLinuxDistribution(release linux.Release) {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.sbom.Artifacts.LinuxDistribution = &release
}
