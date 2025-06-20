package sbomsync

import (
	"sync"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// StreamingBuilder provides thread-safe access to build an SBOM incrementally with streaming output
type StreamingBuilder struct {
	writer     sbom.StreamingWriter
	monitor    func()
	mutex      sync.Mutex
	startOnce  sync.Once
	endOnce    sync.Once
	started    bool
	ended      bool
	srcDesc    source.Description
	descriptor sbom.Descriptor
}

// NewStreamingBuilder creates a new streaming builder with the given writer and optional monitor function
func NewStreamingBuilder(writer sbom.StreamingWriter, monitor func()) *StreamingBuilder {
	return &StreamingBuilder{
		writer:  writer,
		monitor: monitor,
	}
}

// Initialize sets up the SBOM with source and descriptor information
func (b *StreamingBuilder) Initialize(desc source.Description, descriptor sbom.Descriptor) {
	b.startOnce.Do(func() {
		b.started = true
		b.srcDesc = desc
		b.descriptor = descriptor
		if err := b.writer.Start(desc, descriptor); err != nil {
			return
		}
	})
}

// AddPackages adds the given packages to the SBOM in a thread-safe way
func (b *StreamingBuilder) AddPackages(packages ...pkg.Package) {
	if !b.started || b.ended {
		return
	}

	b.mutex.Lock()
	defer b.mutex.Unlock()

	for _, p := range packages {
		if err := b.writer.WritePackage(p); err != nil {
			return
		}
	}

	if b.monitor != nil {
		b.monitor()
	}
}

// AddRelationships adds the given relationships to the SBOM in a thread-safe way
func (b *StreamingBuilder) AddRelationships(relationships ...artifact.Relationship) {
	if !b.started || b.ended {
		return
	}

	b.mutex.Lock()
	defer b.mutex.Unlock()

	for _, r := range relationships {
		if err := b.writer.WriteRelationship(r); err != nil {
			return
		}
	}
}

// DeletePackages is a no-op for the streaming builder (interface compliance)
func (b *StreamingBuilder) DeletePackages(_ ...artifact.ID) {
	// not supported in streaming mode
}

// SetLinuxDistribution is a no-op for streaming builder (interface compliance)
func (b *StreamingBuilder) SetLinuxDistribution(_ linux.Release) {
	// not supported in streaming mode
}

// Finalize completes the SBOM streaming process
func (b *StreamingBuilder) Finalize() {
	b.endOnce.Do(func() {
		b.ended = true
		if err := b.writer.End(); err != nil {
			return
		}
	})
}
