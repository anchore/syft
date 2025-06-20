package sbom

import (
	"sync"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// StreamingWriter defines an interface for writing SBOM components incrementally
type StreamingWriter interface {
	// Start begins the SBOM streaming process with source and tool information
	Start(srcMetadata source.Description, descriptor Descriptor) error

	// WritePackage writes a single package to the output
	WritePackage(p pkg.Package) error

	// WriteRelationship writes a single relationship to the output
	WriteRelationship(r artifact.Relationship) error

	// End finalizes the SBOM streaming process
	End() error
}

// StreamingWriterAdapter adapts a regular SBOM writer to the streaming interface
// by collecting all data and writing it at the end
type StreamingWriterAdapter struct {
	sbom   *SBOM
	writer Writer
	mutex  sync.Mutex
}

// NewStreamingWriterAdapter creates a new adapter for traditional SBOM writers
func NewStreamingWriterAdapter(writer Writer) *StreamingWriterAdapter {
	return &StreamingWriterAdapter{
		sbom: &SBOM{
			Artifacts: Artifacts{
				Packages: pkg.NewCollection(),
			},
		},
		writer: writer,
	}
}

// Start initializes the SBOM with source and descriptor information
func (a *StreamingWriterAdapter) Start(srcMetadata source.Description, descriptor Descriptor) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.sbom.Source = srcMetadata
	a.sbom.Descriptor = descriptor
	return nil
}

// WritePackage adds a package to the SBOM
func (a *StreamingWriterAdapter) WritePackage(p pkg.Package) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.sbom.Artifacts.Packages.Add(p)
	return nil
}

// WriteRelationship adds a relationship to the SBOM
func (a *StreamingWriterAdapter) WriteRelationship(r artifact.Relationship) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.sbom.Relationships = append(a.sbom.Relationships, r)
	return nil
}

// End finalizes and writes the complete SBOM
func (a *StreamingWriterAdapter) End() error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	return a.writer.Write(*a.sbom)
}

// Collector is an implementation of StreamingWriter that builds an in-memory SBOM
type Collector struct {
	sbom  *SBOM
	mutex sync.Mutex
}

// NewCollector creates a new collector for building an in-memory SBOM
func NewCollector() *Collector {
	return &Collector{
		sbom: &SBOM{
			Artifacts: Artifacts{
				Packages: pkg.NewCollection(),
			},
		},
	}
}

// Start initializes the SBOM with source and descriptor information
func (c *Collector) Start(srcMetadata source.Description, descriptor Descriptor) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.sbom.Source = srcMetadata
	c.sbom.Descriptor = descriptor
	return nil
}

// WritePackage adds a package to the SBOM
func (c *Collector) WritePackage(p pkg.Package) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.sbom.Artifacts.Packages.Add(p)
	return nil
}

// WriteRelationship adds a relationship to the SBOM
func (c *Collector) WriteRelationship(r artifact.Relationship) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.sbom.Relationships = append(c.sbom.Relationships, r)
	return nil
}

// End finalizes the SBOM
func (c *Collector) End() error {
	return nil
}

// SBOM returns the collected SBOM
func (c *Collector) SBOM() *SBOM {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.sbom
}

// MultiWriter is a StreamingWriter that writes to multiple writers
type MultiWriter struct {
	writers []StreamingWriter
}

// NewMultiWriter creates a new MultiWriter
func NewMultiWriter(writers ...StreamingWriter) *MultiWriter {
	return &MultiWriter{
		writers: writers,
	}
}

// Start begins the SBOM streaming process with source and tool information for all writers
func (m *MultiWriter) Start(srcMetadata source.Description, descriptor Descriptor) error {
	for _, w := range m.writers {
		if err := w.Start(srcMetadata, descriptor); err != nil {
			return err
		}
	}
	return nil
}

// WritePackage writes a single package to all writers
func (m *MultiWriter) WritePackage(p pkg.Package) error {
	for _, w := range m.writers {
		if err := w.WritePackage(p); err != nil {
			return err
		}
	}
	return nil
}

// WriteRelationship writes a single relationship to all writers
func (m *MultiWriter) WriteRelationship(r artifact.Relationship) error {
	for _, w := range m.writers {
		if err := w.WriteRelationship(r); err != nil {
			return err
		}
	}
	return nil
}

// End finalizes the SBOM streaming process for all writers
func (m *MultiWriter) End() error {
	for _, w := range m.writers {
		if err := w.End(); err != nil {
			return err
		}
	}
	return nil
}
