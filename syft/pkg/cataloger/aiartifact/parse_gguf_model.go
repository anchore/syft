package aiartifact

import (
	"context"
	"fmt"
	"io"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// parseGGUFModel parses a GGUF model file and returns the discovered package.
func parseGGUFModel(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	defer internal.CloseAndLogError(reader, reader.Path())

	// Read header (we'll read a reasonable amount to parse the header without reading entire file)
	// GGUF headers are typically < 1MB, but we'll use a 10MB limit to be safe
	const maxHeaderSize = 10 * 1024 * 1024
	limitedReader := io.LimitReader(reader, maxHeaderSize)

	// We need to buffer the data because we need to check magic and parse
	headerData := make([]byte, 0, 8192) // Start with 8KB buffer
	buf := make([]byte, 8192)
	for {
		n, err := limitedReader.Read(buf)
		if n > 0 {
			headerData = append(headerData, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("error reading file: %w", err)
		}
		// Stop if we've read enough for a reasonable header
		if len(headerData) > maxHeaderSize {
			log.Warnf("GGUF header at %s exceeds max size, truncating", reader.Path())
			break
		}
	}

	// Check if this is actually a GGUF file
	if len(headerData) < 4 {
		return nil, nil, fmt.Errorf("file too small to be a valid GGUF file")
	}

	// Parse the GGUF header
	metadata, err := parseGGUFHeader(headerData, reader.Path())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse GGUF file: %w", err)
	}

	// Create package from metadata
	p := newGGUFPackage(
		metadata,
		reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
	)

	return []pkg.Package{p}, nil, unknown.IfEmptyf([]pkg.Package{p}, "unable to parse GGUF file")
}

// integrity check
var _ generic.Parser = parseGGUFModel
