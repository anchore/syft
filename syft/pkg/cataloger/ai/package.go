package ai

import (
	"encoding/json"
	"fmt"

	"github.com/cespare/xxhash/v2"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newGGUFPackage(metadata *pkg.GGUFFileHeader, locations ...file.Location) pkg.Package {
	// Compute hash if not already set
	if metadata.Hash == "" {
		metadata.Hash = computeMetadataHash(metadata)
	}

	p := pkg.Package{
		Name:      metadata.ModelName,
		Version:   metadata.ModelVersion,
		Locations: file.NewLocationSet(locations...),
		Type:      pkg.ModelPkg,
		Licenses:  pkg.NewLicenseSet(),
		Metadata:  *metadata,
		// NOTE: PURL is intentionally not set as the package-url spec
		// has not yet finalized support for ML model packages
	}

	// Add license to the package if present in metadata
	if metadata.License != "" {
		p.Licenses.Add(pkg.NewLicenseFromFields(metadata.License, "", nil))
	}

	p.SetID()

	return p
}

// computeMetadataHash computes a stable hash of the metadata for use as a global identifier
func computeMetadataHash(metadata *pkg.GGUFFileHeader) string {
	// Create a stable representation of the metadata
	hashData := struct {
		Format       string
		Name         string
		Version      string
		Architecture string
		GGUFVersion  uint32
		TensorCount  uint64
	}{
		Name:         metadata.ModelName,
		Version:      metadata.ModelVersion,
		Architecture: metadata.Architecture,
		GGUFVersion:  metadata.GGUFVersion,
		TensorCount:  metadata.TensorCount,
	}

	// Marshal to JSON for stable hashing
	jsonBytes, err := json.Marshal(hashData)
	if err != nil {
		log.Debugf("failed to marshal metadata for hashing: %v", err)
		return ""
	}

	// Compute xxhash
	hash := xxhash.Sum64(jsonBytes)
	return fmt.Sprintf("%016x", hash) // 16 hex chars (64 bits)
}
