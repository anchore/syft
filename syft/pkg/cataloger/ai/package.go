package ai

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

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
		Format:       metadata.ModelFormat,
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

	// Compute SHA256 hash
	hash := sha256.Sum256(jsonBytes)
	return fmt.Sprintf("%x", hash[:8]) // Use first 8 bytes (16 hex chars)
}
