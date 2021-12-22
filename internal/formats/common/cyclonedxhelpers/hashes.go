package cyclonedxhelpers

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/pkg"
)

func Hashes(p pkg.Package) *[]cyclonedx.Hash {
	hashes := []cyclonedx.Hash{}
	if hasMetadata(p) {
		if metadata, ok := p.Metadata.(pkg.CargoPackageMetadata); ok && metadata.Checksum != "" {
			hashes = append(hashes, cyclonedx.Hash{
				Algorithm: cyclonedx.HashAlgoSHA256,
				Value:     metadata.Checksum,
			})
		}
	}
	if len(hashes) > 0 {
		return &hashes
	}
	return nil
}
