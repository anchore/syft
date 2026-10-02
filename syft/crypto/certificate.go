package crypto

import (
	"slices"
	"time"

	"github.com/anchore/syft/syft/file"
)

// Certificate describes public X.509 certificate metadata discovered in a source.
// Raw certificate and private-key material are intentionally not retained.
type Certificate struct {
	Fingerprint        string
	Subject            string
	Issuer             string
	SerialNumber       string
	NotBefore          time.Time
	NotAfter           time.Time
	PublicKeyAlgorithm string
	PublicKeyDetails   string
	SignatureAlgorithm string
	KeyUsage           []string
	ExtendedKeyUsage   []string
	IsCA               bool
	Format             string
	Locations          []file.Location
}

// Certificates is a deterministic, fingerprint-deduplicated certificate collection.
type Certificates []Certificate

func NewCertificates(certificates ...Certificate) Certificates {
	byFingerprint := make(map[string]Certificate)
	for _, certificate := range certificates {
		if existing, ok := byFingerprint[certificate.Fingerprint]; ok {
			existing.Locations = uniqueLocations(append(existing.Locations, certificate.Locations...))
			byFingerprint[certificate.Fingerprint] = existing
			continue
		}
		certificate.Locations = uniqueLocations(certificate.Locations)
		byFingerprint[certificate.Fingerprint] = certificate
	}
	result := make(Certificates, 0, len(byFingerprint))
	for _, certificate := range byFingerprint {
		result = append(result, certificate)
	}
	slices.SortFunc(result, func(a, b Certificate) int { return compare(a.Fingerprint, b.Fingerprint) })
	return result
}

func uniqueLocations(locations []file.Location) []file.Location {
	byID := make(map[string]file.Location)
	for _, location := range locations {
		byID[string(location.ID())] = location
	}
	result := make([]file.Location, 0, len(byID))
	for _, location := range byID {
		result = append(result, location)
	}
	slices.SortFunc(result, func(a, b file.Location) int {
		if value := compare(a.RealPath, b.RealPath); value != 0 {
			return value
		}
		return compare(a.FileSystemID, b.FileSystemID)
	})
	return result
}

func compare(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
