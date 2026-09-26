package certificate

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"slices"

	syftcrypto "github.com/anchore/syft/syft/crypto"
	"github.com/anchore/syft/syft/file"
)

const maxCertificateFileSize = 10 * 1024 * 1024

var defaultGlobs = []string{"**/*.cer", "**/*.crt", "**/*.der", "**/*.pem"}

type Config struct {
	Enabled bool     `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	Globs   []string `yaml:"globs" json:"globs" mapstructure:"globs"`
}

func DefaultConfig() Config { return Config{Globs: slices.Clone(defaultGlobs)} }

type Cataloger struct{ globs []string }

func NewCataloger(cfg Config) Cataloger {
	globs := cfg.Globs
	if len(globs) == 0 {
		globs = defaultGlobs
	}
	return Cataloger{globs: slices.Clone(globs)}
}

func (c Cataloger) Catalog(_ context.Context, resolver file.Resolver) (syftcrypto.Certificates, error) {
	locations, err := resolver.FilesByGlob(c.globs...)
	if err != nil {
		return nil, fmt.Errorf("find certificate candidates: %w", err)
	}
	var certificates []syftcrypto.Certificate
	for _, location := range locations {
		reader, err := resolver.FileContentsByLocation(location)
		if err != nil {
			continue
		}
		contents, readErr := io.ReadAll(io.LimitReader(reader, maxCertificateFileSize+1))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || len(contents) > maxCertificateFileSize {
			continue
		}
		certificates = append(certificates, parseCertificates(contents, location)...)
	}
	return syftcrypto.NewCertificates(certificates...), nil
}

func parseCertificates(contents []byte, location file.Location) []syftcrypto.Certificate {
	var result []syftcrypto.Certificate
	remainder := contents
	for {
		block, rest := pem.Decode(remainder)
		if block == nil {
			break
		}
		remainder = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		if certificate, err := x509.ParseCertificate(block.Bytes); err == nil {
			result = append(result, toCertificate(certificate, "PEM", location))
		}
	}
	if len(result) == 0 {
		if certificate, err := x509.ParseCertificate(contents); err == nil {
			result = append(result, toCertificate(certificate, "DER", location))
		}
	}
	return result
}

func toCertificate(certificate *x509.Certificate, format string, location file.Location) syftcrypto.Certificate {
	fingerprint := sha256.Sum256(certificate.Raw)
	return syftcrypto.Certificate{
		Fingerprint: hex.EncodeToString(fingerprint[:]), Subject: certificate.Subject.String(),
		Issuer: certificate.Issuer.String(), SerialNumber: certificate.SerialNumber.String(),
		NotBefore: certificate.NotBefore, NotAfter: certificate.NotAfter,
		PublicKeyAlgorithm: certificate.PublicKeyAlgorithm.String(), PublicKeyDetails: publicKeyDetails(certificate.PublicKey),
		SignatureAlgorithm: certificate.SignatureAlgorithm.String(), KeyUsage: keyUsages(certificate.KeyUsage),
		ExtendedKeyUsage: extendedKeyUsages(certificate.ExtKeyUsage), IsCA: certificate.IsCA,
		Format: format, Locations: []file.Location{location},
	}
}

func publicKeyDetails(publicKey any) string {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("%d bits", key.N.BitLen())
	case *ecdsa.PublicKey:
		return key.Curve.Params().Name
	case ed25519.PublicKey:
		return fmt.Sprintf("%d bits", len(key)*8)
	default:
		return ""
	}
}

func keyUsages(usage x509.KeyUsage) []string {
	values := []struct {
		flag x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digital-signature"}, {x509.KeyUsageContentCommitment, "content-commitment"},
		{x509.KeyUsageKeyEncipherment, "key-encipherment"}, {x509.KeyUsageDataEncipherment, "data-encipherment"},
		{x509.KeyUsageKeyAgreement, "key-agreement"}, {x509.KeyUsageCertSign, "certificate-signing"},
		{x509.KeyUsageCRLSign, "crl-signing"}, {x509.KeyUsageEncipherOnly, "encipher-only"},
		{x509.KeyUsageDecipherOnly, "decipher-only"},
	}
	var result []string
	for _, value := range values {
		if usage&value.flag != 0 {
			result = append(result, value.name)
		}
	}
	return result
}

func extendedKeyUsages(usages []x509.ExtKeyUsage) []string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny: "any", x509.ExtKeyUsageServerAuth: "server-auth", x509.ExtKeyUsageClientAuth: "client-auth",
		x509.ExtKeyUsageCodeSigning: "code-signing", x509.ExtKeyUsageEmailProtection: "email-protection",
		x509.ExtKeyUsageTimeStamping: "time-stamping", x509.ExtKeyUsageOCSPSigning: "ocsp-signing",
	}
	result := make([]string, 0, len(usages))
	for _, usage := range usages {
		if name, ok := names[usage]; ok {
			result = append(result, name)
		} else {
			result = append(result, fmt.Sprintf("unknown-%d", usage))
		}
	}
	return result
}
