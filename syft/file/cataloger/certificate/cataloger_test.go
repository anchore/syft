package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/anchore/syft/syft/file"
	"github.com/stretchr/testify/require"
)

func TestParseCertificates(t *testing.T) {
	der := testCertificate(t)
	pemCertificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not retained")})
	location := file.NewLocation("/etc/ssl/test.pem")

	certificates := parseCertificates(append(append(pemCertificate, privateKey...), pemCertificate...), location)
	require.Len(t, certificates, 2)
	require.Equal(t, certificates[0].Fingerprint, certificates[1].Fingerprint)
	require.Equal(t, "CN=example.test", certificates[0].Subject)
	require.Equal(t, "RSA", certificates[0].PublicKeyAlgorithm)
	require.Equal(t, "2048 bits", certificates[0].PublicKeyDetails)
	require.Equal(t, "PEM", certificates[0].Format)
	require.Equal(t, []string{"digital-signature", "key-encipherment"}, certificates[0].KeyUsage)
}

func TestParseCertificatesDERAndMalformedInput(t *testing.T) {
	location := file.NewLocation("/certificate.der")
	certificates := parseCertificates(testCertificate(t), location)
	require.Len(t, certificates, 1)
	require.Equal(t, "DER", certificates[0].Format)
	require.Empty(t, parseCertificates([]byte("not a certificate"), location))
	require.Empty(t, parseCertificates(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")}), location))
}

func testCertificate(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "example.test"},
		Issuer: pkix.Name{CommonName: "example.test"}, NotBefore: time.Unix(1700000000, 0).UTC(),
		NotAfter: time.Unix(1800000000, 0).UTC(), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}
