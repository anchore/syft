package rekor

import (
	"crypto/x509"
	"os"
	"testing"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/stretchr/testify/assert"
)

func Test_verifyEntryTimestamp(t *testing.T) {
	var time int64 = 1656444102

	tests := []struct {
		name         string
		certFilePath string
		entry        models.LogEntryAnon
	}{
		{
			name:         "invalid timestamp",
			certFilePath: "test-fixtures/test-certs/der-cert-1.der",
			entry:        models.LogEntryAnon{IntegratedTime: &time},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			// parse test cert
			certBytes, err := os.ReadFile(test.certFilePath)
			if err != nil {
				t.Fatal("reading test data")
			}
			cert, err := x509.ParseCertificate(certBytes)
			if err != nil {
				t.Fatal("reading test data")
			}

			err = verifyEntryTimestamp(cert, &test.entry)
			assert.Error(t, err)
		})
	}
}
