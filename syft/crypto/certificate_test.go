package crypto

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/stretchr/testify/require"
)

func TestNewCertificatesDeduplicatesAndSorts(t *testing.T) {
	certificates := NewCertificates(
		Certificate{Fingerprint: "b", Locations: []file.Location{file.NewLocation("/b")}},
		Certificate{Fingerprint: "a", Locations: []file.Location{file.NewLocation("/z")}},
		Certificate{Fingerprint: "a", Locations: []file.Location{file.NewLocation("/a")}},
	)
	require.Len(t, certificates, 2)
	require.Equal(t, "a", certificates[0].Fingerprint)
	require.Equal(t, []string{"/a", "/z"}, []string{certificates[0].Locations[0].RealPath, certificates[0].Locations[1].RealPath})
}
