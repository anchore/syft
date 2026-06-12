package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArchitecture_TargetArchitecture(t *testing.T) {
	tests := []struct {
		name     string
		metadata any
		want     string
	}{
		{name: "rpm db entry", metadata: RpmDBEntry{Arch: "x86_64"}, want: "x86_64"},
		{name: "rpm archive", metadata: RpmArchive{Arch: "aarch64"}, want: "aarch64"},
		{name: "rpm noarch passes through", metadata: RpmDBEntry{Arch: "noarch"}, want: "noarch"},
		{name: "dpkg db entry", metadata: DpkgDBEntry{Architecture: "amd64"}, want: "amd64"},
		{name: "dpkg archive entry", metadata: DpkgArchiveEntry{Architecture: "arm64"}, want: "arm64"},
		{name: "apk db entry", metadata: ApkDBEntry{Architecture: "x86_64"}, want: "x86_64"},
		{name: "alpm db entry", metadata: AlpmDBEntry{Architecture: "x86_64"}, want: "x86_64"},
		{name: "bitnami sbom entry", metadata: BitnamiSBOMEntry{Architecture: "arm64"}, want: "arm64"},
		{name: "golang binary buildinfo", metadata: GolangBinaryBuildinfoEntry{Architecture: "amd64"}, want: "amd64"},
		{name: "golang source entry", metadata: GolangSourceEntry{Architecture: "arm64"}, want: "arm64"},
		{name: "elf binary note", metadata: ELFBinaryPackageNoteJSONPayload{Architecture: "x86_64"}, want: "x86_64"},
		{name: "linux kernel", metadata: LinuxKernel{Architecture: "aarch64"}, want: "aarch64"},
		{name: "snap entry", metadata: SnapEntry{Architecture: "amd64"}, want: "amd64"},
		{name: "conda meta package", metadata: CondaMetaPackage{Arch: "x86_64"}, want: "x86_64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, ok := tt.metadata.(Architecture)
			require.True(t, ok, "%T must implement Architecture", tt.metadata)
			assert.Equal(t, tt.want, a.TargetArchitecture())
		})
	}
}

// TestArchitecture_excludesNonCPUArchitecture locks in that metadata whose "architecture"
// is not a CPU architecture does NOT implement the interface — most importantly GGUF, whose
// Architecture field is the AI model architecture ("llama"), not a CPU arch.
func TestArchitecture_excludesNonCPUArchitecture(t *testing.T) {
	excluded := []any{
		GGUFFileHeader{Architecture: "llama"},
	}
	for _, m := range excluded {
		_, ok := m.(Architecture)
		assert.Falsef(t, ok, "%T must NOT implement Architecture", m)
	}
}
