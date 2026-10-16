package kernel

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// spec-level constants, encoded here independently of the implementation:
// the arm64 kernel image header carries the u32 magic 0x644d5241 ("ARM\x64")
// at offset 0x38 (see Documentation/arch/arm64/booting.rst in the kernel tree).
const arm64SpecMagicOffset = 0x38

var arm64SpecMagic = []byte{'A', 'R', 'M', 0x64}

// escapeCPEVersion mirrors the escaping createLinuxKernelCPEs applies when
// binding attributes to a formatted string (backslash before CPE punctuation).
func escapeCPEVersion(version string) string {
	const cpePunctuation = "-!\"#$%&'()+,./:;<=>@[]^`{|}~"
	var sb strings.Builder
	for _, c := range version {
		if strings.ContainsRune(cpePunctuation, c) {
			sb.WriteRune('\\')
		}
		sb.WriteRune(c)
	}
	return sb.String()
}

// arm64ImageBytes constructs a minimal synthetic arm64 kernel image: a header
// carrying the "ARM\x64" magic at offset 0x38 followed by a linux_banner-style
// version string embedded in the payload.
func arm64ImageBytes(banner string) []byte {
	b := make([]byte, 0x400)
	copy(b[arm64SpecMagicOffset:], arm64SpecMagic)
	b = append(b, "Linux version "+banner...)
	b = append(b, 0)
	return b
}

// zbootWrap mimics an EFI zboot binary: a PE32+-looking prefix (MZ magic,
// e_lfanew, PE signature) with the compressed kernel image embedded at a
// non-zero offset, like Amazon Linux / RHEL arm64 vmlinuz files.
func zbootWrap(compressed []byte) []byte {
	prefix := make([]byte, 0x400)
	copy(prefix, []byte{'M', 'Z'})
	binary.LittleEndian.PutUint32(prefix[0x3c:], 0x80)
	copy(prefix[0x80:], []byte{'P', 'E', 0, 0})
	out := make([]byte, 0, len(prefix)+len(compressed)+4)
	out = append(out, prefix...)
	out = append(out, compressed...)
	// trailing junk after the stream must be tolerated (PE overlay data)
	return append(out, 0xde, 0xad, 0xbe, 0xef)
}

// x86BzImageBytes constructs a minimal synthetic x86 bzImage that deitch/magic
// recognizes as a Linux kernel, guarding that the x86 path still takes
// priority over the arm64 fallback.
func x86BzImageBytes(version string) []byte {
	b := make([]byte, 0x300)
	binary.LittleEndian.PutUint16(b[510:], 0xAA55) // boot_flag
	copy(b[514:], []byte("HdrS"))                  // header magic
	binary.LittleEndian.PutUint16(b[518:], 0x0202) // header version > 0x1ff
	binary.LittleEndian.PutUint16(b[526:], 0x40)   // version string offset (0x40 + 0x200 = 0x240)
	b[529] = 1                                     // loadflags: LOADED_HIGH => bzImage (not zImage)
	copy(b[0x240:], version)
	return b
}

func TestParseLinuxKernelFile_arm64(t *testing.T) {
	const amznBanner = "6.18.38-76.139.amzn2023.aarch64 (mockbuild@ip-10-0-48-196.ec2.internal) (gcc (GCC) 11.5.0 20240719 (Red Hat 11.5.0-5)) #1 SMP PREEMPT_DYNAMIC Thu Jan 15 11:03:06 UTC 2026"
	const ubuntuBanner = "7.0.0-1006-aws (buildd@bos03-arm64-012) (aarch64-linux-gnu-gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0) #6-Ubuntu SMP Fri Jan 30 11:21:07 UTC 2026"

	tests := []struct {
		name    string
		data    []byte
		wantVer string
		wantExt string
	}{
		{
			name:    "raw arm64 image",
			data:    arm64ImageBytes(amznBanner),
			wantVer: "6.18.38-76.139.amzn2023.aarch64",
			wantExt: amznBanner,
		},
		{
			name:    "whole-file gzip stream (ubuntu arm64 vmlinuz)",
			data:    gzCompress(arm64ImageBytes(ubuntuBanner)),
			wantVer: "7.0.0-1006-aws",
			wantExt: ubuntuBanner,
		},
		{
			name:    "gzip payload inside efi zboot (amazon/rhel arm64 vmlinuz)",
			data:    zbootWrap(gzCompress(arm64ImageBytes(amznBanner))),
			wantVer: "6.18.38-76.139.amzn2023.aarch64",
			wantExt: amznBanner,
		},
		{
			name:    "zstd payload inside efi zboot",
			data:    zbootWrap(zstCompress(arm64ImageBytes(amznBanner))),
			wantVer: "6.18.38-76.139.amzn2023.aarch64",
			wantExt: amznBanner,
		},
		{
			name:    "xz payload inside efi zboot",
			data:    zbootWrap(xzCompress(arm64ImageBytes(amznBanner))),
			wantVer: "6.18.38-76.139.amzn2023.aarch64",
			wantExt: amznBanner,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := makeLocationReadCloser("/boot/vmlinuz-test.aarch64", tt.data)
			pkgs, rels, err := parseLinuxKernelFile(testContext(t), nil, &generic.Environment{}, reader)
			require.NoError(t, err)
			require.Len(t, pkgs, 1)
			assert.Empty(t, rels)

			p := pkgs[0]
			assert.Equal(t, "linux-kernel", p.Name)
			assert.Equal(t, tt.wantVer, p.Version)
			assert.Equal(t, pkg.LinuxKernelPkg, p.Type)
			assert.Equal(t, "pkg:generic/linux-kernel@"+tt.wantVer, p.PURL)
			// createLinuxKernelCPEs escapes CPE punctuation in the version (e.g.
			// "-" -> "\-"), so the expected CPE must use the escaped form — the raw
			// version with hyphens is not parseable as a formatted string.
			require.Len(t, p.CPEs, 1)
			assert.Equal(t, cpe.Must("cpe:2.3:o:linux:linux_kernel:"+escapeCPEVersion(tt.wantVer)+":*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource), p.CPEs[0])

			meta, ok := p.Metadata.(pkg.LinuxKernel)
			require.True(t, ok)
			assert.Equal(t, "arm64", meta.Architecture)
			assert.Equal(t, "Image", meta.Format)
			assert.Equal(t, tt.wantVer, meta.Version)
			assert.Equal(t, tt.wantExt, meta.ExtendedVersion)
		})
	}
}

func TestParseLinuxKernelFile_arm64_Negative(t *testing.T) {
	t.Run("garbage file", func(t *testing.T) {
		reader := makeLocationReadCloser("/boot/vmlinuz-test.aarch64", bytes.Repeat([]byte{0x5a}, 0x1000))
		pkgs, rels, err := parseLinuxKernelFile(testContext(t), nil, &generic.Environment{}, reader)
		require.NoError(t, err)
		assert.Empty(t, pkgs)
		assert.Empty(t, rels)
	})

	t.Run("arm64 image without version banner", func(t *testing.T) {
		b := make([]byte, 0x400)
		copy(b[arm64SpecMagicOffset:], arm64SpecMagic)
		reader := makeLocationReadCloser("/boot/vmlinuz-test.aarch64", b)
		pkgs, rels, err := parseLinuxKernelFile(testContext(t), nil, &generic.Environment{}, reader)
		require.NoError(t, err)
		assert.Empty(t, pkgs, "no version => no package (parity with the x86 empty-version rule)")
		assert.Empty(t, rels)
	})

	// files that deitch/magic cannot read at all surface the magic error —
	// this is pre-existing behavior that must be preserved
	magicErrorCases := []struct {
		name string
		data []byte
	}{
		{"too small to identify", []byte{'A', 'R', 'M', 0x64}},
		{"gzip payload without arm64 magic", gzCompress(bytes.Repeat([]byte{0x42}, 0x1000))},
	}
	for _, tt := range magicErrorCases {
		t.Run(tt.name, func(t *testing.T) {
			reader := makeLocationReadCloser("/boot/vmlinuz-test.aarch64", tt.data)
			pkgs, _, err := parseLinuxKernelFile(testContext(t), nil, &generic.Environment{}, reader)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unable to get magic type")
			assert.Empty(t, pkgs)
		})
	}
}

func TestParseLinuxKernelFile_x86PathUnchanged(t *testing.T) {
	const version = "5.10.121-linuxkit (root@buildkitsandbox) #1 SMP Fri Dec 2 10:35:42 UTC 2022"
	reader := makeLocationReadCloser("/boot/vmlinuz-test.x86_64", x86BzImageBytes(version))

	pkgs, _, err := parseLinuxKernelFile(testContext(t), nil, &generic.Environment{}, reader)
	require.NoError(t, err)
	require.Len(t, pkgs, 1, "x86 bzImage must still be detected through the deitch/magic path")

	meta, ok := pkgs[0].Metadata.(pkg.LinuxKernel)
	require.True(t, ok)
	assert.Equal(t, "x86", meta.Architecture)
	assert.Equal(t, "bzImage", meta.Format)
	assert.Equal(t, "5.10.121-linuxkit", meta.Version)
	assert.Equal(t, version, meta.ExtendedVersion)
}

func TestIsARM64Image(t *testing.T) {
	img := arm64ImageBytes("1.2.3-test")
	assert.True(t, isARM64Image(img))
	assert.False(t, isARM64Image(nil))
	assert.False(t, isARM64Image(make([]byte, arm64ImageMagicOffset+4)))
	bad := bytes.Clone(img)
	bad[arm64ImageMagicOffset] = 'X'
	assert.False(t, isARM64Image(bad))
}

func TestParseLinuxVersionBanner(t *testing.T) {
	payload := append([]byte{1, 2, 3}, []byte("Linux version 6.1.21-1.25.amzn2023.aarch64 (mockbuild@host) #1 SMP Tue May 1 00:00:00 UTC 2023\x00trailing")...)
	version, extended, ok := parseLinuxVersionBanner(payload)
	require.True(t, ok)
	assert.Equal(t, "6.1.21-1.25.amzn2023.aarch64", version)
	assert.Equal(t, "6.1.21-1.25.amzn2023.aarch64 (mockbuild@host) #1 SMP Tue May 1 00:00:00 UTC 2023", extended)

	_, _, ok = parseLinuxVersionBanner([]byte("no banner here"))
	assert.False(t, ok)
}
