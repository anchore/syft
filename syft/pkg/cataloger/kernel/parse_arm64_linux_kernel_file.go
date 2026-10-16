package kernel

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"io"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/anchore/syft/syft/internal/unionreader"
	"github.com/anchore/syft/syft/pkg"
)

const (
	// arm64ImageMagicOffset is the offset of the arm64 Linux kernel image magic
	// (0x644d5241, "ARM\x64") in the image header; see
	// Documentation/arch/arm64/booting.rst in the kernel source tree.
	arm64ImageMagicOffset = 0x38

	// maxARM64KernelFileSize bounds how much of a candidate kernel file is read
	// while looking for a wrapped arm64 image (distro vmlinuz files are far smaller).
	maxARM64KernelFileSize = 64 << 20

	// maxARM64KernelDecompressedSize bounds decompression of a candidate payload
	// as a safeguard against decompression bombs.
	maxARM64KernelDecompressedSize = 256 << 20
)

var (
	arm64ImageMagic    = []byte{'A', 'R', 'M', 0x64}
	linuxVersionMarker = []byte("Linux version ")
)

// kernelCompressionFormat pairs a compression stream magic with a decoder, used
// when searching for an arm64 kernel image wrapped inside another binary (e.g.
// EFI zboot), mirroring the approach of scripts/extract-vmlinux from the kernel
// source tree. Only formats with decoders already vendored by syft are covered.
type kernelCompressionFormat struct {
	magic      []byte
	decompress func([]byte) []byte
}

var kernelCompressionFormats = []kernelCompressionFormat{
	{[]byte{0x1f, 0x8b, 0x08}, gunzipBytes},             // gzip
	{[]byte{0x28, 0xb5, 0x2f, 0xfd}, unzstdBytes},       // zstd
	{[]byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, unxzBytes}, // xz
	{[]byte{'B', 'Z', 'h'}, bunzip2Bytes},               // bzip2
}

// parseARM64LinuxKernelImage detects arm64 kernel images, which deitch/magic
// does not recognize (its "Linux kernel" test keys off x86-specific bytes).
// arm64 distro kernels are shipped as a raw Image, a whole-file compressed
// Image (e.g. Ubuntu), or an EFI zboot PE binary wrapping a compressed Image
// (Amazon Linux, RHEL).
func parseARM64LinuxKernelImage(ur unionreader.UnionReader) (p pkg.LinuxKernel, ok bool) {
	if _, err := ur.Seek(0, io.SeekStart); err != nil {
		return p, false
	}
	data, err := io.ReadAll(io.LimitReader(ur, maxARM64KernelFileSize))
	if err != nil {
		return p, false
	}
	payload := findARM64ImagePayload(data)
	if payload == nil {
		return p, false
	}
	version, extendedVersion, found := parseLinuxVersionBanner(payload)
	if !found {
		return p, false
	}
	return pkg.LinuxKernel{
		Architecture:    "arm64",
		Version:         version,
		ExtendedVersion: extendedVersion,
		Format:          "Image",
	}, true
}

// findARM64ImagePayload returns the arm64 kernel image contained in data: data
// itself when it is a raw image, or the first embedded compression stream that
// decompresses to an arm64 image.
func findARM64ImagePayload(data []byte) []byte {
	if isARM64Image(data) {
		return data
	}
	for _, format := range kernelCompressionFormats {
		if payload := findCompressedARM64Image(data, format); payload != nil {
			return payload
		}
	}
	return nil
}

func findCompressedARM64Image(data []byte, format kernelCompressionFormat) []byte {
	offset := 0
	for offset < len(data) {
		idx := bytes.Index(data[offset:], format.magic)
		if idx < 0 {
			return nil
		}
		offset += idx
		if payload := format.decompress(data[offset:]); isARM64Image(payload) {
			return payload
		}
		offset++
	}
	return nil
}

// isARM64Image reports whether b starts with an arm64 kernel image header.
func isARM64Image(b []byte) bool {
	return len(b) > arm64ImageMagicOffset+len(arm64ImageMagic) &&
		bytes.Equal(b[arm64ImageMagicOffset:arm64ImageMagicOffset+len(arm64ImageMagic)], arm64ImageMagic)
}

// parseLinuxVersionBanner extracts the version from the "Linux version ..."
// banner string embedded in every kernel image (linux_banner in init/version.c).
func parseLinuxVersionBanner(payload []byte) (version, extendedVersion string, ok bool) {
	idx := bytes.Index(payload, linuxVersionMarker)
	if idx < 0 {
		return "", "", false
	}
	rest := payload[idx+len(linuxVersionMarker):]
	if end := bytes.IndexAny(rest, "\x00\n\r"); end >= 0 {
		rest = rest[:end]
	}
	extendedVersion = strings.TrimSpace(string(rest))
	fields := strings.Fields(extendedVersion)
	if len(fields) == 0 {
		return "", "", false
	}
	return fields[0], extendedVersion, true
}

func gunzipBytes(data []byte) []byte {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	return drainBounded(r)
}

func unzstdBytes(data []byte) []byte {
	r, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	defer r.Close()
	return drainBounded(r)
}

func unxzBytes(data []byte) []byte {
	r, err := xz.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	return drainBounded(r)
}

func bunzip2Bytes(data []byte) []byte {
	return drainBounded(bzip2.NewReader(bytes.NewReader(data)))
}

// drainBounded reads up to maxARM64KernelDecompressedSize bytes, tolerating a
// trailing error after a valid stream prefix (wrapped payloads are commonly
// followed by unrelated bytes).
func drainBounded(r io.Reader) []byte {
	data, _ := io.ReadAll(io.LimitReader(r, maxARM64KernelDecompressedSize))
	if len(data) == 0 {
		return nil
	}
	return data
}
