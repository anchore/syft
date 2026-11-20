package kernel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

const testKernelBanner = "5.10.256 (builderbob@4d9231092e04) (aarch64-linux-gnu-gcc (GCC) 9.2.1 20191025, GNU ld (Linaro_Binutils-2019.12) 2.33.1.20191209) #1 SMP PREEMPT Fri Aug 7 00:01:33 MDT 2026"

func arm64KernelImage(payload string) []byte {
	header := make([]byte, 64)
	copy(header[56:], "ARM\x64")
	return append(header, []byte(payload)...)
}

func TestParseLinuxKernelFileARM64(t *testing.T) {
	for _, efiStub := range []bool{false, true} {
		t.Run(map[bool]string{false: "raw Linux header", true: "MZ-prefixed Linux header"}[efiStub], func(t *testing.T) {
			image := arm64KernelImage("Linux version " + testKernelBanner + "\n\x00")
			if efiStub {
				// Only header recognition is tested here, not PE executable validity.
				copy(image, "MZ")
			}
			packages, relationships, err := parseLinuxKernelFile(context.Background(), nil, nil, file.LocationReadCloser{
				Location: file.NewLocation("/boot/Image.efi"), ReadCloser: io.NopCloser(bytes.NewReader(image)),
			})
			require.NoError(t, err)
			require.Empty(t, relationships)
			require.Len(t, packages, 1)
			require.Equal(t, "linux-kernel", packages[0].Name)
			require.Equal(t, "5.10.256", packages[0].Version)
			require.Equal(t, pkg.LinuxKernel{Architecture: "arm64", Format: "Image", Version: "5.10.256", ExtendedVersion: testKernelBanner}, packages[0].Metadata)
		})
	}
}

func TestReadLinuxKernelBanner(t *testing.T) {
	tests := []struct {
		name, payload, want string
	}{
		{"normal", "Linux version " + testKernelBanner + "\x00", testKernelBanner},
		{"newline terminated", "Linux version " + testKernelBanner + "\n\x00", testKernelBanner},
		{"embedded newline rejected", "Linux version 5.10.256\ninvalid\x00", ""},
		{"split marker", strings.Repeat("\x00", 32760) + "Linux version " + testKernelBanner + "\x00", testKernelBanner},
		{"split banner", strings.Repeat("\x00", 32740) + "Linux version " + testKernelBanner + "\x00", testKernelBanner},
		{"late banner", strings.Repeat("\x00", 17*1024*1024) + "Linux version " + testKernelBanner + "\x00", testKernelBanner},
		{"template then valid", "Linux version %s (%s)\x00Linux version " + testKernelBanner + "\x00", testKernelBanner},
		{"oversized then valid", "Linux version " + strings.Repeat("a", 4097) + "\x00Linux version " + testKernelBanner + "\x00", testKernelBanner},
		{"nonprintable then valid", "Linux version 5.10.256\xff\x00Linux version " + testKernelBanner + "\x00", testKernelBanner},
		{"release suffix", "Linux version 6.12.0-rc1+ (builder@host) (gcc) #1\x00", "6.12.0-rc1+ (builder@host) (gcc) #1"},
		{"standalone plus", "Linux version 6.12.0+ (builder@host) (gcc) #1\x00", "6.12.0+ (builder@host) (gcc) #1"},
		{"custom suffix", "Linux version 6.12.0custom (builder@host) (gcc) #1\x00", "6.12.0custom (builder@host) (gcc) #1"},
		{"unicode metadata", "Linux version 6.12.0 (Jos\u00e9@host) (gcc) #1\x00", "6.12.0 (Jos\u00e9@host) (gcc) #1"},
		{"invalid metadata encoding", "Linux version 6.12.0 (builder\xff@host) (gcc) #1\x00", "6.12.0 (builder\uFFFD@host) (gcc) #1"},
		{"incidental version then valid", "Linux version 1.2.3\x00Linux version " + testKernelBanner + "\x00", testKernelBanner},
		{"missing compiler then valid", "Linux version 1.2.3 (builder@host) #1\x00Linux version " + testKernelBanner + "\x00", testKernelBanner},
		{"incidental version only", "Linux version 1.2.3\x00", ""},
		{"embedded control", "Linux version 6.12.0 (builder@host) (gcc) #1\tSMP\x00", ""},
		{"no banner", strings.Repeat("a", 100000), ""},
		{"unterminated", "Linux version " + testKernelBanner, ""},
		{"template only", "Linux version %s (%s)\x00", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			banner, err := readLinuxKernelBanner(context.Background(), strings.NewReader(test.payload))
			require.NoError(t, err)
			require.Equal(t, test.want, banner)
		})
	}
}

func TestParseARM64LinuxKernelRejectsNonKernel(t *testing.T) {
	for _, image := range [][]byte{
		// Too short to be a valid kernel image header
		[]byte("ARM\x64"),
		// Missing the ARM64 Linux signature at bytes 56–59
		append(make([]byte, 64), []byte("Linux version "+testKernelBanner+"\x00")...),
	} {
		metadata, recognized, err := parseARM64LinuxKernel(context.Background(), bytes.NewReader(image))
		require.NoError(t, err)
		require.False(t, recognized)
		require.Empty(t, metadata)
	}

	// Valid header but has no usable version
	metadata, recognized, err := parseARM64LinuxKernel(context.Background(), bytes.NewReader(arm64KernelImage("Linux version %s (%s)\x00")))
	require.NoError(t, err)
	require.True(t, recognized)
	require.Empty(t, metadata.Version)
}

type failingKernelReader struct{}

func (failingKernelReader) ReadAt([]byte, int64) (int, error) {
	return 0, errors.New("read failure")
}

func TestParseARM64LinuxKernelReadError(t *testing.T) {
	_, _, err := parseARM64LinuxKernel(context.Background(), failingKernelReader{})
	require.ErrorContains(t, err, "read failure")
	_, err = readLinuxKernelBanner(context.Background(), io.NewSectionReader(failingKernelReader{}, 0, 1024))
	require.ErrorContains(t, err, "read failure")
}

func TestReadLinuxKernelBannerSizeBoundary(t *testing.T) {
	for _, size := range []int{maxLinuxKernelBannerSize - 1, maxLinuxKernelBannerSize, maxLinuxKernelBannerSize + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			candidate := "Linux version " + testKernelBanner
			candidate += strings.Repeat("a", size-len(candidate))
			banner, err := readLinuxKernelBanner(context.Background(), strings.NewReader(candidate+"\x00Linux version "+testKernelBanner+"\x00"))
			require.NoError(t, err)
			if size <= maxLinuxKernelBannerSize {
				require.Equal(t, strings.TrimPrefix(candidate, "Linux version "), banner)
			} else {
				require.Equal(t, testKernelBanner, banner)
			}
		})
	}
}

type cancelingKernelReader struct {
	cancel context.CancelFunc
}

func (reader cancelingKernelReader) Read(buffer []byte) (int, error) {
	reader.cancel()
	return copy(buffer, "not a banner"), nil
}

func TestLinuxKernelBannerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := readLinuxKernelBanner(ctx, cancelingKernelReader{cancel: cancel})
	require.ErrorIs(t, err, context.Canceled)
	_, _, err = parseARM64LinuxKernel(ctx, failingKernelReader{})
	require.ErrorIs(t, err, context.Canceled)
}
