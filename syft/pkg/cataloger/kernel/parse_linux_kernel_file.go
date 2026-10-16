package kernel

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/deitch/magic/pkg/magic"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const linuxKernelMagicName = "Linux kernel"

// This is a defensive candidate limit, not a limit imposed by the kernel format.
const maxLinuxKernelBannerSize = 4096

// linux_banner contains release, builder@host, compiler, and build information.
// Local release suffixes are configurable and need not follow semantic versioning.
var linuxKernelBanner = regexp.MustCompile(`^[0-9]+\.[0-9]+[^\s()]* \([^()]*@[^()]*\) \(.+\) .+$`)

func parseLinuxKernelFile(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	unionReader, err := unionreader.GetUnionReader(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get union reader for file: %w", err)
	}
	metadata, arm64Image, err := parseARM64LinuxKernel(ctx, unionReader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse ARM64 kernel image: %w", err)
	}
	if !arm64Image {
		magicType, err := magic.GetType(unionReader)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get magic type for file: %w", err)
		}
		if len(magicType) < 1 || magicType[0] != linuxKernelMagicName {
			return nil, nil, nil
		}
		metadata = parseLinuxKernelMetadata(magicType)
	}
	if metadata.Version == "" {
		return nil, nil, nil
	}

	return []pkg.Package{
		newLinuxKernelPackage(
			metadata,
			reader.Location,
		),
	}, nil, nil
}

func parseARM64LinuxKernel(ctx context.Context, reader io.ReaderAt) (pkg.LinuxKernel, bool, error) {
	if err := ctx.Err(); err != nil {
		return pkg.LinuxKernel{}, false, err
	}
	// The ARM64 boot protocol places its Linux signature at byte 56 of a 64-byte header.
	var header [64]byte
	if _, err := reader.ReadAt(header[:], 0); err != nil {
		if err == io.EOF {
			return pkg.LinuxKernel{}, false, nil
		}
		return pkg.LinuxKernel{}, false, err
	}
	if string(header[56:60]) != "ARM\x64" {
		return pkg.LinuxKernel{}, false, nil
	}

	// Old kernels may have a zero image_size; scan to EOF rather than trusting that field.
	extendedVersion, err := readLinuxKernelBanner(ctx, io.NewSectionReader(reader, 64, math.MaxInt64-64))
	if err != nil {
		return pkg.LinuxKernel{}, true, err
	}
	metadata := pkg.LinuxKernel{Architecture: "arm64", Format: "Image", ExtendedVersion: extendedVersion}
	if fields := strings.Fields(extendedVersion); len(fields) > 0 {
		metadata.Version = fields[0]
	}
	return metadata, true, nil
}

func readLinuxKernelBanner(ctx context.Context, reader io.Reader) (string, error) {
	const prefix = "Linux version "
	chunk := make([]byte, 32*1024)
	var pending []byte
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		count, readErr := reader.Read(chunk)
		pending = append(pending, chunk[:count]...)
		for {
			start := bytes.Index(pending, []byte(prefix))
			if start < 0 {
				// Keep enough overlap to recognize a marker split across reads.
				if len(pending) >= len(prefix) {
					pending = pending[len(pending)-len(prefix)+1:]
				}
				break
			}
			pending = pending[start:]
			end := bytes.IndexByte(pending, 0)
			if end < 0 && len(pending) <= maxLinuxKernelBannerSize {
				break
			}
			if end >= len(prefix) && end <= maxLinuxKernelBannerSize {
				banner := strings.TrimSuffix(string(pending[len(prefix):end]), "\n")
				// Preserve Unicode metadata and make invalid encoding safe for SBOM output.
				banner = strings.ToValidUTF8(banner, "\uFFFD")
				if strings.IndexFunc(banner, unicode.IsControl) < 0 && linuxKernelBanner.MatchString(banner) {
					return banner, nil
				}
			}
			// Skip this marker, but keep searching inside rejected candidates.
			pending = pending[len(prefix):]
		}
		if readErr != nil {
			if readErr == io.EOF {
				return "", nil
			}
			return "", readErr
		}
	}
}

func parseLinuxKernelMetadata(magicType []string) (p pkg.LinuxKernel) {
	// Linux kernel x86 boot executable bzImage,
	// version 5.10.121-linuxkit (root@buildkitsandbox) #1 SMP Fri Dec 2 10:35:42 UTC 2022,
	// RO-rootFS,
	// swap_dev 0XA,
	// Normal VGA
	for _, t := range magicType {
		switch {
		case strings.HasPrefix(t, "x86 "):
			p.Architecture = "x86"
		case strings.Contains(t, "ARM64 "):
			p.Architecture = "arm64"
		case strings.Contains(t, "ARM "):
			p.Architecture = "arm"
		case t == "bzImage":
			p.Format = "bzImage"
		case t == "zImage":
			p.Format = "zImage"
		case strings.HasPrefix(t, "version "):
			p.ExtendedVersion = strings.TrimPrefix(t, "version ")
			fields := strings.Fields(p.ExtendedVersion)
			if len(fields) > 0 {
				p.Version = fields[0]
			}
		case strings.Contains(t, "rootFS") && strings.HasPrefix(t, "RW-"):
			p.RWRootFS = true
		case strings.HasPrefix(t, "swap_dev "):
			swapDevStr := strings.TrimPrefix(t, "swap_dev ")
			swapDev, err := strconv.ParseInt(swapDevStr, 16, 32)
			if err != nil {
				log.Debugf("unable to parse swap device: %s", err)
				continue
			}
			p.SwapDevice = int(swapDev)
		case strings.HasPrefix(t, "root_dev "):
			rootDevStr := strings.TrimPrefix(t, "root_dev ")
			rootDev, err := strconv.ParseInt(rootDevStr, 16, 32)
			if err != nil {
				log.Debugf("unable to parse root device: %s", err)
				continue
			}
			p.SwapDevice = int(rootDev)
		case strings.Contains(t, "VGA") || strings.Contains(t, "Video"):
			p.VideoMode = t
		}
	}
	return p
}
