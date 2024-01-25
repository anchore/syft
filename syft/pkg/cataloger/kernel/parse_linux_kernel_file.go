package kernel

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/deitch/magic/pkg/magic"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const linuxKernelMagicName = "Linux kernel"

func parseLinuxKernelFile(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	unionReader, err := unionreader.GetUnionReader(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get union reader for file: %w", err)
	}
	magicType, err := magic.GetType(unionReader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get magic type for file: %w", err)
	}
	if len(magicType) < 1 || magicType[0] != linuxKernelMagicName {
		return nil, nil, nil
	}
	metadata := parseLinuxKernelMetadata(magicType)
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
				log.Warnf("unable to parse swap device: %s", err)
				continue
			}
			p.SwapDevice = int(swapDev)
		case strings.HasPrefix(t, "root_dev "):
			rootDevStr := strings.TrimPrefix(t, "root_dev ")
			rootDev, err := strconv.ParseInt(rootDevStr, 16, 32)
			if err != nil {
				log.Warnf("unable to parse root device: %s", err)
				continue
			}
			p.SwapDevice = int(rootDev)
		case strings.Contains(t, "VGA") || strings.Contains(t, "Video"):
			p.VideoMode = t
		}
	}
	return p
}
