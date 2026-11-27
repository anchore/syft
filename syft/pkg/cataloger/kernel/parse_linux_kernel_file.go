package kernel

import (
	"bytes"
	"context"
	"debug/elf"
	"fmt"
	"io"
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

const (
	linuxKernelMagicName = "Linux kernel"
	linuxVersionBanner   = "Linux version "
	maxKernelSectionSize = 64 << 20 // 64 MiB; .rodata is far smaller in practice
)

func parseLinuxKernelFile(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	unionReader, err := unionreader.GetUnionReader(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get union reader for file: %w", err)
	}
	magicType, err := magic.GetType(unionReader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get magic type for file: %w", err)
	}
	if len(magicType) >= 1 && magicType[0] == linuxKernelMagicName {
		metadata := parseLinuxKernelMetadata(magicType)
		if metadata.Version != "" {
			return []pkg.Package{
				newLinuxKernelPackage(
					metadata,
					reader.Location,
				),
			}, nil, nil
		}
	}

	// An uncompressed vmlinux has no x86 boot header for libmagic to identify,
	// so look for the version banner in its ELF sections instead.
	if metadata, ok := parseELFLinuxKernel(unionReader); ok {
		return []pkg.Package{
			newLinuxKernelPackage(
				metadata,
				reader.Location,
			),
		}, nil, nil
	}

	return nil, nil, nil
}

// parseELFLinuxKernel recognizes an uncompressed Linux kernel image and reads
// the "Linux version ..." banner from its read-only data. It returns false for
// any ELF that does not carry that banner.
func parseELFLinuxKernel(reader io.ReaderAt) (pkg.LinuxKernel, bool) {
	f, err := elf.NewFile(reader)
	if err != nil {
		return pkg.LinuxKernel{}, false
	}
	defer f.Close()

	var architecture string
	switch f.Machine {
	case elf.EM_X86_64, elf.EM_386:
		architecture = "x86"
	case elf.EM_AARCH64:
		architecture = "arm64"
	case elf.EM_ARM:
		architecture = "arm"
	default:
		return pkg.LinuxKernel{}, false
	}

	banner, ok := findLinuxVersionBanner(f)
	if !ok {
		return pkg.LinuxKernel{}, false
	}
	fields := strings.Fields(banner)
	if len(fields) == 0 {
		return pkg.LinuxKernel{}, false
	}

	return pkg.LinuxKernel{
		Name:            "Linux",
		Architecture:    architecture,
		Version:         fields[0],
		ExtendedVersion: banner,
		Format:          "vmlinux",
	}, true
}

// findLinuxVersionBanner prefers .rodata, where the kernel keeps linux_banner,
// and falls back to other non-empty sections in case a build moved it.
func findLinuxVersionBanner(f *elf.File) (string, bool) {
	var fallback []*elf.Section
	for _, section := range f.Sections {
		if section.Type == elf.SHT_NOBITS || section.Size == 0 {
			continue
		}
		if strings.HasPrefix(section.Name, ".rodata") {
			if banner, ok := linuxVersionFromSection(section); ok {
				return banner, true
			}
			continue
		}
		if section.Size <= maxKernelSectionSize {
			fallback = append(fallback, section)
		}
	}
	for _, section := range fallback {
		if banner, ok := linuxVersionFromSection(section); ok {
			return banner, true
		}
	}
	return "", false
}

func linuxVersionFromSection(section *elf.Section) (string, bool) {
	data, err := section.Data()
	if err != nil {
		return "", false
	}
	index := bytes.Index(data, []byte(linuxVersionBanner))
	if index < 0 {
		return "", false
	}
	rest := data[index+len(linuxVersionBanner):]
	if end := bytes.IndexAny(rest, "\r\n\x00"); end >= 0 {
		rest = rest[:end]
	}
	banner := strings.TrimSpace(string(rest))
	if banner == "" {
		return "", false
	}
	return banner, true
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
