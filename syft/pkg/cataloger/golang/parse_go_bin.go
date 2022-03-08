//nolint
package golang

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const GOARCH = "GOARCH"

var (
	// errUnrecognizedFormat is returned when a given executable file doesn't
	// appear to be in a known format, or it breaks the rules of that format,
	// or when there are I/O errors reading the file.
	errUnrecognizedFormat = errors.New("unrecognized file format")

	// errNotGoExe is returned when a given executable file is valid but does
	// not contain Go build information.
	errNotGoExe = errors.New("not a Go executable")

	// The build info blob left by the linker is identified by
	// a 16-byte header, consisting of buildInfoMagic (14 bytes),
	// the binary's pointer size (1 byte),
	// and whether the binary is big endian (1 byte).
	buildInfoMagic = []byte("\xff Go buildinf:")
)

func newGoBinaryPackage(dep *debug.Module, goVersion, architecture string, location source.Location, buildSettings map[string]string) pkg.Package {
	if dep.Replace != nil {
		dep = dep.Replace
	}

	p := pkg.Package{
		Name:     dep.Path,
		Version:  dep.Version,
		Language: pkg.Go,
		Type:     pkg.GoModulePkg,
		Locations: []source.Location{
			location,
		},
		MetadataType: pkg.GolangBinMetadataType,
		Metadata: pkg.GolangBinMetadata{
			GoCompiledVersion: goVersion,
			H1Digest:          dep.Sum,
			Architecture:      architecture,
			BuildSettings:     buildSettings,
		},
	}

	p.SetID()

	return p
}

func setArch(readers []io.ReaderAt, builds []*debug.BuildInfo) {
	if len(readers) != len(builds) {
		log.Errorf("golang cataloger: bin parsing: number of builds and readers doesn't match")
		return
	}

	for _, build := range builds {
		if getGOARCH(build.Settings) != "" {
			return
		}
		break
	}

	for i, r := range readers {
		a, err := getGOARCHFromBin(r)
		if err != nil || a == "" {
			log.Warnf("golang cataloger: bin parsing: getting arch from binary: %v", err)
			continue
		}

		builds[i].Settings = append(builds[i].Settings, debug.BuildSetting{Key: GOARCH, Value: a})
	}

	fmt.Printf("build: %+v\n", builds[0])
}

func getGOARCH(settings []debug.BuildSetting) string {
	for _, s := range settings {
		if s.Key == GOARCH {
			return s.Value
		}
	}

	return ""
}

func getGOARCHFromBin(r io.ReaderAt) (string, error) {
	// Read the first bytes of the file to identify the format, then delegate to
	// a format-specific function to load segment and section headers.
	ident := make([]byte, 16)
	if n, err := r.ReadAt(ident, 0); n < len(ident) || err != nil {
		return "", errUnrecognizedFormat
	}

	var arch string
	switch {
	case bytes.HasPrefix(ident, []byte("\x7FELF")):
		f, err := elf.NewFile(r)
		if err != nil {
			return "", errUnrecognizedFormat
		}
		arch = f.Machine.String()
	case bytes.HasPrefix(ident, []byte("MZ")):
		f, err := pe.NewFile(r)
		if err != nil {
			return "", errUnrecognizedFormat
		}
		arch = fmt.Sprintf("%d", f.Machine)
	case bytes.HasPrefix(ident, []byte("\xFE\xED\xFA")) || bytes.HasPrefix(ident[1:], []byte("\xFA\xED\xFE")):
		f, err := macho.NewFile(r)
		if err != nil {
			return "", errUnrecognizedFormat
		}
		arch = f.Cpu.String()
	case bytes.HasPrefix(ident, []byte{0x01, 0xDF}) || bytes.HasPrefix(ident, []byte{0x01, 0xF7}):
		arch = "xcoff"
	default:
		return "", errUnrecognizedFormat
	}

	arch = strings.Replace(arch, "EM_", "", 1)
	arch = strings.Replace(arch, "Cpu", "", 1)
	arch = strings.ToLower(arch)

	return arch, nil
}

func getBuildSettings(settings []debug.BuildSetting) map[string]string {
	m := make(map[string]string)
	for _, s := range settings {
		m[s.Key] = s.Value
	}
	return m
}

func buildGoPkgInfo(location source.Location, mod *debug.BuildInfo) []pkg.Package {
	var pkgs []pkg.Package
	if mod == nil {
		return pkgs
	}

	arch := getGOARCH(mod.Settings)
	for _, dep := range mod.Deps {
		if dep == nil {
			continue
		}

		pkgs = append(pkgs, newGoBinaryPackage(dep, mod.GoVersion, arch, location, nil))
	}

	var empty debug.Module
	if mod.Main == empty {
		return pkgs
	}
	gbs := getBuildSettings(mod.Settings)
	main := newGoBinaryPackage(&mod.Main, mod.GoVersion, arch, location, gbs)
	pkgs = append(pkgs, main)

	return pkgs
}
