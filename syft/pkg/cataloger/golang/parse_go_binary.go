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
	"time"

	"golang.org/x/mod/module"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/golang/internal/xcoff"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/unionreader"
	"github.com/anchore/syft/syft/source"
)

const GOARCH = "GOARCH"

var (
	// errUnrecognizedFormat is returned when a given executable file doesn't
	// appear to be in a known format, or it breaks the rules of that format,
	// or when there are I/O errors reading the file.
	errUnrecognizedFormat = errors.New("unrecognized file format")
	// devel is used to recognize the current default version when a golang main distribution is built
	// https://github.com/golang/go/issues/29228 this issue has more details on the progress of being able to
	// inject the correct version into the main module of the build process
)

const devel = "(devel)"

// Catalog is given an object to resolve file references and content, this function returns any discovered Packages after analyzing rpm db installation.
func parseGoBinary(_ source.FileResolver, _ *generic.Environment, reader source.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package

	unionReader, err := unionreader.GetUnionReader(reader.ReadCloser)
	if err != nil {
		return nil, nil, err
	}

	mods, archs := scanFile(unionReader, reader.RealPath)
	internal.CloseAndLogError(reader.ReadCloser, reader.RealPath)

	for i, mod := range mods {
		log.Info(mod.Path)
		pkgs = append(pkgs, buildGoPkgInfo(reader.Location, mod, archs[i])...)
	}
	return pkgs, nil, nil
}

func makeGoMainPackage(mod *debug.BuildInfo, arch string, location source.Location) pkg.Package {
	gbs := getBuildSettings(mod.Settings)
	main := newGoBinaryPackage(&mod.Main, mod.Main.Path, mod.GoVersion, arch, gbs, location)
	if main.Version == devel {
		if version, ok := gbs["vcs.revision"]; ok {
			if timestamp, ok := gbs["vcs.time"]; ok {
				//NOTE: err is ignored, because if parsing fails
				// we still use the empty Time{} struct to generate an empty date, like 00010101000000
				// for consistency with the pseudo-version format: https://go.dev/ref/mod#pseudo-versions
				ts, _ := time.Parse(time.RFC3339, timestamp)
				if len(version) >= 12 {
					version = version[:12]
				}
				version = module.PseudoVersion("", "", ts, version)
			}
			main.Version = version
			main.PURL = packageURL(main.Name, main.Version)
			main.SetID()
		}
	}

	return main
}

// getArchs finds a binary architecture by two ways:
// 1) reading build info from binaries compiled by go1.18+
// 2) reading file headers from binaries compiled by < go1.18
func getArchs(readers []io.ReaderAt, builds []*debug.BuildInfo) []string {
	if len(readers) != len(builds) {
		log.Trace("golang cataloger: bin parsing: number of builds and readers doesn't match")
		return nil
	}

	if len(readers) == 0 || len(builds) == 0 {
		log.Tracef("golang cataloger: bin parsing: %d readers and %d build info items", len(readers), len(builds))
		return nil
	}

	archs := make([]string, len(builds))
	for i, build := range builds {
		archs[i] = getGOARCH(build.Settings)
	}

	// if architecture was found via build settings return
	if archs[0] != "" {
		return archs
	}

	for i, r := range readers {
		a, err := getGOARCHFromBin(r)
		if err != nil {
			log.Tracef("golang cataloger: bin parsing: getting arch from binary: %v", err)
			continue
		}

		archs[i] = a
	}
	return archs
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
		return "", fmt.Errorf("unrecognized file format: %w", err)
	}

	var arch string
	switch {
	case bytes.HasPrefix(ident, []byte("\x7FELF")):
		f, err := elf.NewFile(r)
		if err != nil {
			return "", fmt.Errorf("unrecognized file format: %w", err)
		}
		arch = f.Machine.String()
	case bytes.HasPrefix(ident, []byte("MZ")):
		f, err := pe.NewFile(r)
		if err != nil {
			return "", fmt.Errorf("unrecognized file format: %w", err)
		}
		arch = fmt.Sprintf("%d", f.Machine)
	case bytes.HasPrefix(ident, []byte("\xFE\xED\xFA")) || bytes.HasPrefix(ident[1:], []byte("\xFA\xED\xFE")):
		f, err := macho.NewFile(r)
		if err != nil {
			return "", fmt.Errorf("unrecognized file format: %w", err)
		}
		arch = f.Cpu.String()
	case bytes.HasPrefix(ident, []byte{0x01, 0xDF}) || bytes.HasPrefix(ident, []byte{0x01, 0xF7}):
		f, err := xcoff.NewFile(r)
		if err != nil {
			return "", fmt.Errorf("unrecognized file format: %w", err)
		}
		arch = fmt.Sprintf("%d", f.FileHeader.TargetMachine)
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

func createMainModuleFromPath(path string) (mod debug.Module) {
	mod.Path = path
	mod.Version = devel
	return
}

func buildGoPkgInfo(location source.Location, mod *debug.BuildInfo, arch string) []pkg.Package {
	var pkgs []pkg.Package
	if mod == nil {
		return pkgs
	}

	var empty debug.Module
	if mod.Main == empty && mod.Path != "" {
		mod.Main = createMainModuleFromPath(mod.Path)
	}

	for _, dep := range mod.Deps {
		if dep == nil {
			continue
		}
		p := newGoBinaryPackage(dep, mod.Main.Path, mod.GoVersion, arch, nil, location)
		if pkg.IsValid(&p) {
			pkgs = append(pkgs, p)
		}
	}

	if mod.Main == empty {
		return pkgs
	}

	main := makeGoMainPackage(mod, arch, location)
	pkgs = append(pkgs, main)

	return pkgs
}
