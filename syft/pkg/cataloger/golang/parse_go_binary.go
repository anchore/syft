package golang

import (
	"bytes"
	"context"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"fmt"
	"io"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/mod/module"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/golang/internal/xcoff"
)

const goArch = "GOARCH"

var (
	// errUnrecognizedFormat is returned when a given executable file doesn't
	// appear to be in a known format, or it breaks the rules of that format,
	// or when there are I/O errors reading the file.
	errUnrecognizedFormat = errors.New("unrecognized file format")
	// devel is used to recognize the current default version when a golang main distribution is built
	// https://github.com/golang/go/issues/29228 this issue has more details on the progress of being able to
	// inject the correct version into the main module of the build process

	knownBuildFlagPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?m)\.([gG]it)?([bB]uild)?[vV]er(sion)?=(\S+/)*(?P<version>v?\d+.\d+.\d+[-\w]*)`),
		regexp.MustCompile(`(?m)\.([tT]ag)=(\S+/)*(?P<version>v?\d+.\d+.\d+[-\w]*)`),
	}
)

const devel = "(devel)"

type goBinaryCataloger struct {
	licenses          goLicenses
	mainModuleVersion MainModuleVersionConfig
}

func newGoBinaryCataloger(opts CatalogerConfig) *goBinaryCataloger {
	return &goBinaryCataloger{
		licenses:          newGoLicenses(binaryCatalogerName, opts),
		mainModuleVersion: opts.MainModuleVersion,
	}
}

// parseGoBinary catalogs packages found in the "buildinfo" section of a binary built by the go compiler.
func (c *goBinaryCataloger) parseGoBinary(_ context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package

	unionReader, err := unionreader.GetUnionReader(reader.ReadCloser)
	if err != nil {
		return nil, nil, err
	}

	mods := scanFile(unionReader, reader.RealPath)
	internal.CloseAndLogError(reader.ReadCloser, reader.RealPath)

	for _, mod := range mods {
		pkgs = append(pkgs, c.buildGoPkgInfo(resolver, reader.Location, mod, mod.arch, unionReader)...)
	}

	return pkgs, nil, nil
}

func (c *goBinaryCataloger) buildGoPkgInfo(resolver file.Resolver, location file.Location, mod *extendedBuildInfo, arch string, reader io.ReadSeekCloser) []pkg.Package {
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

		gover, experiments := getExperimentsFromVersion(mod.GoVersion)
		p := c.newGoBinaryPackage(
			resolver,
			dep,
			mod.Main.Path,
			gover,
			arch,
			nil,
			mod.cryptoSettings,
			experiments,
			location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)
		if pkg.IsValid(&p) {
			pkgs = append(pkgs, p)
		}
	}

	if mod.Main == empty {
		return pkgs
	}

	main := c.makeGoMainPackage(resolver, mod, arch, location, reader)
	pkgs = append(pkgs, main)

	return pkgs
}

func (c *goBinaryCataloger) makeGoMainPackage(resolver file.Resolver, mod *extendedBuildInfo, arch string, location file.Location, reader io.ReadSeekCloser) pkg.Package {
	gbs := getBuildSettings(mod.Settings)
	gover, experiments := getExperimentsFromVersion(mod.GoVersion)
	main := c.newGoBinaryPackage(
		resolver,
		&mod.Main,
		mod.Main.Path,
		gover,
		arch,
		gbs,
		mod.cryptoSettings,
		experiments,
		location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
	)

	if main.Version != devel {
		// found a full package with a non-development version... return it as is...
		return main
	}

	// we have a package, but the version is "devel"... let's try and find a better answer
	var metadata *pkg.GolangBinaryBuildinfoEntry
	if v, ok := main.Metadata.(pkg.GolangBinaryBuildinfoEntry); ok {
		metadata = &v
	}
	version := c.findMainModuleVersion(metadata, gbs, reader)

	if version != "" {
		main.Version = version
		main.PURL = packageURL(main.Name, main.Version)

		main.SetID()
	}

	return main
}

// this is checking for (.L)? because at least one binary seems to have \xA0L preceding the version string, but for some reason
// this is unable to be matched by the regex here as \x00\xA0L;
// the only thing that seems to work is to just look for version strings following both \x00 and \x00.L for now
var semverPattern = regexp.MustCompile(`\x00(.L)?(?P<version>v?(\d+\.\d+\.\d+[-\w]*[+\w]*))\x00`)

func (c *goBinaryCataloger) findMainModuleVersion(metadata *pkg.GolangBinaryBuildinfoEntry, gbs pkg.KeyValues, reader io.ReadSeekCloser) string {
	vcsVersion, hasVersion := gbs.Get("vcs.revision")
	timestamp, hasTimestamp := gbs.Get("vcs.time")

	var ldflags, majorVersion, fullVersion string
	if c.mainModuleVersion.FromLDFlags && metadata != nil {
		// we've found a specific version from the ldflags! use it as the version.
		// why not combine that with the pseudo version (e.g. v1.2.3-0.20210101000000-abcdef123456)?
		// short answer: we're assuming that if a specific semver was provided in the ldflags that
		// there is a matching vcs tag to match that could be referenced. This assumption could
		// be incorrect in terms of the go.mod contents, but is not incorrect in terms of the logical
		// version of the package.
		ldflags, _ = metadata.BuildSettings.Get("-ldflags")

		majorVersion, fullVersion = extractVersionFromLDFlags(ldflags)
		if fullVersion != "" {
			return fullVersion
		}
	}

	// guess the version from pattern matching in the binary (can result in false positives)
	if c.mainModuleVersion.FromContents {
		_, err := reader.Seek(0, io.SeekStart)
		if err != nil {
			log.WithFields("error", err).Trace("unable to seek to start of go binary reader")
		} else {
			if v := extractVersionFromContents(reader); v != "" {
				return v
			}
		}
	}

	// fallback to using the go standard pseudo v0.0.0 version
	if c.mainModuleVersion.FromBuildSettings && hasVersion && hasTimestamp {
		version := vcsVersion
		//NOTE: err is ignored, because if parsing fails
		// we still use the empty Time{} struct to generate an empty date, like 00010101000000
		// for consistency with the pseudo-version format: https://go.dev/ref/mod#pseudo-versions
		ts, _ := time.Parse(time.RFC3339, timestamp)
		if len(vcsVersion) >= 12 {
			version = vcsVersion[:12]
		}

		return module.PseudoVersion(majorVersion, fullVersion, ts, version)
	}

	return ""
}

func extractVersionFromContents(reader io.Reader) string {
	contents, err := io.ReadAll(reader)
	if err != nil {
		log.WithFields("error", err).Trace("unable to read from go binary reader")
		return ""
	}
	matchMetadata := internal.MatchNamedCaptureGroups(semverPattern, string(contents))

	version, ok := matchMetadata["version"]
	if ok {
		return version
	}
	return ""
}

func extractVersionFromLDFlags(ldflags string) (majorVersion string, fullVersion string) {
	if ldflags == "" {
		return "", ""
	}

	for _, pattern := range knownBuildFlagPatterns {
		groups := internal.MatchNamedCaptureGroups(pattern, ldflags)
		v, ok := groups["version"]

		if !ok {
			continue
		}

		fullVersion = v
		if !strings.HasPrefix(v, "v") {
			fullVersion = fmt.Sprintf("v%s", v)
		}
		components := strings.Split(v, ".")

		if len(components) == 0 {
			continue
		}

		majorVersion = strings.TrimPrefix(components[0], "v")
		return majorVersion, fullVersion
	}

	return "", ""
}

func getGOARCH(settings []debug.BuildSetting) string {
	for _, s := range settings {
		if s.Key == goArch {
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

func getBuildSettings(settings []debug.BuildSetting) pkg.KeyValues {
	m := make(pkg.KeyValues, 0)
	for _, s := range settings {
		m = append(m, pkg.KeyValue{
			Key:   s.Key,
			Value: s.Value,
		})
	}
	return m
}

func getExperimentsFromVersion(version string) (string, []string) {
	// See: https://github.com/anchore/grype/issues/1851
	var experiments []string
	version, rest, ok := strings.Cut(version, " ")
	if ok {
		// Assume they may add more non-version chunks in the future, so only look for "X:".
		for _, chunk := range strings.Split(rest, " ") {
			if strings.HasPrefix(rest, "X:") {
				csv := strings.TrimPrefix(chunk, "X:")
				experiments = append(experiments, strings.Split(csv, ",")...)
			}
		}
	}

	return version, experiments
}

func createMainModuleFromPath(path string) (mod debug.Module) {
	mod.Path = path
	mod.Version = devel
	return
}
