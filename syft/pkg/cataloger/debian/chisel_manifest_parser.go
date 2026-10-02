package debian

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	"github.com/canonical/chisel-manifest/public/manifest"
	"github.com/mholt/archives"

	"github.com/anchore/syft/internal"
	intfile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const (
	// chiselCopyrightSlice is the conventional name of the slice that installs a package's copyright file
	chiselCopyrightSlice = "copyright"

	// copyrightName is the conventional file name of a debian copyright file
	copyrightName = "copyright"
)

// parseChiselManifest reads a chisel manifest file (e.g. /var/lib/chisel/manifest.wall) from a chiselled
// rootfs and returns the packages found, mapping the chisel manifest fields onto the same pkg.DpkgDBEntry
// metadata that the dpkg status DB parser produces.
func parseChiselManifest(ctx context.Context, resolver file.Resolver, env *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	contentReader, err := chiselManifestReader(ctx, reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read chisel manifest=%q: %w", reader.RealPath, err)
	}
	defer internal.CloseAndLogError(contentReader, reader.RealPath)

	m, err := manifest.Read(contentReader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse chisel manifest=%q: %w", reader.RealPath, err)
	}

	entriesByPackage, err := chiselEntriesByPackage(m)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read paths from chisel manifest=%q: %w", reader.RealPath, err)
	}

	dbLoc := reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)

	var pkgs []pkg.Package
	err = m.IteratePackages(func(p *manifest.Package) error {
		entry := entriesByPackage[p.Name]
		if entry == nil {
			log.WithFields("name", p.Name).Trace("unable to find entry for manifest package")
			return nil
		}
		pkgs = append(pkgs, newChiselPackage(ctx, *p, entry, dbLoc, resolver, env))
		return nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("unable to read packages from chisel manifest=%q: %w", reader.RealPath, err)
	}

	return pkgs, nil, unknown.IfEmptyf(pkgs, "unable to determine packages")
}

// chiselManifestReader returns a reader of the raw jsonwall content: chisel writes the manifest
// zstd-compressed, but tolerate uncompressed content (or other compression methods) by detecting
// the format from the content itself.
func chiselManifestReader(ctx context.Context, reader file.LocationReadCloser) (io.ReadCloser, error) {
	unionReader, err := unionreader.GetUnionReader(reader)
	if err != nil {
		return nil, err
	}

	format, stream, err := intfile.IdentifyArchive(ctx, reader.RealPath, unionReader)
	if err != nil && !errors.Is(err, archives.NoMatch) {
		return nil, err
	}

	if decompressor, ok := format.(archives.Decompressor); ok {
		return decompressor.OpenReader(stream)
	}

	// no compression detected, so treat as plain content: rewind past whatever identification read
	// and let the manifest parser report any content errors
	if _, err := unionReader.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("unable to seek to start of chisel manifest: %w", err)
	}
	return unionReader, nil
}

// chiselPackageEntries holds the manifest path data attributed to a single package.
type chiselPackageEntries struct {
	// files are the file listing entries owned by the package
	files []pkg.DpkgFileRecord

	// copyrights are the copyright file locations to search: explicit file paths or "<directory>/*" globs
	copyrights []string
}

// chiselEntriesByPackage attributes each path entry in the manifest to the owning package(s) by way of
// the slice references on the path, where slice names take the "<package>_<slice>" form. Each package's
// entries hold both its file listing and the copyright file locations recorded by its copyright slice.
func chiselEntriesByPackage(m *manifest.Manifest) (map[string]*chiselPackageEntries, error) {
	byPackage := make(map[string]*chiselPackageEntries)

	err := m.IteratePaths("", func(p *manifest.Path) error {
		// directory entries end with "/"; they are excluded from file listings to emulate the
		// dpkg md5sums file listing, but may still hold a package's copyright files
		isDirectory := strings.HasSuffix(p.Path, "/")

		for _, slice := range p.Slices {
			pkgName, sliceName, _ := strings.Cut(slice, "_")
			if pkgName == "" {
				continue
			}

			entries := byPackage[pkgName]
			if entries == nil {
				entries = &chiselPackageEntries{}
				byPackage[pkgName] = entries
			}

			if sliceName == chiselCopyrightSlice {
				entries.addCopyright(p.Path)
			}
			if !isDirectory {
				entries.addFile(p)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return byPackage, nil
}

// addCopyright records the location to search for a copyright file: either the explicit copyright file
// path, or a glob searching the directory contents.
func (e *chiselPackageEntries) addCopyright(p string) {
	if !strings.HasSuffix(p, "/"+copyrightName) {
		// this is a directory rather than an explicit copyright file, e.g. a symlinked doc directory
		// such as /usr/share/doc/libbinutils -> binutils-common: record a glob to search all files
		// within the directory
		p = path.Join(p, "*")
	}
	if !slices.Contains(e.copyrights, p) {
		e.copyrights = append(e.copyrights, p)
	}
}

// addFile records a file listing entry for a manifest path. A path may be owned by multiple slices of
// the same package; any prior append with the same path is necessarily the last record, so checking it
// suffices to deduplicate.
func (e *chiselPackageEntries) addFile(p *manifest.Path) {
	if len(e.files) > 0 && e.files[len(e.files)-1].Path == p.Path {
		return
	}

	record := pkg.DpkgFileRecord{Path: p.Path}

	// a path that was mutated after installation records the resulting digest as final_sha256
	digest := p.SHA256
	if p.FinalSHA256 != "" {
		digest = p.FinalSHA256
	}
	if digest != "" {
		record.Digest = &file.Digest{
			Algorithm: "sha256",
			Value:     digest,
		}
	}

	e.files = append(e.files, record)
}

// addChiselLicenses attempts license discovery from the copyright file paths recorded in the manifest,
// returning whether any licenses were found.
func addChiselLicenses(ctx context.Context, resolver file.Resolver, dbLocation file.Location, copyrightPaths []string, p *pkg.Package) bool {
	found := false
	for _, copyrightPath := range copyrightPaths {
		if addChiselCopyrightLicenses(ctx, resolver, dbLocation, copyrightPath, p) {
			found = true
		}
	}
	return found
}

// addChiselCopyrightLicenses attempts license discovery from a single copyright candidate: either an
// explicit copyright file path or a "<directory>/*" glob for copyright slices that install a directory.
// Returns whether any licenses were found.
func addChiselCopyrightLicenses(ctx context.Context, resolver file.Resolver, dbLocation file.Location, copyrightPath string, p *pkg.Package) bool {
	if strings.HasSuffix(copyrightPath, "/*") {
		locations, err := resolver.FilesByGlob(copyrightPath)
		if err != nil {
			log.WithFields("error", err, "pkg", p.Name, "glob", copyrightPath).Trace("failed to glob chisel copyright files")
			return false
		}
		found := false
		for _, location := range locations {
			if addCopyrightLicensesFromLocation(ctx, resolver, location, p) {
				found = true
			}
		}
		return found
	}

	location := resolver.RelativeFileByPath(dbLocation, copyrightPath)
	if location == nil {
		return false
	}
	return addCopyrightLicensesFromLocation(ctx, resolver, *location, p)
}

// addCopyrightLicensesFromLocation parses the file at the given location as a debian copyright file,
// returning whether any licenses were found.
func addCopyrightLicensesFromLocation(ctx context.Context, resolver file.Resolver, location file.Location, p *pkg.Package) bool {
	reader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		log.WithFields("error", err, "pkg", p.Name, "path", location.RealPath).Trace("failed to fetch chisel copyright contents")
		return false
	}
	defer internal.CloseAndLogError(reader, location.AccessPath)

	licenseStrs := parseLicensesFromCopyright(reader)
	if len(licenseStrs) == 0 {
		return false
	}

	for _, licenseStr := range licenseStrs {
		p.Licenses.Add(pkg.NewLicenseFromLocationsWithContext(ctx, licenseStr, location.WithoutAnnotations()))
	}
	// keep a record of the file where this was discovered
	p.Locations.Add(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))
	return true
}

// newChiselPackage maps a chisel manifest package and its attributed entries onto a pkg.Package with
// the same pkg.DpkgDBEntry metadata shape that the dpkg status DB parser produces.
func newChiselPackage(ctx context.Context, cp manifest.Package, entries *chiselPackageEntries, dbLocation file.Location, resolver file.Resolver, env *generic.Environment) pkg.Package {
	if entries == nil {
		entries = &chiselPackageEntries{}
	}

	files := entries.files
	if files == nil {
		// ensure the default value for a collection is never nil since this may be shown as JSON
		files = make([]pkg.DpkgFileRecord, 0)
	} else {
		slices.SortFunc(files, func(a, b pkg.DpkgFileRecord) int {
			return strings.Compare(a.Path, b.Path)
		})
	}

	entry := pkg.DpkgDBEntry{
		Package:      cp.Name,
		Version:      cp.Version,
		Architecture: cp.Arch,
		Files:        files,
	}

	p := pkg.Package{
		Name:      entry.Package,
		Version:   entry.Version,
		Locations: file.NewLocationSet(dbLocation),
		PURL:      packageURL(entry, env.LinuxRelease),
		Type:      pkg.DebPkg,
		Metadata:  entry,
	}

	if resolver != nil {
		// prefer the copyright file locations recorded in the manifest itself (paths owned by the
		// package's copyright slice), falling back to the same conventional /usr/share/doc/<pkg>/copyright
		// discovery performed for dpkg status DB entries
		if !addChiselLicenses(ctx, resolver, dbLocation, entries.copyrights, &p) {
			addLicenses(ctx, resolver, dbLocation, &p)
		}
	}

	p.SetID()

	return p
}
