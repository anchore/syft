package licenses

import (
	"context"
	"path"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// RelativeToPackage searches for licenses in the same directory as primary evidence locations
// on the package and returns the package with licenses set and ID reset if the package has no licenses already
func RelativeToPackage(ctx context.Context, resolver file.Resolver, p pkg.Package) pkg.Package {
	// if licenses were already found, don't search for more
	if !p.Licenses.Empty() {
		return p
	}
	var out []pkg.License
	for _, l := range p.Locations.ToUnorderedSlice() {
		if evidenceType, ok := l.Annotations[pkg.EvidenceAnnotationKey]; ok && evidenceType != pkg.PrimaryEvidenceAnnotation {
			continue
		}
		// search for license files relative to any primary evidence on the package
		out = append(out, FindRelativeToLocations(ctx, resolver, l)...)
	}
	if len(out) > 0 {
		p.Licenses = pkg.NewLicenseSet(out...)
		p.SetID()
	}
	return p
}

// FindAtLocations creates License objects by reading license files directly the provided locations
func FindAtLocations(ctx context.Context, resolver file.Resolver, locations ...file.Location) []pkg.License {
	var out []pkg.License
	for _, loc := range locations {
		out = append(out, readFromResolver(ctx, resolver, loc)...)
	}
	return out
}

// FindAtPaths creates License objects by reading license files directly at the provided paths
func FindAtPaths(ctx context.Context, resolver file.Resolver, paths ...string) []pkg.License {
	var out []pkg.License
	for _, p := range paths {
		locs, err := resolver.FilesByPath(p)
		if err != nil {
			log.WithFields("error", err, "path", p).Trace("unable to resolve license path")
			continue
		}
		for _, loc := range locs {
			out = append(out, readFromResolver(ctx, resolver, loc)...)
		}
	}
	return out
}

// FindInDirs creates License objects by searching for known license files in the provided directories
func FindInDirs(ctx context.Context, resolver file.Resolver, dirs ...string) []pkg.License {
	var out []pkg.License
	for _, dir := range dirs {
		glob := path.Join(dir, "*") // only search in the directory
		out = append(out, FindByGlob(ctx, resolver, glob)...)
	}
	return out
}

// FindRelativeToLocations creates License objects by searching for known license files relative to the provided locations, in the same directory path
func FindRelativeToLocations(ctx context.Context, resolver file.Resolver, locations ...file.Location) []pkg.License {
	var out []pkg.License
	for _, location := range locations {
		dir := path.Dir(location.AccessPath)
		out = append(out, FindInDirs(ctx, resolver, dir)...)
	}
	return out
}

// FindByGlob creates License objects by searching for license files with the provided glob.
// only file names which match licenses.LowerFileNames() case-insensitive will be included,
// so a recursive glob search such as: `<path>/**/*` will only attempt to read LICENSE files it finds, for example
func FindByGlob(ctx context.Context, resolver file.Resolver, glob string) []pkg.License {
	locs, err := resolver.FilesByGlob(glob)
	if err != nil {
		log.WithFields("glob", glob, "error", err).Debug("error searching for license files")
		return nil
	}
	var out []pkg.License
	for _, l := range locs {
		fileName := path.Base(l.Path())
		if IsLicenseFile(fileName) {
			out = append(out, readFromResolver(ctx, resolver, l)...)
		}
	}
	return out
}

func NewFromValues(ctx context.Context, locations []file.Location, values ...string) []pkg.License {
	if len(locations) == 0 {
		return pkg.NewLicensesFromValuesWithContext(ctx, values...)
	}

	var out []pkg.License
	for _, value := range values {
		if value == "" {
			continue
		}
		out = append(out, pkg.NewLicenseFromLocationsWithContext(ctx, value, locations...))
	}

	return out
}

func readFromResolver(ctx context.Context, resolver file.Resolver, location file.Location) []pkg.License {
	metadataContents, err := resolver.FileContentsByLocation(location)
	if err != nil || metadataContents == nil {
		log.WithFields("error", err, "path", location.Path()).Trace("unable to license file contents")
		return nil
	}
	defer internal.CloseAndLogError(metadataContents, location.Path())
	return pkg.NewLicensesFromReadCloserWithContext(ctx, file.NewLocationReadCloser(location, metadataContents))
}
