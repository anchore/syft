package java

import (
	"context"
	"fmt"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal"
	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

// archiveEntries is where an archive parser reads a java archive's entries from.
//
// The parser needs three things of an archive and nothing else: which entries match a glob, the
// contents of some of them, and the digest of the archive as a whole. Everything else it does -
// which manifest wins, how pom.properties decides identity, license discovery - is logic over those
// answers. Naming the three makes them replaceable, which is what lets the same logic run over an
// archive file and over an archive that has already been extracted to a filesystem.
//
// Entry names are archive-relative with no leading slash, matching zip entry names, because they
// become map keys and pom paths that identity is derived from. An implementation over a filesystem
// has to strip the root to match.
type archiveEntries interface {
	// glob returns the names of the entries matching any of the patterns.
	glob(caseInsensitive bool, patterns ...string) []string

	// contents reads the named entries, returning a map keyed by the same names.
	contents(ctx context.Context, names ...string) (map[string]string, error)

	// digests returns the digests of the archive as a whole, which is a property of the archive file
	// rather than of anything inside it.
	digests(ctx context.Context) ([]file.Digest, error)
}

// zipEntries reads entries out of a java archive on disk. This is the original source, kept for
// scans where nothing has extracted the archive: it copies the archive to a temp file, reads its
// central directory once, and opens it again for each set of entries it is asked for.
type zipEntries struct {
	archivePath  string
	fileManifest intFile.ZipFileManifest
}

func newZipEntries(ctx context.Context, archivePath string) (*zipEntries, error) {
	fileManifest, err := intFile.NewZipFileManifest(ctx, archivePath)
	if err != nil {
		return nil, fmt.Errorf("unable to read files from java archive: %w", err)
	}
	return &zipEntries{archivePath: archivePath, fileManifest: fileManifest}, nil
}

func (z *zipEntries) glob(caseInsensitive bool, patterns ...string) []string {
	return z.fileManifest.GlobMatch(caseInsensitive, patterns...)
}

func (z *zipEntries) contents(ctx context.Context, names ...string) (map[string]string, error) {
	return intFile.ContentsFromZip(ctx, z.archivePath, names...)
}

func (z *zipEntries) digests(ctx context.Context) ([]file.Digest, error) {
	return getDigestsFromArchive(ctx, z.archivePath)
}

// resolverEntries reads entries out of an archive that has already been extracted and indexed - the
// filesystem the archive cataloger task builds for every archive it enters.
//
// Nothing is copied and nothing is re-opened: the entries are files in an indexed resolver, and the
// archive's own digests were taken by whoever extracted it, since the archive file itself is not
// present in its own contents.
type resolverEntries struct {
	resolver        file.Resolver
	archiveDigests  []file.Digest
	locationsByName map[string]file.Location
}

func newResolverEntries(resolver file.Resolver, archiveDigests []file.Digest) *resolverEntries {
	return &resolverEntries{
		resolver:        resolver,
		archiveDigests:  archiveDigests,
		locationsByName: make(map[string]file.Location),
	}
}

func (r *resolverEntries) glob(caseInsensitive bool, patterns ...string) []string {
	if caseInsensitive {
		return r.globCaseInsensitive(patterns...)
	}

	// deduplicated within this call and not across calls: the parser globs the same pattern more than
	// once (identity resolution asks for the poms, and so does aux package discovery), and a source
	// that remembered what it had already returned would hand back nothing the second time. That
	// silently cost every package derived from a bundled pom.properties.
	seen := strset.New()
	var names []string
	for _, pattern := range patterns {
		locations, err := r.resolver.FilesByGlob(pattern)
		if err != nil {
			log.WithFields("pattern", pattern, "error", err).Trace("unable to glob archive contents")
			continue
		}
		for _, location := range locations {
			name := strings.TrimPrefix(location.Path(), "/")
			r.locationsByName[name] = location
			if seen.Has(name) {
				continue
			}
			seen.Add(name)
			names = append(names, name)
		}
	}
	return names
}

// globCaseInsensitive matches the way the zip-backed source does, by lowercasing both sides. The
// resolver's own glob is case sensitive, so this lists the archive's files once and matches them
// here. License discovery is the only caller that asks, and what it costs is one listing of a
// filesystem holding one archive's entries.
func (r *resolverEntries) globCaseInsensitive(patterns ...string) []string {
	all, err := r.resolver.FilesByGlob("**/*")
	if err != nil {
		log.WithFields("error", err).Trace("unable to list archive contents")
		return nil
	}
	seen := strset.New()
	var names []string
	for _, pattern := range patterns {
		lowered := strings.ToLower(pattern)
		for _, location := range all {
			// matched with a leading slash, the way the zip-backed source normalizes an entry before
			// matching, because the patterns are written that way ("/META-INF/*"). An extracted
			// archive's resolver reports paths without one - they are entry names, not absolute paths -
			// so matching them raw silently matches nothing, which cost the license found in every
			// jar that carries one as a file.
			name := strings.TrimPrefix(location.Path(), "/")
			if ok, matchErr := doublestar.Match(lowered, "/"+strings.ToLower(name)); matchErr != nil || !ok {
				continue
			}
			r.locationsByName[name] = location
			if seen.Has(name) {
				continue
			}
			seen.Add(name)
			names = append(names, name)
		}
	}
	return names
}

func (r *resolverEntries) contents(_ context.Context, names ...string) (map[string]string, error) {
	out := make(map[string]string, len(names))
	for _, name := range names {
		location, ok := r.locationsByName[name]
		if !ok {
			// only names this source handed out can be read back; a name from anywhere else is a bug
			// rather than a missing file
			return nil, fmt.Errorf("entry %q was not found by any glob against this archive", name)
		}
		contents, err := r.read(location)
		if err != nil {
			return nil, fmt.Errorf("unable to read archive entry %q: %w", name, err)
		}
		out[name] = contents
	}
	return out, nil
}

func (r *resolverEntries) digests(_ context.Context) ([]file.Digest, error) {
	return r.archiveDigests, nil
}

// read reads one entry's content to the end and closes the stream. The parser wants entry contents as
// strings, since every consumer of them parses text.
//
// The copy is bounded the same way the zip-backed source bounds its own: an entry of an extracted
// archive is still attacker-supplied content, and reading it into a string is exactly the allocation
// a decompression bomb is aiming at.
func (r *resolverEntries) read(location file.Location) (string, error) {
	reader, err := r.resolver.FileContentsByLocation(location)
	if err != nil {
		return "", err
	}
	defer internal.CloseAndLogError(reader, location.RealPath)

	var contents strings.Builder
	if err := intFile.SafeCopy(&contents, reader); err != nil {
		return "", err
	}
	return contents.String(), nil
}
