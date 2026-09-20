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
// A parser needs three things of an archive: which entries match a glob, the contents of some of
// them, and the digest of the archive as a whole. Everything else - which manifest wins, how
// pom.properties decides identity, license discovery - is logic over those answers, so naming the
// three lets the same logic run over an archive file and over one already extracted to a filesystem.
//
// Entry names are archive-relative with no leading slash, matching zip entry names, since they become
// the map keys and pom paths identity is derived from. An implementation over a filesystem must strip
// the root to match.
type archiveEntries interface {
	glob(caseInsensitive bool, patterns ...string) []string

	// contents reads the named entries, returning a map keyed by the same names.
	contents(ctx context.Context, names ...string) (map[string]string, error)

	// digests returns the digests of the archive as a whole, a property of the archive file rather
	// than of anything inside it.
	digests(ctx context.Context) ([]file.Digest, error)
}

// zipEntries reads entries out of a java archive on disk, for scans where nothing has already
// extracted it. It copies the archive to a temp file, reads its central directory once, and reopens
// it for each set of entries it is asked for.
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

// resolverEntries reads entries out of an archive already extracted and indexed by the archive
// cataloger task. Nothing is copied or reopened. The archive's own digests come from whoever
// extracted it, since the archive file is not present in its own contents.
type resolverEntries struct {
	resolver       file.Resolver
	archiveDigests []file.Digest
}

func newResolverEntries(resolver file.Resolver, archiveDigests []file.Digest) *resolverEntries {
	return &resolverEntries{
		resolver:       resolver,
		archiveDigests: archiveDigests,
	}
}

func (r *resolverEntries) glob(caseInsensitive bool, patterns ...string) []string {
	if caseInsensitive {
		return r.globCaseInsensitive(patterns...)
	}

	// deduplicated within this call only: the parser globs the same pattern more than once (identity
	// resolution and aux package discovery both ask for the poms), so remembering across calls would
	// return nothing the second time and lose every package derived from a bundled pom.properties
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
			if seen.Has(name) {
				continue
			}
			seen.Add(name)
			names = append(names, name)
		}
	}
	return names
}

// globCaseInsensitive matches the way zipEntries does, by lowercasing both sides. The resolver's own
// glob is case sensitive, so this lists the archive's files once and matches them here. License
// discovery is the only caller.
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
			// matched with a leading slash, since the patterns are written that way ("/META-INF/*") and
			// zipEntries normalizes the same way; an extracted archive's resolver reports names without
			// one, so matching raw would match nothing
			name := strings.TrimPrefix(location.Path(), "/")
			if ok, matchErr := doublestar.Match(lowered, "/"+strings.ToLower(name)); matchErr != nil || !ok {
				continue
			}
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
		locations, err := r.resolver.FilesByPath(name)
		if err != nil {
			return nil, fmt.Errorf("unable to look up archive entry %q: %w", name, err)
		}
		if len(locations) == 0 {
			return nil, fmt.Errorf("entry %q is not in this archive", name)
		}
		contents, err := r.read(locations[0])
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

// read reads one entry's content to the end and closes the stream, returning a string because every
// consumer parses text.
//
// The copy is bounded the way zipEntries bounds its own: an entry of an extracted archive is still
// attacker-supplied, and reading it into a string is the allocation a decompression bomb targets.
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
