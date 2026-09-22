package java

import (
	"context"
	"fmt"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal"
	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

// archiveEntries is where the archive parser reads a java archive's entries from, so the same parser
// runs over an archive file and over an archive already extracted to a filesystem. Entry names are
// archive-relative with no leading slash, as zip entry names are.
type archiveEntries interface {
	// glob returns the entries matching any pattern. Patterns are written against a leading slash
	// ("/META-INF/*"); the names returned have none.
	glob(patterns ...string) []string

	// contents reads the named entries, keyed by the same names.
	contents(ctx context.Context, names ...string) (map[string]string, error)
}

// zipEntries reads entries out of a java archive file on disk.
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

func (z *zipEntries) glob(patterns ...string) []string {
	return z.fileManifest.GlobMatch(patterns...)
}

func (z *zipEntries) contents(ctx context.Context, names ...string) (map[string]string, error) {
	return intFile.ContentsFromZip(ctx, z.archivePath, names...)
}

// resolverEntries reads entries out of an archive the archive cataloger task has extracted.
type resolverEntries struct {
	resolver file.Resolver
}

func (r *resolverEntries) glob(patterns ...string) []string {
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

// read returns one entry's content, bounded against decompression bombs as zipEntries bounds its own.
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
