package java

import (
	"context"
	"fmt"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var genericTarGlobs = []string{
	"**/*.tar",
	// gzipped tar
	"**/*.tar.gz",
	"**/*.tgz",
	// bzip2
	"**/*.tar.bz",
	"**/*.tar.bz2",
	"**/*.tbz",
	"**/*.tbz2",
	// brotli
	"**/*.tar.br",
	"**/*.tbr",
	// lz4
	"**/*.tar.lz4",
	"**/*.tlz4",
	// sz
	"**/*.tar.sz",
	"**/*.tsz",
	// xz
	"**/*.tar.xz",
	"**/*.txz",
	// zst
	"**/*.tar.zst",
	"**/*.tzst",
	"**/*.tar.zstd",
	"**/*.tzstd",
}

// TODO: when the generic archive cataloger is implemented, this should be removed (https://github.com/anchore/syft/issues/246)

// parseTarWrappedJavaArchive is a parser function for java archive contents contained within arbitrary tar files.
// note: for compressed tars this is an extremely expensive operation and can lead to performance degradation. This is
// due to the fact that there is no central directory header (say as in zip), which means that in order to get
// a file listing within the archive you must decompress the entire archive and seek through all of the entries.

type genericTarWrappedJavaArchiveParser struct {
	cfg ArchiveCatalogerConfig
}

func newGenericTarWrappedJavaArchiveParser(cfg ArchiveCatalogerConfig) genericTarWrappedJavaArchiveParser {
	return genericTarWrappedJavaArchiveParser{
		cfg: cfg,
	}
}

func (gtp genericTarWrappedJavaArchiveParser) parseTarWrappedJavaArchive(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	contentPath, archivePath, cleanupFn, err := saveArchiveToTmp(reader.Path(), reader)
	// note: even on error, we should always run cleanup functions
	defer cleanupFn()
	if err != nil {
		return nil, nil, err
	}

	// look for java archives within the tar archive
	return discoverPkgsFromTar(ctx, reader.Location, archivePath, contentPath, gtp.cfg)
}

func discoverPkgsFromTar(ctx context.Context, location file.Location, archivePath, contentPath string, cfg ArchiveCatalogerConfig) ([]pkg.Package, []artifact.Relationship, error) {
	openers, err := intFile.ExtractGlobsFromTarToUniqueTempFile(ctx, archivePath, contentPath, archiveFormatGlobs...)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to extract files from tar: %w", err)
	}

	return discoverPkgsFromOpeners(ctx, location, openers, nil, cfg)
}
