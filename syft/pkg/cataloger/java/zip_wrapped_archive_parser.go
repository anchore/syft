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

var genericZipGlobs = []string{
	"**/*.zip",
}

// TODO: when the generic archive cataloger is implemented, this should be removed (https://github.com/anchore/syft/issues/246)

// parseZipWrappedJavaArchive is a parser function for java archive contents contained within arbitrary zip files.

type genericZipWrappedJavaArchiveParser struct {
	cfg ArchiveCatalogerConfig
}

func newGenericZipWrappedJavaArchiveParser(cfg ArchiveCatalogerConfig) genericZipWrappedJavaArchiveParser {
	return genericZipWrappedJavaArchiveParser{
		cfg: cfg,
	}
}

func (gzp genericZipWrappedJavaArchiveParser) parseZipWrappedJavaArchive(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	contentPath, archivePath, cleanupFn, err := saveArchiveToTmp(reader.Path(), reader)
	// note: even on error, we should always run cleanup functions
	defer cleanupFn()
	if err != nil {
		return nil, nil, err
	}

	// we use our zip helper functions instead of that from the archiver package or the standard lib. Why? These helper
	// functions support zips with shell scripts prepended to the file. Specifically, the helpers use the central
	// header at the end of the file to determine where the beginning of the zip payload is (unlike the standard lib
	// or archiver).
	fileManifest, err := intFile.NewZipFileManifest(ctx, archivePath)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read files from java archive: %w", err)
	}

	// look for java archives within the zip archive
	return discoverPkgsFromZip(ctx, reader.Location, archivePath, contentPath, fileManifest, nil, gzp.cfg)
}
