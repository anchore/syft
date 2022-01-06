package java

import (
	"fmt"
	"io"

	"github.com/anchore/syft/internal/file"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// integrity check
var _ common.ParserFn = parseTarWrappedJavaArchive

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
}

// TODO: when the generic archive cataloger is implemented, this should be removed (https://github.com/anchore/syft/issues/246)

// parseTarWrappedJavaArchive is a parser function for java archive contents contained within arbitrary tar files.
// note: for compressed tars this is an extremely expensive operation and can lead to performance degradation. This is
// due to the fact that there is no central directory header (say as in zip), which means that in order to get
// a file listing within the archive you must decompress the entire archive and seek through all of the entries.
func parseTarWrappedJavaArchive(virtualPath string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	contentPath, archivePath, cleanupFn, err := saveArchiveToTmp(virtualPath, reader)
	// note: even on error, we should always run cleanup functions
	defer cleanupFn()
	if err != nil {
		return nil, nil, err
	}

	// look for java archives within the tar archive
	return discoverPkgsFromTar(virtualPath, archivePath, contentPath)
}

func discoverPkgsFromTar(virtualPath, archivePath, contentPath string) ([]*pkg.Package, []artifact.Relationship, error) {
	openers, err := file.ExtractGlobsFromTarToUniqueTempFile(archivePath, contentPath, archiveFormatGlobs...)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to extract files from tar: %w", err)
	}

	return discoverPkgsFromOpeners(virtualPath, openers, nil)
}
