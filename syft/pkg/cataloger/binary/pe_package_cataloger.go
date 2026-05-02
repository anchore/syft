package binary

import (
	"context"
	"fmt"

	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pe"
)

// NewPEPackageCataloger returns a cataloger that interprets packages from PE
// files. The default extensions covered are .dll, .exe, and .bpl. The latter
// is the Borland Package Library used by Delphi and C++Builder; .bpl files
// are standard Windows PE binaries with a different filename convention
// (issue #4664).
func NewPEPackageCataloger() pkg.Cataloger {
	return generic.NewCataloger("pe-binary-package-cataloger").
		WithParserByGlobs(parsePE, "**/*.dll", "**/*.exe", "**/*.bpl")
}

func parsePE(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	f, err := pe.Read(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse PE file %q: %w", reader.RealPath, err)
	}

	if f == nil {
		return nil, nil, unknown.Newf(reader, "unable to determine packages")
	}

	if f.CLR.HasEvidenceOfCLR() {
		// this is for a .NET application, which is covered by other catalogers already
		return nil, nil, nil
	}

	p := newPEPackage(f.VersionResources, f.Location)

	return []pkg.Package{p}, nil, nil
}
