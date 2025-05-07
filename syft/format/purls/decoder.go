package purls

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/internal"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

var _ sbom.FormatDecoder = (*decoder)(nil)

type decoder struct{}

type PURLLiteralMetadata struct {
	PURL string
}

type PURLFileMetadata struct {
	Path string
}

func NewFormatDecoder() sbom.FormatDecoder {
	return decoder{}
}

func (d decoder) Decode(r io.Reader) (*sbom.SBOM, sbom.FormatID, string, error) {
	if r == nil {
		return nil, "", "", fmt.Errorf("no reader provided")
	}
	s, err := toSyftModel(r)
	return s, ID, version, err
}

func (d decoder) Identify(r io.Reader) (sbom.FormatID, string) {
	if r == nil {
		return "", ""
	}

	buf := [4]byte{}
	bufs := buf[:]
	_, _ = r.Read(bufs)
	if string(bufs) == "pkg:" {
		return ID, version
	}
	return "", ""
}

func toSyftModel(r io.Reader) (*sbom.SBOM, error) {
	var errs []error
	pkgs := pkg.NewCollection()

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			continue
		}

		// skip invalid PURLs
		_, err := packageurl.FromString(line)
		if err != nil {
			log.WithFields("error", err, "line", line).Debug("unable to parse purl")
			continue
		}
		p := pkg.Package{
			// name, version and other properties set during Backfill
			PURL: line,
		}

		internal.Backfill(&p)
		p.SetID()
		pkgs.Add(p)
	}

	return &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages:     pkgs,
			FileMetadata: map[file.Coordinates]file.Metadata{},
			FileDigests:  map[file.Coordinates][]file.Digest{},
			FileContents: map[file.Coordinates]string{},
			FileLicenses: map[file.Coordinates][]file.License{},
			Executables:  map[file.Coordinates]file.Executable{},
		},
		Source:     source.Description{},
		Descriptor: sbom.Descriptor{},
	}, errors.Join(errs...)
}
