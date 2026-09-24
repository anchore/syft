package freebsd

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/mholt/archives"

	"github.com/anchore/syft/internal"
	intfile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const pkgManifestEntryName = "+MANIFEST"

// pkgManifest models the subset of fields captured within a FreeBSD pkgng package archive's "+MANIFEST" file
// that are relevant for building package metadata.
type pkgManifest struct {
	Name           string                     `json:"name"`
	Origin         string                     `json:"origin"`
	Version        string                     `json:"version"`
	Comment        string                     `json:"comment"`
	Description    string                     `json:"desc"`
	WWW            string                     `json:"www"`
	Maintainer     string                     `json:"maintainer"`
	Abi            string                     `json:"abi"`
	Arch           string                     `json:"arch"`
	Prefix         string                     `json:"prefix"`
	FlatSize       int64                      `json:"flatsize"`
	LicenseLogic   string                     `json:"licenselogic"`
	Licenses       []string                   `json:"licenses"`
	Categories     []string                   `json:"categories"`
	ShlibsRequired []string                   `json:"shlibs_required"`
	Annotations    map[string]string          `json:"annotations"`
	Files          map[string]pkgManifestFile `json:"files"`
}

type pkgManifestFile struct {
	Sum   string `json:"sum"`
	UName string `json:"uname"`
	GName string `json:"gname"`
}

// parsePkgArchive parses a FreeBSD pkgng package archive (.pkg) file and returns the package described within
// it. A .pkg file is a tar archive, optionally compressed (xz, zstd, gzip, or bzip2), containing a "+MANIFEST"
// file with package metadata along with the files to be installed.
func parsePkgArchive(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	tarReader, closer, err := openArchiveTar(ctx, reader)
	if err != nil {
		return nil, nil, unknown.New(reader.Location, fmt.Errorf("failed to open FreeBSD pkg archive: %w", err))
	}
	defer closer()

	var manifest *pkgManifest
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, unknown.New(reader.Location, fmt.Errorf("failed to read FreeBSD pkg archive: %w", err))
		}

		if header.Name == pkgManifestEntryName {
			manifest = &pkgManifest{}
			if err := json.NewDecoder(tarReader).Decode(manifest); err != nil {
				return nil, nil, unknown.New(reader.Location, fmt.Errorf("failed to parse %s: %w", pkgManifestEntryName, err))
			}
			break
		}
	}

	if manifest == nil {
		return nil, nil, unknown.New(reader.Location, fmt.Errorf("no %s found in FreeBSD pkg archive", pkgManifestEntryName))
	}

	return []pkg.Package{
		newArchivePackage(ctx, reader.Location, manifest.toEntry()),
	}, nil, nil
}

func (m pkgManifest) toEntry() pkg.FreeBSDPkgArchiveEntry {
	var files []pkg.FreeBSDFileRecord
	for path, f := range m.Files {
		files = append(files, pkg.FreeBSDFileRecord{
			Path:      path,
			Digest:    stripDigestAlgoPrefix(f.Sum),
			UserName:  f.UName,
			GroupName: f.GName,
		})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	return pkg.FreeBSDPkgArchiveEntry{
		Origin:         m.Origin,
		Name:           m.Name,
		Version:        m.Version,
		Comment:        m.Comment,
		Description:    m.Description,
		WWW:            m.WWW,
		Maintainer:     m.Maintainer,
		ABI:            m.Abi,
		Arch:           m.Arch,
		Prefix:         m.Prefix,
		FlatSize:       m.FlatSize,
		LicenseLogic:   m.LicenseLogic,
		Licenses:       m.Licenses,
		Categories:     m.Categories,
		ShlibsRequired: m.ShlibsRequired,
		Annotations:    m.Annotations,
		Files:          files,
	}
}

// openArchiveTar returns a tar reader over the contents of a FreeBSD pkg archive, transparently decompressing
// the stream when the archive is compressed. Plain (uncompressed) tar archives are also supported.
func openArchiveTar(ctx context.Context, reader file.LocationReadCloser) (*tar.Reader, func(), error) {
	format, stream, err := intfile.IdentifyArchive(ctx, reader.RealPath, reader)
	if err != nil {
		if errors.Is(err, archives.NoMatch) {
			return tar.NewReader(stream), func() {}, nil
		}
		return nil, nil, fmt.Errorf("failed to identify FreeBSD pkg archive format: %w", err)
	}

	decompressor, ok := format.(archives.Decompressor)
	if !ok {
		// not a single-stream compressed format; assume it is already a plain tar stream
		return tar.NewReader(stream), func() {}, nil
	}

	rc, err := decompressor.OpenReader(stream)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open decompression stream: %w", err)
	}

	return tar.NewReader(rc), func() { internal.CloseAndLogError(rc, reader.RealPath) }, nil
}
