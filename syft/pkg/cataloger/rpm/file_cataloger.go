package rpm

import (
	"fmt"
	"strconv"
	"strings"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"github.com/sassoftware/go-rpmutils"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type FileCataloger struct{}

// NewFileCataloger returns a new RPM file cataloger object.
func NewFileCataloger() *FileCataloger {
	return &FileCataloger{}
}

// Name returns a string that uniquely describes a cataloger
func (c *FileCataloger) Name() string {
	return "rpm-file-cataloger"
}

// Catalog is given an object to resolve file references and content, this function returns any discovered Packages after analyzing rpm files
//nolint:funlen
func (c *FileCataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	fileMatches, err := resolver.FilesByGlob("**/*.rpm")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find rpm files's by glob: %w", err)
	}

	var pkgs []pkg.Package
	for _, location := range fileMatches {
		contentReader, err := resolver.FileContentsByLocation(location)
		if err != nil {
			return nil, nil, err
		}

		rpm, err := rpmutils.ReadRpm(contentReader)
		if err != nil {
			log.Debugf("RPM file found but unable to read: %s (%v)", location.RealPath, err)
			continue
		}

		nevra, err := rpm.Header.GetNEVRA()
		if err != nil {
			return nil, nil, err
		}

		licenses, _ := rpm.Header.GetStrings(rpmutils.LICENSE)
		sourceRpm, _ := rpm.Header.GetString(rpmutils.SOURCERPM)
		vendor, _ := rpm.Header.GetString(rpmutils.VENDOR)
		digestAlgorithm := getDigestAlgorithm(rpm.Header)
		size, _ := rpm.Header.InstalledSize()
		files, _ := rpm.Header.GetFiles()

		p := pkg.Package{
			Name:         nevra.Name,
			Version:      nevra.Version,
			FoundBy:      c.Name(),
			Licenses:     licenses,
			Locations:    source.NewLocationSet(location),
			Type:         pkg.RpmPkg,
			MetadataType: pkg.RpmMetadataType,
			Metadata: pkg.RpmMetadata{
				Name:      nevra.Name,
				Version:   nevra.Version,
				Epoch:     parseEpoch(nevra.Epoch),
				Arch:      nevra.Arch,
				Release:   nevra.Release,
				SourceRpm: sourceRpm,
				Vendor:    vendor,
				License:   strings.Join(licenses, " AND "),
				Size:      int(size),
				Files:     mapFiles(files, digestAlgorithm),
			},
		}
		p.SetID()
		pkgs = append(pkgs, p)

		internal.CloseAndLogError(contentReader, location.VirtualPath)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to catalog rpm file=%+v: %w", location.RealPath, err)
		}
	}

	return pkgs, nil, nil
}

func getDigestAlgorithm(header *rpmutils.RpmHeader) string {
	digestAlgorithm, _ := header.GetString(rpmutils.FILEDIGESTALGO)
	if digestAlgorithm != "" {
		return digestAlgorithm
	}
	digestAlgorithms, _ := header.GetUint32s(rpmutils.FILEDIGESTALGO)
	if len(digestAlgorithms) > 0 {
		digestAlgo := int(digestAlgorithms[0])
		return rpmutils.GetFileAlgoName(digestAlgo)
	}
	return ""
}

func mapFiles(files []rpmutils.FileInfo, digestAlgorithm string) []pkg.RpmdbFileRecord {
	var out []pkg.RpmdbFileRecord
	for _, f := range files {
		digest := file.Digest{}
		if f.Digest() != "" {
			digest = file.Digest{
				Algorithm: digestAlgorithm,
				Value:     f.Digest(),
			}
		}
		out = append(out, pkg.RpmdbFileRecord{
			Path:      f.Name(),
			Mode:      pkg.RpmdbFileMode(f.Mode()),
			Size:      int(f.Size()),
			Digest:    digest,
			UserName:  f.UserName(),
			GroupName: f.GroupName(),
			Flags:     rpmdb.FileFlags(f.Flags()).String(),
		})
	}
	return out
}

func parseEpoch(epoch string) *int {
	i, err := strconv.Atoi(epoch)
	if err != nil {
		return nil
	}
	return &i
}
