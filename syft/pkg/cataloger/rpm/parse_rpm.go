package rpm

import (
	"fmt"
	"strconv"
	"strings"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"github.com/sassoftware/go-rpmutils"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
)

// parseRpm parses a single RPM
func parseRpm(_ source.FileResolver, _ *generic.Environment, reader source.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	rpm, err := rpmutils.ReadRpm(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("RPM file found but unable to read: %s (%v)", reader.Location.RealPath, err)
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

	metadata := pkg.RpmMetadata{
		Name:      nevra.Name,
		Version:   nevra.Version,
		Epoch:     parseEpoch(nevra.Epoch),
		Arch:      nevra.Arch,
		Release:   nevra.Release,
		SourceRpm: sourceRpm,
		Vendor:    vendor,
		License:   strings.Join(licenses, " AND "), // TODO: AND conjunction is not necessarily correct, but we don't have a way to represent multiple licenses yet
		Size:      int(size),
		Files:     mapFiles(files, digestAlgorithm),
	}

	return []pkg.Package{newPackage(reader.Location, metadata, nil)}, nil, nil
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
