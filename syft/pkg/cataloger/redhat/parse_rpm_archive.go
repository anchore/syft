package redhat

import (
	"context"
	"fmt"
	"strconv"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"github.com/sassoftware/go-rpmutils"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// parseRpmArchive parses a single RPM
func parseRpmArchive(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	rpm, err := rpmutils.ReadRpm(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("RPM file found but unable to read: %s (%w)", reader.Location.RealPath, err)
	}

	nevra, err := rpm.Header.GetNEVRA()
	if err != nil {
		return nil, nil, err
	}

	licenses, err := rpm.Header.GetStrings(rpmutils.LICENSE)
	logRpmArchiveErr(reader.Location, "license", err)

	sourceRpm, err := rpm.Header.GetString(rpmutils.SOURCERPM)
	logRpmArchiveErr(reader.Location, "sourcerpm", err)

	vendor, err := rpm.Header.GetString(rpmutils.VENDOR)
	logRpmArchiveErr(reader.Location, "vendor", err)

	digestAlgorithm := getDigestAlgorithm(reader.Location, rpm.Header)

	size, err := rpm.Header.InstalledSize()
	logRpmArchiveErr(reader.Location, "size", err)

	files, err := rpm.Header.GetFiles()
	logRpmArchiveErr(reader.Location, "files", err)

	metadata := pkg.RpmArchive{
		Name:      nevra.Name,
		Version:   nevra.Version,
		Epoch:     parseEpoch(nevra.Epoch),
		Arch:      nevra.Arch,
		Release:   nevra.Release,
		SourceRpm: sourceRpm,
		Vendor:    vendor,
		Size:      int(size),
		Files:     mapFiles(files, digestAlgorithm),
	}

	return []pkg.Package{newArchivePackage(reader.Location, metadata, licenses)}, nil, nil
}

func getDigestAlgorithm(location file.Location, header *rpmutils.RpmHeader) string {
	digestAlgorithm, err := header.GetString(rpmutils.FILEDIGESTALGO)
	logRpmArchiveErr(location, "file digest algo", err)

	if digestAlgorithm != "" {
		return digestAlgorithm
	}
	digestAlgorithms, err := header.GetUint32s(rpmutils.FILEDIGESTALGO)
	logRpmArchiveErr(location, "file digest algo 32-bit", err)

	if len(digestAlgorithms) > 0 {
		digestAlgo := int(digestAlgorithms[0])
		return rpmutils.GetFileAlgoName(digestAlgo)
	}
	return ""
}

func mapFiles(files []rpmutils.FileInfo, digestAlgorithm string) []pkg.RpmFileRecord {
	var out []pkg.RpmFileRecord
	for _, f := range files {
		digest := file.Digest{}
		if f.Digest() != "" {
			digest = file.Digest{
				Algorithm: digestAlgorithm,
				Value:     f.Digest(),
			}
		}
		out = append(out, pkg.RpmFileRecord{
			Path:      f.Name(),
			Mode:      pkg.RpmFileMode(f.Mode()),
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

func logRpmArchiveErr(location file.Location, operation string, err error) {
	if err != nil {
		log.Debugf("ERROR in parse_rpm_archive %s file: %s: %v", operation, location.RealPath, err)
	}
}
