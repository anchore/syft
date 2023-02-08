package rpm

import (
	"fmt"
	"strconv"
	"strings"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func newPackage(dbLocation source.Location, metadata pkg.RpmMetadata, distro *linux.Release) pkg.Package {
	p := pkg.Package{
		Name:         metadata.Name,
		Version:      toELVersion(metadata),
		PURL:         packageURL(metadata, distro),
		Locations:    source.NewLocationSet(dbLocation),
		Type:         pkg.RpmPkg,
		MetadataType: pkg.RpmMetadataType,
		Metadata:     metadata,
	}

	if metadata.License != "" {
		p.Licenses.Simple = append(p.Licenses.Simple, metadata.License)
	}

	p.SetID()
	return p
}

func newMetadataFromEntry(entry rpmdb.PackageInfo, files []pkg.RpmdbFileRecord) pkg.RpmMetadata {
	return pkg.RpmMetadata{
		Name:            entry.Name,
		Version:         entry.Version,
		Epoch:           entry.Epoch,
		Arch:            entry.Arch,
		Release:         entry.Release,
		SourceRpm:       entry.SourceRpm,
		Vendor:          entry.Vendor,
		License:         entry.License,
		Size:            entry.Size,
		ModularityLabel: entry.Modularitylabel,
		Files:           files,
	}
}

func newMetadataFromManifestLine(entry string) (*pkg.RpmMetadata, error) {
	parts := strings.Split(entry, "\t")
	if len(parts) < 10 {
		return nil, fmt.Errorf("unexpected number of fields in line: %s", entry)
	}

	versionParts := strings.Split(parts[1], "-")
	if len(versionParts) != 2 {
		return nil, fmt.Errorf("unexpected version field: %s", parts[1])
	}
	version := versionParts[0]
	release := versionParts[1]

	converted, err := strconv.Atoi(parts[8])
	var epoch *int
	if err != nil || parts[5] == "(none)" {
		epoch = nil
	} else {
		epoch = &converted
	}

	converted, err = strconv.Atoi(parts[6])
	var size int
	if err == nil {
		size = converted
	}

	return &pkg.RpmMetadata{
		Name:      parts[0],
		Version:   version,
		Epoch:     epoch,
		Arch:      parts[7],
		Release:   release,
		SourceRpm: parts[9],
		Vendor:    parts[4],
		Size:      size,
	}, nil
}

// packageURL returns the PURL for the specific RHEL package (see https://github.com/package-url/purl-spec)
func packageURL(m pkg.RpmMetadata, distro *linux.Release) string {
	var namespace string
	if distro != nil {
		namespace = distro.ID
	}

	qualifiers := map[string]string{
		pkg.PURLQualifierArch: m.Arch,
	}

	if m.Epoch != nil {
		qualifiers[pkg.PURLQualifierEpoch] = strconv.Itoa(*m.Epoch)
	}

	if m.SourceRpm != "" {
		qualifiers[pkg.PURLQualifierUpstream] = m.SourceRpm
	}

	return packageurl.NewPackageURL(
		packageurl.TypeRPM,
		namespace,
		m.Name,
		// for purl the epoch is a qualifier, not part of the version
		// see https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst under the RPM section
		fmt.Sprintf("%s-%s", m.Version, m.Release),
		pkg.PURLQualifiers(
			qualifiers,
			distro,
		),
		"",
	).ToString()
}
