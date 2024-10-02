package redhat

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
)

func newDBPackage(dbOrRpmLocation file.Location, m pkg.RpmDBEntry, distro *linux.Release, licenses []string) pkg.Package {
	p := pkg.Package{
		Name:      m.Name,
		Version:   toELVersion(m.Epoch, m.Version, m.Release),
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromLocation(dbOrRpmLocation, licenses...)...),
		PURL:      packageURL(m.Name, m.Arch, m.Epoch, m.SourceRpm, m.Version, m.Release, distro),
		Locations: file.NewLocationSet(dbOrRpmLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Type:      pkg.RpmPkg,
		Metadata:  m,
	}

	p.SetID()
	return p
}

func newArchivePackage(archiveLocation file.Location, m pkg.RpmArchive, licenses []string) pkg.Package {
	p := pkg.Package{
		Name:      m.Name,
		Version:   toELVersion(m.Epoch, m.Version, m.Release),
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromLocation(archiveLocation, licenses...)...),
		PURL:      packageURL(m.Name, m.Arch, m.Epoch, m.SourceRpm, m.Version, m.Release, nil),
		Locations: file.NewLocationSet(archiveLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Type:      pkg.RpmPkg,
		Metadata:  m,
	}

	p.SetID()
	return p
}

// newMetadataFromManifestLine parses an entry in an RPM manifest file as used in Mariner distroless containers.
// Each line is the output from:
// - rpm --query --all --query-format "%{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\t%{BUILDTIME}\t%{VENDOR}\t%{EPOCH}\t%{SIZE}\t%{ARCH}\t%{EPOCHNUM}\t%{SOURCERPM}\n"
// - https://github.com/microsoft/CBL-Mariner/blob/3df18fac373aba13a54bd02466e64969574f13af/toolkit/docs/how_it_works/5_misc.md?plain=1#L150
func newMetadataFromManifestLine(entry string) (*pkg.RpmDBEntry, error) {
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
	return &pkg.RpmDBEntry{
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
func packageURL(name, arch string, epoch *int, srpm string, version, release string, distro *linux.Release) string {
	var namespace string
	if distro != nil {
		namespace = distro.ID
	}
	if namespace == "rhel" {
		namespace = "redhat"
	}

	qualifiers := map[string]string{}

	if arch != "" {
		qualifiers[pkg.PURLQualifierArch] = arch
	}

	if epoch != nil {
		qualifiers[pkg.PURLQualifierEpoch] = strconv.Itoa(*epoch)
	}

	if srpm != "" {
		qualifiers[pkg.PURLQualifierUpstream] = srpm
	}

	return packageurl.NewPackageURL(
		packageurl.TypeRPM,
		namespace,
		name,
		// for purl the epoch is a qualifier, not part of the version
		// see https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst under the RPM section
		fmt.Sprintf("%s-%s", version, release),
		pkg.PURLQualifiers(
			qualifiers,
			distro,
		),
		"",
	).ToString()
}
