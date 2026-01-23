package linux

import (
	"io"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/file"
)

func supplementDebianVersion(resolver file.Resolver, release *Release) error {
	// we're only looking for version information for debian when none is present in /etc/os-release
	if release.Version != "" || release.VersionID != "" || !strings.EqualFold(release.ID, "debian") {
		return nil
	}
	// if we have a debian release with no version, look for a debian_version
	locations, err := resolver.FilesByGlob("/etc/debian_version")
	if err != nil {
		return err
	}
	for _, location := range locations {
		version, err := readDebianVersionFile(resolver, location)
		if err != nil {
			return err
		}
		if version != "" {
			release.Version = version
			release.VersionID = version
			return nil
		}
	}
	return nil
}

func readDebianVersionFile(resolver file.Resolver, location file.Location) (string, error) {
	rdr, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return "", err
	}
	defer internal.CloseAndLogError(rdr, location.RealPath)
	contents, err := io.ReadAll(rdr)
	if err != nil {
		return "", err
	}
	version := strings.TrimSpace(string(contents))
	if regexp.MustCompile(`\d+(:?.\d+)?`).MatchString(version) {
		return version, nil
	}
	return "", nil
}
