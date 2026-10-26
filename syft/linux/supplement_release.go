package linux

import (
	"io"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

func supplementDebianVersion(resolver file.Resolver, release *Release) {
	if !strings.EqualFold(release.ID, "debian") {
		return
	}
	// debian_version has a more specific point release than os-release
	locations, err := resolver.FilesByGlob("/etc/debian_version")
	if err != nil {
		log.Debugf("error reading /etc/debian_version: %v", err)
		return
	}
	for _, location := range locations {
		version := readDebianVersionFile(resolver, location)
		if version != "" {
			release.VersionID = version
			if release.Version == "" {
				release.Version = version
			}
			return // keep the first result
		}
	}
}

func readDebianVersionFile(resolver file.Resolver, location file.Location) string {
	rdr, err := resolver.FileContentsByLocation(location)
	if err != nil {
		log.Debugf("error getting contents for %s: %v", location.RealPath, err)
		return ""
	}
	defer internal.CloseAndLogError(rdr, location.RealPath)
	contents, err := io.ReadAll(io.LimitReader(rdr, 5*1024*1024))
	if err != nil {
		log.Debugf("error reading %s: %v", location.RealPath, err)
		return ""
	}
	version := strings.TrimSpace(string(contents))
	if regexp.MustCompile(`^\d+(?:\.\d+)?$`).MatchString(version) {
		return version
	}
	return ""
}
