package distro

import (
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/source"
)

// returns a distro or nil
type parseFunc func(string) *Distro

type parseEntry struct {
	path string
	fn   parseFunc
}

// Identify parses distro-specific files to determine distro metadata like version and release.
func Identify(resolver source.Resolver) *Distro {
	var distro *Distro

	identityFiles := []parseEntry{
		{
			// most distros provide a link at this location
			path: "/etc/os-release",
			fn:   parseOsRelease,
		},
		{
			// standard location for rhel & debian distros
			path: "/usr/lib/os-release",
			fn:   parseOsRelease,
		},
		{
			// check for busybox (important to check this last since other distros contain the busybox binary)
			path: "/bin/busybox",
			fn:   parseBusyBox,
		},
	}

identifyLoop:
	for _, entry := range identityFiles {
		locations, err := resolver.FilesByPath(entry.path)
		if err != nil {
			log.Errorf("unable to get path locations from %s: %s", entry.path, err)
			break
		}

		if len(locations) == 0 {
			log.Debugf("No Refs found from path: %s", entry.path)
			continue
		}

		for _, location := range locations {
			content, err := resolver.FileContentsByLocation(location)

			if err != nil {
				log.Debugf("unable to get contents from %s: %s", entry.path, err)
				continue
			}

			if content == "" {
				log.Debugf("no contents in file, skipping: %s", entry.path)
				continue
			}

			if candidateDistro := entry.fn(content); candidateDistro != nil {
				distro = candidateDistro
				break identifyLoop
			}
		}
	}

	if distro != nil && distro.Type == UnknownDistroType {
		return nil
	}

	return distro
}

func assemble(name, version, like string) *Distro {
	distroType, ok := IDMapping[name]

	// Both distro and version must be present
	if len(name) == 0 {
		return nil
	}

	if ok {
		distro, err := NewDistro(distroType, version, like)
		if err != nil {
			return nil
		}
		return &distro
	}

	return nil
}

func parseOsRelease(contents string) *Distro {
	id, vers, like := "", "", ""
	for _, line := range strings.Split(contents, "\n") {
		parts := strings.Split(line, "=")
		prefix := parts[0]
		value := strings.ReplaceAll(parts[len(parts)-1], `"`, "")

		switch prefix {
		case "ID":
			id = strings.TrimSpace(value)
		case "VERSION_ID":
			vers = strings.TrimSpace(value)
		case "ID_LIKE":
			like = strings.TrimSpace(value)
		}
	}

	return assemble(id, vers, like)
}

var busyboxVersionMatcher = regexp.MustCompile(`BusyBox v[\d.]+`)

func parseBusyBox(contents string) *Distro {
	matches := busyboxVersionMatcher.FindAllString(contents, -1)
	for _, match := range matches {
		parts := strings.Split(match, " ")
		version := strings.ReplaceAll(parts[1], "v", "")
		distro := assemble("busybox", version, "")
		if distro != nil {
			return distro
		}
	}
	return nil
}
