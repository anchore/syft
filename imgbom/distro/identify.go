package distro

import (
	"regexp"
	"strings"

	"github.com/anchore/imgbom/internal/log"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
)

// returns a distro or nil
type parseFunc func(string) *Distro

// Identify parses distro-specific files to determine distro metadata like version and release
func Identify(img *image.Image) *Distro {
	// TODO: implement me based off of https://github.com/anchore/anchore-engine/blob/78b23d7e8f007005c070673405b5e23730a660e0/anchore_engine/analyzers/utils.py#L131

	identityFiles := map[file.Path]parseFunc{
		"/etc/os-release": parseOsRelease,
		// Debian and Debian-based distros have the same contents linked from this path
		"/usr/lib/os-release": parseOsRelease,
		"/bin/busybox":        parseBusyBox,
	}

	for path, fn := range identityFiles {
		contents, err := img.FileContentsFromSquash(path) // TODO: this call replaced with "MultipleFileContents"

		if err != nil {
			log.Debugf("unable to get contents from %s: %s", path, err)
			continue
		}

		if contents == "" {
			log.Debugf("no contents in file, skipping: %s", path)
			continue
		}
		distro := fn(contents)

		if distro == nil {
			continue
		}

		return distro
	}
	// TODO: is it useful to know partially detected distros? where the ID is known but not the version (and viceversa?)
	return nil
}

func assembleDistro(name, version string) *Distro {
	distroType, ok := Mappings[name]

	// Both distro and version must be present
	if len(name) == 0 || len(version) == 0 {
		return nil
	}

	if ok {
		distro, err := NewDistro(distroType, version)
		if err != nil {
			return nil
		}
		return &distro
	}

	return nil
}

func parseOsRelease(contents string) *Distro {
	id, vers := "", ""
	for _, line := range strings.Split(contents, "\n") {
		parts := strings.Split(line, "=")
		prefix := parts[0]
		value := strings.ReplaceAll(parts[len(parts)-1], `"`, "")

		switch prefix {
		case "ID":
			id = value
		case "VERSION_ID":
			vers = value
		}
	}

	return assembleDistro(id, vers)
}

var busyboxVersionMatcher = regexp.MustCompile(`BusyBox v[\d\.]+`)

func parseBusyBox(contents string) *Distro {
	matches := busyboxVersionMatcher.FindAllString(contents, -1)
	for _, match := range matches {
		parts := strings.Split(match, " ")
		version := strings.ReplaceAll(parts[1], "v", "")
		distro := assembleDistro("busybox", version)
		if distro != nil {
			return distro
		}
	}
	return nil
}
