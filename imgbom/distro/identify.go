package distro

import (
	"regexp"
	"strings"

	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/anchore/imgbom/internal/log"
	"github.com/anchore/stereoscope/pkg/file"
)

// returns a distro or nil
type parseFunc func(string) *Distro

// Identify parses distro-specific files to determine distro metadata like version and release
func Identify(s scope.Scope) *Distro {
	identityFiles := map[file.Path]parseFunc{
		"/etc/os-release": parseOsRelease,
		// Debian and Debian-based distros have the same contents linked from this path
		"/usr/lib/os-release": parseOsRelease,
		"/bin/busybox":        parseBusyBox,
	}

	for path, fn := range identityFiles {
		// this is always a slice with a single ref, the API is odd because it was meant for images
		refs, err := s.FilesByPath(path)
		if err != nil {
			log.Errorf("unable to get path refs from %s: %s", path, err)
			return nil
		}

		if len(refs) == 0 {
			continue
		}
		ref := refs[0]

		contents, err := s.MultipleFileContentsByRef(ref)
		log.Infof("contents are: %+v", contents)
		content, ok := contents[ref]
		// XXX is it possible to get a ref and no contents at all?
		if !ok {
			continue
		}

		if err != nil {
			log.Debugf("unable to get contents from %s: %s", path, err)
			continue
		}

		if content == "" {
			log.Debugf("no contents in file, skipping: %s", path)
			continue
		}

		distro := fn(content)

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
