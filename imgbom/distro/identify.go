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
func Identify(s scope.Scope) Distro {
	distro := NewUnknownDistro()

	identityFiles := map[file.Path]parseFunc{
		"/etc/os-release": parseOsRelease,
		// Debian and Debian-based distros have the same contents linked from this path
		"/usr/lib/os-release": parseOsRelease,
		"/bin/busybox":        parseBusyBox,
	}

	for path, fn := range identityFiles {
		refs, err := s.FilesByPath(path)
		if err != nil {
			log.Errorf("unable to get path refs from %s: %s", path, err)
			break
		}

		if len(refs) == 0 {
			continue
		}

		for _, ref := range refs {
			contents, err := s.MultipleFileContentsByRef(ref)
			content, ok := contents[ref]

			if !ok {
				log.Infof("no content present for ref: %s", ref)
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

			if candidateDistro := fn(content); candidateDistro != nil {
				distro = *candidateDistro
				break
			}
		}
	}

	return distro
}

func assemble(name, version string) *Distro {
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
			id = strings.TrimSpace(value)
		case "VERSION_ID":
			vers = strings.TrimSpace(value)
		}
	}

	return assemble(id, vers)
}

var busyboxVersionMatcher = regexp.MustCompile(`BusyBox v[\d\.]+`)

func parseBusyBox(contents string) *Distro {
	matches := busyboxVersionMatcher.FindAllString(contents, -1)
	for _, match := range matches {
		parts := strings.Split(match, " ")
		version := strings.ReplaceAll(parts[1], "v", "")
		distro := assemble("busybox", version)
		if distro != nil {
			return distro
		}
	}
	return nil
}
