package distro

import (
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/scope"
)

// returns a distro or nil
// TODO: refactor to io.Reader
type parseFunc func(string) *Distro

type parseEntry struct {
	path file.Path
	fn   parseFunc
}

// nolint: funlen
// Identify parses distro-specific files to determine distro metadata like version and release.
func Identify(resolver scope.Resolver) Distro {
	distro := NewUnknownDistro()

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
		refs, err := resolver.FilesByPath(entry.path)
		if err != nil {
			log.Errorf("unable to get path refs from %s: %s", entry.path, err)
			break
		}

		if len(refs) == 0 {
			continue
		}

		for _, ref := range refs {
			contentReaders, err := resolver.MultipleFileContentsByRef(ref)
			contentReader, ok := contentReaders[ref]

			if !ok {
				log.Infof("no content present for ref: %s", ref)
				continue
			}

			if err != nil {
				log.Debugf("unable to get contents from %s: %s", entry.path, err)
				continue
			}

			bytes, err := ioutil.ReadAll(contentReader)
			if err != nil {
				log.Debugf("unable to read contents from %s: %s", entry.path, err)
				continue
			}

			content := string(bytes)

			if content == "" {
				log.Debugf("no contents in file, skipping: %s", entry.path)
				continue
			}

			if candidateDistro := entry.fn(content); candidateDistro != nil {
				distro = *candidateDistro
				break identifyLoop
			}
		}
	}

	return distro
}

func assemble(name, version string) *Distro {
	distroType, ok := IDMapping[name]

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
