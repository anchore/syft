package dotnet

import (
	"encoding/json"
	"path"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// libmanJSON represents the libman.json file format in ASP.NET projects for describing javascript assets to be downloaded and bundled
// see https://github.com/aspnet/LibraryManager/wiki/libman.json-reference
type libmanJSON struct {
	Location        file.Location `json:"-"`
	Version         string        `json:"version"`
	DefaultProvider string        `json:"defaultProvider"`
	Libraries       []struct {
		Library     string   `json:"library"`
		Files       []string `json:"files"`
		Destination string   `json:"destination"`
		Provider    string   `json:"provider,omitempty"`
	} `json:"libraries"`
}

func (l *libmanJSON) packages() []pkg.Package {
	if l == nil {
		return nil
	}

	var pkgs []pkg.Package
	for _, lib := range l.Libraries {
		if lib.Provider == "filesystem" {
			// there is no name and version with filesystem providers
			continue
		}
		fields := strings.Split(lib.Library, "@")
		if len(fields) != 2 {
			continue
		}

		name := fields[0]
		version := fields[1]

		p := pkg.Package{
			Name:      name,
			Version:   version,
			Locations: file.NewLocationSet(l.Location),
			Type:      pkg.NpmPkg,
			PURL: packageurl.NewPackageURL(
				packageurl.TypeNPM,
				"",
				name,
				version,
				nil,
				"",
			).ToString(),
			Language: pkg.JavaScript,
		}

		p.SetID()
		pkgs = append(pkgs, p)
	}

	return pkgs
}

func newLibmanJSON(reader file.LocationReadCloser) (*libmanJSON, error) {
	var doc libmanJSON
	dec := json.NewDecoder(reader)
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}

	for i := range doc.Libraries {
		l := &doc.Libraries[i]
		if l.Provider == "" {
			l.Provider = doc.DefaultProvider
		}
	}

	doc.Location = reader.Location

	return &doc, nil
}

func findLibmanJSON(resolver file.Resolver, depsJSON file.Location) (*libmanJSON, error) {
	parent := path.Dir(depsJSON.RealPath)
	loc := resolver.RelativeFileByPath(depsJSON, path.Join(parent, "libman.json"))
	if loc == nil {
		return nil, nil
	}

	reader, err := resolver.FileContentsByLocation(*loc)
	defer internal.CloseAndLogError(reader, loc.RealPath)
	if err != nil {
		return nil, err
	}
	internal.CloseAndLogError(reader, loc.RealPath)

	lj, err := newLibmanJSON(file.NewLocationReadCloser(*loc, reader))
	if err != nil {
		return nil, err
	}

	return lj, nil
}
