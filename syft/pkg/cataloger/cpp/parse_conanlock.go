package cpp

import (
	"encoding/json"
	"io"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// integrity check
var _ common.ParserFn = parseConanlock

type conanLock struct {
	GraphLock struct {
		Nodes map[string]struct {
			Ref     string `json:"ref"`
			Options string `json:"options"`
			Path    string `json:"path"`
			Context string `json:"context"`
		} `json:"nodes"`
	} `json:"graph_lock"`
	Version     string `json:"version"`
	ProfileHost string `json:"profile_host"`
}

// parseConanlock is a parser function for conan.lock contents, returning all packages discovered.
func parseConanlock(_ string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	pkgs := []*pkg.Package{}
	var cl conanLock
	if err := json.NewDecoder(reader).Decode(&cl); err != nil {
		return nil, nil, err
	}
	for _, node := range cl.GraphLock.Nodes {
		metadata := pkg.ConanMetadata{
			Ref:     node.Ref,
			Options: node.Options,
			Path:    node.Path,
			Context: node.Context,
		}

		pkgName, pkgVersion := metadata.NameAndVersion()
		if pkgName == "" || pkgVersion == "" {
			continue
		}

		pkgs = append(pkgs, &pkg.Package{
			Name:         pkgName,
			Version:      pkgVersion,
			Language:     pkg.CPP,
			Type:         pkg.ConanPkg,
			MetadataType: pkg.ConanaMetadataType,
			Metadata:     metadata,
		})
	}

	return pkgs, nil, nil
}
