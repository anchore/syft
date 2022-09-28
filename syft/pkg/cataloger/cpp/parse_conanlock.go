package cpp

import (
	"encoding/json"
	"io"
	"strings"

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
		if len(node.Ref) > 0 {
			// ref: pkga/0.1@user/testing
			splits := strings.Split(strings.Split(node.Ref, "@")[0], "/")
			if len(splits) < 2 {
				continue
			}
			pkgName, pkgVersion := splits[0], splits[1]
			pkgs = append(pkgs, &pkg.Package{
				Name:         pkgName,
				Version:      pkgVersion,
				Language:     pkg.CPP,
				Type:         pkg.ConanPkg,
				MetadataType: pkg.ConanaMetadataType,
				Metadata: pkg.ConanMetadata{
					Name:    pkgName,
					Version: pkgVersion,
					Options: node.Options,
					Path:    node.Path,
					Context: node.Context,
				},
			})
		}
	}

	return pkgs, nil, nil
}
