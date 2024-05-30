package alias

import (
	"encoding/json"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/source"
)

// NPMPackageAliasIdentifier augments name and version with what's found in a root package.json
func NPMPackageAliasIdentifier(src source.Source) *source.Alias {
	type js struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}

	// it's possible older layers would have a package.json that gets removed,
	// but we can probably skip identifying a directory as those
	r, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		log.Debugf("error getting file resolver: %v", err)
		return nil
	}
	locs, err := r.FilesByPath("package.json")
	if err != nil {
		log.Debugf("error getting package.json: %v", err)
		return nil
	}
	// if we don't have exactly 1 package.json in the root directory, we can't guess which is the right one to use
	if len(locs) == 0 {
		// expected, not found
		return nil
	}
	if len(locs) > 1 {
		log.Debugf("multiple package.json files found: %v", locs)
		return nil
	}

	contents, err := r.FileContentsByLocation(locs[0])
	if err != nil {
		log.Tracef("error getting package.json contents: %v", err)
		return nil
	}
	defer internal.CloseAndLogError(contents, locs[0].RealPath)

	dec := json.NewDecoder(contents)
	project := js{}
	err = dec.Decode(&project)
	if err != nil {
		log.Tracef("error decoding package.json contents: %v", err)
		return nil
	}

	return &source.Alias{
		Name:    project.Name,
		Version: project.Version,
	}
}
