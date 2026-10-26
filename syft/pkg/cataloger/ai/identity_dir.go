package ai

import (
	"context"
	"encoding/json"
	"path"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// resolveSafeTensorsDirIdentity handles the directory-scan case for safe tensors
// find config.json beside the model files (or one directory up, for the shard
// subdirectory layout) and a sibling README.md. It returns
// the group's name candidates, resolved licenses, and supporting evidence.
func resolveSafeTensorsDirIdentity(ctx context.Context, resolver file.Resolver, dir string, md *pkg.SafeTensorsModelInfo) safeTensorsIdentity {
	id := safeTensorsIdentity{fallbackName: safeTensorsDirName(dir)}

	if loc, cfg := findDirHFConfig(resolver, dir); cfg != nil {
		applyHFConfig(md, cfg)
		id.nameOrPath = sanitizeModelName(cfg.NameOrPath)
		id.supporting = append(id.supporting, *loc)
	}

	if loc, fm := readDirReadmeFrontmatter(resolver, path.Join(dir, "README.md")); fm != nil {
		if len(fm.Licenses) > 0 {
			id.licenses = pkg.NewLicensesFromValuesWithContext(ctx, fm.Licenses...)
		}
		if id.nameOrPath == "" {
			id.nameOrPath = firstModelName(fm.BaseModel)
		}
		id.supporting = append(id.supporting, *loc)
	}
	return id
}

// findDirHFConfig looks for an HF config.json beside the model files, then in
// the parent directory (covers weights kept in a subdirectory of the model). It
// does not walk further up, so an unrelated config.json higher in the tree can't
// name every model below it.
func findDirHFConfig(resolver file.Resolver, dir string) (*file.Location, *hfConfig) {
	if loc, cfg := readDirHFConfig(resolver, path.Join(dir, "config.json")); cfg != nil {
		return loc, cfg
	}
	if parent := path.Dir(dir); parent != dir {
		return readDirHFConfig(resolver, path.Join(parent, "config.json"))
	}
	return nil, nil
}

func readDirHFConfig(resolver file.Resolver, p string) (*file.Location, *hfConfig) {
	locations, err := resolver.FilesByPath(p)
	if err != nil || len(locations) == 0 {
		return nil, nil
	}
	rc, err := resolver.FileContentsByLocation(locations[0])
	if err != nil {
		return nil, nil
	}
	defer internal.CloseAndLogError(rc, p)

	buf, err := readBounded(rc, maxHFConfigSize)
	if err != nil {
		log.Debugf("failed to read %s: %v", p, err)
		return nil, nil
	}
	var cfg hfConfig
	if err := json.Unmarshal(buf, &cfg); err != nil {
		log.Debugf("failed to decode %s: %v", p, err)
		return nil, nil
	}
	if !cfg.looksLikeHF() {
		return nil, nil
	}
	return &locations[0], &cfg
}

func readDirReadmeFrontmatter(resolver file.Resolver, p string) (*file.Location, *readmeFrontmatter) {
	locations, err := resolver.FilesByPath(p)
	if err != nil || len(locations) == 0 {
		return nil, nil
	}
	rc, err := resolver.FileContentsByLocation(locations[0])
	if err != nil {
		return nil, nil
	}
	defer internal.CloseAndLogError(rc, p)

	buf, err := readPrefix(rc, maxReadmePrefixSize)
	if err != nil {
		log.Debugf("failed to read %s: %v", p, err)
		return nil, nil
	}
	fm := parseFrontmatter(buf)
	if fm == nil {
		return nil, nil
	}
	return &locations[0], fm
}
