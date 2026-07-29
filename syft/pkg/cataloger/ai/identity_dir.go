package ai

import (
	"context"
	"encoding/json"
	"io"
	"path"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// resolveSafeTensorsDirIdentity handles the directory-scan case for safe tensors
// find config.json beside the model files (walking up parent directories to the
// scanned source root if no sibling exists) and a sibling README.md. It returns
// the group's name candidates, resolved licenses, and supporting evidence.
func resolveSafeTensorsDirIdentity(ctx context.Context, resolver file.Resolver, dir string, md *pkg.SafeTensorsModelInfo) safeTensorsIdentity {
	id := safeTensorsIdentity{fallbackName: safeTensorsDirName(dir)}

	if loc, cfg := findDirHFConfig(resolver, dir); cfg != nil {
		applyHFConfig(md, cfg)
		id.nameOrPath = cfg.NameOrPath
		id.supporting = append(id.supporting, *loc)
	}

	if loc, fm := readDirReadmeFrontmatter(resolver, path.Join(dir, "README.md")); fm != nil {
		if fm.License != "" {
			id.licenses = pkg.NewLicensesFromValuesWithContext(ctx, fm.License)
		}
		if id.nameOrPath == "" && len(fm.BaseModel) > 0 {
			id.nameOrPath = fm.BaseModel[0]
		}
		id.supporting = append(id.supporting, *loc)
	}
	return id
}

// findDirHFConfig looks for a config.json beside the model files
func findDirHFConfig(resolver file.Resolver, dir string) (*file.Location, *hfConfig) {
	for {
		if loc, cfg := readDirHFConfig(resolver, path.Join(dir, "config.json")); cfg != nil {
			return loc, cfg
		}
		parent := path.Dir(dir)
		if parent == dir {
			return nil, nil // reached the source root
		}
		dir = parent
	}
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

	var cfg hfConfig
	if err := json.NewDecoder(rc).Decode(&cfg); err != nil {
		log.Debugf("failed to decode %s: %v", p, err)
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

	buf, err := io.ReadAll(io.LimitReader(rc, 1024*1024))
	if err != nil {
		return nil, nil
	}
	fm := parseFrontmatter(buf)
	if fm == nil {
		return nil, nil
	}
	return &locations[0], fm
}
