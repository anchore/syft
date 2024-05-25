package python

import (
	"bufio"
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

type virtualEnvInfo struct {
	// Context
	Location         file.Location
	SitePackagesPath string

	// Config values
	Version                   string
	IncludeSystemSitePackages bool
}

func (v virtualEnvInfo) majorMinorVersion() string {
	parts := strings.Split(v.Version, ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts[:2], ".")
}

func findVirtualEnvs(_ context.Context, resolver file.Resolver, sitePackagePaths []string) ([]virtualEnvInfo, []string, error) {
	locations, err := resolver.FilesByGlob("**/pyvenv.cfg")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find python virtualenvs: %w", err)
	}

	sitePackagePathsSet := strset.New(sitePackagePaths...)

	var virtualEnvs []virtualEnvInfo
	for _, location := range locations {
		cfg, err := parsePyvenvCfg(context.Background(), resolver, location)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse pyvenv.cfg: %w", err)
		}
		if cfg == nil {
			continue
		}

		cfg.SitePackagesPath = cfg.matchVirtualEnvSitePackagesPath(sitePackagePaths)

		if cfg.SitePackagesPath != "" {
			sitePackagePathsSet.Remove(cfg.SitePackagesPath)
		}

		virtualEnvs = append(virtualEnvs, *cfg)
	}

	unusedSitePackageDirs := sitePackagePathsSet.List()
	sort.Strings(unusedSitePackageDirs)

	return virtualEnvs, unusedSitePackageDirs, nil
}

func (v virtualEnvInfo) matchSystemPackagesPath(sitePackagePaths []string) string {
	sitePackagePathsSet := strset.New(sitePackagePaths...)

	// we are searchin for the system site-packages directory within the virtualenv
	search := "**/python" + v.majorMinorVersion() + "/*-packages"

	var matches []string
	for _, p := range sitePackagePathsSet.List() {
		doesMatch, err := doublestar.Match(search, p)
		if err != nil {
			log.Tracef("unable to match system site-packages path %q: %v", p, err)
			continue
		}
		if doesMatch {
			matches = append(matches, p)
		}
	}

	// we should get either 0 or 1 matches, we cannot reason about multiple matches
	if len(matches) == 1 {
		return matches[0]
	}

	return ""
}

func (v virtualEnvInfo) matchVirtualEnvSitePackagesPath(sitePackagePaths []string) string {
	sitePackagePathsSet := strset.New(sitePackagePaths...)
	// the parent directory of the venv config is the top-level directory of the virtualenv
	// e.g. /app/project1/venv/pyvenv.cfg -> /app/project1/venv
	parent := strings.TrimLeft(path.Dir(v.Location.RealPath), "/")

	// we are searchin for the site-packages directory within the virtualenv
	search := parent + "/lib/python" + v.majorMinorVersion() + "/site-packages"

	var matches []string
	for _, p := range sitePackagePathsSet.List() {
		if strings.Contains(p, search) {
			matches = append(matches, p)
		}
	}

	// we should get either 0 or 1 matches, we cannot reason about multiple matches
	if len(matches) == 1 {
		return matches[0]
	}

	return ""
}

func parsePyvenvCfg(_ context.Context, resolver file.Resolver, location file.Location) (*virtualEnvInfo, error) {
	reader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, fmt.Errorf("unable to read file %q: %w", location.Path(), err)
	}
	defer internal.CloseAndLogError(reader, location.Path())

	cfg, err := parsePyvenvCfgReader(file.NewLocationReadCloser(location, reader))
	if err != nil {
		return nil, fmt.Errorf("unable to parse pyvenv.cfg: %w", err)
	}

	return cfg, nil
}

func parsePyvenvCfgReader(reader file.LocationReadCloser) (*virtualEnvInfo, error) {
	scanner := bufio.NewScanner(reader)

	venv := virtualEnvInfo{
		Location: reader.Location,
	}

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			// skip empty lines and comments
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			// skip malformed lines
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "version":
			venv.Version = value
		case "include-system-site-packages":
			venv.IncludeSystemSitePackages = strings.ToLower(value) == "true"
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &venv, nil
}
