package golang

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/afero"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// resolveModuleLicenses finds and parses license files for Go modules
func resolveModuleLicenses(ctx context.Context, pkgInfos []pkgInfo, fs afero.Fs) pkg.LicenseSet {
	licenses := pkg.NewLicenseSet()

	for _, info := range pkgInfos {
		modDir, pkgDir, err := getAbsolutePkgPaths(info)
		if err != nil {
			continue
		}

		licenseFiles, err := findAllLicenseCandidatesUpwards(pkgDir, licenseRegexp, modDir, fs)
		if err != nil {
			continue
		}

		for _, f := range licenseFiles {
			contents, err := fs.Open(f)
			if err != nil {
				continue
			}
			licenses.Add(pkg.NewLicensesFromReadCloserWithContext(ctx, file.NewLocationReadCloser(file.Location{}, contents))...)
			_ = contents.Close()
		}
	}

	return licenses
}

/*
findAllLicenseCandidatesUpwards performs a bubble-up search per package:
1. pkgInfos represents a sparse vertical distribution of packages within modules
2. we get more pkgInfos for free when the build configuration is updated

The recursion terminates via two conditions:
- When dir is outside stopAt boundary (happy case)
- When reaching filesystem root where parent == dir (edge case)

Note: The code does NOT follow symlinks. It returns a slice of absolute paths that
represent license file matches that are resolved independently of the bubble-up.

When we should consider redesign tip to stem:
- Reduced filesystem calls: Single traversal vs multiple per-package
- Path deduplication: Avoids re-scanning common parent directories
- Better for wide module structures: Efficient when many packages share parent paths
- We need to consider the case here where nested modules are visited by accident and licenses
are erroneously associated to a 'parent module'; bubble up currently prevents this
*/
func findAllLicenseCandidatesUpwards(dir string, r *regexp.Regexp, stopAt string, fs afero.Fs) ([]string, error) {
	// Validate that both paths are absolute
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("dir must be an absolute path, got: %s", dir)
	}
	if !filepath.IsAbs(stopAt) {
		return nil, fmt.Errorf("stopAt must be an absolute path, got: %s", stopAt)
	}

	licenses, err := findLicenseCandidates(dir, r, stopAt, fs)
	if err != nil {
		return nil, err
	}

	// Ensure we return an empty slice rather than nil for consistency
	if licenses == nil {
		return []string{}, nil
	}
	return licenses, nil
}

func findLicenseCandidates(dir string, r *regexp.Regexp, stopAt string, fs afero.Fs) ([]string, error) {
	// stop if we've gone outside the stopAt directory
	if !strings.HasPrefix(dir, stopAt) {
		return []string{}, nil
	}

	licenses, err := findLicensesInDir(dir, r, fs)
	if err != nil {
		return nil, err
	}

	parent := filepath.Dir(dir)
	// can't go any higher up the directory tree: "/" case
	if parent == dir {
		return licenses, nil
	}

	// search parent directory and combine results
	parentLicenses, err := findLicenseCandidates(parent, r, stopAt, fs)
	if err != nil {
		return nil, err
	}

	// Combine current directory licenses with parent directory licenses
	return append(licenses, parentLicenses...), nil
}

func getAbsolutePkgPaths(info pkgInfo) (modDir string, pkgDir string, err error) {
	pkgDir, err = filepath.Abs(info.pkgDir)
	if err != nil {
		return modDir, pkgDir, err
	}

	modDir, err = filepath.Abs(info.moduleDir)
	if err != nil {
		return modDir, pkgDir, err
	}

	if !strings.HasPrefix(pkgDir, modDir) {
		return modDir, pkgDir, fmt.Errorf("modDir %s should contain pkgDir %s", modDir, pkgDir)
	}

	return modDir, pkgDir, nil
}

func findLicensesInDir(dir string, r *regexp.Regexp, fs afero.Fs) ([]string, error) {
	var licenses []string

	dirContents, err := afero.ReadDir(fs, dir)
	if err != nil {
		return nil, err
	}

	for _, f := range dirContents {
		if f.IsDir() {
			continue
		}

		if r.MatchString(f.Name()) {
			path := filepath.Join(dir, f.Name())
			licenses = append(licenses, path)
		}
	}

	return licenses, nil
}
