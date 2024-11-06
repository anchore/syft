package fileresolver

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/thediveo/procfsroot"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/internal/windows"
)

// ChrootContext helps to modify path from a real filesystem to a chroot-like filesystem, taking into account
// the user given root, the base path (if any) to consider as the root, and the current working directory.
// Note: this only works on a real filesystem, not on a virtual filesystem (such as a stereoscope filetree).
type ChrootContext struct {
	root              string
	base              string
	cwd               string
	cwdRelativeToRoot string
}

func NewChrootContextFromCWD(root, base string) (*ChrootContext, error) {
	var currentWD string
	var err error

	cleanBase, err := NormalizeBaseDirectory(base)
	if err != nil {
		return nil, err
	}

	inProcfs, err := isPathInProcfsPid(base)
	if err != nil {
		return nil, err
	}

	if inProcfs {
		currentWD, err = getProcfsCwd(cleanBase)
		if err != nil {
			return nil, fmt.Errorf("could not get current working directory: %w", err)
		}
	} else {
		currentWD, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("could not get current working directory: %w", err)
		}
	}

	log.Tracef("cwd: %q", currentWD)

	return NewChrootContext(root, base, currentWD)
}

func NewChrootContext(root, base, cwd string) (*ChrootContext, error) {
	cleanBase, err := NormalizeBaseDirectory(base)
	if err != nil {
		return nil, err
	}

	cleanRoot, err := NormalizeRootDirectory(root, cleanBase)
	if err != nil {
		return nil, err
	}

	chroot := &ChrootContext{
		root: cleanRoot,
		base: cleanBase,
		cwd:  cwd,
	}

	return chroot, chroot.ChangeDirectory(cwd)
}

// Evaluate all the symlinks from source until we find the base path, which we
// assume it's a new root filesystem (it can be used as a chroot target). From
// there, all the absolute symbolic links are resolved relative to the base
// path. We return the path (either relative or absolute) that can be used by
// the host to access the directory/file inside the chroot.
//
// If the base is empty or we are running on Windows, this function returns
// filepath.Evalsymlinks(source)
//
// If the source doesn't contain the base path, we do regular symlink
// resolution.
func EvalSymlinksRelativeToBase(source string, base string) (string, error) {
	var err error
	var index int
	var absPath string
	var path string
	var resolvedPath string

	// For windows we don't support resolving absolute symlinks inside a
	// chroot, so we preserve the existing behavior
	if base == "" || windows.HostRunningOnWindows() {
		return filepath.EvalSymlinks(source)
	}

	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}

	log.Tracef("solving source %q relative to base %q", source, base)
	source = filepath.Clean(source)

	// we don't support resolving relative paths when the base is a procfs path
	inProcfs, err := isPathInProcfsPid(absBase)
	if err != nil {
		return "", err
	}

	if inProcfs && !filepath.IsAbs(source) {
		return "", fmt.Errorf("relative paths are not supported with procfs base")
	}

	containedPaths := allContainedPaths(source)
	for index, path = range containedPaths {
		resolvedPath, err = evalSymlinksExceptProcfs(path)
		if err != nil {
			return "", err
		}
		absPath, err = filepath.Abs(resolvedPath)
		if err != nil {
			return "", err
		}
		log.Tracef("path %q absPath %q resolvedPath %q\n", path, absPath, resolvedPath)
		if strings.HasPrefix(absPath, absBase) {
			break
		}
	}

	// if we don't encounter base, return the resolved path (which could be relative)
	// note, the absolutePath is absolute, so we don't want to return that one
	if !strings.HasPrefix(absPath, absBase) {
		log.Tracef("prefix not found, resolved path = %s", resolvedPath)
		return resolvedPath, nil
	}

	chrootPath := strings.TrimPrefix(source, path)
	if chrootPath == "" {
		log.Tracef("resolved path = %s", resolvedPath)
		return resolvedPath, nil
	}

	log.Tracef("found chroot symlink, chrootPath %q, absPath: %q, base %q, absBase %q, index %d, path %q", chrootPath, absPath, base, absBase, index, path)

	normalizedPath, err := procfsroot.EvalSymlinks(chrootPath, absBase, procfsroot.EvalFullPath)
	if err != nil {
		return "", fmt.Errorf("could not evaluate source=%q, base=%q absBase=%q symlinks: %w", source, base, absBase, err)
	}

	log.Tracef("resolved path = %s", base+normalizedPath)
	// we use base instead of absBase, since base could be relative
	// it's the same argument as returning resolvedPath instead of absResolvedPath
	return base + normalizedPath, nil
}

func getProcfsCwd(base string) (string, error) {
	inProcfs, err := isPathInProcfsPid(base)
	if err != nil {
		return "", err
	}
	if !inProcfs {
		return "", fmt.Errorf("path %q not in procfs", base)
	}

	components := strings.Split(base, "/")
	pidStr := components[2]

	processProcfsCwd := filepath.Join("/proc", pidStr, "cwd")
	processProcfsCwd, err = os.Readlink(processProcfsCwd)
	if err != nil {
		return "", err
	}
	log.Tracef("base: %q, processProcfsCwd %q", base, processProcfsCwd)
	return filepath.Join("/proc", pidStr, "root", processProcfsCwd), nil
}

func NormalizeRootDirectory(root string, base string) (string, error) {
	cleanRoot, err := EvalSymlinksRelativeToBase(root, base)
	if err != nil {
		return "", fmt.Errorf("could not evaluate root=%q symlinks: %w", root, err)
	}

	return cleanRoot, nil
}

func isPathInProcfsPid(path string) (bool, error) {
	match, err := regexp.MatchString("/proc/[1-9][0-9]*/root", path)
	if err != nil {
		return false, err
	}
	return match, nil
}

// If both source and base are absolute we support base being a symlink
// This is mainly needed for procfs paths, e.g. /proc/PID/root, where
// PID could be in a different mount namespace, so we can't follow the
// symlink
func evalSymlinksExceptProcfs(path string) (string, error) {
	// don't follow symlink for paths in procfs
	inProcfs, err := isPathInProcfsPid(path)
	if err != nil {
		return "", err
	}
	if inProcfs {
		return path, nil
	}
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("could not evaluate path=%q err: %w", path, err)
	}
	return resolvedPath, nil
}

func NormalizeBaseDirectory(base string) (string, error) {
	var cleanBase string
	var err error
	if base == "" {
		return "", nil
	}

	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}

	cleanBase, err = evalSymlinksExceptProcfs(absBase)
	if err != nil {
		return "", fmt.Errorf("could not evaluate base=%q symlinks: %w", base, err)
	}

	return cleanBase, nil
}

// Root returns the root path with all symlinks evaluated.
func (r ChrootContext) Root() string {
	return r.root
}

// Base returns the absolute base path with all symlinks evaluated.
func (r ChrootContext) Base() string {
	return r.base
}

// ChangeRoot swaps the path for the chroot.
func (r *ChrootContext) ChangeRoot(dir string) error {
	newR, err := NewChrootContext(dir, r.base, r.cwd)
	if err != nil {
		return fmt.Errorf("could not change root: %w", err)
	}

	*r = *newR

	return nil
}

// ChangeDirectory changes the current working directory so that any relative paths passed
// into ToNativePath() and ToChrootPath() honor the new CWD. If the process changes the CWD in-flight, this should be
// called again to ensure correct functionality of ToNativePath() and ToChrootPath().
func (r *ChrootContext) ChangeDirectory(dir string) error {
	var (
		cwdRelativeToRoot string
		err               error
	)

	dir, err = filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("could not determine absolute path to CWD: %w", err)
	}

	if path.IsAbs(r.root) {
		cwdRelativeToRoot, err = filepath.Rel(dir, r.root)
		if err != nil {
			return fmt.Errorf("could not determine given root path to CWD: %w", err)
		}
	} else {
		cwdRelativeToRoot = filepath.Clean(r.root)
	}

	r.cwd = dir
	r.cwdRelativeToRoot = cwdRelativeToRoot
	return nil
}

// ToNativePath takes a path in the context of the chroot-like filesystem and converts it to a path in the underlying fs domain.
func (r ChrootContext) ToNativePath(chrootPath string) (string, error) {
	responsePath := chrootPath

	if filepath.IsAbs(responsePath) {
		// don't allow input to potentially hop above root path
		responsePath = path.Join(r.root, responsePath)
	} else {
		// ensure we take into account any relative difference between the root path and the CWD for relative requests
		responsePath = path.Join(r.cwdRelativeToRoot, responsePath)
	}

	var err error
	responsePath, err = filepath.Abs(responsePath)
	if err != nil {
		return "", err
	}
	return responsePath, nil
}

func (r ChrootContext) ToNativeGlob(chrootPath string) (string, error) {
	// split on any *
	parts := strings.Split(chrootPath, "*")
	if len(parts) == 0 || parts[0] == "" {
		// either this is an empty string or a path that starts with * so there is nothing we can do
		return chrootPath, nil
	}

	if len(parts) == 1 {
		// this has no glob, treat it like a path
		return r.ToNativePath(chrootPath)
	}

	responsePath, err := r.ToNativePath(parts[0])
	if err != nil {
		return "", err
	}

	parts[0] = strings.TrimRight(responsePath, "/") + "/"

	return strings.Join(parts, "*"), nil
}

// ToChrootPath takes a path from the underlying fs domain and converts it to a path that is relative to the current root context.
func (r ChrootContext) ToChrootPath(nativePath string) string {
	responsePath := nativePath
	// check to see if we need to encode back to Windows from posix
	if windows.HostRunningOnWindows() {
		responsePath = windows.FromPosix(responsePath)
	}

	// clean references to the request path (either the root, or the base if set)
	if filepath.IsAbs(responsePath) {
		var prefix string
		if r.base != "" {
			prefix = r.base
		} else {
			// we need to account for the cwd relative to the running process and the given root for the directory resolver
			prefix = filepath.Clean(filepath.Join(r.cwd, r.cwdRelativeToRoot))
			prefix += string(filepath.Separator)
		}
		responsePath = strings.TrimPrefix(responsePath, prefix)
	}

	return responsePath
}
