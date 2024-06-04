package fileresolver

import (
	"io/fs"
	"os"
	"sort"
	"strings"

	"github.com/moby/sys/mountinfo"

	"github.com/anchore/syft/internal/log"
)

type pathSkipper struct {
	// scanTarget is the root path that is being scanned (without any base-path logic applied).
	scanTarget string

	// ignorableMountTypes is a set of mount types that should be ignored. Optionally a list of paths (the map values)
	// can be provided that this mount type should be ignored at.  For example in some containers /dev is mounted
	// as a tmpfs and should be ignored, but /tmp should not be ignored. An empty list of paths means that paths
	// within the mount type should always be ignored.
	ignorableMountTypes map[string][]string

	// current mount paths for the current system
	mounts       []*mountinfo.Info
	mountsByType map[string][]*mountinfo.Info
}

// skipPathsByMountTypeAndName accepts the root path and returns a PathIndexVisitor that will skip paths based
// the filesystem type, the mountpoint, and configured blocklist paths for each filesystem type.
// This will help syft dodge filesystem topologies that have the potential to make the search space much bigger in
// areas known to not traditionally contain files of interest (installed software).  It is meant to allow scanning
// "/" on a unix host to succeed, while also not causing any files in a narrow directory scan to be skipped unnecessarily.
func skipPathsByMountTypeAndName(root string) PathIndexVisitor {
	infos, err := mountinfo.GetMounts(nil)
	if err != nil {
		log.WithFields("error", err).Warnf("unable to get system mounts")
		return func(_ string, _ string, _ os.FileInfo, _ error) error {
			return nil
		}
	}

	return newPathSkipperFromMounts(root, infos).pathIndexVisitor
}

func newPathSkipperFromMounts(root string, infos []*mountinfo.Info) pathSkipper {
	// we're only interested in ignoring the logical filesystems typically found at these mount points:
	// - /proc
	//     - procfs
	//     - proc
	// - /sys
	//     - sysfs
	// - /dev
	//     - devfs - BSD/darwin flavored systems and old linux systems
	//     - devtmpfs - driver core maintained /dev tmpfs
	//     - udev - userspace implementation that replaced devfs
	//     - tmpfs - used for /dev in special instances (within a container)
	ignorableMountTypes := map[string][]string{
		"proc":     nil,
		"procfs":   nil,
		"sysfs":    nil,
		"devfs":    nil,
		"devtmpfs": nil,
		"udev":     nil,
		// note: there should be no order required (e.g. search /sys/thing before /sys) since that would imply that
		// we could not ignore a nested path within a path that would be ignored anyway.
		"tmpfs": {"/run", "/dev", "/var/run", "/var/lock", "/sys"},
	}

	// The longest path is the most specific path, e.g.
	// if / is mounted as tmpfs, but /home/syft/permanent is mounted as ext4,
	// then the mount type for /home/syft/permanent/foo is ext4, and the mount info
	// stating that /home/syft/permanent is ext4 has the longer mount point.
	sort.Slice(infos, func(i, j int) bool {
		return len(infos[i].Mountpoint) > len(infos[j].Mountpoint)
	})

	mountsByType := make(map[string][]*mountinfo.Info)

	for _, mi := range infos {
		mountsByType[mi.FSType] = append(mountsByType[mi.FSType], mi)
	}

	return pathSkipper{
		scanTarget:          root,
		ignorableMountTypes: ignorableMountTypes,
		mounts:              infos,
		mountsByType:        mountsByType,
	}
}

func (ps pathSkipper) pathIndexVisitor(_ string, givenPath string, _ os.FileInfo, _ error) error {
	for _, mi := range ps.mounts {
		conditionalPaths, ignorable := ps.ignorableMountTypes[mi.FSType]

		if len(conditionalPaths) == 0 {
			// Rule 1: ignore any path within a mount point that is of the given filesystem type unconditionally
			if !containsPath(givenPath, mi.Mountpoint) {
				continue
			}

			if !ignorable {
				// we've matched on the most specific path at this point, which means we should stop searching
				// mount points for this path
				break
			}

			log.WithFields(
				"path", givenPath,
				"mountpoint", mi.Mountpoint,
				"fs", mi.FSType,
			).Debug("ignoring path based on mountpoint filesystem type")

			return fs.SkipDir
		}

		// Rule 2: ignore any path within a mount point that is of the given filesystem type, only if
		// the path is on a known blocklist of paths for that filesystem type.
		// For example: /dev can be mounted as a tmpfs, which should always be skipped.
		for _, conditionalPath := range conditionalPaths {
			if !containsPath(givenPath, conditionalPath) {
				continue
			}

			log.WithFields(
				"path", givenPath,
				"mountpoint", mi.Mountpoint,
				"fs", mi.FSType,
				"condition", conditionalPath,
			).Debug("ignoring path based on mountpoint filesystem type")

			return fs.SkipDir
		}
	}

	return nil
}

func containsPath(p1, p2 string) bool {
	p1Clean := simpleClean(p1)
	p2Clean := simpleClean(p2)
	if p1Clean == p2Clean {
		return true
	}
	return strings.HasPrefix(p1Clean, p2Clean+"/")
}

func simpleClean(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "."
	}
	if p == "/" {
		return "/"
	}
	return strings.TrimSuffix(p, "/")
}
