package fileresolver

import (
	"github.com/anchore/syft/internal/log"
	"github.com/moby/sys/mountinfo"
	"io/fs"
	"os"
	"sort"
	"strings"
)

// ignorableMountTypes is a set of mount types that should be ignored.
var ignorableMountTypes = map[string]struct{}{
	"proc":     {},
	"sysfs":    {},
	"devfs":    {},
	"devtmpfs": {},
}

// tmpfsSuffixes is a list of paths that we ignore a tmpfs at. For example
// in some containers /dev is mounted as a tmpfs, but should be ignored
var tmpfsSuffixes = []string{"/run", "/dev", "/var/run", "/var/lock", "/sys"}

// NewPathSkipper accepts the root and base paths, just as a new directory scanner does.
// It returns a PathIndexVisitor that is meant to skip directories with files that
// block forever when read from, never terminate, etc, such as /dev/random, while
// including as far as possible everything else.
// It is meant to allow scanning / on a Linux host to succeed, while also not
// causing any files in a narrow directory scan to be skipped unnecessarily.
func NewPathSkipper(root string, base string) PathIndexVisitor {
	infos, err := mountinfo.GetMounts(nil)
	if err != nil {
		log.WithFields("error", err).Warnf("unable to get system mounts")
		// TODO: better / safe to just return nil?
		return func(_ string, _ string, _ os.FileInfo, _ error) error {
			return nil
		}
	}
	return newPathSkipper(root, base, infos)
}

func newPathSkipper(_ string, _ string, mountInfos []*mountinfo.Info) PathIndexVisitor {
	// The longest path is the most specific path, e.g.
	// if / is mounted as tmpfs, but /home/syft/permanent is mounted as ext4,
	// then the mount type for /home/syft/permanent/foo is ext4, and the mount info
	// stating that /home/syft/permanent is ext4 has the longer mount point.
	sort.Slice(mountInfos, func(i, j int) bool {
		return len(mountInfos[i].Mountpoint) > len(mountInfos[j].Mountpoint)
	})
	// TODO: what's the differencces between base and scan target?
	return func(scanTarget string, path string, info os.FileInfo, err error) error {
		// Rule 1: don't entirely ignore the dir we're supposed to be scanning
		if path == scanTarget {
			return nil
		}

		// Rule 2: ignore mount types that typically contain never ending files
		for _, mi := range mountInfos {
			if strings.HasPrefix(path, mi.Mountpoint) {
				if _, ignorable := ignorableMountTypes[mi.FSType]; ignorable {
					return fs.SkipDir
				}
				break
			}
		}

		// Rule 3: if there's a suspicious looking path, like /dev, mounted as a tmpfs
		// then skip that. But don't skip tmpfs by default, because untaring an artifact
		// to /tmp and then scanning it is a common use case.
		for _, suffix := range tmpfsSuffixes {
			if strings.HasSuffix(path, suffix) {
				for _, mi := range mountInfos {
					if strings.HasPrefix(path, mi.Mountpoint) && mi.FSType == "tmpfs" {
						return fs.SkipDir
					}
				}
			}
		}

		return nil
	}
}
