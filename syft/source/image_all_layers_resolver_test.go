package source

import (
	"io"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/imagetest"
)

type resolution struct {
	layer uint
	path  string
}

func TestAllLayersResolver_FilesByPath(t *testing.T) {
	cases := []struct {
		name                 string
		linkPath             string
		resolutions          []resolution
		forcePositiveHasPath bool
	}{
		{
			name:     "link with previous data",
			linkPath: "/link-1",
			resolutions: []resolution{
				{
					layer: 1,
					path:  "/file-1.txt",
				},
			},
		},
		{
			name:     "link with in layer data",
			linkPath: "/link-within",
			resolutions: []resolution{
				{
					layer: 5,
					path:  "/file-3.txt",
				},
			},
		},
		{
			name:     "link with overridden data",
			linkPath: "/link-2",
			resolutions: []resolution{
				{
					layer: 4,
					path:  "/file-2.txt",
				},
				{
					layer: 7,
					path:  "/file-2.txt",
				},
			},
		},
		{
			name:     "indirect link (with overridden data)",
			linkPath: "/link-indirect",
			resolutions: []resolution{
				{
					layer: 4,
					path:  "/file-2.txt",
				},
				{
					layer: 7,
					path:  "/file-2.txt",
				},
			},
		},
		{
			name:                 "dead link",
			linkPath:             "/link-dead",
			resolutions:          []resolution{},
			forcePositiveHasPath: true,
		},
		{
			name:        "ignore directories",
			linkPath:    "/bin",
			resolutions: []resolution{},
			// directories don't resolve BUT do exist
			forcePositiveHasPath: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			img := imagetest.GetFixtureImage(t, "docker-archive", "image-symlinks")

			resolver, err := newAllLayersResolver(img)
			if err != nil {
				t.Fatalf("could not create resolver: %+v", err)
			}

			hasPath := resolver.HasPath(c.linkPath)
			if !c.forcePositiveHasPath {
				if len(c.resolutions) > 0 && !hasPath {
					t.Errorf("expected HasPath() to indicate existance, but did not")
				} else if len(c.resolutions) == 0 && hasPath {
					t.Errorf("expeced HasPath() to NOT indicate existance, but does")
				}
			} else if !hasPath {
				t.Errorf("expected HasPath() to indicate existance, but did not (force path)")
			}

			refs, err := resolver.FilesByPath(c.linkPath)
			if err != nil {
				t.Fatalf("could not use resolver: %+v", err)
			}

			if len(refs) != len(c.resolutions) {
				t.Fatalf("unexpected number of resolutions: %d", len(refs))
			}

			for idx, actual := range refs {
				expected := c.resolutions[idx]

				if string(actual.ref.RealPath) != expected.path {
					t.Errorf("bad resolve path: '%s'!='%s'", string(actual.ref.RealPath), expected.path)
				}

				if expected.path != "" && string(actual.ref.RealPath) != actual.RealPath {
					t.Errorf("we should always prefer real paths over ones with links")
				}

				layer := img.FileCatalog.Layer(actual.ref)
				if layer.Metadata.Index != expected.layer {
					t.Errorf("bad resolve layer: '%d'!='%d'", layer.Metadata.Index, expected.layer)
				}
			}
		})
	}
}

func TestAllLayersResolver_FilesByGlob(t *testing.T) {
	cases := []struct {
		name        string
		glob        string
		resolutions []resolution
	}{
		{
			name: "link with previous data",
			glob: "**/*ink-1",
			resolutions: []resolution{
				{
					layer: 1,
					path:  "/file-1.txt",
				},
			},
		},
		{
			name: "link with in layer data",
			glob: "**/*nk-within",
			resolutions: []resolution{
				{
					layer: 5,
					path:  "/file-3.txt",
				},
			},
		},
		{
			name: "link with overridden data",
			glob: "**/*ink-2",
			resolutions: []resolution{
				{
					layer: 4,
					path:  "/file-2.txt",
				},
				{
					layer: 7,
					path:  "/file-2.txt",
				},
			},
		},
		{
			name: "indirect link (with overridden data)",
			glob: "**/*nk-indirect",
			resolutions: []resolution{
				{
					layer: 4,
					path:  "/file-2.txt",
				},
				{
					layer: 7,
					path:  "/file-2.txt",
				},
			},
		},
		{
			name:        "dead link",
			glob:        "**/*k-dead",
			resolutions: []resolution{},
		},
		{
			name:        "ignore directories",
			glob:        "**/bin",
			resolutions: []resolution{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			img := imagetest.GetFixtureImage(t, "docker-archive", "image-symlinks")

			resolver, err := newAllLayersResolver(img)
			if err != nil {
				t.Fatalf("could not create resolver: %+v", err)
			}

			refs, err := resolver.FilesByGlob(c.glob)
			if err != nil {
				t.Fatalf("could not use resolver: %+v", err)
			}

			if len(refs) != len(c.resolutions) {
				t.Fatalf("unexpected number of resolutions: %d", len(refs))
			}

			for idx, actual := range refs {
				expected := c.resolutions[idx]

				if string(actual.ref.RealPath) != expected.path {
					t.Errorf("bad resolve path: '%s'!='%s'", string(actual.ref.RealPath), expected.path)
				}

				if expected.path != "" && string(actual.ref.RealPath) != actual.RealPath {
					t.Errorf("we should always prefer real paths over ones with links")
				}

				layer := img.FileCatalog.Layer(actual.ref)

				if layer.Metadata.Index != expected.layer {
					t.Errorf("bad resolve layer: '%d'!='%d'", layer.Metadata.Index, expected.layer)
				}
			}
		})
	}
}

func Test_imageAllLayersResolver_FilesByMIMEType(t *testing.T) {

	tests := []struct {
		fixtureName   string
		mimeType      string
		expectedPaths []string
	}{
		{
			fixtureName:   "image-duplicate-path",
			mimeType:      "text/plain",
			expectedPaths: []string{"/somefile-1.txt", "/somefile-1.txt"},
		},
	}
	for _, test := range tests {
		t.Run(test.fixtureName, func(t *testing.T) {
			img := imagetest.GetFixtureImage(t, "docker-archive", test.fixtureName)

			resolver, err := newAllLayersResolver(img)
			assert.NoError(t, err)

			locations, err := resolver.FilesByMIMEType(test.mimeType)
			assert.NoError(t, err)

			assert.Len(t, test.expectedPaths, len(locations))
			for idx, l := range locations {
				assert.Equal(t, test.expectedPaths[idx], l.RealPath, "does not have path %q", l.RealPath)
			}
		})
	}
}

func Test_imageAllLayersResolver_hasFilesystemIDInLocation(t *testing.T) {
	img := imagetest.GetFixtureImage(t, "docker-archive", "image-duplicate-path")

	resolver, err := newAllLayersResolver(img)
	assert.NoError(t, err)

	locations, err := resolver.FilesByMIMEType("text/plain")
	assert.NoError(t, err)
	assert.NotEmpty(t, locations)
	for _, location := range locations {
		assert.NotEmpty(t, location.FileSystemID)
	}

	locations, err = resolver.FilesByGlob("*.txt")
	assert.NoError(t, err)
	assert.NotEmpty(t, locations)
	for _, location := range locations {
		assert.NotEmpty(t, location.FileSystemID)
	}

	locations, err = resolver.FilesByPath("/somefile-1.txt")
	assert.NoError(t, err)
	assert.NotEmpty(t, locations)
	for _, location := range locations {
		assert.NotEmpty(t, location.FileSystemID)
	}

}

func TestAllLayersImageResolver_FilesContents(t *testing.T) {

	tests := []struct {
		name     string
		fixture  string
		contents []string
	}{
		{
			name:    "one degree",
			fixture: "link-2",
			contents: []string{
				"file 2!",            // from the first resolved layer's perspective
				"NEW file override!", // from the second resolved layers perspective
			},
		},
		{
			name:    "two degrees",
			fixture: "link-indirect",
			contents: []string{
				"file 2!",
				"NEW file override!",
			},
		},
		{
			name:     "dead link",
			fixture:  "link-dead",
			contents: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			img := imagetest.GetFixtureImage(t, "docker-archive", "image-symlinks")

			resolver, err := newAllLayersResolver(img)
			assert.NoError(t, err)

			refs, err := resolver.FilesByPath(test.fixture)
			require.NoError(t, err)

			// the given path should have an overridden file
			require.Len(t, refs, len(test.contents))

			for idx, loc := range refs {
				reader, err := resolver.FileContentsByLocation(loc)
				require.NoError(t, err)

				actual, err := io.ReadAll(reader)
				require.NoError(t, err)

				assert.Equal(t, test.contents[idx], string(actual))
			}

		})
	}
}

func TestAllLayersImageResolver_FilesContents_errorOnDirRequest(t *testing.T) {

	img := imagetest.GetFixtureImage(t, "docker-archive", "image-symlinks")

	resolver, err := newAllLayersResolver(img)
	assert.NoError(t, err)

	var dirLoc *Location
	for loc := range resolver.AllLocations() {
		entry, err := resolver.img.FileCatalog.Get(loc.ref)
		require.NoError(t, err)
		if entry.Metadata.IsDir {
			dirLoc = &loc
			break
		}
	}

	require.NotNil(t, dirLoc)

	reader, err := resolver.FileContentsByLocation(*dirLoc)
	require.Error(t, err)
	require.Nil(t, reader)
}

func Test_imageAllLayersResolver_resolvesLinks(t *testing.T) {
	tests := []struct {
		name     string
		runner   func(FileResolver) []Location
		expected []Location
	}{
		{
			name: "by mimetype",
			runner: func(resolver FileResolver) []Location {
				// links should not show up when searching mimetype
				actualLocations, err := resolver.FilesByMIMEType("text/plain")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []Location{
				{
					Coordinates: Coordinates{
						RealPath: "/etc/group",
					},
					VirtualPath: "/etc/group",
				},
				{
					Coordinates: Coordinates{
						RealPath: "/etc/passwd",
					},
					VirtualPath: "/etc/passwd",
				},
				{
					Coordinates: Coordinates{
						RealPath: "/etc/shadow",
					},
					VirtualPath: "/etc/shadow",
				},
				{
					Coordinates: Coordinates{
						RealPath: "/file-1.txt",
					},
					VirtualPath: "/file-1.txt",
				},
				// copy 1
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/file-2.txt",
				},
				// note: we're de-duping the redundant access to file-3.txt
				// ... (there would usually be two copies)
				{
					Coordinates: Coordinates{
						RealPath: "/file-3.txt",
					},
					VirtualPath: "/file-3.txt",
				},
				// copy 2
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/file-2.txt",
				},
				// copy 1
				{
					Coordinates: Coordinates{
						RealPath: "/parent/file-4.txt",
					},
					VirtualPath: "/parent/file-4.txt",
				},
				// copy 2
				{
					Coordinates: Coordinates{
						RealPath: "/parent/file-4.txt",
					},
					VirtualPath: "/parent/file-4.txt",
				},
			},
		},
		{
			name: "by glob to links",
			runner: func(resolver FileResolver) []Location {
				// links are searched, but resolve to the real files
				actualLocations, err := resolver.FilesByGlob("*ink-*")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []Location{
				{
					Coordinates: Coordinates{
						RealPath: "/file-1.txt",
					},
					VirtualPath: "/link-1",
				},
				// copy 1
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/link-2",
				},
				// copy 2
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/link-2",
				},
				{
					Coordinates: Coordinates{
						RealPath: "/file-3.txt",
					},
					VirtualPath: "/link-within",
				},
			},
		},
		{
			name: "by basename",
			runner: func(resolver FileResolver) []Location {
				// links are searched, but resolve to the real files
				actualLocations, err := resolver.FilesByGlob("**/file-2.txt")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []Location{
				// copy 1
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/file-2.txt",
				},
				// copy 2
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/file-2.txt",
				},
			},
		},
		{
			name: "by basename glob",
			runner: func(resolver FileResolver) []Location {
				// links are searched, but resolve to the real files
				actualLocations, err := resolver.FilesByGlob("**/file-?.txt")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []Location{
				{
					Coordinates: Coordinates{
						RealPath: "/file-1.txt",
					},
					VirtualPath: "/file-1.txt",
				},
				// copy 1
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/file-2.txt",
				},
				// copy 2
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/file-2.txt",
				},
				{
					Coordinates: Coordinates{
						RealPath: "/file-3.txt",
					},
					VirtualPath: "/file-3.txt",
				},
				{
					Coordinates: Coordinates{
						RealPath: "/parent/file-4.txt",
					},
					VirtualPath: "/parent/file-4.txt",
				},
				// when we copy into the link path, the same file-4.txt is copied
				{
					Coordinates: Coordinates{
						RealPath: "/parent/file-4.txt",
					},
					VirtualPath: "/parent/file-4.txt",
				},
			},
		},
		{
			name: "by extension",
			runner: func(resolver FileResolver) []Location {
				// links are searched, but resolve to the real files
				actualLocations, err := resolver.FilesByGlob("**/*.txt")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []Location{
				{
					Coordinates: Coordinates{
						RealPath: "/file-1.txt",
					},
					VirtualPath: "/file-1.txt",
				},
				// copy 1
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/file-2.txt",
				},
				// copy 2
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/file-2.txt",
				},
				{
					Coordinates: Coordinates{
						RealPath: "/file-3.txt",
					},
					VirtualPath: "/file-3.txt",
				},
				{
					Coordinates: Coordinates{
						RealPath: "/parent/file-4.txt",
					},
					VirtualPath: "/parent/file-4.txt",
				},
				// when we copy into the link path, the same file-4.txt is copied
				{
					Coordinates: Coordinates{
						RealPath: "/parent/file-4.txt",
					},
					VirtualPath: "/parent/file-4.txt",
				},
			},
		},
		{
			name: "by path to degree 1 link",
			runner: func(resolver FileResolver) []Location {
				// links resolve to the final file
				actualLocations, err := resolver.FilesByPath("/link-2")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []Location{
				// we have multiple copies across layers
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/link-2",
				},
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/link-2",
				},
			},
		},
		{
			name: "by path to degree 2 link",
			runner: func(resolver FileResolver) []Location {
				// multiple links resolves to the final file
				actualLocations, err := resolver.FilesByPath("/link-indirect")
				assert.NoError(t, err)
				return actualLocations
			},
			expected: []Location{
				// we have multiple copies across layers
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/link-indirect",
				},
				{
					Coordinates: Coordinates{
						RealPath: "/file-2.txt",
					},
					VirtualPath: "/link-indirect",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			img := imagetest.GetFixtureImage(t, "docker-archive", "image-symlinks")

			resolver, err := newAllLayersResolver(img)
			assert.NoError(t, err)

			actual := test.runner(resolver)

			compareLocations(t, test.expected, actual)
		})
	}

}

func TestAllLayersResolver_AllLocations(t *testing.T) {
	img := imagetest.GetFixtureImage(t, "docker-archive", "image-symlinks")

	resolver, err := newAllLayersResolver(img)
	assert.NoError(t, err)

	paths := strset.New()
	for loc := range resolver.AllLocations() {
		paths.Add(loc.RealPath)
	}
	expected := []string{
		"/file-1.txt",
		"/file-2.txt",
		"/file-3.txt",
		"/link-1",
		"/link-2",
		"/link-dead",
		"/link-indirect",
		"/link-within",
		"/parent",
		"/parent-link",
		"/parent/file-4.txt",

		// from base image...
		"/bin",
		"/bin/[",
		"/bin/[[",
		"/bin/acpid",
		"/bin/add-shell",
		"/bin/addgroup",
		"/bin/adduser",
		"/bin/adjtimex",
		"/bin/ar",
		"/bin/arch",
		"/bin/arp",
		"/bin/arping",
		"/bin/ascii",
		"/bin/ash",
		"/bin/awk",
		"/bin/base32",
		"/bin/base64",
		"/bin/basename",
		"/bin/bc",
		"/bin/beep",
		"/bin/blkdiscard",
		"/bin/blkid",
		"/bin/blockdev",
		"/bin/bootchartd",
		"/bin/brctl",
		"/bin/bunzip2",
		"/bin/busybox",
		"/bin/bzcat",
		"/bin/bzip2",
		"/bin/cal",
		"/bin/cat",
		"/bin/chat",
		"/bin/chattr",
		"/bin/chgrp",
		"/bin/chmod",
		"/bin/chown",
		"/bin/chpasswd",
		"/bin/chpst",
		"/bin/chroot",
		"/bin/chrt",
		"/bin/chvt",
		"/bin/cksum",
		"/bin/clear",
		"/bin/cmp",
		"/bin/comm",
		"/bin/conspy",
		"/bin/cp",
		"/bin/cpio",
		"/bin/crc32",
		"/bin/crond",
		"/bin/crontab",
		"/bin/cryptpw",
		"/bin/cttyhack",
		"/bin/cut",
		"/bin/date",
		"/bin/dc",
		"/bin/dd",
		"/bin/deallocvt",
		"/bin/delgroup",
		"/bin/deluser",
		"/bin/depmod",
		"/bin/devmem",
		"/bin/df",
		"/bin/dhcprelay",
		"/bin/diff",
		"/bin/dirname",
		"/bin/dmesg",
		"/bin/dnsd",
		"/bin/dnsdomainname",
		"/bin/dos2unix",
		"/bin/dpkg",
		"/bin/dpkg-deb",
		"/bin/du",
		"/bin/dumpkmap",
		"/bin/dumpleases",
		"/bin/echo",
		"/bin/ed",
		"/bin/egrep",
		"/bin/eject",
		"/bin/env",
		"/bin/envdir",
		"/bin/envuidgid",
		"/bin/ether-wake",
		"/bin/expand",
		"/bin/expr",
		"/bin/factor",
		"/bin/fakeidentd",
		"/bin/fallocate",
		"/bin/false",
		"/bin/fatattr",
		"/bin/fbset",
		"/bin/fbsplash",
		"/bin/fdflush",
		"/bin/fdformat",
		"/bin/fdisk",
		"/bin/fgconsole",
		"/bin/fgrep",
		"/bin/find",
		"/bin/findfs",
		"/bin/flock",
		"/bin/fold",
		"/bin/free",
		"/bin/freeramdisk",
		"/bin/fsck",
		"/bin/fsck.minix",
		"/bin/fsfreeze",
		"/bin/fstrim",
		"/bin/fsync",
		"/bin/ftpd",
		"/bin/ftpget",
		"/bin/ftpput",
		"/bin/fuser",
		"/bin/getconf",
		"/bin/getopt",
		"/bin/getty",
		"/bin/grep",
		"/bin/groups",
		"/bin/gunzip",
		"/bin/gzip",
		"/bin/halt",
		"/bin/hd",
		"/bin/hdparm",
		"/bin/head",
		"/bin/hexdump",
		"/bin/hexedit",
		"/bin/hostid",
		"/bin/hostname",
		"/bin/httpd",
		"/bin/hush",
		"/bin/hwclock",
		"/bin/i2cdetect",
		"/bin/i2cdump",
		"/bin/i2cget",
		"/bin/i2cset",
		"/bin/i2ctransfer",
		"/bin/id",
		"/bin/ifconfig",
		"/bin/ifdown",
		"/bin/ifenslave",
		"/bin/ifplugd",
		"/bin/ifup",
		"/bin/inetd",
		"/bin/init",
		"/bin/insmod",
		"/bin/install",
		"/bin/ionice",
		"/bin/iostat",
		"/bin/ip",
		"/bin/ipaddr",
		"/bin/ipcalc",
		"/bin/ipcrm",
		"/bin/ipcs",
		"/bin/iplink",
		"/bin/ipneigh",
		"/bin/iproute",
		"/bin/iprule",
		"/bin/iptunnel",
		"/bin/kbd_mode",
		"/bin/kill",
		"/bin/killall",
		"/bin/killall5",
		"/bin/klogd",
		"/bin/last",
		"/bin/less",
		"/bin/link",
		"/bin/linux32",
		"/bin/linux64",
		"/bin/linuxrc",
		"/bin/ln",
		"/bin/loadfont",
		"/bin/loadkmap",
		"/bin/logger",
		"/bin/login",
		"/bin/logname",
		"/bin/logread",
		"/bin/losetup",
		"/bin/lpd",
		"/bin/lpq",
		"/bin/lpr",
		"/bin/ls",
		"/bin/lsattr",
		"/bin/lsmod",
		"/bin/lsof",
		"/bin/lspci",
		"/bin/lsscsi",
		"/bin/lsusb",
		"/bin/lzcat",
		"/bin/lzma",
		"/bin/lzop",
		"/bin/makedevs",
		"/bin/makemime",
		"/bin/man",
		"/bin/md5sum",
		"/bin/mdev",
		"/bin/mesg",
		"/bin/microcom",
		"/bin/mim",
		"/bin/mkdir",
		"/bin/mkdosfs",
		"/bin/mke2fs",
		"/bin/mkfifo",
		"/bin/mkfs.ext2",
		"/bin/mkfs.minix",
		"/bin/mkfs.vfat",
		"/bin/mknod",
		"/bin/mkpasswd",
		"/bin/mkswap",
		"/bin/mktemp",
		"/bin/modinfo",
		"/bin/modprobe",
		"/bin/more",
		"/bin/mount",
		"/bin/mountpoint",
		"/bin/mpstat",
		"/bin/mt",
		"/bin/mv",
		"/bin/nameif",
		"/bin/nanddump",
		"/bin/nandwrite",
		"/bin/nbd-client",
		"/bin/nc",
		"/bin/netstat",
		"/bin/nice",
		"/bin/nl",
		"/bin/nmeter",
		"/bin/nohup",
		"/bin/nologin",
		"/bin/nproc",
		"/bin/nsenter",
		"/bin/nslookup",
		"/bin/ntpd",
		"/bin/od",
		"/bin/openvt",
		"/bin/partprobe",
		"/bin/passwd",
		"/bin/paste",
		"/bin/patch",
		"/bin/pgrep",
		"/bin/pidof",
		"/bin/ping",
		"/bin/ping6",
		"/bin/pipe_progress",
		"/bin/pivot_root",
		"/bin/pkill",
		"/bin/pmap",
		"/bin/popmaildir",
		"/bin/poweroff",
		"/bin/powertop",
		"/bin/printenv",
		"/bin/printf",
		"/bin/ps",
		"/bin/pscan",
		"/bin/pstree",
		"/bin/pwd",
		"/bin/pwdx",
		"/bin/raidautorun",
		"/bin/rdate",
		"/bin/rdev",
		"/bin/readahead",
		"/bin/readlink",
		"/bin/readprofile",
		"/bin/realpath",
		"/bin/reboot",
		"/bin/reformime",
		"/bin/remove-shell",
		"/bin/renice",
		"/bin/reset",
		"/bin/resize",
		"/bin/resume",
		"/bin/rev",
		"/bin/rm",
		"/bin/rmdir",
		"/bin/rmmod",
		"/bin/route",
		"/bin/rpm",
		"/bin/rpm2cpio",
		"/bin/rtcwake",
		"/bin/run-init",
		"/bin/run-parts",
		"/bin/runlevel",
		"/bin/runsv",
		"/bin/runsvdir",
		"/bin/rx",
		"/bin/script",
		"/bin/scriptreplay",
		"/bin/sed",
		"/bin/sendmail",
		"/bin/seq",
		"/bin/setarch",
		"/bin/setconsole",
		"/bin/setfattr",
		"/bin/setfont",
		"/bin/setkeycodes",
		"/bin/setlogcons",
		"/bin/setpriv",
		"/bin/setserial",
		"/bin/setsid",
		"/bin/setuidgid",
		"/bin/sh",
		"/bin/sha1sum",
		"/bin/sha256sum",
		"/bin/sha3sum",
		"/bin/sha512sum",
		"/bin/showkey",
		"/bin/shred",
		"/bin/shuf",
		"/bin/slattach",
		"/bin/sleep",
		"/bin/smemcap",
		"/bin/softlimit",
		"/bin/sort",
		"/bin/split",
		"/bin/ssl_client",
		"/bin/start-stop-daemon",
		"/bin/stat",
		"/bin/strings",
		"/bin/stty",
		"/bin/su",
		"/bin/sulogin",
		"/bin/sum",
		"/bin/sv",
		"/bin/svc",
		"/bin/svlogd",
		"/bin/svok",
		"/bin/swapoff",
		"/bin/swapon",
		"/bin/switch_root",
		"/bin/sync",
		"/bin/sysctl",
		"/bin/syslogd",
		"/bin/tac",
		"/bin/tail",
		"/bin/tar",
		"/bin/taskset",
		"/bin/tc",
		"/bin/tcpsvd",
		"/bin/tee",
		"/bin/telnet",
		"/bin/telnetd",
		"/bin/test",
		"/bin/tftp",
		"/bin/tftpd",
		"/bin/time",
		"/bin/timeout",
		"/bin/top",
		"/bin/touch",
		"/bin/tr",
		"/bin/traceroute",
		"/bin/traceroute6",
		"/bin/true",
		"/bin/truncate",
		"/bin/ts",
		"/bin/tty",
		"/bin/ttysize",
		"/bin/tunctl",
		"/bin/ubiattach",
		"/bin/ubidetach",
		"/bin/ubimkvol",
		"/bin/ubirename",
		"/bin/ubirmvol",
		"/bin/ubirsvol",
		"/bin/ubiupdatevol",
		"/bin/udhcpc",
		"/bin/udhcpc6",
		"/bin/udhcpd",
		"/bin/udpsvd",
		"/bin/uevent",
		"/bin/umount",
		"/bin/uname",
		"/bin/unexpand",
		"/bin/uniq",
		"/bin/unix2dos",
		"/bin/unlink",
		"/bin/unlzma",
		"/bin/unshare",
		"/bin/unxz",
		"/bin/unzip",
		"/bin/uptime",
		"/bin/users",
		"/bin/usleep",
		"/bin/uudecode",
		"/bin/uuencode",
		"/bin/vconfig",
		"/bin/vi",
		"/bin/vlock",
		"/bin/volname",
		"/bin/w",
		"/bin/wall",
		"/bin/watch",
		"/bin/watchdog",
		"/bin/wc",
		"/bin/wget",
		"/bin/which",
		"/bin/who",
		"/bin/whoami",
		"/bin/whois",
		"/bin/xargs",
		"/bin/xxd",
		"/bin/xz",
		"/bin/xzcat",
		"/bin/yes",
		"/bin/zcat",
		"/bin/zcip",
		"/dev",
		"/etc",
		"/etc/group",
		"/etc/localtime",
		"/etc/network",
		"/etc/network/if-down.d",
		"/etc/network/if-post-down.d",
		"/etc/network/if-pre-up.d",
		"/etc/network/if-up.d",
		"/etc/passwd",
		"/etc/shadow",
		"/home",
		"/proc",
		"/root",
		"/sys",
		"/tmp",
		"/usr",
		"/usr/sbin",
		"/var",
		"/var/spool",
		"/var/spool/mail",
		"/var/www",
	}

	pathsList := paths.List()
	sort.Strings(pathsList)

	assert.ElementsMatchf(t, expected, pathsList, "expected all paths to be indexed, but found different paths: \n%s", cmp.Diff(expected, paths.List()))
}
