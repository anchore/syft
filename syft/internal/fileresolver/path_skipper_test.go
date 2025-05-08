package fileresolver

import (
	"io/fs"
	"testing"

	"github.com/moby/sys/mountinfo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newPathSkipper(t *testing.T) {
	type expect struct {
		path    string
		wantErr assert.ErrorAssertionFunc
	}
	unixSubject := []*mountinfo.Info{
		{
			Mountpoint: "/proc",
			FSType:     "procfs",
		},
		{
			Mountpoint: "/sys",
			FSType:     "sysfs",
		},
		{
			Mountpoint: "/dev",
			FSType:     "devfs",
		},
		{
			Mountpoint: "/",
			FSType:     "/dev/disk3s1s1",
		},
		{
			Mountpoint: "/dev/shm",
			FSType:     "shm",
		},
		{
			Mountpoint: "/tmp",
			FSType:     "tmpfs",
		},
	}

	tests := []struct {
		name   string
		root   string
		base   string
		mounts []*mountinfo.Info
		want   []expect
	}{
		{
			name: "happy path",
			root: "/somewhere",
			mounts: []*mountinfo.Info{
				{
					Mountpoint: "/home/somewhere/else",
					FSType:     "/dev/disk3s6",
				},
				{
					Mountpoint: "/somewhere",
					FSType:     "/dev/disk3s7",
				},
			},
			want: []expect{
				{
					// within a known mountpoint with valid type (1)
					path: "/somewhere/dev",
				},
				{
					// is a known mountpoint with valid type
					path: "/somewhere",
				},
				{
					// within a known mountpoint with valid type (2)
					path: "/home/somewhere/else/too",
				},
				{
					// outside of any known mountpoint should not be an error
					path: "/bogus",
				},
			},
		},
		{
			name: "ignore paths within a scan target",
			root: "/somewhere",
			mounts: []*mountinfo.Info{
				{
					Mountpoint: "/somewhere/doesnt/matter/proc",
					FSType:     "procfs",
				},
				{
					Mountpoint: "/somewhere",
					FSType:     "/dev/disk3s7",
				},
			},
			want: []expect{
				{
					// within a known mountpoint with valid type (1)
					path: "/somewhere/dev",
				},
				{
					// is a known mountpoint with valid type
					path: "/somewhere",
				},
				{
					// mountpoint that should be ignored
					path:    "/somewhere/doesnt/matter/proc",
					wantErr: assertSkipErr(),
				},
				{
					// within a mountpoint that should be ignored
					path:    "/somewhere/doesnt/matter/proc",
					wantErr: assertSkipErr(),
				},
			},
		},
		{
			name: "nested mountpoints behave correctly",
			root: "/somewhere",
			mounts: []*mountinfo.Info{
				{
					Mountpoint: "/somewhere/dev",
					FSType:     "devfs",
				},
				{
					Mountpoint: "/somewhere/dev/includeme",
					FSType:     "/dev/disk3s7",
				},
			},
			want: []expect{
				{
					// is a known mountpoint with valid type
					path:    "/somewhere/dev",
					wantErr: assertSkipErr(),
				},
				{
					// is a known mountpoint with valid type
					path: "/somewhere/dev/includeme",
				},
				{
					// within a known mountpoint with valid type
					path: "/somewhere/dev/includeme/too!",
				},
			},
		},
		{
			name: "keep some tmpfs mounts conditionally",
			root: "/",
			mounts: []*mountinfo.Info{
				{
					Mountpoint: "/run/somewhere",
					FSType:     "tmpfs",
				},
				{
					Mountpoint: "/run/terrafirma",
					FSType:     "/dev/disk3s8",
				},
				{
					Mountpoint: "/tmp",
					FSType:     "tmpfs",
				},
				{
					Mountpoint: "/else/othertmp",
					FSType:     "tmpfs",
				},
				{
					Mountpoint: "/else/othertmp/includeme",
					FSType:     "/dev/disk3s7",
				},
			},
			want: []expect{
				{
					// since /run is explicitly ignored, this should be skipped
					path:    "/run/somewhere/else",
					wantErr: assertSkipErr(),
				},
				{
					path: "/run/terrafirma",
				},
				{
					path: "/run/terrafirma/nested",
				},
				{
					path: "/tmp",
				},
				{
					path: "/else/othertmp/includeme",
				},
				{
					path: "/else/othertmp/includeme/nested",
				},
				{
					// no mount path, so we should include it
					path: "/somewhere/dev/includeme",
				},
				{
					// keep additional tmpfs mounts that are not explicitly ignored
					path: "/else/othertmp",
				},
			},
		},
		{
			name: "ignore known trixy tmpfs paths",
			root: "/",
			mounts: []*mountinfo.Info{
				{
					Mountpoint: "/",
					FSType:     "/dev/disk3s7",
				},
				{
					Mountpoint: "/dev",
					FSType:     "tmpfs",
				},
				{
					Mountpoint: "/run",
					FSType:     "tmpfs",
				},
				{
					Mountpoint: "/var/run",
					FSType:     "tmpfs",
				},
				{
					Mountpoint: "/var/lock",
					FSType:     "tmpfs",
				},
				{
					Mountpoint: "/sys",
					FSType:     "tmpfs",
				},
				{
					Mountpoint: "/tmp",
					FSType:     "tmpfs",
				},
			},
			want: []expect{
				{
					path:    "/dev",
					wantErr: assertSkipErr(),
				},
				{
					path:    "/run",
					wantErr: assertSkipErr(),
				},
				{
					path:    "/var/run",
					wantErr: assertSkipErr(),
				},
				{
					path:    "/var/lock",
					wantErr: assertSkipErr(),
				},
				{
					path:    "/sys",
					wantErr: assertSkipErr(),
				},
				// show that we honor ignoring nested paths
				{
					path:    "/sys/nested",
					wantErr: assertSkipErr(),
				},
				// show that paths outside of the known mountpoints are not skipped
				{
					path: "/stuff",
				},
				// show that we allow other tmpfs paths that are not on the blocklist
				{
					path: "/tmp/allowed",
				},
				// show sibling paths with same prefix (e.g. /sys vs /system) to that of not allowed paths are not skipped
				{
					path: "/system",
				},
			},
		},
		{
			name:   "test unix paths",
			mounts: unixSubject,
			root:   "/",
			want: []expect{
				{
					// relative path to proc is allowed
					path: "proc/place",
				},
				{
					// relative path within proc is not allowed
					path:    "/proc/place",
					wantErr: assertSkipErr(),
				},
				{
					// path exactly to proc is not allowed
					path:    "/proc",
					wantErr: assertSkipErr(),
				},
				{
					// similar to proc
					path: "/pro/c",
				},
				{
					// similar to proc
					path: "/pro",
				},
				{
					// dev is not allowed
					path:    "/dev",
					wantErr: assertSkipErr(),
				},
				{
					// sys is not allowed
					path:    "/sys",
					wantErr: assertSkipErr(),
				},
			},
		},
		{
			name:   "test unix paths with base",
			mounts: unixSubject,
			root:   "/",
			base:   "/a/b/c",
			want: []expect{
				{
					// do not consider base when matching paths (non-matching)
					path: "/a/b/c/dev",
				},
				{
					// do not consider base when matching paths (matching)
					path:    "/dev",
					wantErr: assertSkipErr(),
				},
			},
		},
		{
			name: "mimic nixos setup",
			root: "/",
			mounts: []*mountinfo.Info{
				{
					Mountpoint: "/",
					FSType:     "tmpfs", // this is an odd setup, but valid
				},
				{
					Mountpoint: "/home",
					FSType:     "/dev/disk3s7",
				},
			},
			want: []expect{
				{
					path: "/home/somewhere",
				},
				{
					path: "/home",
				},
				{
					path: "/somewhere",
				},
				{
					// still not allowed...
					path:    "/run",
					wantErr: assertSkipErr(),
				},
			},
		},
		{
			name: "buildkit github ubuntu 22.04",
			root: "/run/src/core/sbom",
			mounts: []*mountinfo.Info{
				{Mountpoint: "/", FSType: "overlay"},
				{Mountpoint: "/proc", FSType: "proc"},
				{Mountpoint: "/dev", FSType: "tmpfs"},
				{Mountpoint: "/dev/pts", FSType: "devpts"},
				{Mountpoint: "/dev/shm", FSType: "tmpfs"},
				{Mountpoint: "/dev/mqueue", FSType: "mqueue"},
				{Mountpoint: "/sys", FSType: "sysfs"},
				{Mountpoint: "/etc/resolv.conf", FSType: "ext4"},
				{Mountpoint: "/etc/hosts", FSType: "ext4"},
				{Mountpoint: "/sys/fs/cgroup", FSType: "cgroup2"},
				{Mountpoint: "/run/out", FSType: "ext4"},
				{Mountpoint: "/run/src/core/sbom", FSType: "overlay"},
				{Mountpoint: "/tmp", FSType: "tmpfs"},
				{Mountpoint: "/dev/otel-grpc.sock", FSType: "overlay"},
				{Mountpoint: "/proc/bus", FSType: "proc"},
				{Mountpoint: "/proc/fs", FSType: "proc"},
				{Mountpoint: "/proc/irq", FSType: "proc"},
				{Mountpoint: "/proc/sys", FSType: "proc"},
				{Mountpoint: "/proc/sysrq-trigger", FSType: "proc"},
				{Mountpoint: "/proc/acpi", FSType: "tmpfs"},
				{Mountpoint: "/proc/kcore", FSType: "tmpfs"},
				{Mountpoint: "/proc/keys", FSType: "tmpfs"},
				{Mountpoint: "/proc/latency_stats", FSType: "tmpfs"},
				{Mountpoint: "/proc/timer_list", FSType: "tmpfs"},
				{Mountpoint: "/sys/firmware", FSType: "tmpfs"},
				{Mountpoint: "/proc/scsi", FSType: "tmpfs"},
			},
			want: []expect{
				{
					path: "/run/src/core/sbom",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.base == "" {
				tt.base = tt.root
			}

			require.NotEmpty(t, tt.want)
			ps := newPathSkipperFromMounts(tt.root, tt.mounts)

			for _, exp := range tt.want {
				t.Run(exp.path, func(t *testing.T) {

					got := ps.pathIndexVisitor(tt.base, exp.path, nil, nil)
					if exp.wantErr == nil {
						assert.NoError(t, got)
						return
					}
					exp.wantErr(t, got)

				})
			}
		})
	}
}

func assertSkipErr() assert.ErrorAssertionFunc {
	return assertErrorIs(fs.SkipDir)
}

func assertErrorIs(want error) assert.ErrorAssertionFunc {
	return func(t assert.TestingT, got error, msgAndArgs ...interface{}) bool {
		return assert.ErrorIs(t, got, want, msgAndArgs...)
	}
}
