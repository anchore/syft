package fileresolver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/moby/sys/mountinfo"
)

// BenchmarkNewFromFile is the cost of building a resolver for a single-file source, which is
// paid once per file by callers that catalog files individually. The default case is
// NewFromFile as shipped. The with-mount-skipper case attaches skipPathsByMountTypeAndName
// the way the file indexer used to, so the difference is what reading the mount table for
// every file source cost. That cost scales with the mount table, so its size is reported as
// the mounts metric: expect a bigger gap on a container host than on a laptop.
//
//	go test ./syft/internal/fileresolver/ -run '^$' -bench NewFromFile -benchmem -count 6 | tee bench.txt
//	benchstat -col /variant bench.txt
func BenchmarkNewFromFile(b *testing.B) {
	path := filepath.Join(b.TempDir(), "file.txt")
	if err := os.WriteFile(path, []byte("hello\n"), 0o644); err != nil {
		b.Fatal(err)
	}
	mounts, err := mountinfo.GetMounts(nil)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("variant=default", func(b *testing.B) {
		for b.Loop() {
			if _, err := NewFromFile(path); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportMetric(float64(len(mounts)), "mounts")
	})

	b.Run("variant=with-mount-skipper", func(b *testing.B) {
		for b.Loop() {
			r, err := newFromFileWithoutIndex(path, skipPathsByMountTypeAndName(path))
			if err != nil {
				b.Fatal(err)
			}
			if err := r.buildIndex(); err != nil {
				b.Fatal(err)
			}
		}
		b.ReportMetric(float64(len(mounts)), "mounts")
	})
}
