package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// maxMalformedScanRSS is far above what scanning a handful of tiny files needs. RSS only sees memory that was actually
// touched, so a large allocation that is never filled can slip under it; the fuzz harness in syft/pkg/cataloger
// measures allocations directly.
const maxMalformedScanRSS = 1 << 30

// each directory under testdata/malformed holds a few tiny files shaped to trip parsers up (deep nesting, huge declared
// counts, truncation, type mismatches, non-finite floats). None of them should cost the rest of the SBOM, so each is
// scanned next to a well-formed requirements.txt whose package must still be reported.
func TestMalformedInputsStillProduceSBOM(t *testing.T) {
	dirs, err := filepath.Glob("testdata/malformed/*")
	require.NoError(t, err)
	require.NotEmpty(t, dirs)

	for _, dir := range dirs {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			root := t.TempDir()
			require.NoError(t, os.CopyFS(root, os.DirFS(dir)))
			require.NoError(t, os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("well-formed==1.0.0\n"), 0o600))

			out := filepath.Join(t.TempDir(), "sbom.json")
			env := map[string]string{"GOMEMLIMIT": "512MiB"}
			// runSyft aborts the process after 60s
			cmd, stdout, stderr := runSyft(t, env, "scan", "dir:"+root, "--override-default-catalogers", "all", "-o", "syft-json="+out)
			defer logOutputOnFailure(t, cmd, stdout, stderr)

			assertSuccessfulReturnCode(t, stdout, stderr, cmd.ProcessState.ExitCode())

			if ru, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
				rss := int64(ru.Maxrss) // int32 on 32-bit linux
				if runtime.GOOS == "linux" {
					rss *= 1024 // kilobytes on linux, bytes on darwin
				}
				assert.Less(t, rss, int64(maxMalformedScanRSS), "max RSS %d MB", rss>>20)
			}

			b, err := os.ReadFile(out)
			require.NoError(t, err, "no SBOM written")
			var doc struct {
				Artifacts []struct {
					Name string `json:"name"`
				} `json:"artifacts"`
				Files []struct {
					Location struct {
						Path string `json:"path"`
					} `json:"location"`
					Unknowns []string `json:"unknowns"`
				} `json:"files"`
			}
			require.NoError(t, json.Unmarshal(b, &doc), "SBOM is not valid JSON")
			var names []string
			for _, a := range doc.Artifacts {
				names = append(names, a.Name)
			}
			assert.Contains(t, names, "well-formed", "package from the well-formed file is missing")

			// a per-file panic is recovered into an unknown and the scan still exits 0, so look for it explicitly
			for _, f := range doc.Files {
				for _, u := range f.Unknowns {
					assert.NotContains(t, u, "recovered from panic", "parser panicked on %s", f.Location.Path)
				}
			}
		})
	}
}
