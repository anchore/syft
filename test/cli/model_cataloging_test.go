package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// modelSize is larger than the 50 MB syft copies from a model to parse its header, and than the tensor data
// the header fixture declares.
const modelSize = 512 << 20

// TestGGUFModelIsCataloged scans a model larger than the header copy syft parses: a real GGUF header followed
// by a sparse range standing in for the tensor data. Models under the copy size are parsed whole, so only a
// model this large catches a parser that checks the declared tensor data against the bytes it was given.
func TestGGUFModelIsCataloged(t *testing.T) {
	root := t.TempDir()
	header, err := os.ReadFile("testdata/models/gguf-header-only/header.gguf")
	require.NoError(t, err)
	modelPath := filepath.Join(root, "qwen2.5-0.5b-instruct-q2_k.gguf")
	require.NoError(t, os.WriteFile(modelPath, header, 0o600))
	require.NoError(t, os.Truncate(modelPath, modelSize))

	out := filepath.Join(t.TempDir(), "sbom.json")
	cmd, stdout, stderr := runSyft(t, nil, "scan", "dir:"+root, "-o", "syft-json="+out)
	defer logOutputOnFailure(t, cmd, stdout, stderr)
	assertSuccessfulReturnCode(t, stdout, stderr, cmd.ProcessState.ExitCode())

	b, err := os.ReadFile(out)
	require.NoError(t, err, "no SBOM written")
	var doc struct {
		Artifacts []struct {
			Name     string `json:"name"`
			Type     string `json:"type"`
			Licenses []struct {
				Value string `json:"value"`
			} `json:"licenses"`
			Metadata struct {
				Architecture string `json:"architecture"`
				Quantization string `json:"quantization"`
				Parameters   uint64 `json:"parameters"`
				TensorCount  uint64 `json:"tensorCount"`
			} `json:"metadata"`
		} `json:"artifacts"`
	}
	require.NoError(t, json.Unmarshal(b, &doc), "SBOM is not valid JSON")
	require.Len(t, doc.Artifacts, 1, "expected the model package")

	model := doc.Artifacts[0]
	assert.Equal(t, "qwen2.5-0.5b-instruct", model.Name)
	assert.Equal(t, "model", model.Type)
	require.Len(t, model.Licenses, 1)
	assert.Equal(t, "apache-2.0", model.Licenses[0].Value)
	assert.Equal(t, "qwen2", model.Metadata.Architecture)
	assert.Equal(t, "Q2_K_L", model.Metadata.Quantization)
	assert.Equal(t, uint64(290), model.Metadata.TensorCount)
	assert.Equal(t, uint64(494032768), model.Metadata.Parameters)
}
