package testutils

import (
	"bytes"
	"testing"

	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/go-testutils"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/sbom"
)

type imageCfg struct {
	fromSnapshot bool
}

type ImageOption func(cfg *imageCfg)

func FromSnapshot() ImageOption {
	return func(cfg *imageCfg) {
		cfg.fromSnapshot = true
	}
}

type EncoderSnapshotTestConfig struct {
	Subject                     sbom.SBOM
	Format                      sbom.Format
	UpdateSnapshot              bool
	PersistRedactionsInSnapshot bool
	IsJSON                      bool
	Redactor                    Redactor
}

func AssertEncoderAgainstGoldenSnapshot(t *testing.T, cfg EncoderSnapshotTestConfig) {
	t.Helper()
	var buffer bytes.Buffer

	err := cfg.Format.Encode(&buffer, cfg.Subject)
	assert.NoError(t, err)
	actual := buffer.Bytes()

	if cfg.UpdateSnapshot && !cfg.PersistRedactionsInSnapshot {
		// replace the expected snapshot contents with the current (unredacted) encoder contents
		testutils.UpdateGoldenFileContents(t, actual)
		return
	}

	var expected []byte
	if cfg.Redactor != nil {
		actual = cfg.Redactor.Redact(actual)
		expected = cfg.Redactor.Redact(testutils.GetGoldenFileContents(t))
	} else {
		expected = testutils.GetGoldenFileContents(t)
	}

	if cfg.UpdateSnapshot && cfg.PersistRedactionsInSnapshot {
		// replace the expected snapshot contents with the current (redacted) encoder contents
		testutils.UpdateGoldenFileContents(t, actual)
		return
	}

	if cfg.IsJSON {
		require.JSONEq(t, string(expected), string(actual))
	} else if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(expected), string(actual), true)
		t.Logf("len: %d\nexpected: %s", len(expected), expected)
		t.Logf("len: %d\nactual: %s", len(actual), actual)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}
}

type ImageSnapshotTestConfig struct {
	Image               string
	UpdateImageSnapshot bool
}

func AssertEncoderAgainstGoldenImageSnapshot(t *testing.T, imgCfg ImageSnapshotTestConfig, cfg EncoderSnapshotTestConfig) {
	if imgCfg.UpdateImageSnapshot {
		// grab the latest image contents and persist
		imagetest.UpdateGoldenFixtureImage(t, imgCfg.Image)
	}

	AssertEncoderAgainstGoldenSnapshot(t, cfg)
}
