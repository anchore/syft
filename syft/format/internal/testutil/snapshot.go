package testutil

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
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
	Format                      sbom.FormatEncoder
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

	if cfg.Redactor != nil {
		actual = cfg.Redactor.Redact(actual)
	}

	if cfg.UpdateSnapshot && cfg.PersistRedactionsInSnapshot {
		// replace the expected snapshot contents with the current (redacted) encoder contents
		testutils.UpdateGoldenFileContents(t, actual)
		return
	}

	var expected []byte
	if cfg.Redactor != nil {
		expected = cfg.Redactor.Redact(testutils.GetGoldenFileContents(t))
	} else {
		expected = testutils.GetGoldenFileContents(t)
	}

	if cfg.IsJSON {
		require.JSONEq(t, string(expected), string(actual))
	} else {
		requireEqual(t, expected, actual)
	}
}

func requireEqual(t *testing.T, expected any, actual any) {
	if diff := cmp.Diff(expected, actual); diff != "" {
		// uncomment to debug
		// t.Logf("expected: %s", expected)
		// t.Logf("actual: %s", actual)
		t.Fatalf("mismatched output: %s", diff)
	}
}

type ImageSnapshotTestConfig struct {
	Image               string
	UpdateImageSnapshot bool
}

func AssertEncoderAgainstGoldenImageSnapshot(t *testing.T, imgCfg ImageSnapshotTestConfig, cfg EncoderSnapshotTestConfig) {
	if imgCfg.UpdateImageSnapshot {
		defer changeToDirectoryWithGoldenFixture(t, imgCfg.Image)()

		// grab the latest image contents and persist
		imagetest.UpdateGoldenFixtureImage(t, imgCfg.Image)
	}

	AssertEncoderAgainstGoldenSnapshot(t, cfg)
}
