package options

import (
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/format"
)

func Test_getEncoders(t *testing.T) {
	allDefaultEncoderNames := strset.New()
	for _, e := range format.DefaultEncoders() {
		allDefaultEncoderNames.Add(e.ID().String())
	}

	opts := Output{
		OutputTemplate: OutputTemplate{
			Path: "somewhere",
		},
	}

	encoders, err := opts.createEncoders()
	require.NoError(t, err)
	require.NotEmpty(t, encoders)

	encoderNames := strset.New()
	for _, e := range encoders {
		encoderNames.Add(e.ID().String())
	}

	assert.ElementsMatch(t, allDefaultEncoderNames.List(), encoderNames.List())
}
