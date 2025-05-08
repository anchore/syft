package format

import (
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/format/internal/cyclonedxutil"
	"github.com/anchore/syft/syft/format/internal/spdxutil"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/format/template"
	"github.com/anchore/syft/syft/sbom"
)

func Test_Encoders(t *testing.T) {
	// this is an explicit test that the default encoders and encoders are the same and does not error
	encs, err := DefaultEncodersConfig().Encoders()
	require.NoError(t, err)
	assert.NotEmpty(t, encs)

	expected := expectedDefaultEncoders()
	assertHasEncoders(t, expected, encs)
	assertHasEncoders(t, expected, Encoders())
}

func expectedDefaultEncoders() *strset.Set {
	expected := strset.New()
	// note: template is not expected in the default encoders
	expected.Add("syft-json@" + internal.JSONSchemaVersion) // TODO: support multiple versions
	expected.Add("syft-table@")                             // no version
	expected.Add("syft-text@")                              // no version
	expected.Add("github-json@")                            // no version
	for _, v := range spdxjson.SupportedVersions() {
		expected.Add("spdx-json@" + v)
	}
	for _, v := range spdxtagvalue.SupportedVersions() {
		expected.Add("spdx-tag-value@" + v)
	}
	for _, v := range cyclonedxjson.SupportedVersions() {
		expected.Add("cyclonedx-json@" + v)
	}
	for _, v := range cyclonedxxml.SupportedVersions() {
		expected.Add("cyclonedx-xml@" + v)
	}
	return expected
}

func assertHasEncoders(t *testing.T, expected *strset.Set, encs []sbom.FormatEncoder) {
	for _, enc := range encs {
		assert.True(t, expected.Has(string(enc.ID())+"@"+enc.Version()), "missing: "+string(enc.ID())+"@"+enc.Version())
	}

	if t.Failed() {
		t.Log("got encoders:")
		for _, enc := range encs {
			t.Log(" - " + string(enc.ID()) + "@" + enc.Version())
		}
	}
}

func TestEncodersConfig_Encoders(t *testing.T) {

	tests := []struct {
		name    string
		cfg     EncodersConfig
		want    *strset.Set
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "default",
			cfg:  DefaultEncodersConfig(),
			want: expectedDefaultEncoders(),
		},
		{
			name: "with template",
			cfg: func() EncodersConfig {
				cfg := DefaultEncodersConfig()
				cfg.Template.TemplatePath = "foo"
				return cfg
			}(),
			want: func() *strset.Set {
				expected := expectedDefaultEncoders()
				expected.Add("template@")
				return expected
			}(),
		},
		{
			name: "explicit versions template",
			cfg: EncodersConfig{
				Template:      template.DefaultEncoderConfig(),
				SyftJSON:      syftjson.DefaultEncoderConfig(),
				SPDXJSON:      spdxjson.DefaultEncoderConfig(),
				SPDXTagValue:  spdxtagvalue.DefaultEncoderConfig(),
				CyclonedxJSON: cyclonedxjson.DefaultEncoderConfig(),
				CyclonedxXML:  cyclonedxxml.DefaultEncoderConfig(),
			},
			want: func() *strset.Set {
				expected := strset.New()
				// note: template is not expected in the default encoders
				expected.Add("syft-json@" + internal.JSONSchemaVersion) // TODO: support multiple versions
				expected.Add("syft-table@")                             // no version
				expected.Add("syft-text@")                              // no version
				expected.Add("github-json@")                            // no version
				expected.Add("spdx-json@" + spdxutil.DefaultVersion)
				expected.Add("spdx-tag-value@" + spdxutil.DefaultVersion)
				expected.Add("cyclonedx-json@" + cyclonedxutil.DefaultVersion)
				expected.Add("cyclonedx-xml@" + cyclonedxutil.DefaultVersion)

				return expected
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			got, err := tt.cfg.Encoders()
			tt.wantErr(t, err)
			if err != nil {
				return
			}

			assertHasEncoders(t, tt.want, got)
		})
	}
}
