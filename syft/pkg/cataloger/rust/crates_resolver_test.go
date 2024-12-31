package rust

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
)

func Test_parseCratesResponse(t *testing.T) {
	type args struct {
		filename string
	}
	tests := []struct {
		name    string
		args    args
		want    pkg.RustCratesEnrichment
		wantErr bool
	}{
		{
			name: "clap crate metadata json",
			args: args{
				filename: "test-fixtures/glob-paths/crates_io-clap-crate.json",
			},
			wantErr: false,
			want: pkg.RustCratesEnrichment{
				Name:             "clap",
				Version:          "4.5.23",
				Description:      "A simple to use, efficient, and full-featured Command Line Argument Parser",
				DownloadLocation: "https://crates.io/api/v1/crates/clap/4.5.23/download",
				CreatedBy:        "Ed Page",
				Repository:       "https://github.com/clap-rs/clap",
				LicenseInfo:      "MIT OR Apache-2.0",
				Supplier:         "Ed Page",
				ReleaseTime:      "2024-12-05T21:16:57.892342+00:00",
				Summary:          "A simple to use, efficient, and full-featured Command Line Argument Parser",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := newCratesResolver("crates.io", DefaultCatalogerConfig())
			reader, _ := os.Open(tt.args.filename)
			defer reader.Close()
			got, err := cr.parseCratesResponse(reader)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseCratesResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
