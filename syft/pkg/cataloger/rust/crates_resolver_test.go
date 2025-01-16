package rust

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/anchore/syft/internal/cache"
	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parseCratesResponse(t *testing.T) {
	type args struct {
		filename string
	}
	tests := []struct {
		name    string
		args    args
		want    pkg.RustCratesEnrichedEntry
		wantErr bool
	}{
		{
			name: "clap crate metadata json",
			args: args{
				filename: "test-fixtures/glob-paths/crates_io-clap-crate.json",
			},
			wantErr: false,
			want: pkg.RustCratesEnrichedEntry{
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
		{
			name: "error crate metadata json",
			args: args{
				filename: "test-fixtures/glob-paths/crates_io-error.json",
			},
			wantErr: true,
			want:    pkg.RustCratesEnrichedEntry{},
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

func Test_setHeaders(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://foo/bar", nil)
	type args struct {
		request *http.Request
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "set header",
			args: args{
				request: req,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := setHeaders(tt.args.request)
			assert.Contains(t, got.Header, "Accept")
		})
	}
}

func Test_newCratesLookupClient(t *testing.T) {
	type args struct {
		opts CatalogerConfig
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "new default client",
			args: args{
				opts: DefaultCatalogerConfig(),
			},
		},
		{
			name: "proxy client",
			args: args{
				opts: CatalogerConfig{
					proxyURL: &url.URL{
						Scheme: "https",
						Host:   "proxy-host:8080",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newCratesLookupClient(tt.args.opts)
			switch v := got.Transport.(type) {
			case *http.Transport:
				assert.Equal(t, v.TLSClientConfig.InsecureSkipVerify, tt.args.opts.InsecureSkipTLSVerify)
				if tt.args.opts.proxyURL != nil {
					assert.NotNil(t, v.Proxy)
				}
			}
			assert.Equal(t, got.Timeout, tt.args.opts.CratesTimeout)
		})
	}
}

func Test_rustCratesResolver_fetchRemoteCratesInfo(t *testing.T) {
	responsePayload, err := os.Open("test-fixtures/glob-paths/crates_io-clap-crate.json")
	require.NoError(t, err)
	defer responsePayload.Close()

	buf := &bytes.Buffer{}
	sz, err := buf.ReadFrom(responsePayload)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/clap/4.5.23" {
			http.Error(w, "not found", http.StatusNotFound)
		}
		w.Header().Add("Content-Type", "application/json")
		w.Header().Add("Content-Length", fmt.Sprintf("%d", sz))

		_, err = w.Write(buf.Bytes())
		require.NoError(t, err)
	}))
	defer server.Close()

	client := &http.Client{
		Transport: http.DefaultTransport,
		Timeout:   5 * time.Second,
	}

	type fields struct {
		catalogerName string
		client        *http.Client
		cratesAPI     string
		cratesBaseURL string
		cratesCache   cache.Resolver[pkg.RustCratesEnrichedEntry]
	}
	type args struct {
		ctx          context.Context
		crateName    string
		crateVersion string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    pkg.RustCratesEnrichedEntry
		wantErr bool
	}{
		{
			name: "valid mock request and response",
			args: args{
				ctx:          context.Background(),
				crateName:    "clap",
				crateVersion: "4.5.23",
			},
			fields: fields{
				catalogerName: "crates.io mock",
				client:        client,
				cratesAPI:     server.URL,
			},
			wantErr: false,
			want: pkg.RustCratesEnrichedEntry{
				Name:             "clap",
				Version:          "4.5.23",
				Description:      "A simple to use, efficient, and full-featured Command Line Argument Parser",
				DownloadLocation: "/api/v1/crates/clap/4.5.23/download",
				CreatedBy:        "Ed Page",
				Repository:       "https://github.com/clap-rs/clap",
				LicenseInfo:      "MIT OR Apache-2.0",
				Supplier:         "Ed Page",
				ReleaseTime:      "2024-12-05T21:16:57.892342+00:00",
				Summary:          "A simple to use, efficient, and full-featured Command Line Argument Parser",
			},
		},
		{
			name: "invalid (non-existent crate)",
			args: args{
				ctx:          context.Background(),
				crateName:    "deeze",
				crateVersion: "999.999.999",
			},
			fields: fields{
				catalogerName: "crates io mock testing",
				client:        client,
				cratesAPI:     server.URL,
			},
			wantErr: true,
			want:    pkg.RustCratesEnrichedEntry{},
		},
		{
			name: "invalid (dns error)",
			args: args{
				ctx:          context.Background(),
				crateName:    "invalid-package-name",
				crateVersion: "no-version",
			},
			fields: fields{
				catalogerName: "crates io mock testing",
				client:        client,
				cratesAPI:     "https://invalid-hostname-here",
			},
			wantErr: true,
			want:    pkg.RustCratesEnrichedEntry{},
		},
		{
			name: "invalid (connection error)",
			args: args{
				ctx:          context.Background(),
				crateName:    "invalid-package-name",
				crateVersion: "no-version",
			},
			fields: fields{
				catalogerName: "crates io mock testing",
				client:        client,
				cratesAPI:     "https://localhost:9999",
			},
			wantErr: true,
			want:    pkg.RustCratesEnrichedEntry{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := &rustCratesResolver{
				catalogerName: tt.fields.catalogerName,
				client:        tt.fields.client,
				cratesAPI:     tt.fields.cratesAPI,
				cratesBaseURL: tt.fields.cratesBaseURL,
				cratesCache:   tt.fields.cratesCache,
			}
			got, err := cr.fetchRemoteCratesInfo(tt.args.ctx, tt.args.crateName, tt.args.crateVersion)
			if (err != nil) != tt.wantErr {
				t.Errorf("rustCratesResolver.fetchRemoteCratesInfo() expected error and got = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
			assert.NotNil(t, got)
		})
	}
}
