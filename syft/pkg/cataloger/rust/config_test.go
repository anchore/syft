package rust

import (
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_CatalogerConfig_WithProxy(t *testing.T) {
	type args struct {
		env   bool
		input string
	}
	tests := []struct {
		name string
		args args
		want CatalogerConfig
	}{
		{
			name: "with proxy",
			args: args{
				env:   false,
				input: "https://proxy-host:8080",
			},
			want: CatalogerConfig{
				proxyURL: &url.URL{Scheme: "https", Host: "proxy-host:8080"},
			},
		},
		{
			name: "proxy set using env not config",
			args: args{
				env:   true,
				input: "",
			},
			want: CatalogerConfig{
				proxyURL: &url.URL{
					Scheme: "https",
					Host:   "invalid-domain.com:8080",
				},
				InsecureSkipTLSVerify: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := DefaultCatalogerConfig()
			if tt.args.env {
				_ = os.Setenv("HTTPS_PROXY", "https://invalid-domain.com:8080/")
				defer os.Unsetenv("HTTPS_PROXY")
			}
			got := g.WithProxy(tt.args.input)
			assert.Equal(t, tt.want.proxyURL.Scheme, got.proxyURL.Scheme)
			assert.Equal(t, tt.want.proxyURL.Host, got.proxyURL.Host)
		})
	}
}

func Test_CatalogerConfig_WithProxyPanic(t *testing.T) {
	type args struct {
		env   bool
		input string
	}
	tests := []struct {
		name string
		args args
		want CatalogerConfig
	}{
		{
			name: "invalid proxy panic",
			args: args{
				input: "http://[fe80::%31%25en0]:8080/",
			},
			want: CatalogerConfig{
				proxyURL: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := DefaultCatalogerConfig()
			assert.Panics(t, func() { g.WithProxy(tt.args.input) }, "CatalogerConfig.WithProxy() should panic when an invalid proxy is provided")
		})
	}
}

func TestCatalogerConfig_WithCratesTimeout(t *testing.T) {
	type args struct {
		input time.Duration
	}
	tests := []struct {
		name   string
		fields CatalogerConfig
		args   args
		want   CatalogerConfig
	}{
		{
			name:   "override default timeout",
			fields: DefaultCatalogerConfig(),
			args: args{
				input: 30 * time.Second,
			},
			want: CatalogerConfig{
				CratesTimeout: 30 * time.Second,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := CatalogerConfig{
				InsecureSkipTLSVerify: tt.fields.InsecureSkipTLSVerify,
				UseCratesEnrichment:   tt.fields.UseCratesEnrichment,
				Proxy:                 tt.fields.Proxy,
				CratesTimeout:         tt.fields.CratesTimeout,
				proxyURL:              tt.fields.proxyURL,
			}
			got := c.WithCratesTimeout(tt.args.input)
			assert.Equal(t, tt.want.CratesTimeout, got.CratesTimeout, "CatalogerConfig.WithCratesTimeout() = %v, want %v", got, tt.want)
		})
	}
}

func TestCatalogerConfig_WithUseCratesEnrichment(t *testing.T) {
	type args struct {
		input bool
	}
	tests := []struct {
		name   string
		fields CatalogerConfig
		args   args
		want   CatalogerConfig
	}{
		{
			name:   "override default crates enrichment",
			fields: DefaultCatalogerConfig(),
			args: args{
				input: true,
			},
			want: CatalogerConfig{
				UseCratesEnrichment: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := CatalogerConfig{
				InsecureSkipTLSVerify: tt.fields.InsecureSkipTLSVerify,
				UseCratesEnrichment:   tt.fields.UseCratesEnrichment,
				Proxy:                 tt.fields.Proxy,
				CratesTimeout:         tt.fields.CratesTimeout,
				proxyURL:              tt.fields.proxyURL,
			}
			got := c.WithUseCratesEnrichment(tt.args.input)
			assert.Equal(t, tt.want.UseCratesEnrichment, got.UseCratesEnrichment, "CatalogerConfig.WithUseCratesEnrichment() = %v, want %v", got, tt.want)
		})
	}
}

func TestCatalogerConfig_WithInsecureSkipTLSVerify(t *testing.T) {
	type args struct {
		input bool
	}
	tests := []struct {
		name   string
		fields CatalogerConfig
		args   args
		want   CatalogerConfig
	}{
		{
			name:   "override default insecure skip tls verify",
			fields: DefaultCatalogerConfig(),
			args: args{
				input: true,
			},
			want: CatalogerConfig{
				InsecureSkipTLSVerify: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := CatalogerConfig{
				InsecureSkipTLSVerify: tt.fields.InsecureSkipTLSVerify,
				UseCratesEnrichment:   tt.fields.UseCratesEnrichment,
				Proxy:                 tt.fields.Proxy,
				CratesTimeout:         tt.fields.CratesTimeout,
				proxyURL:              tt.fields.proxyURL,
			}
			got := c.WithInsecureSkipTLSVerify(tt.args.input)
			assert.Equal(t, tt.want.InsecureSkipTLSVerify, got.InsecureSkipTLSVerify, "CatalogerConfig.WithInsecureSkipTLSVerify() = %v, want %v", got, tt.want)
		})
	}
}
