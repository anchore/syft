package options

import (
	"strings"

	"github.com/anchore/clio"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
)

type golangConfig struct {
	SearchLocalModCacheLicenses *bool                         `json:"search-local-mod-cache-licenses" yaml:"search-local-mod-cache-licenses" mapstructure:"search-local-mod-cache-licenses"`
	LocalModCacheDir            string                        `json:"local-mod-cache-dir" yaml:"local-mod-cache-dir" mapstructure:"local-mod-cache-dir"`
	SearchLocalVendorLicenses   *bool                         `json:"search-local-vendor-licenses" yaml:"search-local-vendor-licenses" mapstructure:"search-local-vendor-licenses"`
	LocalVendorDir              string                        `json:"local-vendor-dir" yaml:"local-vendor-dir" mapstructure:"local-vendor-dir"`
	SearchRemoteLicenses        *bool                         `json:"search-remote-licenses" yaml:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	Proxy                       string                        `json:"proxy" yaml:"proxy" mapstructure:"proxy"`
	NoProxy                     string                        `json:"no-proxy" yaml:"no-proxy" mapstructure:"no-proxy"`
	MainModuleVersion           golangMainModuleVersionConfig `json:"main-module-version" yaml:"main-module-version" mapstructure:"main-module-version"`
	UsePackagesLib              *bool                         `json:"use-packages-lib" yaml:"use-packages-lib" mapstructure:"use-packages-lib"`
	CaptureSymbols              cataloging.SymbolScope        `json:"capture-symbols" yaml:"capture-symbols" mapstructure:"capture-symbols"`
	CaptureSymbolsModules       []string                      `json:"capture-symbols-modules" yaml:"capture-symbols-modules" mapstructure:"capture-symbols-modules"`
}

var _ interface {
	clio.FieldDescriber
	clio.PostLoader
} = (*golangConfig)(nil)

func (o *golangConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.SearchLocalModCacheLicenses, `search for go package licences in the GOPATH of the system running Syft, note that this is outside the
container filesystem and potentially outside the root of a local directory scan`)
	descriptions.Add(&o.LocalModCacheDir, `specify an explicit go mod cache directory, if unset this defaults to $GOPATH/pkg/mod or $HOME/go/pkg/mod`)
	descriptions.Add(&o.SearchLocalVendorLicenses, `search for go package licences in the vendor folder on the system running Syft, note that this is outside the
container filesystem and potentially outside the root of a local directory scan`)
	descriptions.Add(&o.LocalVendorDir, `specify an explicit go vendor directory, if unset this defaults to ./vendor`)
	descriptions.Add(&o.SearchRemoteLicenses, `search for go package licences by retrieving the package from a network proxy`)
	descriptions.Add(&o.Proxy, `remote proxy to use when retrieving go packages from the network,
if unset this defaults to $GOPROXY followed by https://proxy.golang.org`)
	descriptions.Add(&o.NoProxy, `specifies packages which should not be fetched by proxy
if unset this defaults to $GONOPROXY`)
	descriptions.Add(&o.MainModuleVersion, `the go main module version discovered from binaries built with the go compiler will
always show (devel) as the version. Use these options to control heuristics to guess
a more accurate version from the binary.`)
	descriptions.Add(&o.UsePackagesLib, `use the golang.org/x/tools/go/packages library, which executes golang tooling found on the path in addition to potential network access to get the most accurate results`)
	// note: descriptions must be static string literals; the app config discovery that generates the
	// capability docs reads them straight out of the AST
	descriptions.Add(&o.CaptureSymbols, `capture function symbols from the binary symbol table (pclntab). valid values are:
"none" (disabled), "stdlib" (only the synthetic stdlib package), "extended-stdlib" (stdlib plus every
module under golang.org/x/), and "all" (all module packages plus stdlib)`)
	descriptions.Add(&o.CaptureSymbolsModules, `glob patterns matched against go module paths (e.g. github.com/klauspost/**) that should have symbols
captured in addition to whatever capture-symbols selects. ** crosses path separators, * does not.
a trailing major version suffix is ignored when matching, so github.com/foo/* covers github.com/foo/bar/v2;
spelling a suffix out in the pattern selects only that major version.
this can only widen the selection, never narrow it, and is inert when capture-symbols is none`)
	descriptions.Add(&o.MainModuleVersion.FromLDFlags, `look for LD flags that appear to be setting a version (e.g. -X main.version=1.0.0)`)
	descriptions.Add(&o.MainModuleVersion.FromBuildSettings, `use the build settings (e.g. vcs.version & vcs.time) to craft a v0 pseudo version
(e.g. v0.0.0-20220308212642-53e6d0aaf6fb) when a more accurate version cannot be found otherwise`)
	descriptions.Add(&o.MainModuleVersion.FromContents, `search for semver-like strings in the binary contents`)
}

func (o *golangConfig) PostLoad() error {
	raw := strings.TrimSpace(string(o.CaptureSymbols))
	o.CaptureSymbols = o.CaptureSymbols.Parse()

	// an unrecognized value still resolves to "none", but say so rather than silently capturing nothing.
	// stay quiet for unset and an explicit "none", which is the default and would otherwise warn on nearly
	// every scan.
	if o.CaptureSymbols == cataloging.SymbolScopeNone && raw != "" && !strings.EqualFold(raw, string(cataloging.SymbolScopeNone)) {
		log.Warnf("unknown golang.capture-symbols value %q, defaulting to %q (valid values: none, stdlib, extended-stdlib, all)", raw, cataloging.SymbolScopeNone)
	}

	// trim only, deliberately not Flatten: viper already splits a comma-separated scalar (env var or a bare
	// yaml string) into a slice before this point, and there is no CLI flag feeding this key. The one thing
	// Flatten would add is splitting commas *inside* a list entry, which silently breaks doublestar brace
	// alternation like github.com/{foo,bar}/**. Viper's split does not trim, so that part is still needed.
	for i, pattern := range o.CaptureSymbolsModules {
		o.CaptureSymbolsModules[i] = strings.TrimSpace(pattern)
	}

	return nil
}

type golangMainModuleVersionConfig struct {
	FromLDFlags       bool `json:"from-ld-flags" yaml:"from-ld-flags" mapstructure:"from-ld-flags"`
	FromContents      bool `json:"from-contents" yaml:"from-contents" mapstructure:"from-contents"`
	FromBuildSettings bool `json:"from-build-settings" yaml:"from-build-settings" mapstructure:"from-build-settings"`
}

func defaultGolangConfig() golangConfig {
	def := golang.DefaultCatalogerConfig()
	return golangConfig{
		SearchLocalModCacheLicenses: nil, // this defaults to false, which is the API default
		LocalModCacheDir:            def.LocalModCacheDir,
		SearchLocalVendorLicenses:   nil, // this defaults to false, which is the API default
		LocalVendorDir:              def.LocalVendorDir,
		SearchRemoteLicenses:        nil, // this defaults to false, which is the API default
		Proxy:                       strings.Join(def.Proxies, ","),
		NoProxy:                     strings.Join(def.NoProxy, ","),
		MainModuleVersion: golangMainModuleVersionConfig{
			FromLDFlags:       def.MainModuleVersion.FromLDFlags,
			FromContents:      def.MainModuleVersion.FromContents,
			FromBuildSettings: def.MainModuleVersion.FromBuildSettings,
		},
		UsePackagesLib:        nil, // this defaults to true, which is the API default
		CaptureSymbols:        def.CaptureSymbols,
		CaptureSymbolsModules: def.CaptureSymbolsModules,
	}
}
