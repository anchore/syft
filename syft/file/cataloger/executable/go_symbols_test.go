package executable

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_buildNmTypes(t *testing.T) {
	tests := []struct {
		name     string
		types    []string
		wantSize int
		contains []string
	}{
		{
			name:     "empty types uses defaults",
			types:    nil,
			wantSize: len(goNMTypes),
			contains: []string{"T", "t", "R", "r", "D", "d", "B", "b", "C", "U"},
		},
		{
			name:     "custom types",
			types:    []string{"T", "t"},
			wantSize: 2,
			contains: []string{"T", "t"},
		},
		{
			name:     "invalid types",
			types:    []string{"T", "t", "m", ",", "thing!"},
			wantSize: 2,
			contains: []string{"T", "t"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildNmTypes(tt.types)
			assert.Equal(t, tt.wantSize, got.Size())
			for _, c := range tt.contains {
				assert.True(t, got.Has(c), "expected set to contain %q", c)
			}
		})
	}
}

func Test_isCompilerLiteral(t *testing.T) {
	tests := []struct {
		name    string
		symName string
		want    bool
	}{
		{
			name:    "64-bit float literal",
			symName: "$f64.3fceb851eb851eb8",
			want:    true,
		},
		{
			name:    "32-bit float literal",
			symName: "$f32.3f800000",
			want:    true,
		},
		{
			name:    "other dollar prefix",
			symName: "$something",
			want:    true,
		},
		{
			name:    "regular symbol",
			symName: "main.main",
			want:    false,
		},
		{
			name:    "empty string",
			symName: "",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isCompilerLiteral(tt.symName)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_shouldIncludeByExportStatus(t *testing.T) {
	tests := []struct {
		name              string
		exported          bool
		includeExported   bool
		includeUnexported bool
		want              bool
	}{
		{
			name:              "exported symbol with both enabled",
			exported:          true,
			includeExported:   true,
			includeUnexported: true,
			want:              true,
		},
		{
			name:              "unexported symbol with both enabled",
			exported:          false,
			includeExported:   true,
			includeUnexported: true,
			want:              true,
		},
		{
			name:              "exported symbol with only exported enabled",
			exported:          true,
			includeExported:   true,
			includeUnexported: false,
			want:              true,
		},
		{
			name:              "unexported symbol with only exported enabled",
			exported:          false,
			includeExported:   true,
			includeUnexported: false,
			want:              false,
		},
		{
			name:              "exported symbol with only unexported enabled",
			exported:          true,
			includeExported:   false,
			includeUnexported: true,
			want:              false,
		},
		{
			name:              "unexported symbol with only unexported enabled",
			exported:          false,
			includeExported:   false,
			includeUnexported: true,
			want:              true,
		},
		{
			name:              "exported symbol with both disabled",
			exported:          true,
			includeExported:   false,
			includeUnexported: false,
			want:              false,
		},
		{
			name:              "unexported symbol with both disabled",
			exported:          false,
			includeExported:   false,
			includeUnexported: false,
			want:              false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldIncludeByExportStatus(tt.exported, tt.includeExported, tt.includeUnexported)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_isTypeEqualityFunction(t *testing.T) {
	tests := []struct {
		name    string
		symName string
		want    bool
	}{
		{
			name:    "type equality function",
			symName: "type:.eq.myStruct",
			want:    true,
		},
		{
			name:    "type equality with package",
			symName: "type:.eq.main.MyType",
			want:    true,
		},
		{
			name:    "regular function",
			symName: "main.main",
			want:    false,
		},
		{
			name:    "similar but not type equality",
			symName: "mytype:.eq.something",
			want:    false,
		},
		{
			name:    "empty string",
			symName: "",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTypeEqualityFunction(tt.symName)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_isGCShapeStencil(t *testing.T) {
	tests := []struct {
		name    string
		symName string
		want    bool
	}{
		{
			name:    "gc shape stencil function prefix",
			symName: "go.shape.func()",
			want:    true,
		},
		{
			name:    "gc shape with type prefix",
			symName: "go.shape.int",
			want:    true,
		},
		{
			name:    "gc shape in generic type parameter - struct",
			symName: `slices.partitionCmpFunc[go.shape.struct { Key string "json:\"key,omitempty\""; Value go.opentelemetry.io/otel/trace/internal/telemetry.Value "json:\"value,omitempty\"" }]`,
			want:    true,
		},
		{
			name:    "gc shape in generic type parameter - interface",
			symName: "slices.pdqsortCmpFunc[go.shape.interface { Info() (io/fs.FileInfo, error); IsDir() bool; Name() string; Type() io/fs.FileMode }]",
			want:    true,
		},
		{
			name:    "gc shape in generic - syft location",
			symName: `slices.partitionCmpFunc[go.shape.struct { github.com/anchore/syft/syft/file.LocationData "cyclonedx:\"\""; github.com/anchore/syft/syft/file.LocationMetadata "cyclonedx:\"\"" }]`,
			want:    true,
		},
		{
			name:    "gc shape in generic - rotate",
			symName: "slices.rotateCmpFunc[go.shape.struct { Key go.opentelemetry.io/otel/attribute.Key; Value go.opentelemetry.io/otel/attribute.Value }]",
			want:    true,
		},
		{
			name:    "regular function",
			symName: "main.main",
			want:    false,
		},
		{
			name:    "go package but not shape",
			symName: "go.string.something",
			want:    false,
		},
		{
			name:    "generic without go.shape",
			symName: "slices.Sort[int]",
			want:    false,
		},
		{
			name:    "go.shape in comment or string would not match",
			symName: "mypackage.FuncWithComment",
			want:    false,
		},
		{
			name:    "empty string",
			symName: "",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isGCShapeStencil(tt.symName)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_normalizeVendoredPath(t *testing.T) {
	tests := []struct {
		name      string
		symName   string
		normalize bool
		want      string
	}{
		{
			name:      "vendored path with normalization enabled",
			symName:   "vendor/github.com/foo/bar.Baz",
			normalize: true,
			want:      "github.com/foo/bar.Baz",
		},
		{
			name:      "vendored path with normalization disabled",
			symName:   "vendor/github.com/foo/bar.Baz",
			normalize: false,
			want:      "vendor/github.com/foo/bar.Baz",
		},
		{
			name:      "non-vendored path with normalization enabled",
			symName:   "github.com/foo/bar.Baz",
			normalize: true,
			want:      "github.com/foo/bar.Baz",
		},
		{
			name:      "non-vendored path with normalization disabled",
			symName:   "github.com/foo/bar.Baz",
			normalize: false,
			want:      "github.com/foo/bar.Baz",
		},
		{
			name:      "stdlib path with normalization enabled",
			symName:   "fmt.Println",
			normalize: true,
			want:      "fmt.Println",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeVendoredPath(tt.symName, tt.normalize)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_isVendoredPath(t *testing.T) {
	tests := []struct {
		name    string
		symName string
		want    bool
	}{
		{
			name:    "vendored third-party",
			symName: "vendor/github.com/foo/bar.Baz",
			want:    true,
		},
		{
			name:    "non-vendored third-party",
			symName: "github.com/foo/bar.Baz",
			want:    false,
		},
		{
			name:    "stdlib",
			symName: "fmt.Println",
			want:    false,
		},
		{
			name:    "main package",
			symName: "main.main",
			want:    false,
		},
		{
			name:    "empty string",
			symName: "",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isVendoredPath(tt.symName)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_isExtendedStdlib(t *testing.T) {
	tests := []struct {
		name    string
		pkgPath string
		want    bool
	}{
		{
			name:    "golang.org/x/net",
			pkgPath: "golang.org/x/net",
			want:    true,
		},
		{
			name:    "golang.org/x/text/encoding",
			pkgPath: "golang.org/x/text/encoding",
			want:    true,
		},
		{
			name:    "golang.org/x/sys/unix",
			pkgPath: "golang.org/x/sys/unix",
			want:    true,
		},
		{
			name:    "regular golang.org package",
			pkgPath: "golang.org/protobuf",
			want:    false,
		},
		{
			name:    "github package",
			pkgPath: "github.com/foo/bar",
			want:    false,
		},
		{
			name:    "stdlib",
			pkgPath: "fmt",
			want:    false,
		},
		{
			name:    "empty string",
			pkgPath: "",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isExtendedStdlib(tt.pkgPath)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_extractPackagePath(t *testing.T) {
	tests := []struct {
		name    string
		symName string
		want    string
	}{
		{
			name:    "simple package",
			symName: "fmt.Println",
			want:    "fmt",
		},
		{
			name:    "nested stdlib package",
			symName: "net/http.ListenAndServe",
			want:    "net/http",
		},
		{
			name:    "third-party package",
			symName: "github.com/foo/bar.Baz",
			want:    "github.com/foo/bar",
		},
		{
			name:    "deep third-party package",
			symName: "github.com/foo/bar/pkg/util.Helper",
			want:    "github.com/foo/bar/pkg/util",
		},
		{
			name:    "main package",
			symName: "main.main",
			want:    "main",
		},
		{
			name:    "no dot (just package name)",
			symName: "fmt",
			want:    "fmt",
		},
		{
			name:    "empty string",
			symName: "",
			want:    "",
		},
		{
			name:    "method with receiver",
			symName: "github.com/foo/bar.(*MyType).Method",
			want:    "github.com/foo/bar.(*MyType)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPackagePath(tt.symName)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_isExportedSymbol(t *testing.T) {
	tests := []struct {
		name    string
		symName string
		want    bool
	}{
		{
			name:    "exported function",
			symName: "fmt.Println",
			want:    true,
		},
		{
			name:    "unexported function",
			symName: "fmt.println",
			want:    false,
		},
		{
			name:    "exported in main",
			symName: "main.Main",
			want:    true,
		},
		{
			name:    "unexported main",
			symName: "main.main",
			want:    false,
		},
		{
			name:    "exported third-party",
			symName: "github.com/foo/bar.Export",
			want:    true,
		},
		{
			name:    "unexported third-party",
			symName: "github.com/foo/bar.private",
			want:    false,
		},
		{
			name:    "unicode uppercase",
			symName: "main.Über",
			want:    true,
		},
		{
			name:    "unicode lowercase",
			symName: "main.über",
			want:    false,
		},
		{
			name:    "no dot",
			symName: "nodot",
			want:    false,
		},
		{
			name:    "empty string",
			symName: "",
			want:    false,
		},
		{
			name:    "dot at end",
			symName: "main.",
			want:    false,
		},
		{
			name:    "underscore start (unexported)",
			symName: "main._private",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isExportedSymbol(tt.symName)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_isStdlibPackage(t *testing.T) {
	tests := []struct {
		name    string
		pkgPath string
		want    bool
	}{
		{
			name:    "fmt",
			pkgPath: "fmt",
			want:    true,
		},
		{
			name:    "net/http",
			pkgPath: "net/http",
			want:    true,
		},
		{
			name:    "crypto/sha256",
			pkgPath: "crypto/sha256",
			want:    true,
		},
		{
			name:    "main",
			pkgPath: "main",
			want:    true,
		},
		{
			name:    "runtime",
			pkgPath: "runtime",
			want:    true,
		},
		{
			name:    "github.com third-party",
			pkgPath: "github.com/foo/bar",
			want:    false,
		},
		{
			name:    "golang.org/x extended stdlib",
			pkgPath: "golang.org/x/net",
			want:    false,
		},
		{
			name:    "gopkg.in third-party",
			pkgPath: "gopkg.in/yaml.v3",
			want:    false,
		},
		{
			name:    "empty string",
			pkgPath: "",
			want:    true, // no dots means stdlib by our heuristic
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isStdlibPackage(tt.pkgPath)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_createGoSymbolFilter(t *testing.T) {
	tests := []struct {
		name     string
		cfg      SymbolConfig
		symName  string
		symType  string
		wantName string
		keep     bool
	}{
		// NM type filtering
		{
			name: "valid NM type with defaults",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:   true,
					UnexportedSymbols: true,
					StandardLibrary:   true,
				},
			},
			symName:  "fmt.Println",
			symType:  "T",
			wantName: "fmt.Println",
			keep:     true,
		},
		{
			name: "invalid NM type with defaults",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:   true,
					UnexportedSymbols: true,
					StandardLibrary:   true,
				},
			},
			symName:  "fmt.Println",
			symType:  "X", // important!
			wantName: "",
			keep:     false,
		},
		{
			name: "custom NM types - included",
			cfg: SymbolConfig{
				Types: []string{"T"},
				Go: GoSymbolConfig{
					ExportedSymbols:   true,
					UnexportedSymbols: true,
					StandardLibrary:   true,
				},
			},
			symName:  "fmt.Println",
			symType:  "T",
			wantName: "fmt.Println",
			keep:     true,
		},
		{
			name: "custom NM types - excluded",
			cfg: SymbolConfig{
				Types: []string{"T"},
				Go: GoSymbolConfig{
					ExportedSymbols:   true,
					UnexportedSymbols: true,
					StandardLibrary:   true,
				},
			},
			symName:  "fmt.Println",
			symType:  "t",
			wantName: "",
			keep:     false,
		},

		// floating point literal filtering
		{
			name: "floating point literal filtered",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:   true,
					UnexportedSymbols: true,
					StandardLibrary:   true,
				},
			},
			symName:  "$f64.3fceb851eb851eb8",
			symType:  "R",
			wantName: "",
			keep:     false,
		},

		// export status filtering
		{
			name: "exported symbol with only exported enabled",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:   true,
					UnexportedSymbols: false,
					StandardLibrary:   true,
				},
			},
			symName:  "fmt.Println",
			symType:  "T",
			wantName: "fmt.Println",
			keep:     true,
		},
		{
			name: "unexported symbol with only exported enabled",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:   true,
					UnexportedSymbols: false,
					StandardLibrary:   true,
				},
			},
			symName:  "fmt.println",
			symType:  "T",
			wantName: "",
			keep:     false,
		},

		// type equality functions
		{
			name: "type equality function - enabled",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:       true,
					UnexportedSymbols:     true,
					TypeEqualityFunctions: true,
				},
			},
			symName:  "type:.eq.myStruct",
			symType:  "T",
			wantName: "type:.eq.myStruct",
			keep:     true,
		},
		{
			name: "type equality function - disabled",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:       true,
					UnexportedSymbols:     true,
					TypeEqualityFunctions: false,
				},
			},
			symName:  "type:.eq.myStruct",
			symType:  "T",
			wantName: "",
			keep:     false,
		},

		// GC shape stencils
		{
			name: "gc shape stencil - enabled",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:   true,
					UnexportedSymbols: true,
					GCShapeStencils:   true,
				},
			},
			symName:  "go.shape.func()",
			symType:  "T",
			wantName: "go.shape.func()",
			keep:     true,
		},
		{
			name: "gc shape stencil - disabled",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:   true,
					UnexportedSymbols: true,
					GCShapeStencils:   false,
				},
			},
			symName:  "go.shape.func()",
			symType:  "T",
			wantName: "",
			keep:     false,
		},
		{
			name: "gc shape stencil embedded in generic - enabled",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:   true,
					UnexportedSymbols: true,
					GCShapeStencils:   true,
				},
			},
			symName:  "slices.partitionCmpFunc[go.shape.struct { Key string; Value int }]",
			symType:  "T",
			wantName: "slices.partitionCmpFunc[go.shape.struct { Key string; Value int }]",
			keep:     true,
		},
		{
			name: "gc shape stencil embedded in generic - disabled",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:   true,
					UnexportedSymbols: true,
					GCShapeStencils:   false,
				},
			},
			symName:  "slices.partitionCmpFunc[go.shape.struct { Key string; Value int }]",
			symType:  "T",
			wantName: "",
			keep:     false,
		},

		// vendored module normalization
		{
			name: "vendored path - normalization enabled",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:          true,
					UnexportedSymbols:        true,
					ThirdPartyModules:        true,
					NormalizeVendoredModules: true,
				},
			},
			symName:  "vendor/github.com/foo/bar.Baz",
			symType:  "T",
			wantName: "github.com/foo/bar.Baz",
			keep:     true,
		},
		{
			name: "vendored path - normalization disabled",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:          true,
					UnexportedSymbols:        true,
					ThirdPartyModules:        true,
					NormalizeVendoredModules: false,
				},
			},
			symName:  "vendor/github.com/foo/bar.Baz",
			symType:  "T",
			wantName: "vendor/github.com/foo/bar.Baz",
			keep:     true,
		},

		// extended stdlib
		{
			name: "extended stdlib - enabled",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:         true,
					UnexportedSymbols:       true,
					ExtendedStandardLibrary: true,
				},
			},
			symName:  "golang.org/x/net/html.Parse",
			symType:  "T",
			wantName: "golang.org/x/net/html.Parse",
			keep:     true,
		},
		{
			name: "extended stdlib - disabled",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:         true,
					UnexportedSymbols:       true,
					ExtendedStandardLibrary: false,
				},
			},
			symName:  "golang.org/x/net/html.Parse",
			symType:  "T",
			wantName: "",
			keep:     false,
		},

		// stdlib
		{
			name: "stdlib - enabled",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:   true,
					UnexportedSymbols: true,
					StandardLibrary:   true,
				},
			},
			symName:  "fmt.Println",
			symType:  "T",
			wantName: "fmt.Println",
			keep:     true,
		},
		{
			name: "stdlib - disabled",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:   true,
					UnexportedSymbols: true,
					StandardLibrary:   false,
				},
			},
			symName:  "fmt.Println",
			symType:  "T",
			wantName: "",
			keep:     false,
		},
		{
			name: "nested stdlib - enabled",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:   true,
					UnexportedSymbols: true,
					StandardLibrary:   true,
				},
			},
			symName:  "net/http.ListenAndServe",
			symType:  "T",
			wantName: "net/http.ListenAndServe",
			keep:     true,
		},

		// third party
		{
			name: "third party - enabled",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:   true,
					UnexportedSymbols: true,
					ThirdPartyModules: true,
				},
			},
			symName:  "github.com/spf13/cobra.Command",
			symType:  "T",
			wantName: "github.com/spf13/cobra.Command",
			keep:     true,
		},
		{
			name: "third party - disabled",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:   true,
					UnexportedSymbols: true,
					ThirdPartyModules: false,
				},
			},
			symName:  "github.com/spf13/cobra.Command",
			symType:  "T",
			wantName: "",
			keep:     false,
		},

		// main package (treated as stdlib)
		{
			name: "main package - stdlib enabled",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:   true,
					UnexportedSymbols: true,
					StandardLibrary:   true,
				},
			},
			symName:  "main.main",
			symType:  "T",
			wantName: "main.main",
			keep:     true,
		},
		{
			name: "main package - stdlib disabled",
			cfg: SymbolConfig{
				Go: GoSymbolConfig{
					ExportedSymbols:   true,
					UnexportedSymbols: true,
					StandardLibrary:   false,
				},
			},
			symName:  "main.main",
			symType:  "T",
			wantName: "",
			keep:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := createGoSymbolFilter(tt.cfg)
			require.NotNil(t, filter)

			gotName, gotKeep := filter(tt.symName, tt.symType)
			assert.Equal(t, tt.keep, gotKeep)
			if gotKeep {
				assert.Equal(t, tt.wantName, gotName)
			}
		})
	}
}
