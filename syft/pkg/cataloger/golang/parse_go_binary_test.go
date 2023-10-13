package golang

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/pkg"
)

// make will run the default make target for the given test fixture path
func runMakeTarget(t *testing.T, fixtureName string) {
	cwd, err := os.Getwd()
	require.NoError(t, err)
	fixtureDir := filepath.Join(cwd, "test-fixtures/", fixtureName)

	t.Logf("Generating Fixture in %q", fixtureDir)

	cmd := exec.Command("make")
	cmd.Dir = fixtureDir

	stderr, err := cmd.StderrPipe()
	require.NoError(t, err)

	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)

	err = cmd.Start()
	require.NoError(t, err)

	show := func(label string, reader io.ReadCloser) {
		scanner := bufio.NewScanner(reader)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			t.Logf("%s: %s", label, scanner.Text())
		}
	}
	go show("out", stdout)
	go show("err", stderr)

	if err := cmd.Wait(); err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			// The program has exited with an exit code != 0

			// This works on both Unix and Windows. Although package
			// syscall is generally platform dependent, WaitStatus is
			// defined for both Unix and Windows and in both cases has
			// an ExitStatus() method with the same signature.
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				if status.ExitStatus() != 0 {
					t.Fatalf("failed to generate fixture: rc=%d", status.ExitStatus())
				}
			}
		} else {
			t.Fatalf("unable to get generate fixture result: %+v", err)
		}
	}
}

func Test_getGOARCHFromBin(t *testing.T) {
	runMakeTarget(t, "archs")

	tests := []struct {
		name     string
		filepath string
		expected string
	}{
		{
			name:     "pe",
			filepath: "test-fixtures/archs/binaries/hello-win-amd64",
			// see: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
			expected: strconv.Itoa(0x8664),
		},
		{
			name:     "elf-ppc64",
			filepath: "test-fixtures/archs/binaries/hello-linux-ppc64le",
			expected: "ppc64",
		},
		{
			name:     "mach-o-arm64",
			filepath: "test-fixtures/archs/binaries/hello-mach-o-arm64",
			expected: "arm64",
		},
		{
			name:     "linux-arm",
			filepath: "test-fixtures/archs/binaries/hello-linux-arm",
			expected: "arm",
		},
		{
			name:     "xcoff-32bit",
			filepath: "internal/xcoff/testdata/gcc-ppc32-aix-dwarf2-exec",
			expected: strconv.Itoa(0x1DF),
		},
		{
			name:     "xcoff-64bit",
			filepath: "internal/xcoff/testdata/gcc-ppc64-aix-dwarf2-exec",
			expected: strconv.Itoa(0x1F7),
		},
	}

	for _, tt := range tests {
		f, err := os.Open(tt.filepath)
		require.NoError(t, err)
		arch, err := getGOARCHFromBin(f)
		require.NoError(t, err, "test name: %s", tt.name)
		assert.Equal(t, tt.expected, arch)
	}

}

func TestBuildGoPkgInfo(t *testing.T) {
	const (
		goCompiledVersion = "1.18"
		archDetails       = "amd64"
	)
	defaultBuildSettings := map[string]string{
		"GOARCH":  "amd64",
		"GOOS":    "darwin",
		"GOAMD64": "v1",
	}

	unmodifiedMain := pkg.Package{
		Name:     "github.com/anchore/syft",
		Language: pkg.Go,
		Type:     pkg.GoModulePkg,
		Version:  "(devel)",
		PURL:     "pkg:golang/github.com/anchore/syft@(devel)",
		Locations: file.NewLocationSet(
			file.NewLocationFromCoordinates(
				file.Coordinates{
					RealPath:     "/a-path",
					FileSystemID: "layer-id",
				},
			).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
		MetadataType: pkg.GolangBinMetadataType,
		Metadata: pkg.GolangBinMetadata{
			GoCompiledVersion: goCompiledVersion,
			Architecture:      archDetails,
			BuildSettings:     defaultBuildSettings,
			MainModule:        "github.com/anchore/syft",
		},
	}

	tests := []struct {
		name     string
		mod      *extendedBuildInfo
		expected []pkg.Package
	}{
		{
			name: "package without name",
			mod: &extendedBuildInfo{
				BuildInfo: &debug.BuildInfo{
					Deps: []*debug.Module{
						{
							Path: "github.com/adrg/xdg",
						},
						{
							Path:    "",
							Version: "v0.2.1",
						},
					},
				},
				cryptoSettings: nil,
				arch:           "",
			},
			expected: []pkg.Package{
				{
					Name:     "github.com/adrg/xdg",
					PURL:     "pkg:golang/github.com/adrg/xdg",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: file.NewLocationSet(
						file.NewLocationFromCoordinates(
							file.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					MetadataType: pkg.GolangBinMetadataType,
					Metadata:     pkg.GolangBinMetadata{},
				},
			},
		},
		{
			name:     "buildGoPkgInfo parses a blank mod and returns no packages",
			mod:      &extendedBuildInfo{&debug.BuildInfo{}, nil, ""},
			expected: []pkg.Package(nil),
		},
		{
			name: "parse a mod without main module",
			mod: &extendedBuildInfo{
				BuildInfo: &debug.BuildInfo{
					GoVersion: goCompiledVersion,
					Settings: []debug.BuildSetting{
						{Key: "GOARCH", Value: archDetails},
						{Key: "GOOS", Value: "darwin"},
						{Key: "GOAMD64", Value: "v1"},
					},
					Deps: []*debug.Module{
						{
							Path:    "github.com/adrg/xdg",
							Version: "v0.2.1",
							Sum:     "h1:VSVdnH7cQ7V+B33qSJHTCRlNgra1607Q8PzEmnvb2Ic=",
						},
					},
				},
				cryptoSettings: nil,
				arch:           archDetails,
			},
			expected: []pkg.Package{
				{
					Name:     "github.com/adrg/xdg",
					Version:  "v0.2.1",
					PURL:     "pkg:golang/github.com/adrg/xdg@v0.2.1",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: file.NewLocationSet(
						file.NewLocationFromCoordinates(
							file.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						H1Digest:          "h1:VSVdnH7cQ7V+B33qSJHTCRlNgra1607Q8PzEmnvb2Ic=",
					},
				},
			},
		},
		{
			name: "parse a mod with path but no main module",
			mod: &extendedBuildInfo{
				BuildInfo: &debug.BuildInfo{
					GoVersion: goCompiledVersion,
					Settings: []debug.BuildSetting{
						{Key: "GOARCH", Value: archDetails},
						{Key: "GOOS", Value: "darwin"},
						{Key: "GOAMD64", Value: "v1"},
					},
					Path: "github.com/a/b/c",
				},
				cryptoSettings: []string{"boringcrypto + fips"},
				arch:           archDetails,
			},
			expected: []pkg.Package{
				{
					Name:     "github.com/a/b/c",
					Version:  "(devel)",
					PURL:     "pkg:golang/github.com/a/b/c@(devel)",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: file.NewLocationSet(
						file.NewLocationFromCoordinates(
							file.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						H1Digest:          "",
						BuildSettings: map[string]string{
							"GOAMD64": "v1",
							"GOARCH":  "amd64",
							"GOOS":    "darwin",
						},
						MainModule:       "github.com/a/b/c",
						GoCryptoSettings: []string{"boringcrypto + fips"},
					},
				},
			},
		},
		{
			name: "parse a mod without packages",
			mod: &extendedBuildInfo{
				BuildInfo: &debug.BuildInfo{
					GoVersion: goCompiledVersion,
					Main:      debug.Module{Path: "github.com/anchore/syft", Version: "(devel)"},
					Settings: []debug.BuildSetting{
						{Key: "GOARCH", Value: archDetails},
						{Key: "GOOS", Value: "darwin"},
						{Key: "GOAMD64", Value: "v1"},
					},
				},
				cryptoSettings: nil,
				arch:           archDetails,
			},
			expected: []pkg.Package{unmodifiedMain},
		},
		{
			name: "parse main mod and replace devel pseudo version and ldflags exists (but contains no version)",
			mod: &extendedBuildInfo{
				BuildInfo: &debug.BuildInfo{
					GoVersion: goCompiledVersion,
					Main:      debug.Module{Path: "github.com/anchore/syft", Version: "(devel)"},
					Settings: []debug.BuildSetting{
						{Key: "GOARCH", Value: archDetails},
						{Key: "GOOS", Value: "darwin"},
						{Key: "GOAMD64", Value: "v1"},
						{Key: "vcs.revision", Value: "41bc6bb410352845f22766e27dd48ba93aa825a4"},
						{Key: "vcs.time", Value: "2022-10-14T19:54:57Z"},
						{Key: "-ldflags", Value: `build	-ldflags="-w -s -extldflags '-static' -X blah=foobar`},
					},
				},
				cryptoSettings: nil,
				arch:           archDetails,
			},
			expected: []pkg.Package{
				{
					Name:     "github.com/anchore/syft",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Version:  "v0.0.0-20221014195457-41bc6bb41035",
					PURL:     "pkg:golang/github.com/anchore/syft@v0.0.0-20221014195457-41bc6bb41035",
					Locations: file.NewLocationSet(
						file.NewLocationFromCoordinates(
							file.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						BuildSettings: map[string]string{
							"GOARCH":       archDetails,
							"GOOS":         "darwin",
							"GOAMD64":      "v1",
							"vcs.revision": "41bc6bb410352845f22766e27dd48ba93aa825a4",
							"vcs.time":     "2022-10-14T19:54:57Z",
							"-ldflags":     `build	-ldflags="-w -s -extldflags '-static' -X blah=foobar`,
						},
						MainModule: "github.com/anchore/syft",
					},
				},
			},
		},
		{
			name: "parse main mod and replace devel version with one from ldflags with vcs. build settings",
			mod: &extendedBuildInfo{
				BuildInfo: &debug.BuildInfo{
					GoVersion: goCompiledVersion,
					Main:      debug.Module{Path: "github.com/anchore/syft", Version: "(devel)"},
					Settings: []debug.BuildSetting{
						{Key: "GOARCH", Value: archDetails},
						{Key: "GOOS", Value: "darwin"},
						{Key: "GOAMD64", Value: "v1"},
						{Key: "vcs.revision", Value: "41bc6bb410352845f22766e27dd48ba93aa825a4"},
						{Key: "vcs.time", Value: "2022-10-14T19:54:57Z"},
						{Key: "-ldflags", Value: `build	-ldflags="-w -s -extldflags '-static' -X github.com/anchore/syft/internal/version.version=0.79.0`},
					},
				},
				cryptoSettings: nil,
				arch:           archDetails,
			},
			expected: []pkg.Package{
				{
					Name:     "github.com/anchore/syft",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Version:  "v0.79.0",
					PURL:     "pkg:golang/github.com/anchore/syft@v0.79.0",
					Locations: file.NewLocationSet(
						file.NewLocationFromCoordinates(
							file.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						BuildSettings: map[string]string{
							"GOARCH":       archDetails,
							"GOOS":         "darwin",
							"GOAMD64":      "v1",
							"vcs.revision": "41bc6bb410352845f22766e27dd48ba93aa825a4",
							"vcs.time":     "2022-10-14T19:54:57Z",
							"-ldflags":     `build	-ldflags="-w -s -extldflags '-static' -X github.com/anchore/syft/internal/version.version=0.79.0`,
						},
						MainModule: "github.com/anchore/syft",
					},
				},
			},
		},
		{
			name: "parse main mod and replace devel version with one from ldflags without any vcs. build settings",
			mod: &extendedBuildInfo{
				BuildInfo: &debug.BuildInfo{
					GoVersion: goCompiledVersion,
					Main:      debug.Module{Path: "github.com/anchore/syft", Version: "(devel)"},
					Settings: []debug.BuildSetting{
						{Key: "GOARCH", Value: archDetails},
						{Key: "GOOS", Value: "darwin"},
						{Key: "GOAMD64", Value: "v1"},
						{Key: "-ldflags", Value: `build	-ldflags="-w -s -extldflags '-static' -X github.com/anchore/syft/internal/version.version=0.79.0`},
					},
				},
				cryptoSettings: nil,
				arch:           archDetails,
			},
			expected: []pkg.Package{
				{
					Name:     "github.com/anchore/syft",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Version:  "v0.79.0",
					PURL:     "pkg:golang/github.com/anchore/syft@v0.79.0",
					Locations: file.NewLocationSet(
						file.NewLocationFromCoordinates(
							file.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						BuildSettings: map[string]string{
							"GOARCH":   archDetails,
							"GOOS":     "darwin",
							"GOAMD64":  "v1",
							"-ldflags": `build	-ldflags="-w -s -extldflags '-static' -X github.com/anchore/syft/internal/version.version=0.79.0`,
						},
						MainModule: "github.com/anchore/syft",
					},
				},
			},
		},
		{
			name: "parse main mod and replace devel version with one from ldflags main.version without any vcs. build settings",
			mod: &extendedBuildInfo{
				BuildInfo: &debug.BuildInfo{
					GoVersion: goCompiledVersion,
					Main:      debug.Module{Path: "github.com/anchore/syft", Version: "(devel)"},
					Settings: []debug.BuildSetting{
						{Key: "GOARCH", Value: archDetails},
						{Key: "GOOS", Value: "darwin"},
						{Key: "GOAMD64", Value: "v1"},
						{Key: "-ldflags", Value: `build	-ldflags="-w -s -extldflags '-static' -X main.version=0.79.0`},
					},
				},
				cryptoSettings: nil,
				arch:           archDetails,
			},
			expected: []pkg.Package{
				{
					Name:     "github.com/anchore/syft",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Version:  "v0.79.0",
					PURL:     "pkg:golang/github.com/anchore/syft@v0.79.0",
					Locations: file.NewLocationSet(
						file.NewLocationFromCoordinates(
							file.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						BuildSettings: map[string]string{
							"GOARCH":   archDetails,
							"GOOS":     "darwin",
							"GOAMD64":  "v1",
							"-ldflags": `build	-ldflags="-w -s -extldflags '-static' -X main.version=0.79.0`,
						},
						MainModule: "github.com/anchore/syft",
					},
				},
			},
		},
		{
			name: "parse main mod and replace devel version with one from ldflags main.Version without any vcs. build settings",
			mod: &extendedBuildInfo{
				BuildInfo: &debug.BuildInfo{
					GoVersion: goCompiledVersion,
					Main:      debug.Module{Path: "github.com/anchore/syft", Version: "(devel)"},
					Settings: []debug.BuildSetting{
						{Key: "GOARCH", Value: archDetails},
						{Key: "GOOS", Value: "darwin"},
						{Key: "GOAMD64", Value: "v1"},
						{Key: "-ldflags", Value: `build	-ldflags="-w -s -extldflags '-static' -X main.Version=0.79.0`},
					},
				},
				cryptoSettings: nil,
				arch:           archDetails,
			},
			expected: []pkg.Package{
				{
					Name:     "github.com/anchore/syft",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Version:  "v0.79.0",
					PURL:     "pkg:golang/github.com/anchore/syft@v0.79.0",
					Locations: file.NewLocationSet(
						file.NewLocationFromCoordinates(
							file.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						BuildSettings: map[string]string{
							"GOARCH":   archDetails,
							"GOOS":     "darwin",
							"GOAMD64":  "v1",
							"-ldflags": `build	-ldflags="-w -s -extldflags '-static' -X main.Version=0.79.0`,
						},
						MainModule: "github.com/anchore/syft",
					},
				},
			},
		},
		{
			name: "parse main mod and replace devel version with a pseudo version",
			mod: &extendedBuildInfo{
				BuildInfo: &debug.BuildInfo{
					GoVersion: goCompiledVersion,
					Main:      debug.Module{Path: "github.com/anchore/syft", Version: "(devel)"},
					Settings: []debug.BuildSetting{
						{Key: "GOARCH", Value: archDetails},
						{Key: "GOOS", Value: "darwin"},
						{Key: "GOAMD64", Value: "v1"},
						{Key: "vcs.revision", Value: "41bc6bb410352845f22766e27dd48ba93aa825a4"},
						{Key: "vcs.time", Value: "2022-10-14T19:54:57Z"},
					},
				},
				cryptoSettings: nil,
				arch:           archDetails,
			},
			expected: []pkg.Package{
				{
					Name:     "github.com/anchore/syft",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Version:  "v0.0.0-20221014195457-41bc6bb41035",
					PURL:     "pkg:golang/github.com/anchore/syft@v0.0.0-20221014195457-41bc6bb41035",
					Locations: file.NewLocationSet(
						file.NewLocationFromCoordinates(
							file.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						BuildSettings: map[string]string{
							"GOARCH":       archDetails,
							"GOOS":         "darwin",
							"GOAMD64":      "v1",
							"vcs.revision": "41bc6bb410352845f22766e27dd48ba93aa825a4",
							"vcs.time":     "2022-10-14T19:54:57Z",
						},
						MainModule: "github.com/anchore/syft",
					},
				},
			},
		},
		{
			name: "parse a populated mod string and returns packages but no source info",
			mod: &extendedBuildInfo{
				BuildInfo: &debug.BuildInfo{
					GoVersion: goCompiledVersion,
					Main:      debug.Module{Path: "github.com/anchore/syft", Version: "(devel)"},
					Settings: []debug.BuildSetting{
						{Key: "GOARCH", Value: archDetails},
						{Key: "GOOS", Value: "darwin"},
						{Key: "GOAMD64", Value: "v1"},
					},
					Deps: []*debug.Module{
						{
							Path:    "github.com/adrg/xdg",
							Version: "v0.2.1",
							Sum:     "h1:VSVdnH7cQ7V+B33qSJHTCRlNgra1607Q8PzEmnvb2Ic=",
						},
						{
							Path:    "github.com/anchore/client-go",
							Version: "v0.0.0-20210222170800-9c70f9b80bcf",
							Sum:     "h1:DYssiUV1pBmKqzKsm4mqXx8artqC0Q8HgZsVI3lMsAg=",
						},
					},
				},
				cryptoSettings: nil,
				arch:           archDetails,
			},
			expected: []pkg.Package{
				{
					Name:     "github.com/adrg/xdg",
					Version:  "v0.2.1",
					PURL:     "pkg:golang/github.com/adrg/xdg@v0.2.1",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: file.NewLocationSet(
						file.NewLocationFromCoordinates(
							file.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						H1Digest:          "h1:VSVdnH7cQ7V+B33qSJHTCRlNgra1607Q8PzEmnvb2Ic=",
						MainModule:        "github.com/anchore/syft",
					},
				},
				{
					Name:     "github.com/anchore/client-go",
					Version:  "v0.0.0-20210222170800-9c70f9b80bcf",
					PURL:     "pkg:golang/github.com/anchore/client-go@v0.0.0-20210222170800-9c70f9b80bcf",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: file.NewLocationSet(
						file.NewLocationFromCoordinates(
							file.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						H1Digest:          "h1:DYssiUV1pBmKqzKsm4mqXx8artqC0Q8HgZsVI3lMsAg=",
						MainModule:        "github.com/anchore/syft",
					},
				},
				unmodifiedMain,
			},
		},
		{
			name: "parse a populated mod string and returns packages when a replace directive exists",
			mod: &extendedBuildInfo{
				BuildInfo: &debug.BuildInfo{
					GoVersion: goCompiledVersion,
					Main:      debug.Module{Path: "github.com/anchore/syft", Version: "(devel)"},
					Settings: []debug.BuildSetting{
						{Key: "GOARCH", Value: archDetails},
						{Key: "GOOS", Value: "darwin"},
						{Key: "GOAMD64", Value: "v1"},
					},
					Deps: []*debug.Module{
						{
							Path:    "golang.org/x/sys",
							Version: "v0.0.0-20211006194710-c8a6f5223071",
							Sum:     "h1:PjhxBct4MZii8FFR8+oeS7QOvxKOTZXgk63EU2XpfJE=",
						},
						{
							Path:    "golang.org/x/term",
							Version: "v0.0.0-20210927222741-03fcf44c2211",
							Sum:     "h1:PjhxBct4MZii8FFR8+oeS7QOvxKOTZXgk63EU2XpfJE=",
							Replace: &debug.Module{
								Path:    "golang.org/x/term",
								Version: "v0.0.0-20210916214954-140adaaadfaf",
								Sum:     "h1:Ihq/mm/suC88gF8WFcVwk+OV6Tq+wyA1O0E5UEvDglI=",
							},
						},
					},
				},
				cryptoSettings: nil,
				arch:           archDetails,
			},
			expected: []pkg.Package{
				{
					Name:     "golang.org/x/sys",
					Version:  "v0.0.0-20211006194710-c8a6f5223071",
					PURL:     "pkg:golang/golang.org/x/sys@v0.0.0-20211006194710-c8a6f5223071",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: file.NewLocationSet(
						file.NewLocationFromCoordinates(
							file.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						H1Digest:          "h1:PjhxBct4MZii8FFR8+oeS7QOvxKOTZXgk63EU2XpfJE=",
						MainModule:        "github.com/anchore/syft",
					}},
				{
					Name:     "golang.org/x/term",
					Version:  "v0.0.0-20210916214954-140adaaadfaf",
					PURL:     "pkg:golang/golang.org/x/term@v0.0.0-20210916214954-140adaaadfaf",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: file.NewLocationSet(
						file.NewLocationFromCoordinates(
							file.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						H1Digest:          "h1:Ihq/mm/suC88gF8WFcVwk+OV6Tq+wyA1O0E5UEvDglI=",
						MainModule:        "github.com/anchore/syft",
					},
				},
				unmodifiedMain,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for i := range test.expected {
				p := &test.expected[i]
				p.SetID()
			}
			location := file.NewLocationFromCoordinates(
				file.Coordinates{
					RealPath:     "/a-path",
					FileSystemID: "layer-id",
				},
			)

			c := goBinaryCataloger{}
			pkgs := c.buildGoPkgInfo(fileresolver.Empty{}, location, test.mod, test.mod.arch)
			assert.Equal(t, test.expected, pkgs)
		})
	}
}

func Test_extractVersionFromLDFlags(t *testing.T) {
	tests := []struct {
		name             string
		ldflags          string
		wantMajorVersion string
		wantFullVersion  string
	}{
		{
			name:    "empty ldflags",
			ldflags: "",
		},
		{
			name:             "syft ldflags",
			ldflags:          `	build	-ldflags="-w -s -extldflags '-static' -X github.com/anchore/syft/internal/version.version=0.79.0 -X github.com/anchore/syft/internal/version.gitCommit=b2b332e8b2b66af0905e98b54ebd713a922be1a8 -X github.com/anchore/syft/internal/version.buildDate=2023-04-21T16:20:25Z -X github.com/anchore/syft/internal/version.gitDescription=v0.79.0 "`,
			wantMajorVersion: "0",
			wantFullVersion:  "v0.79.0",
		},
		{
			name: "kubectl ldflags",
			ldflags: `	build	-asmflags=all=-trimpath=/workspace/src/k8s.io/kubernetes/_output/dockerized/go/src/k8s.io/kubernetes
	build	-compiler=gc
	build	-gcflags="all=-trimpath=/workspace/src/k8s.io/kubernetes/_output/dockerized/go/src/k8s.io/kubernetes "
	build	-ldflags="all=-X 'k8s.io/kubernetes/vendor/k8s.io/client-go/pkg/version.buildDate=2023-04-12T12:16:51Z' -X 'k8s.io/kubernetes/vendor/k8s.io/component-base/version.buildDate=2023-04-12T12:16:51Z' -X 'k8s.io/client-go/pkg/version.buildDate=2023-04-12T12:16:51Z' -X 'k8s.io/component-base/version.buildDate=2023-04-12T12:16:51Z' -X 'k8s.io/kubernetes/vendor/k8s.io/client-go/pkg/version.gitCommit=a1a87a0a2bcd605820920c6b0e618a8ab7d117d4' -X 'k8s.io/kubernetes/vendor/k8s.io/component-base/version.gitCommit=a1a87a0a2bcd605820920c6b0e618a8ab7d117d4' -X 'k8s.io/client-go/pkg/version.gitCommit=a1a87a0a2bcd605820920c6b0e618a8ab7d117d4' -X 'k8s.io/component-base/version.gitCommit=a1a87a0a2bcd605820920c6b0e618a8ab7d117d4' -X 'k8s.io/kubernetes/vendor/k8s.io/client-go/pkg/version.gitTreeState=clean' -X 'k8s.io/kubernetes/vendor/k8s.io/component-base/version.gitTreeState=clean' -X 'k8s.io/client-go/pkg/version.gitTreeState=clean' -X 'k8s.io/component-base/version.gitTreeState=clean' -X 'k8s.io/kubernetes/vendor/k8s.io/client-go/pkg/version.gitVersion=v1.25.9' -X 'k8s.io/kubernetes/vendor/k8s.io/component-base/version.gitVersion=v1.25.9' -X 'k8s.io/client-go/pkg/version.gitVersion=v1.25.9' -X 'k8s.io/component-base/version.gitVersion=v1.25.9' -X 'k8s.io/kubernetes/vendor/k8s.io/client-go/pkg/version.gitMajor=1' -X 'k8s.io/kubernetes/vendor/k8s.io/component-base/version.gitMajor=1' -X 'k8s.io/client-go/pkg/version.gitMajor=1' -X 'k8s.io/component-base/version.gitMajor=1' -X 'k8s.io/kubernetes/vendor/k8s.io/client-go/pkg/version.gitMinor=25' -X 'k8s.io/kubernetes/vendor/k8s.io/component-base/version.gitMinor=25' -X 'k8s.io/client-go/pkg/version.gitMinor=25' -X 'k8s.io/component-base/version.gitMinor=25'  -s -w"`,
			wantMajorVersion: "1",
			wantFullVersion:  "v1.25.9",
		},
		{
			name:             "nerdctl ldflags",
			ldflags:          `	build	-ldflags="-s -w -X github.com/containerd/nerdctl/pkg/version.Version=v1.3.1 -X github.com/containerd/nerdctl/pkg/version.Revision=b224b280ff3086516763c7335fc0e0997aca617a"`,
			wantMajorVersion: "1",
			wantFullVersion:  "v1.3.1",
		},
		{
			name:             "limactl ldflags",
			ldflags:          `	build	-ldflags="-s -w -X github.com/lima-vm/lima/pkg/version.Version=v0.15.1"`,
			wantMajorVersion: "0",
			wantFullVersion:  "v0.15.1",
		},
		{
			name:             "terraform ldflags",
			ldflags:          `	build	-ldflags="-w -s -X 'github.com/hashicorp/terraform/version.Version=1.4.6' -X 'github.com/hashicorp/terraform/version.Prerelease='"`,
			wantMajorVersion: "1",
			wantFullVersion:  "v1.4.6",
		},
		{
			name: "kube-apiserver ldflags",
			ldflags: `	build	-asmflags=all=-trimpath=/workspace/src/k8s.io/kubernetes/_output/dockerized/go/src/k8s.io/kubernetes
	build	-buildmode=exe
	build	-compiler=gc
	build	-gcflags="all=-trimpath=/workspace/src/k8s.io/kubernetes/_output/dockerized/go/src/k8s.io/kubernetes "
	build	-ldflags="all=-X 'k8s.io/kubernetes/vendor/k8s.io/client-go/pkg/version.buildDate=2023-04-14T13:14:42Z' -X 'k8s.io/kubernetes/vendor/k8s.io/component-base/version.buildDate=2023-04-14T13:14:42Z' -X 'k8s.io/client-go/pkg/version.buildDate=2023-04-14T13:14:42Z' -X 'k8s.io/component-base/version.buildDate=2023-04-14T13:14:42Z' -X 'k8s.io/kubernetes/vendor/k8s.io/client-go/pkg/version.gitCommit=4c9411232e10168d7b050c49a1b59f6df9d7ea4b' -X 'k8s.io/kubernetes/vendor/k8s.io/component-base/version.gitCommit=4c9411232e10168d7b050c49a1b59f6df9d7ea4b' -X 'k8s.io/client-go/pkg/version.gitCommit=4c9411232e10168d7b050c49a1b59f6df9d7ea4b' -X 'k8s.io/component-base/version.gitCommit=4c9411232e10168d7b050c49a1b59f6df9d7ea4b' -X 'k8s.io/kubernetes/vendor/k8s.io/client-go/pkg/version.gitTreeState=clean' -X 'k8s.io/kubernetes/vendor/k8s.io/component-base/version.gitTreeState=clean' -X 'k8s.io/client-go/pkg/version.gitTreeState=clean' -X 'k8s.io/component-base/version.gitTreeState=clean' -X 'k8s.io/kubernetes/vendor/k8s.io/client-go/pkg/version.gitVersion=v1.27.1' -X 'k8s.io/kubernetes/vendor/k8s.io/component-base/version.gitVersion=v1.27.1' -X 'k8s.io/client-go/pkg/version.gitVersion=v1.27.1' -X 'k8s.io/component-base/version.gitVersion=v1.27.1' -X 'k8s.io/kubernetes/vendor/k8s.io/client-go/pkg/version.gitMajor=1' -X 'k8s.io/kubernetes/vendor/k8s.io/component-base/version.gitMajor=1' -X 'k8s.io/client-go/pkg/version.gitMajor=1' -X 'k8s.io/component-base/version.gitMajor=1' -X 'k8s.io/kubernetes/vendor/k8s.io/client-go/pkg/version.gitMinor=27' -X 'k8s.io/kubernetes/vendor/k8s.io/component-base/version.gitMinor=27' -X 'k8s.io/client-go/pkg/version.gitMinor=27' -X 'k8s.io/component-base/version.gitMinor=27'  -s -w"`,
			wantMajorVersion: "1",
			wantFullVersion:  "v1.27.1",
		},
		{
			name: "prometheus ldflags",
			ldflags: `	build	-ldflags="-X github.com/prometheus/common/version.Version=2.44.0 -X github.com/prometheus/common/version.Revision=1ac5131f698ebc60f13fe2727f89b115a41f6558 -X github.com/prometheus/common/version.Branch=HEAD -X github.com/prometheus/common/version.BuildUser=root@739e8181c5db -X github.com/prometheus/common/version.BuildDate=20230514-06:18:11  -extldflags '-static'"
	build	-tags=netgo,builtinassets,stringlabels`,
			wantMajorVersion: "2",
			wantFullVersion:  "v2.44.0",
		},
		{
			name: "influxdb ldflags",
			ldflags: `	build	-ldflags="-s -w -X main.version=v2.7.1 -X main.commit=407fa622e9 -X main.date=2023-04-28T13:24:27Z -linkmode=external -extld=/musl/x86_64/bin/musl-gcc -extldflags '-fno-PIC -static-pie -Wl,-z,stack-size=8388608'"
	build	-tags=assets,sqlite_foreign_keys,sqlite_json,static_build,noasm`,
			wantMajorVersion: "2",
			wantFullVersion:  "v2.7.1",
		},
		{
			name:             "gitea ldflags",
			ldflags:          `	build	-ldflags=" -X \"main.MakeVersion=GNU Make 4.1\" -X \"main.Version=1.19.3\" -X \"main.Tags=bindata sqlite sqlite_unlock_notify\" "`,
			wantMajorVersion: "1",
			wantFullVersion:  "v1.19.3",
		},
		{
			name:             "docker sbom cli ldflags",
			ldflags:          `	build	-ldflags="-w -s -extldflags '-static' -X github.com/docker/sbom-cli-plugin/internal/version.version=0.6.1-SNAPSHOT-02cf1c8 -X github.com/docker/sbom-cli-plugin/internal/version.gitCommit=02cf1c888ad6662109ac6e3be618392514a56316 -X github.com/docker/sbom-cli-plugin/internal/version.gitDescription=v0.6.1-dirty "`,
			wantMajorVersion: "0",
			wantFullVersion:  "v0.6.1-SNAPSHOT-02cf1c8",
		},
		{
			name:             "docker scout ldflags",
			ldflags:          `	build	-ldflags="-w -s -extldflags '-static' -X github.com/docker/scout-cli-plugin/internal.version=0.10.0 "`,
			wantMajorVersion: "0",
			wantFullVersion:  "v0.10.0",
		},
		{
			name:             "influx telegraf ldflags",
			ldflags:          `	build	-ldflags="-w -s -X github.com/influxdata/telegraf/internal.Commit=a3a884a1 -X github.com/influxdata/telegraf/internal.Branch=HEAD -X github.com/influxdata/telegraf/internal.Version=1.26.2"`,
			wantMajorVersion: "1",
			wantFullVersion:  "v1.26.2",
		},
		{
			name:             "argocd ldflags",
			ldflags:          `	build	-ldflags="-X github.com/argoproj/argo-cd/v2/common.version=2.7.2 -X github.com/argoproj/argo-cd/v2/common.buildDate=2023-05-12T14:06:49Z -X github.com/argoproj/argo-cd/v2/common.gitCommit=cbee7e6011407ed2d1066c482db74e97e0cc6bdb -X github.com/argoproj/argo-cd/v2/common.gitTreeState=clean -X github.com/argoproj/argo-cd/v2/common.kubectlVersion=v0.24.2 -extldflags=\"-static\""`,
			wantMajorVersion: "2",
			wantFullVersion:  "v2.7.2",
		},
		{
			name:             "kustomize ldflags",
			ldflags:          `	build	-ldflags="-s -X sigs.k8s.io/kustomize/api/provenance.version=kustomize/v4.5.7 -X sigs.k8s.io/kustomize/api/provenance.gitCommit=56d82a8378dfc8dc3b3b1085e5a6e67b82966bd7 -X sigs.k8s.io/kustomize/api/provenance.buildDate=2022-08-02T16:35:54Z "`,
			wantMajorVersion: "4",
			wantFullVersion:  "v4.5.7",
		},
		//////////////////////////////////////////////////////////////////
		// negative cases
		{
			name:    "hugo ldflags",
			ldflags: `	build	-ldflags="-s -w -X github.com/gohugoio/hugo/common/hugo.vendorInfo=gohugoio"`,
		},
		{
			name:    "ghostunnel ldflags",
			ldflags: `	build	-ldflags="-X main.version=77d9aaa"`,
		},
		{
			name:    "opa ldflags",
			ldflags: `build	-ldflags=" -X github.com/open-policy-agent/opa/version.Hostname=9549178459bc"`,
		},
		///////////////////////////////////////////////////////////////////
		// trickier cases
		{
			name:             "macvlan plugin for cri-o ldflags",
			ldflags:          `	build	-ldflags="-extldflags -static -X github.com/containernetworking/plugins/pkg/utils/buildversion.BuildVersion=v1.2.0"`,
			wantMajorVersion: "1",
			wantFullVersion:  "v1.2.0",
		},
		{
			name:             "coder ldflags",
			ldflags:          `	build	-ldflags="-s -w -X 'github.com/coder/coder/buildinfo.tag=0.23.4'"`,
			wantMajorVersion: "0",
			wantFullVersion:  "v0.23.4",
		},
		///////////////////////////////////////////////////////////////////
		// don't know how to handle these... yet
		//{
		//	// package name: pkgName: "github.com/krakendio/krakend-ce/v2",
		//	name:             "krakenD ldflags",
		//	ldflags:          `	build	-ldflags="-X github.com/luraproject/lura/v2/core.KrakendVersion=2.3.2 -X github.com/luraproject/lura/v2/core.GoVersion=1.20.4 -X github.com/luraproject/lura/v2/core.GlibcVersion=GLIBC-2.31_(debian-11) "`,
		//	wantMajorVersion: "2.3.2",
		//	wantFullVersion:  "v2.3.2",
		//},
		//{
		//	// package name: pkgName: "github.com/krakendio/krakend-ce/v2",
		//	name:             "krakenD ldflags -- answer embedded in the middle",
		//	ldflags:          `	build	-ldflags=" -X github.com/luraproject/lura/v2/core.GoVersion=1.20.4 -X github.com/luraproject/lura/v2/core.KrakendVersion=2.3.2 -X github.com/luraproject/lura/v2/core.GlibcVersion=GLIBC-2.31_(debian-11) "`,
		//	wantMajorVersion: "2.3.2",
		//	wantFullVersion:  "v2.3.2",
		//},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMajorVersion, gotFullVersion := extractVersionFromLDFlags(tt.ldflags)
			assert.Equal(t, tt.wantMajorVersion, gotMajorVersion, "unexpected major version")
			assert.Equal(t, tt.wantFullVersion, gotFullVersion, "unexpected full version")
		})
	}
}
