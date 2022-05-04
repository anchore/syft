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

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	buildSettings := map[string]string{
		"GOARCH":  "amd64",
		"GOOS":    "darwin",
		"GOAMD64": "v1",
	}

	expectedMain := pkg.Package{
		Name:     "github.com/anchore/syft",
		FoundBy:  catalogerName,
		Language: pkg.Go,
		Type:     pkg.GoModulePkg,
		Version:  "(devel)",
		Locations: source.NewLocationSet(
			source.Location{
				Coordinates: source.Coordinates{
					RealPath:     "/a-path",
					FileSystemID: "layer-id",
				},
			},
		),
		MetadataType: pkg.GolangBinMetadataType,
		Metadata: pkg.GolangBinMetadata{
			GoCompiledVersion: goCompiledVersion,
			Architecture:      archDetails,
			BuildSettings:     buildSettings,
		},
	}

	tests := []struct {
		name     string
		mod      *debug.BuildInfo
		arch     string
		expected []pkg.Package
	}{
		{
			name:     "buildGoPkgInfo parses a nil mod",
			mod:      nil,
			expected: []pkg.Package(nil),
		},
		{
			name:     "buildGoPkgInfo parses a blank mod and returns no packages",
			mod:      &debug.BuildInfo{},
			expected: []pkg.Package(nil),
		},
		{
			name: "buildGoPkgInfo parses a mod without main module",
			arch: archDetails,
			mod: &debug.BuildInfo{
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
			expected: []pkg.Package{
				{
					Name:     "github.com/adrg/xdg",
					FoundBy:  catalogerName,
					Version:  "v0.2.1",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: source.NewLocationSet(
						source.Location{
							Coordinates: source.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						},
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
			name: "buildGoPkgInfo parses a mod without packages",
			arch: archDetails,
			mod: &debug.BuildInfo{
				GoVersion: goCompiledVersion,
				Main:      debug.Module{Path: "github.com/anchore/syft", Version: "(devel)"},
				Settings: []debug.BuildSetting{
					{Key: "GOARCH", Value: archDetails},
					{Key: "GOOS", Value: "darwin"},
					{Key: "GOAMD64", Value: "v1"},
				},
			},
			expected: []pkg.Package{expectedMain},
		},
		{
			name: "buildGoPkgInfo parses a populated mod string and returns packages but no source info",
			arch: archDetails,
			mod: &debug.BuildInfo{
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
			expected: []pkg.Package{
				{
					Name:     "github.com/adrg/xdg",
					FoundBy:  catalogerName,
					Version:  "v0.2.1",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: source.NewLocationSet(
						source.Location{
							Coordinates: source.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						},
					),
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						H1Digest:          "h1:VSVdnH7cQ7V+B33qSJHTCRlNgra1607Q8PzEmnvb2Ic=",
					},
				},
				{
					Name:     "github.com/anchore/client-go",
					FoundBy:  catalogerName,
					Version:  "v0.0.0-20210222170800-9c70f9b80bcf",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: source.NewLocationSet(
						source.Location{
							Coordinates: source.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						},
					),
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						H1Digest:          "h1:DYssiUV1pBmKqzKsm4mqXx8artqC0Q8HgZsVI3lMsAg=",
					},
				},
				expectedMain,
			},
		},
		{
			name: "buildGoPkgInfo parses a populated mod string and returns packages when a replace directive exists",
			arch: archDetails,
			mod: &debug.BuildInfo{
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
			expected: []pkg.Package{
				{
					Name:     "golang.org/x/sys",
					FoundBy:  catalogerName,
					Version:  "v0.0.0-20211006194710-c8a6f5223071",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: source.NewLocationSet(
						source.Location{
							Coordinates: source.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						},
					),
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						H1Digest:          "h1:PjhxBct4MZii8FFR8+oeS7QOvxKOTZXgk63EU2XpfJE="}},
				{
					Name:     "golang.org/x/term",
					FoundBy:  catalogerName,
					Version:  "v0.0.0-20210916214954-140adaaadfaf",
					Language: pkg.Go,
					Type:     pkg.GoModulePkg,
					Locations: source.NewLocationSet(
						source.Location{
							Coordinates: source.Coordinates{
								RealPath:     "/a-path",
								FileSystemID: "layer-id",
							},
						},
					),
					MetadataType: pkg.GolangBinMetadataType,
					Metadata: pkg.GolangBinMetadata{
						GoCompiledVersion: goCompiledVersion,
						Architecture:      archDetails,
						H1Digest:          "h1:Ihq/mm/suC88gF8WFcVwk+OV6Tq+wyA1O0E5UEvDglI="},
				},
				expectedMain,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for i := range test.expected {
				p := &test.expected[i]
				p.SetID()
			}
			location := source.Location{
				Coordinates: source.Coordinates{
					RealPath:     "/a-path",
					FileSystemID: "layer-id",
				},
			}
			pkgs := buildGoPkgInfo(location, test.mod, test.arch)
			assert.Equal(t, test.expected, pkgs)
		})
	}
}
