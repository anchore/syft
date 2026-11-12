package redhat

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseRpmManifest(t *testing.T) {
	fixture := "testdata/container-manifest-2"
	location := file.NewLocation(fixture)
	expected := []pkg.Package{
		{
			Name:      "mariner-release",
			Version:   "2.0-12.cm2",
			PURL:      "pkg:rpm/mariner-release@2.0-12.cm2?arch=noarch&upstream=mariner-release-2.0-12.cm2.src.rpm",
			Locations: file.NewLocationSet(location),
			Type:      pkg.RpmPkg,
			Metadata: pkg.RpmDBEntry{
				Name:      "mariner-release",
				Epoch:     nil,
				Arch:      "noarch",
				Release:   "12.cm2",
				Version:   "2.0",
				SourceRpm: "mariner-release-2.0-12.cm2.src.rpm",
				Size:      580,
				Vendor:    "Microsoft Corporation",
			},
		},
		{
			Name:      "filesystem",
			Version:   "1.1-9.cm2",
			PURL:      "pkg:rpm/filesystem@1.1-9.cm2?arch=x86_64&upstream=filesystem-1.1-9.cm2.src.rpm",
			Locations: file.NewLocationSet(location),
			Type:      pkg.RpmPkg,
			Metadata: pkg.RpmDBEntry{
				Name:      "filesystem",
				Epoch:     nil,
				Arch:      "x86_64",
				Release:   "9.cm2",
				Version:   "1.1",
				SourceRpm: "filesystem-1.1-9.cm2.src.rpm",
				Size:      7596,
				Vendor:    "Microsoft Corporation",
			},
		},
		{
			Name:      "glibc",
			Version:   "2.35-2.cm2",
			PURL:      "pkg:rpm/glibc@2.35-2.cm2?arch=x86_64&upstream=glibc-2.35-2.cm2.src.rpm",
			Locations: file.NewLocationSet(location),
			Type:      pkg.RpmPkg,
			Metadata: pkg.RpmDBEntry{
				Name:      "glibc",
				Epoch:     nil,
				Arch:      "x86_64",
				Release:   "2.cm2",
				Version:   "2.35",
				SourceRpm: "glibc-2.35-2.cm2.src.rpm",
				Size:      10855265,
				Vendor:    "Microsoft Corporation",
			},
		},
		{
			Name:      "openssl-libs",
			Version:   "1.1.1k-15.cm2",
			PURL:      "pkg:rpm/openssl-libs@1.1.1k-15.cm2?arch=x86_64&upstream=openssl-1.1.1k-15.cm2.src.rpm",
			Locations: file.NewLocationSet(location),
			Type:      pkg.RpmPkg,
			Metadata: pkg.RpmDBEntry{
				Name:      "openssl-libs",
				Epoch:     nil,
				Arch:      "x86_64",
				Release:   "15.cm2",
				Version:   "1.1.1k",
				SourceRpm: "openssl-1.1.1k-15.cm2.src.rpm",
				Size:      4365048,
				Vendor:    "Microsoft Corporation",
			},
		},
		{
			Name:      "vim",
			Version:   "2:9.0-1.cm2",
			PURL:      "pkg:rpm/vim@9.0-1.cm2?arch=x86_64&epoch=2&upstream=vim-9.0-1.cm2.src.rpm",
			Locations: file.NewLocationSet(location),
			Type:      pkg.RpmPkg,
			Metadata: pkg.RpmDBEntry{
				Name:      "vim",
				Epoch:     intRef(2),
				Arch:      "x86_64",
				Release:   "1.cm2",
				Version:   "9.0",
				SourceRpm: "vim-9.0-1.cm2.src.rpm",
				Size:      45000,
				Vendor:    "Microsoft Corporation",
			},
		},
	}

	pkgtest.NewCatalogTester().
		FromFile(t, fixture).
		Expects(expected, nil).
		TestParser(t, parseRpmManifest)

}

func TestNewMetadataFromManifestLine(t *testing.T) {
	// fields are: NAME, VERSION-RELEASE, INSTALLTIME, BUILDTIME, VENDOR, EPOCH, SIZE, ARCH, EPOCHNUM, SOURCERPM
	line := func(epoch, size, epochNum string) string {
		return strings.Join([]string{
			"vim", "9.0-1.cm2", "1653816591", "1653753130", "Microsoft Corporation",
			epoch, size, "x86_64", epochNum, "vim-9.0-1.cm2.src.rpm",
		}, "\t")
	}

	tests := []struct {
		name      string
		entry     string
		wantEpoch *int
		wantSize  int
		wantErr   require.ErrorAssertionFunc
	}{
		{
			name:      "no epoch",
			entry:     line("(none)", "45000", "0"),
			wantEpoch: nil,
			wantSize:  45000,
		},
		{
			name:      "explicit zero epoch is distinct from no epoch",
			entry:     line("0", "45000", "0"),
			wantEpoch: intRef(0),
			wantSize:  45000,
		},
		{
			name:      "unparsable epochnum yields no epoch",
			entry:     line("2", "45000", ""),
			wantEpoch: nil,
			wantSize:  45000,
		},
		{
			name:      "unparsable size yields zero size",
			entry:     line("2", "bogus", "2"),
			wantEpoch: intRef(2),
			wantSize:  0,
		},
		{
			name:    "too few fields",
			entry:   "vim\t9.0-1.cm2",
			wantErr: require.Error,
		},
		{
			name:    "version field missing the release",
			entry:   strings.Replace(line("(none)", "45000", "0"), "9.0-1.cm2", "9.0", 1),
			wantErr: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			metadata, err := newMetadataFromManifestLine(tt.entry)
			tt.wantErr(t, err)
			if err != nil {
				return
			}

			require.NotNil(t, metadata)
			assert.Equal(t, tt.wantEpoch, metadata.Epoch)
			assert.Equal(t, tt.wantSize, metadata.Size)
		})
	}
}
