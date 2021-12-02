package distro

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	hashiVer "github.com/hashicorp/go-version"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

const CustomDistro Type = "scientific"

func TestIdentifyDistro(t *testing.T) {
	tests := []struct {
		fixture string
		Type    Type
		Version string
	}{
		{
			fixture: "test-fixtures/os/alpine",
			Type:    Alpine,
			Version: "3.11.6",
		},
		{
			fixture: "test-fixtures/os/amazon",
			Type:    AmazonLinux,
			Version: "2.0.0",
		},
		{
			fixture: "test-fixtures/os/busybox",
			Type:    Busybox,
			Version: "1.31.1",
		},
		{
			fixture: "test-fixtures/os/centos",
			Type:    CentOS,
			Version: "8.0.0",
		},
		{
			fixture: "test-fixtures/os/debian",
			Type:    Debian,
			Version: "8.0.0",
		},
		{
			fixture: "test-fixtures/os/fedora",
			Type:    Fedora,
			Version: "31.0.0",
		},
		{
			fixture: "test-fixtures/os/redhat",
			Type:    RedHat,
			Version: "7.3.0",
		},
		{
			fixture: "test-fixtures/os/ubuntu",
			Type:    Ubuntu,
			Version: "20.4.0",
		},
		{
			fixture: "test-fixtures/os/oraclelinux",
			Type:    OracleLinux,
			Version: "8.3.0",
		},
		{
			fixture: "test-fixtures/os/empty",
			Type:    UnknownDistroType,
		},
		{
			fixture: "test-fixtures/os/custom",
			Type:    CustomDistro,
			Version: "8.0.0",
		},
		{
			fixture: "test-fixtures/os/opensuse-leap",
			Type:    OpenSuseLeap,
			Version: "15.2.0",
		},
		{
			fixture: "test-fixtures/os/sles",
			Type:    SLES,
			Version: "15.2.0",
		},
		{
			fixture: "test-fixtures/os/photon",
			Type:    Photon,
			Version: "2.0.0",
		},
		{
			fixture: "test-fixtures/os/arch",
			Type:    ArchLinux,
		},
		{
			fixture: "test-fixtures/partial-fields/missing-id",
			Type:    Debian,
			Version: "8.0.0",
		},
		{
			fixture: "test-fixtures/partial-fields/unknown-id",
			Type:    Debian,
			Version: "8.0.0",
		},
		{
			fixture: "test-fixtures/partial-fields/missing-version",
			Type:    UnknownDistroType,
		},
		{
			fixture: "test-fixtures/os/centos6",
			Type:    CentOS,
			Version: "6.0.0",
		},
		{
			fixture: "test-fixtures/os/centos5",
			Type:    CentOS,
			Version: "5.7.0",
		},
		{
			fixture: "test-fixtures/os/mariner",
			Type:    Mariner,
			Version: "1.0.0",
		},
		{
			fixture: "test-fixtures/os/rockylinux",
			Type:    RockyLinux,
			Version: "8.4.0",
		},
		{
			fixture: "test-fixtures/os/almalinux",
			Type:    AlmaLinux,
			Version: "8.4.0",
		},
	}
	}

	observedDistros := internal.NewStringSet()
	definedDistros := internal.NewStringSet()

	for _, distroType := range All {
		definedDistros.Add(string(distroType))
	}

	// Somewhat cheating with Windows. There is no support for detecting/parsing a Windows OS, so it is not
	// possible to comply with this test unless it is added manually to the "observed distros"
	definedDistros.Remove(string(Windows))

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			s, err := source.NewFromDirectory(test.fixture)
			if err != nil {
				t.Fatalf("unable to produce a new source for testing: %s", test.fixture)
			}

			resolver, err := s.FileResolver(source.SquashedScope)
			if err != nil {
				t.Fatalf("unable to get resolver: %+v", err)
			}

			d := Identify(resolver)
			if d == nil {
				if test.Type == UnknownDistroType {
					return
				}
				t.Fatalf("expected a distro but got none")
			}
			observedDistros.Add(d.String())

			if d.Type != test.Type {
				t.Errorf("expected distro doesn't match: %v != %v", d.Type, test.Type)
			}

			if d.Type == UnknownDistroType && d.Version != nil {
				t.Fatalf("version should be nil for unknown distros")
			} else if d.Type == UnknownDistroType && d.Version == nil {
				// don't check versions for unknown distro types
				return
			}

			if d.Version == nil && test.Version == "" {
				// this distro does not have a version
				return
			}

			assert.Equal(t, d.Version.String(), test.Version)
		})
	}

	// ensure that test cases stay in sync with the distros that can be identified
	if len(observedDistros) < len(definedDistros) {
		for _, d := range definedDistros.ToSlice() {
			t.Logf("   defined: %s", d)
		}
		for _, d := range observedDistros.ToSlice() {
			t.Logf("   observed: %s", d)
		}
		t.Errorf("distro coverage incomplete (defined=%d, coverage=%d)", len(definedDistros), len(observedDistros))
	}
}

func TestParseOsRelease(t *testing.T) {

	tests := []struct {
		fixture    string
		name       string
		RawVersion string
	}{
		{
			fixture:    "test-fixtures/ubuntu-20.04",
			name:       "ubuntu",
			RawVersion: "20.04",
		},
		{
			fixture:    "test-fixtures/debian-8",
			name:       "debian",
			RawVersion: "8",
		},
		{
			fixture:    "test-fixtures/centos-8",
			name:       "centos",
			RawVersion: "8",
		},
		{
			fixture:    "test-fixtures/rhel-8",
			name:       "redhat",
			RawVersion: "8.1",
		},
		{
			fixture:    "test-fixtures/unprintable",
			name:       "debian",
			RawVersion: "8",
		},
	}

	for _, test := range tests {
		name := fmt.Sprintf("%s:%s", test.name, test.RawVersion)
		contents := retrieveFixtureContentsAsString(test.fixture, t)

		t.Run(name, func(t *testing.T) {
			distro := parseOsRelease(contents)
			if distro.Name() != test.name {
				t.Errorf("mismatched name in distro: '%s' != '%s'", distro.Name(), test.name)
			}
			if distro.RawVersion != test.RawVersion {
				t.Errorf("mismatched distro version: '%s' != '%s'", distro.RawVersion, test.RawVersion)
			}
		})
	}

}

func TestParseOsReleaseFailures(t *testing.T) {

	tests := []struct {
		fixture string
		name    string
	}{
		{
			fixture: "test-fixtures/bad-id",
			name:    "No name ID",
		},
	}

	for _, test := range tests {
		name := fmt.Sprintf("%s:%s", test.name, test.fixture)
		contents := retrieveFixtureContentsAsString(test.fixture, t)

		t.Run(name, func(t *testing.T) {
			distro := parseOsRelease(contents)
			if distro != nil {
				t.Errorf("unexpected non-nil distro: '%s' != nil", distro)
			}
		})
	}
}

func TestParseSystemReleaseCPE(t *testing.T) {
	centos6Version, _ := hashiVer.NewVersion("6")
	tests := []struct {
		fixture  string
		name     string
		expected *Distro
	}{
		{
			fixture: "test-fixtures/os/centos6/etc/system-release-cpe",
			name:    "Centos 6",
			expected: &Distro{
				Type:       CentOS,
				Version:    centos6Version,
				RawVersion: "6",
			},
		},
		{
			fixture:  "test-fixtures/bad-system-release-cpe",
			name:     "Centos 6 Bad CPE",
			expected: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			contents := retrieveFixtureContentsAsString(test.fixture, t)
			actual := parseSystemReleaseCPE(contents)

			if test.expected == nil {
				assert.Nil(t, actual)
				return
			}

			// not comparing the full distro object because the hashiVer is a pointer
			assert.Equal(t, test.expected.Type, actual.Type)
			assert.Equal(t, &test.expected.Version, &actual.Version)
			assert.Equal(t, test.expected.RawVersion, actual.RawVersion)
		})
	}
}

func TestParseRedhatRelease(t *testing.T) {
	centos5Version, _ := hashiVer.NewVersion("5.7")
	tests := []struct {
		fixture  string
		name     string
		expected *Distro
	}{
		{
			fixture: "test-fixtures/os/centos5/etc/redhat-release",
			name:    "Centos 5",
			expected: &Distro{
				Type:       CentOS,
				Version:    centos5Version,
				RawVersion: "5.7",
			},
		},
		{
			fixture:  "test-fixtures/bad-redhat-release",
			name:     "Centos 5 Bad Redhat Release",
			expected: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			contents := retrieveFixtureContentsAsString(test.fixture, t)
			actual := parseRedhatRelease(contents)

			if test.expected == nil {
				assert.Nil(t, actual)
				return
			}

			// not comparing the full distro object because the hashiVer is a pointer
			assert.Equal(t, test.expected.Type, actual.Type)
			assert.Equal(t, &test.expected.Version, &actual.Version)
			assert.Equal(t, test.expected.RawVersion, actual.RawVersion)
		})
	}
}

func retrieveFixtureContentsAsString(fixturePath string, t *testing.T) string {
	fixture, err := os.Open(fixturePath)
	if err != nil {
		t.Fatalf("could not open test fixture=%s: %+v", fixturePath, err)
	}
	defer fixture.Close()

	b, err := ioutil.ReadAll(fixture)
	if err != nil {
		t.Fatalf("unable to read fixture file: %+v", err)
	}

	return string(b)
}
