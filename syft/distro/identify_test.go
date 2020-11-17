package distro

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/anchore/syft/internal"

	"github.com/anchore/syft/syft/source"
)

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
			fixture: "test-fixtures/os/empty",
			Type:    UnknownDistroType,
		},
		{
			fixture: "test-fixtures/os/unmatchable",
			Type:    UnknownDistroType,
		},
		{
			fixture: "test-fixtures/os/opensuse-leap",
			Type:    OpenSuseLeap,
			Version: "15.2.0",
		},
		{
			fixture: "test-fixtures/os/arch",
			Type:    ArchLinux,
		},
	}

	observedDistros := internal.NewStringSet()
	definedDistros := internal.NewStringSet()
	for _, distroType := range All {
		definedDistros.Add(string(distroType))
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			s, err := source.NewFromDirectory(test.fixture)
			if err != nil {
				t.Fatalf("unable to produce a new source for testing: %s", test.fixture)
			}

			d := Identify(s.Resolver)
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

			if d.Version == nil {
				t.Log("Distro doesn't have a Version")
				return
			}

			if d.Version.String() != test.Version {
				t.Errorf("expected distro version doesn't match: %v != %v", d.Version.String(), test.Version)
			}
		})
	}

	// ensure that test cases stay in sync with the distros that can be identified
	if len(observedDistros) < len(definedDistros) {
		t.Errorf("distro coverage incomplete (distro=%d, coverage=%d)", len(definedDistros), len(observedDistros))
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
		fixture, err := os.Open(test.fixture)
		if err != nil {
			t.Fatalf("could not open test fixture=%s: %+v", test.fixture, err)
		}
		defer fixture.Close()

		b, err := ioutil.ReadAll(fixture)
		if err != nil {
			t.Fatalf("unable to read fixture file: %+v", err)
		}

		contents := string(b)

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
		fixture, err := os.Open(test.fixture)
		if err != nil {
			t.Fatalf("could not open test fixture=%s: %+v", test.fixture, err)
		}
		defer fixture.Close()

		b, err := ioutil.ReadAll(fixture)
		if err != nil {
			t.Fatalf("unable to read fixture file: %+v", err)
		}

		contents := string(b)

		t.Run(name, func(t *testing.T) {
			distro := parseOsRelease(contents)
			if distro != nil {
				t.Errorf("unexpected non-nil distro: '%s' != nil", distro)
			}
		})
	}

}
