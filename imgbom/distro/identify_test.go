package distro

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

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
	}

	for _, test := range tests {
		name := fmt.Sprintf("%s:%s", test.name, test.RawVersion)
		fixture, err := os.Open(test.fixture)
		defer fixture.Close()

		if err != nil {
			t.Fatalf("failed to open fixture: %+v", err)
		}

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
			fixture: "test-fixtures/bad-version",
			name:    "No version",
		},
		{
			fixture: "test-fixtures/bad-id",
			name:    "No name ID",
		},
	}

	for _, test := range tests {
		name := fmt.Sprintf("%s:%s", test.name, test.fixture)
		fixture, err := os.Open(test.fixture)
		defer fixture.Close()

		if err != nil {
			t.Fatalf("failed to open fixture: %+v", err)
		}

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
