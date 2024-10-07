package erlang

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseOTPApplication(t *testing.T) {
	tests := []struct {
		fixture  string
		expected []pkg.Package
	}{
		{
			fixture: "test-fixtures/rabbitmq.app",
			expected: []pkg.Package{
				{
					Name:     "rabbit",
					Version:  "3.12.10",
					Language: pkg.Erlang,
					Type:     pkg.ErlangOTPPkg,
					PURL:     "pkg:otp/rabbit@3.12.10",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			// TODO: relationships are not under test
			var expectedRelationships []artifact.Relationship

			for idx := range test.expected {
				test.expected[idx].Locations = file.NewLocationSet(file.NewLocation(test.fixture))
			}

			pkgtest.TestFileParser(t, test.fixture, parseOTPApp, test.expected, expectedRelationships)
		})
	}
}

func Test_corruptOtpApp(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/corrupt/rabbitmq.app").
		WithError().
		TestParser(t, parseOTPApp)
}
