package freebsd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func Test_packageURL(t *testing.T) {
	tests := []struct {
		name     string
		metadata pkg.FreeBSDPkgDBEntry
		expected string
	}{
		{
			name: "with arch and origin",
			metadata: pkg.FreeBSDPkgDBEntry{
				Name:    "curl",
				Version: "8.9.1",
				Arch:    "FreeBSD:14:amd64",
				Origin:  "www/curl",
			},
			expected: "pkg:freebsd/curl@8.9.1?arch=FreeBSD%3A14%3Aamd64&origin=www%2Fcurl",
		},
		{
			name: "without arch or origin",
			metadata: pkg.FreeBSDPkgDBEntry{
				Name:    "curl",
				Version: "8.9.1",
			},
			expected: "pkg:freebsd/curl@8.9.1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, packageURL(test.metadata))
		})
	}
}

func Test_newPackage(t *testing.T) {
	loc := file.NewLocation("var/db/pkg/local.sqlite")
	m := pkg.FreeBSDPkgDBEntry{
		Name:     "curl",
		Version:  "8.9.1",
		Arch:     "FreeBSD:14:amd64",
		Origin:   "www/curl",
		Licenses: []string{"MIT", "ISC"},
	}

	p := newPackage(context.Background(), loc, m)

	assert.Equal(t, "curl", p.Name)
	assert.Equal(t, "8.9.1", p.Version)
	assert.Equal(t, pkg.FreeBSDPkg, p.Type)
	assert.Equal(t, "pkg:freebsd/curl@8.9.1?arch=FreeBSD%3A14%3Aamd64&origin=www%2Fcurl", p.PURL)
	assert.Equal(t, m, p.Metadata)

	var licenseValues []string
	for _, l := range p.Licenses.ToSlice() {
		licenseValues = append(licenseValues, l.Value)
	}
	assert.ElementsMatch(t, []string{"MIT", "ISC"}, licenseValues)
}

func TestStripDigestAlgoPrefix(t *testing.T) {
	tests := []struct {
		name string
		sum  string
		want string
	}{
		{
			name: "sha256 prefix is stripped",
			sum:  "1$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			want: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			name: "no prefix is returned as-is",
			sum:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			want: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			name: "empty sum",
			sum:  "",
			want: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, stripDigestAlgoPrefix(test.sum))
		})
	}
}
