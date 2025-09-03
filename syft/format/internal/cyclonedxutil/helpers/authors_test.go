package helpers

import (
	"reflect"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/pkg"
)

func TestEncodeAuthors(t *testing.T) {
	p := pkg.Package{
		Metadata: pkg.NpmPackage{
			Authors: `[{"name":"Alice","email":"a@example.com"},{"name":"Bob","email":"b@example.com"}]`,
		},
	}

	got := EncodeAuthors(p)
	if got == nil {
		t.Fatalf("expected non-nil authors")
	}

	want := []cyclonedx.OrganizationalContact{
		{Name: "Alice", Email: "a@example.com"},
		{Name: "Bob", Email: "b@example.com"},
	}

	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("authors mismatch\nwant: %#v\ngot:  %#v", want, *got)
	}
}
