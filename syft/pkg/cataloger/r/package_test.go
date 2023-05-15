package r

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
)

func Test_NewPackageLicenses(t *testing.T) {
	testCases := []struct {
		name string
		pd   parseData
		want []pkg.License
	}{
		{
			"License field with single valid spdx",
			parseData{
				Package: "Foo",
				Version: "1",
				License: "MIT",
			},
			[]pkg.License{
				pkg.NewLicense("MIT"),
			},
		},
		{
			"License field with single version separator no +",
			parseData{
				Package: "Bar",
				Version: "2",
				License: "LGPL (== 2.0)",
			},
			[]pkg.License{
				pkg.NewLicense("LGPL2.0"),
			},
		},
		{
			"License field with multiple version separator",
			parseData{
				Package: "Bar",
				Version: "2",
				License: "LGPL (>= 2.0, < 3)",
			},
			[]pkg.License{
				pkg.NewLicense("LGPL2.0+"),
			},
		},
		{
			"License field with file reference",
			parseData{
				Package: "Baz",
				Version: "3",
				License: "GPL-2 + file LICENSE",
			},
			[]pkg.License{
				pkg.NewLicense("GPL-2"),
			},
		},
		{
			"License field which covers no case",
			parseData{
				Package: "Baz",
				Version: "3",
				License: "Mozilla Public License",
			},
			[]pkg.License{
				pkg.NewLicense("Mozilla Public License"),
			},
		},
		{
			"License field with multiple cases",
			parseData{
				Package: "Baz",
				Version: "3",
				License: "GPL-2 | file LICENSE | LGPL (>= 2.0)",
			},
			[]pkg.License{
				pkg.NewLicense("GPL-2"),
				pkg.NewLicense("LGPL2.0+"),
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLicenseData(tt.pd.License)
			if len(got) != len(tt.want) {
				t.Errorf("unexpected number of licenses: got=%d, want=%d", len(got), len(tt.want))
			}

			for _, wantLicense := range tt.want {
				found := false
				for _, gotLicense := range got {
					if wantLicense.Type == gotLicense.Type &&
						wantLicense.SPDXExpression == gotLicense.SPDXExpression &&
						wantLicense.Value == gotLicense.Value {
						found = true
					}
				}
				if !found {
					t.Errorf("could not find expected license: %+v; got: %+v", wantLicense, got)
				}
			}
		})
	}
}
