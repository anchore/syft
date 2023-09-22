package portage

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// you can get a good sense of test fixtures with:
//   docker run --rm -it gentoo/stage3 bash -c 'find var/db/pkg/ | grep LICENSE | xargs cat'

func Test_extractLicenses(t *testing.T) {

	tests := []struct {
		name    string
		license string
		want    string
	}{
		{
			name:    "empty",
			license: "",
			want:    "",
		},
		{
			name:    "single",
			license: "GPL-2",
			want:    "GPL-2",
		},
		{
			name:    "multiple",
			license: "GPL-2 GPL-3 ", // note the extra space
			want:    "GPL-2 AND GPL-3",
		},
		// the following cases are NOT valid interpretations, but capture the behavior today.
		// when we follow up later with SPDX license expressions, this can be fixed then.
		{
			name:    "license choices",
			license: "|| ( GPL-2 GPL-3 )",
			want:    "GPL-2 OR GPL-3",
		},
		{
			name:    "license choices with missing useflag suffix",
			license: "GPL-3+ LGPL-3+ || ( GPL-3+ libgcc libstdc++ gcc-runtime-library-exception-3.1 ) FDL-1.3+", // no use flag so what do we do with FDL here?
			want:    "GPL-3+ AND LGPL-3+ AND (GPL-3+ OR libgcc OR libstdc++ OR gcc-runtime-library-exception-3.1 OR FDL-1.3+)",
			// GPL-3+ AND LGPL-3+ AND (GPL-3+ OR libgcc OR libstdc++ OR gcc-runtime-library-exception-3.1)
			//want: []string{
			//	"FDL-1.3+", // is it right to include this? what does this represent since a useflag was not specified?
			//	"GPL-3+",
			//	"LGPL-3+",
			//	"gcc-runtime-library-exception-3.1",
			//	"libgcc",
			//	"libstdc++",
			//},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expression, _ := extractLicenses(strings.NewReader(tt.license))
			assert.Equalf(t, tt.want, expression, "extractLicenses(%v)", tt.license)
		})
	}
}
