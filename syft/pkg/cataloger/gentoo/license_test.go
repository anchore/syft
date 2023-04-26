package gentoo

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// you can get a good sense of test fixtures with:
//   docker run --rm -it gentoo/stage3 bash -c 'find var/db/pkg/ | grep LICENSE | xargs cat'

func Test_extractLicenses(t *testing.T) {

	tests := []struct {
		name           string
		license        string
		wantExpression string
	}{
		{
			name:           "empty",
			license:        "",
			wantExpression: "",
		},
		{
			name:           "single",
			license:        "GPL-2",
			wantExpression: "GPL-2",
		},
		{
			name:           "multiple",
			license:        "GPL-2 GPL-3 ", // note the extra space
			wantExpression: "GPL-2 AND GPL-3",
		},
		// the following cases are NOT valid interpretations, but capture the behavior today.
		// when we follow up later with SPDX license expressions, this can be fixed then.
		{
			name:           "license choices",
			license:        "|| ( GPL-2 GPL-3 )",
			wantExpression: "GPL-2 OR GPL-3",
		},
		{
			name:           "license choices with missing useflag suffix",
			license:        "GPL-3+ LGPL-3+ || ( GPL-3+ libgcc libstdc++ gcc-runtime-library-exception-3.1 ) FDL-1.3+",                // no use flag so what do we do with FDL here?
			wantExpression: "GPL-3+ AND LGPL-3+ AND (GPL-3+ OR libgcc OR libstdc++ OR gcc-runtime-library-exception-3.1 OR FDL-1.3+)", // "OR FDL-1.3+" is wrong at the end...
			// GPL-3+ AND LGPL-3+ AND (GPL-3+ OR libgcc OR libstdc++ OR gcc-runtime-library-exception-3.1)
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expression := extractLicenses(strings.NewReader(tt.license))
			assert.Equalf(t, tt.wantExpression, expression, "unexpected expression for %v", tt.license)
		})
	}
}
