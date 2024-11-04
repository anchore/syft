package maven

import (
	"encoding/base64"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal"
)

func Test_getUtf8Reader(t *testing.T) {
	tests := []struct {
		name     string
		contents string
	}{
		{
			name: "unknown encoding",
			// random binary contents
			contents: "BkiJz02JyEWE0nXR6TH///9NicpJweEETIucJIgAAABJicxPjQwhTY1JCE05WQh0BU2J0eunTYshTIusJIAAAAAPHwBNOeV1BUUx2+tWTIlUJDhMiUwkSEyJRCQgSIl8JFBMiQ==",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(tt.contents))

			got, err := getUtf8Reader(decoder)
			require.NoError(t, err)
			gotBytes, err := io.ReadAll(got)
			require.NoError(t, err)
			// if we couldn't decode the section as UTF-8, we should get a replacement character
			assert.Contains(t, string(gotBytes), "�")
		})
	}
}

func Test_decodePomXML_surviveNonUtf8Encoding(t *testing.T) {
	// regression for https://github.com/anchore/syft/issues/2044

	// we are storing the base64 contents of the pom.xml file. We are doing this to prevent accidental changes to the
	// file, which is extremely important for this test.

	// for instance, even changing a single character in the file and saving in an IntelliJ IDE will automatically
	// convert the file to UTF-8, which will break this test:

	// xxd with the original pom.xml
	// 00000780: 6964 3e0d 0a20 2020 2020 2020 2020 2020  id>..
	// 00000790: 203c 6e61 6d65 3e4a e972 f46d 6520 4d69   <name>J.r.me Mi
	// 000007a0: 7263 3c2f 6e61 6d65 3e0d 0a20 2020 2020  rc</name>..

	// xxd with the pom.xml converted to UTF-8 (from a simple change with IntelliJ)
	// 00000780: 6964 3e0d 0a20 2020 2020 2020 2020 2020  id>..
	// 00000790: 203c 6e61 6d65 3e4a efbf bd72 efbf bd6d   <name>J...r...m
	// 000007a0: 6520 4d69 7263 3c2f 6e61 6d65 3e0d 0a20  e Mirc</name>..

	// Note that the name "Jérôme Mirc" was originally interpreted as "J.r.me Mi" and after the save
	// is now encoded as "J...r...m" which is not what we want (note the extra bytes for each non UTF-8 character.
	// The original 0xe9 byte (é) was converted to 0xefbfbd (�) which is the UTF-8 replacement character.
	// This is quite silly on the part of IntelliJ, but it is what it is.

	cases := []struct {
		name    string
		fixture string
	}{
		{
			name:    "undeclared encoding",
			fixture: "test-fixtures/undeclared-iso-8859-encoded-pom.xml.base64",
		},
		{
			name:    "declared encoding",
			fixture: "test-fixtures/declared-iso-8859-encoded-pom.xml.base64",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fh, err := os.Open(c.fixture)
			require.NoError(t, err)
			defer internal.CloseAndLogError(fh, c.fixture)

			decoder := base64.NewDecoder(base64.StdEncoding, fh)

			proj, err := ParsePomXML(decoder)

			require.NoError(t, err)
			require.NotEmpty(t, proj.Developers)
		})
	}
}
