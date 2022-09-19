package template

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/formats/common/testutils"
)

var updateTmpl = flag.Bool("update-tmpl", false, "update the *.golden files for json encoders")

func TestFormatWithOption(t *testing.T) {
	f := OutputFormat{}
	f.SetTemplatePath("test-fixtures/csv.template")

	testutils.AssertEncoderAgainstGoldenSnapshot(t,
		f,
		testutils.DirectoryInput(t),
		*updateTmpl,
	)

}

func TestFormatWithoutOptions(t *testing.T) {
	f := Format()
	err := f.Encode(nil, testutils.DirectoryInput(t))
	assert.ErrorContains(t, err, "no template file: please provide a template path")
}
