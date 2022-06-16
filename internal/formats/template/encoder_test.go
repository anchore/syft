package template

import (
	"flag"
	"testing"

	"github.com/anchore/syft/internal/formats/common/testutils"
	options "github.com/anchore/syft/syft/format-options"
)

var updateTmpl = flag.Bool("update-tmpl", false, "update the *.golden files for json encoders")

func Test_makeEncoderWithTemplate(t *testing.T) {
	testutils.AssertEncoderAgainstGoldenSnapshot(t,
		MakeFormatter(options.Format{TemplateFilePath: "test-fixtures/csv.template"}),
		testutils.DirectoryInput(t),
		*updateTmpl,
	)
}
