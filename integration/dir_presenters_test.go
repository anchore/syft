// +build integration

package integration

import (
	"bytes"
	"flag"
	"testing"

	"github.com/anchore/go-testutils"
	"github.com/anchore/imgbom/imgbom"
	"github.com/anchore/imgbom/imgbom/presenter"
	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/sergi/go-diff/diffmatchpatch"
)

var update = flag.Bool("update", false, "update the *.golden files for json presenters")

func TestDirTextPresenter(t *testing.T) {
	var buffer bytes.Buffer
	protocol := imgbom.NewProtocol("dir://test-fixtures")
	if protocol.Type != imgbom.DirProtocol {
		t.Errorf("unexpected protocol returned: %v != %v", protocol.Type, imgbom.DirProtocol)
	}

	catalog, err := imgbom.CatalogDir(protocol.Value, scope.AllLayersScope)
	if err != nil {
		t.Errorf("could not produce catalog: %w", err)
	}
	presenterOpt := presenter.ParseOption("text")
	dirPresenter := presenter.GetDirPresenter(presenterOpt, protocol.Value, catalog)

	dirPresenter.Present(&buffer)
	actual := buffer.Bytes()
	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(actual), string(expected), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}

}

func TestDirJsonPresenter(t *testing.T) {
	var buffer bytes.Buffer
	protocol := imgbom.NewProtocol("dir://test-fixtures")
	if protocol.Type != imgbom.DirProtocol {
		t.Errorf("unexpected protocol returned: %v != %v", protocol.Type, imgbom.DirProtocol)
	}

	catalog, err := imgbom.CatalogDir(protocol.Value, scope.AllLayersScope)
	if err != nil {
		t.Errorf("could not produce catalog: %w", err)
	}
	presenterOpt := presenter.ParseOption("json")
	dirPresenter := presenter.GetDirPresenter(presenterOpt, protocol.Value, catalog)

	dirPresenter.Present(&buffer)
	actual := buffer.Bytes()
	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(actual), string(expected), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}

}
