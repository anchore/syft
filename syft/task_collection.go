package syft

import (
	"fmt"
	"github.com/anchore/syft/syft/cataloger"
	"github.com/scylladb/go-set/strset"
	"sort"
	"strings"
)

const (
	packageTaskLabel   = "package"
	packagesTaskLabel  = "packages"
	fileTaskLabel      = "file"
	filesTaskLabel     = "files"
	osTaskLabel        = "os"
	languageTaskLabel  = "language"
	installedTaskLabel = "installed"
	declaredTaskLabel  = "declared"
)

type taskCollection struct {
	taskConstructorByName map[string]taskGenerator // name -> generator
	namesByLabel          map[string][]string      // label -> names
}

func newTaskCollection() (*taskCollection, error) {
	c := &taskCollection{
		taskConstructorByName: make(map[string]taskGenerator),
		namesByLabel:          make(map[string][]string),
	}
	return c, c.addAllCatalogers()
}

func (c *taskCollection) add(name string, g taskGenerator, labels ...string) error {
	if _, exists := c.taskConstructorByName[name]; exists {
		return fmt.Errorf("task constructor already exists: %q", name)
	}

	c.taskConstructorByName[name] = g

	labelSet := strset.New(labels...)
	labelSet.Add(name)
	for _, n := range labelSet.List() {
		c.namesByLabel[n] = append(c.namesByLabel[n], name)
	}
	return nil
}

func (c *taskCollection) addAllCatalogers() error {
	for _, d := range []struct {
		id        cataloger.ID
		generator taskGenerator
		labels    []string
	}{
		{
			id:        cataloger.ApkDBID,
			generator: newAPKDBCatalogingTask,
			labels:    []string{packageTaskLabel, packagesTaskLabel, osTaskLabel, installedTaskLabel, "alpine", "apk", "apkdb"},
		},
		{
			id:        cataloger.DpkgID,
			generator: newDPKGCatalogingTask,
			labels:    []string{packageTaskLabel, packagesTaskLabel, osTaskLabel, installedTaskLabel, "debian", "dpkg", "deb", "dpkgdb"},
		},
		{
			id:        cataloger.RpmDBID,
			generator: newRPMDBCatalogingTask,
			labels:    []string{packageTaskLabel, packagesTaskLabel, osTaskLabel, installedTaskLabel, "redhat", "rhel", "centos", "rpm", "rpmdb"},
		},
		{
			id:        cataloger.RubyGemspecID,
			generator: newRubyGemSpecCatalogingTask,
			labels:    []string{packageTaskLabel, packagesTaskLabel, languageTaskLabel, installedTaskLabel, "ruby", "gemspec", "gem"},
		},
		{
			id:        cataloger.RubyGemfileLockID,
			generator: newRubyGemFileLockCatalogingTask,
			labels:    []string{packageTaskLabel, packagesTaskLabel, languageTaskLabel, declaredTaskLabel, "ruby", "gemfile", "gem", "gemfile.lock"},
		},
		{
			id:        cataloger.PythonPackageID,
			generator: newPythonPackageCatalogingTask,
			labels:    []string{packageTaskLabel, packagesTaskLabel, languageTaskLabel, installedTaskLabel, "python", "egg", "wheel"},
		},
		{
			id:        cataloger.PythonRequirementsID,
			generator: newPythonRequirementsCatalogingTask,
			labels:    []string{packageTaskLabel, packagesTaskLabel, languageTaskLabel, declaredTaskLabel, "python", "requirements", "requirements.txt"},
		},
		{
			id:        cataloger.PythonPoetryID,
			generator: newPythonPoetryCatalogingTask,
			labels:    []string{packageTaskLabel, packagesTaskLabel, languageTaskLabel, declaredTaskLabel, "python", "poetry", "poetry.lock"},
		},
		{
			id:        cataloger.PythonSetupID,
			generator: newPythonSetupCatalogingTask,
			labels:    []string{packageTaskLabel, packagesTaskLabel, languageTaskLabel, declaredTaskLabel, "python", "setup", "setup.py"},
		},
		{
			id:        cataloger.PythonPipFileID,
			generator: newPythonPipfileCatalogingTask,
			labels:    []string{packageTaskLabel, packagesTaskLabel, languageTaskLabel, declaredTaskLabel, "python", "pip", "pipfile"},
		},
		{
			id:        cataloger.JavascriptPackageJSONID,
			generator: newJavascriptPackageJSONCatalogingTask,
			labels:    []string{packageTaskLabel, packagesTaskLabel, languageTaskLabel, installedTaskLabel, "javascript", "node", "package.json"},
		},
		{
			id:        cataloger.JavascriptPackageLockID,
			generator: newJavascriptPackageLockCatalogingTask,
			labels:    []string{packageTaskLabel, packagesTaskLabel, languageTaskLabel, declaredTaskLabel, "javascript", "node", "package-lock.json"},
		},
		{
			id:        cataloger.JavaScriptYarnLockID,
			generator: newJavascriptYarnLockCatalogingTask,
			labels:    []string{packageTaskLabel, packagesTaskLabel, languageTaskLabel, declaredTaskLabel, "javascript", "node", "yarn", "yarn.lock"},
		},
		{
			id:        cataloger.JavaArchiveID,
			generator: newJavaCatalogingTask,
			labels:    []string{packageTaskLabel, packagesTaskLabel, languageTaskLabel, installedTaskLabel, "java", "maven", "jar", "war", "ear", "jenkins", "hudson", "hpi", "jpi", "par", "sar", "lpkg"},
		},
		{
			id:        cataloger.GoModID,
			generator: newGolangModuleCatalogingTask,
			labels:    []string{packageTaskLabel, packagesTaskLabel, languageTaskLabel, declaredTaskLabel, "go", "golang", "go-module", "go.mod"},
		},
		{
			id:        cataloger.GoBinaryID,
			generator: newGolangBinaryCatalogingTask,
			labels:    []string{packageTaskLabel, packagesTaskLabel, languageTaskLabel, installedTaskLabel, "go", "golang", "go-module", "binary"},
		},
		{
			id:        cataloger.RustCargoLockID,
			generator: newRustCargoLockCatalogingTask,
			labels:    []string{packageTaskLabel, packagesTaskLabel, languageTaskLabel, declaredTaskLabel, "rust", "cargo", "cargo.lock"},
		},
		{
			id:        cataloger.PHPInstalledJSONID,
			generator: newPHPInstalledCatalogingTask,
			labels:    []string{packageTaskLabel, packagesTaskLabel, languageTaskLabel, installedTaskLabel, "php", "composer", "installed.json"},
		},
		{
			id:        cataloger.PHPComposerLockID,
			generator: newPHPComposerLockCatalogingTask,
			labels:    []string{packageTaskLabel, packagesTaskLabel, languageTaskLabel, declaredTaskLabel, "php", "composer", "composer.lock"},
		},
		{
			id:        cataloger.FileMetadataID,
			generator: newFileMetadataCatalogingTask,
			labels:    []string{fileTaskLabel, filesTaskLabel},
		},
		{
			id:        cataloger.FileDigestsID,
			generator: newFileDigestsCatalogingTask,
			labels:    []string{fileTaskLabel, filesTaskLabel, "digests", "digest", "file-digests"},
		},
		{
			id:        cataloger.SecretsID,
			generator: newSecretsCatalogingTask,
			labels:    []string{"secrets"},
		},
		{
			id:        cataloger.FileClassifierID,
			generator: newFileClassifierTask,
			labels:    []string{fileTaskLabel, filesTaskLabel, "classifier"},
		},
		{
			id:        cataloger.FileContentsID,
			generator: newFileContentsCatalogingTask,
			labels:    []string{fileTaskLabel, filesTaskLabel, "contents", "content", "file-contents"},
		},
	} {
		if err := c.add(string(d.id), d.generator, d.labels...); err != nil {
			return err
		}
	}
	return nil
}

func (c taskCollection) query(q string) []cataloger.ID {
	fields := strings.FieldsFunc(q, func(r rune) bool {
		switch r {
		case '+', '&':
			return true
		}
		return false
	})

	return c.withLabels(fields...)
}

func (c taskCollection) all() []cataloger.ID {
	var ret []cataloger.ID
	for k := range c.taskConstructorByName {
		ret = append(ret, cataloger.ID(k))
	}

	sort.Sort(cataloger.IDs(ret))

	return ret
}

func (c taskCollection) withLabels(q ...string) []cataloger.ID {
	req := strset.New()
	for i, f := range q {
		switch i {
		case 0:
			req.Add(c.namesByLabel[f]...)
			continue
		default:
			req = strset.Intersection(req, strset.New(c.namesByLabel[f]...))
		}
	}

	var ret []cataloger.ID
	for _, i := range req.List() {
		ret = append(ret, cataloger.ID(i))
	}

	// ensure stable results
	sort.Sort(cataloger.IDs(ret))

	return ret
}

func (c taskCollection) tasks(config CatalogingConfig, ids ...cataloger.ID) ([]task, error) {
	var ts []task
	for _, id := range ids {
		g, exists := c.taskConstructorByName[string(id)]
		if !exists {
			continue
		}

		t, err := g(id, config)
		if err != nil {
			return nil, fmt.Errorf("unable to construct task %q: %w", id, err)
		}

		if t == nil {
			continue
		}

		ts = append(ts, t)
	}
	return ts, nil
}
