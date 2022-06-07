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
	fileTaskLabel      = "file"
	osTaskLabel        = "os"
	languageTaskLabel  = "language"
	installedTaskLabel = "installed"
	declaredTaskLabel  = "declared"
)

type taskCollection struct {
	taskByName   map[string]task     // name -> generator
	namesByLabel map[string][]string // label -> names
}

func newTaskCollection() *taskCollection {
	return &taskCollection{
		taskByName:   make(map[string]task),
		namesByLabel: make(map[string][]string),
	}
}

func (c *taskCollection) add(t task, labels ...string) error {
	var name string
	switch v := t.(type) {
	case pkgCatalogerTask:
		name = string(v.id)
	case catalogerTask:
		name = string(v.id)
	default:
		if len(labels) == 0 {
			return fmt.Errorf("no ID found for generic task")
		}
		name = labels[0]
	}

	if _, exists := c.taskByName[name]; exists {
		return fmt.Errorf("task already exists: %q", name)
	}

	c.taskByName[name] = t

	labelSet := strset.New(labels...)
	labelSet.Add(name)
	for _, n := range labelSet.List() {
		c.namesByLabel[n] = append(c.namesByLabel[n], name)
	}
	return nil
}

func (c *taskCollection) addAllCatalogers(config CatalogingConfig) error {
	for _, d := range []struct {
		generator taskGenerator
		labels    []string
	}{
		{
			generator: newAPKDBCatalogingTask,
			labels:    []string{packageTaskLabel, osTaskLabel, installedTaskLabel, "alpine", "apk", "apkdb"},
		},
		{
			generator: newDPKGCatalogingTask,
			labels:    []string{packageTaskLabel, osTaskLabel, installedTaskLabel, "debian", "dpkg", "deb", "dpkgdb"},
		},
		{
			generator: newRPMDBCatalogingTask,
			labels:    []string{packageTaskLabel, osTaskLabel, installedTaskLabel, "redhat", "rhel", "centos", "rpm", "rpmdb"},
		},
		{
			generator: newRubyGemSpecCatalogingTask,
			labels:    []string{packageTaskLabel, languageTaskLabel, installedTaskLabel, "ruby", "gemspec", "gem"},
		},
		{
			generator: newRubyGemFileLockCatalogingTask,
			labels:    []string{packageTaskLabel, languageTaskLabel, declaredTaskLabel, "ruby", "gemfile", "gem", "gemfile.lock"},
		},
		{
			generator: newPythonPackageCatalogingTask,
			labels:    []string{packageTaskLabel, languageTaskLabel, installedTaskLabel, "python", "egg", "wheel"},
		},
		{
			generator: newPythonRequirementsCatalogingTask,
			labels:    []string{packageTaskLabel, languageTaskLabel, declaredTaskLabel, "python", "requirements", "requirements.txt"},
		},
		{
			generator: newPythonPoetryCatalogingTask,
			labels:    []string{packageTaskLabel, languageTaskLabel, declaredTaskLabel, "python", "poetry", "poetry.lock"},
		},
		{
			generator: newPythonSetupCatalogingTask,
			labels:    []string{packageTaskLabel, languageTaskLabel, declaredTaskLabel, "python", "setup", "setup.py"},
		},
		{
			generator: newPythonPipfileCatalogingTask,
			labels:    []string{packageTaskLabel, languageTaskLabel, declaredTaskLabel, "python", "pip", "pipfile"},
		},
		{
			generator: newJavascriptPackageJSONCatalogingTask,
			labels:    []string{packageTaskLabel, languageTaskLabel, installedTaskLabel, "javascript", "node", "package.json"},
		},
		{
			generator: newJavascriptPackageLockCatalogingTask,
			labels:    []string{packageTaskLabel, languageTaskLabel, declaredTaskLabel, "javascript", "node", "package-lock.json"},
		},
		{
			generator: newJavascriptYarnLockCatalogingTask,
			labels:    []string{packageTaskLabel, languageTaskLabel, declaredTaskLabel, "javascript", "node", "yarn", "yarn.lock"},
		},
		{
			generator: newJavaCatalogingTask,
			labels:    []string{packageTaskLabel, languageTaskLabel, installedTaskLabel, "java", "maven", "jar", "war", "ear", "jenkins", "hudson", "hpi", "jpi", "par", "sar", "lpkg"},
		},
		{
			generator: newGolangModuleCatalogingTask,
			labels:    []string{packageTaskLabel, languageTaskLabel, declaredTaskLabel, "go", "golang", "go-module", "go.mod"},
		},
		{
			generator: newGolangBinaryCatalogingTask,
			labels:    []string{packageTaskLabel, languageTaskLabel, installedTaskLabel, "go", "golang", "go-module", "binary"},
		},
		{
			generator: newRustCargoLockCatalogingTask,
			labels:    []string{packageTaskLabel, languageTaskLabel, declaredTaskLabel, "rust", "cargo", "cargo.lock"},
		},
		{
			generator: newPHPInstalledCatalogingTask,
			labels:    []string{packageTaskLabel, languageTaskLabel, installedTaskLabel, "php", "composer", "installed.json"},
		},
		{
			generator: newPHPComposerLockCatalogingTask,
			labels:    []string{packageTaskLabel, languageTaskLabel, declaredTaskLabel, "php", "composer", "composer.lock"},
		},
		{
			generator: newFileMetadataCatalogingTask,
			labels:    []string{fileTaskLabel},
		},
		{
			generator: newFileDigestsCatalogingTask,
			labels:    []string{fileTaskLabel, "digests", "digest", "file-digests"},
		},
		{
			generator: newSecretsCatalogingTask,
			labels:    []string{"secrets"},
		},
		{
			generator: newFileClassifierTask,
			labels:    []string{fileTaskLabel, "classifier"},
		},
		{
			generator: newFileContentsCatalogingTask,
			labels:    []string{fileTaskLabel, "contents", "content", "file-contents"},
		},
	} {
		t, err := d.generator(config)
		if err != nil {
			return err
		}

		if t == nil {
			continue
		}

		if err := c.add(t, d.labels...); err != nil {
			return err
		}
	}
	return nil
}

func (c taskCollection) query(q string) []cataloger.ID {
	fields := strings.FieldsFunc(q, func(r rune) bool {
		switch r {
		case '+', ',', '&':
			return true
		}
		return false
	})

	return c.withLabels(fields...)
}

func (c taskCollection) all() []cataloger.ID {
	var ret []cataloger.ID
	for k := range c.taskByName {
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

func (c taskCollection) tasks(ids ...cataloger.ID) (ts []task) {
	for _, id := range ids {
		t, exists := c.taskByName[string(id)]
		if !exists {
			continue
		}
		ts = append(ts, t)
	}
	return ts
}
