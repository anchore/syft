package template

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/mitchellh/go-homedir"
)

func makeTemplateExecutor(templateFilePath string) (*template.Template, error) {
	if templateFilePath == "" {
		return nil, errors.New("no template file: please provide a template path")
	}

	expandedPathToTemplateFile, err := homedir.Expand(templateFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to expand path %s", templateFilePath)
	}

	templateContents, err := os.ReadFile(expandedPathToTemplateFile)
	if err != nil {
		return nil, fmt.Errorf("unable to get template content: %w", err)
	}

	templateName := expandedPathToTemplateFile
	tmpl, err := template.New(templateName).Funcs(funcMap).Parse(string(templateContents))
	if err != nil {
		return nil, fmt.Errorf("unable to parse template: %w", err)
	}

	return tmpl, nil
}

// These are custom functions available to template authors.
var funcMap = func() template.FuncMap {
	f := sprig.HermeticTxtFuncMap()
	f["getLastIndex"] = func(collection interface{}) int {
		if v := reflect.ValueOf(collection); v.Kind() == reflect.Slice {
			return v.Len() - 1
		}

		return 0
	}
	// Checks if a field is defined
	f["hasField"] = func(obj interface{}, field string) bool {
		t := reflect.TypeOf(obj)
		_, ok := t.FieldByName(field)
		return ok
	}
	return f
}()
