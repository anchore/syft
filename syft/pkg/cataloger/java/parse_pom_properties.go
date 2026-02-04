package java

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/go-viper/mapstructure/v2"

	"github.com/anchore/syft/syft/pkg"
)

const pomPropertiesGlob = "**/*pom.properties"

func parsePomProperties(path string, reader io.Reader) (*pkg.JavaPomProperties, error) {
	var props pkg.JavaPomProperties
	propMap := make(map[string]string)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()

		// ignore empty lines and comments
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimLeft(line, " "), "#") {
			continue
		}

		idx := strings.IndexAny(line, "=:")
		if idx == -1 {
			return nil, fmt.Errorf("unable to split pom.properties key-value pairs: %q", line)
		}

		key := strings.TrimSpace(line[0:idx])
		value := strings.TrimSpace(line[idx+1:])
		propMap[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("unable to read pom.properties: %w", err)
	}

	if err := mapstructure.Decode(propMap, &props); err != nil {
		return nil, fmt.Errorf("unable to parse pom.properties: %w", err)
	}

	props.Path = path

	return &props, nil
}
