package maven

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/saintfish/chardet"
	"github.com/vifraa/gopom"
	"golang.org/x/net/html/charset"
)

type (
	Project    = gopom.Project
	Properties = gopom.Properties
	Parent     = gopom.Parent
	Dependency = gopom.Dependency
	License    = gopom.License
)

// ParsePomXML decodes a pom XML file, detecting and converting non-UTF-8 charsets. this DOES NOT perform any logic to resolve properties such as groupID, artifactID, and version
func ParsePomXML(content io.Reader) (project *Project, err error) {
	inputReader, err := getUtf8Reader(content)
	if err != nil {
		return nil, fmt.Errorf("unable to read pom.xml: %w", err)
	}

	decoder := xml.NewDecoder(inputReader)
	// when an xml file has a character set declaration (e.g. '<?xml version="1.0" encoding="ISO-8859-1"?>') read that and use the correct decoder
	decoder.CharsetReader = charset.NewReaderLabel

	project = &Project{}
	if err := decoder.Decode(project); err != nil {
		return nil, fmt.Errorf("unable to unmarshal pom.xml: %w", err)
	}

	return project, nil
}

func getUtf8Reader(content io.Reader) (io.Reader, error) {
	pomContents, err := io.ReadAll(content)
	if err != nil {
		return nil, err
	}

	detector := chardet.NewTextDetector()
	detection, err := detector.DetectBest(pomContents)

	var inputReader io.Reader
	if err == nil && detection != nil {
		if detection.Charset == "UTF-8" {
			inputReader = bytes.NewReader(pomContents)
		} else {
			inputReader, err = charset.NewReaderLabel(detection.Charset, bytes.NewReader(pomContents))
			if err != nil {
				return nil, fmt.Errorf("unable to get encoding: %w", err)
			}
		}
	} else {
		// we could not detect the encoding, but we want a valid file to read. Replace unreadable
		// characters with the UTF-8 replacement character.
		inputReader = strings.NewReader(strings.ToValidUTF8(string(pomContents), "�"))
	}
	return inputReader, nil
}
