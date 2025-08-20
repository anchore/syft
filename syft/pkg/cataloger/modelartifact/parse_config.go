package modelartifact

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"gopkg.in/yaml.v3"
)

// declare enum with modelartifactory types
const (
	HuggingFace = "huggingface"
	LocalModel  = "local_model"
)

// parseConfigJSON parses a config.json file and returns discovered model artifacts
func parseConfigJSON(_ context.Context, resolver file.Resolver, env *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var config map[string]interface{}

	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&config); err != nil {
		return nil, nil, nil // Return empty results for invalid JSON
	}

	// Check if this is a model config file
	if !isModelConfig(config) {
		return nil, nil, nil
	}

	// Get the directory containing the config.json file using the absolute path
	repoDirectory := filepath.Dir(string(reader.Location.Reference().RealPath))

	// Extract model information
	modelInfo := &pkg.ModelArtifact{
		ConfigPath: reader.Location.RealPath,
	}

	// Extract _name_or_path if present
	if nameOrPath, ok := config["name_or_path"].(string); ok {
		modelInfo.Name = nameOrPath
	}

	// Extract model_type if present
	if modelType, ok := config["model_type"].(string); ok {
		modelInfo.ModelType = modelType
	}

	// Extract architectures if present
	if architectures, ok := config["architectures"].([]interface{}); ok {
		var archStrings []string
		for _, arch := range architectures {
			if archStr, ok := arch.(string); ok {
				archStrings = append(archStrings, archStr)
			}
		}
		modelInfo.Architectures = archStrings
	}

	// Check for Git repository and extract remote URL
	gitRemoteURL := getGitRemoteURL(repoDirectory)
	var modelName, version, purl string

	if gitRemoteURL != "" && strings.Contains(gitRemoteURL, "huggingface.co") {
		// Extract model name and version from HuggingFace URL
		modelName, version = parseHuggingFaceURL(gitRemoteURL)
		purl = getAIModelPurl(HuggingFace, modelName, version)
	} else {
		// Local model - use name from config if available, otherwise use directory name
		if modelInfo.Name != "" {
			modelName = modelInfo.Name
		} else {
			dirName := filepath.Base(repoDirectory)
			if dirName == "" || dirName == "." {
				dirName = "unknown-model"
			}
			modelName = dirName
		}
		modelInfo.Artifactory = LocalModel
		version = "UNKNOWN"
		purl = getAIModelPurl(LocalModel, modelName, version)
	}

	// Create the main package
	mainPkg := pkg.Package{
		Name:      modelName,
		Version:   version,
		Type:      pkg.ModelArtifactPkg,
		Locations: file.NewLocationSet(reader.Location),
		PURL:      purl,
		Metadata:  *modelInfo,
	}

	packages := []pkg.Package{mainPkg}
	relationships := []artifact.Relationship{}

	// Parse README.md for base models
	baseModels := parseBaseModelsFromReadme(resolver, repoDirectory)
	for _, baseModel := range baseModels {
		// As basemodel extraction is done by Model card specification provided by hugging face, the basemodel's artifactory is set as huggingface
		baseModelPkg := createBaseModelPackage(HuggingFace, baseModel, "", reader.Location)
		packages = append(packages, baseModelPkg)
		relationships = append(relationships, artifact.Relationship{
			From: mainPkg,
			To:   baseModelPkg,
			Type: artifact.ContainsRelationship,
		})
	}

	return packages, relationships, nil
}

// isModelConfig checks if the config contains model-specific fields
// config json specifications: https://huggingface.co/docs/transformers/main_classes/configuration
func isModelConfig(config map[string]interface{}) bool {
	// Check for common model config indicators
	if _, hasNameOrPath := config["name_or_path"]; hasNameOrPath {
		return true
	}
	if _, hasModelType := config["model_type"]; hasModelType {
		return true
	}
	if _, hasArchitectures := config["architectures"]; hasArchitectures {
		return true
	}
	return false
}

// getGitRemoteURL checks if there's a .git directory and extracts the remote URL
func getGitRemoteURL(repoDirectory string) string {
	gitDir := filepath.Join(repoDirectory, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return ""
	}

	// Try to read the remote URL from .git/config
	configPath := filepath.Join(gitDir, "config")
	if configContent, err := os.ReadFile(configPath); err == nil {
		// Look for remote "origin" URL
		remotePattern := regexp.MustCompile(`\[remote "origin"\][\s\S]*?url = (.+)`)
		if matches := remotePattern.FindSubmatch(configContent); len(matches) > 1 {
			return strings.TrimSpace(string(matches[1]))
		}
	}

	return ""
}

// parseHuggingFaceURL extracts model name and version from HuggingFace URL
func parseHuggingFaceURL(gitURL string) (modelname string, branch string) {
	// Remove .git suffix if present
	gitURL = strings.TrimSuffix(gitURL, ".git")

	// Extract the model path from URL like https://huggingface.co/zai-org/GLM-4.5V
	urlPattern := regexp.MustCompile(`https://huggingface\.co/(.+)`)
	if matches := urlPattern.FindStringSubmatch(gitURL); len(matches) > 1 {
		modelPath := matches[1]
		// For every new version of the Model hugging face have different repository
		// Even though by context new models versions are successors of old versions
		// they are completly seperate artifact and may not technically related to older version
		// e.g. llama3 is successor of llama2 but they are completly seperate artifact trained of different parameter counts
		// 1. meta-llama/Llama-3.2-3B-Instruct
		// 2. meta-llama/Meta-Llama-3-8B-Instruct

		// Thus, the version of the model is hardcoded to main, as it refers to latest commit in huggingface repository.
		return modelPath, "main"
	}

	return "unknown", "unknown"
}

// parseBaseModelsFromReadme reads README.md and extracts base_model information
// For huggingface repo, Model card is Markdown readme file with YAML Section at the top
// Specification: https://huggingface.co/docs/hub/en/model-cards#model-card-metadata
func parseBaseModelsFromReadme(resolver file.Resolver, repoDirectory string) (baseModels []string) {
	if resolver == nil {
		return baseModels
	}
	readmePath := filepath.Join(repoDirectory, "README.md")
	readmeLocations, err := resolver.FilesByPath(readmePath)
	if err != nil || len(readmeLocations) == 0 {
		return baseModels
	}
	readmeLocation := readmeLocations[0]
	readmeReader, err := resolver.FileContentsByLocation(readmeLocation)
	if err != nil {
		return nil
	}
	defer readmeReader.Close()

	fileContent, err := io.ReadAll(readmeReader)
	if err != nil {
		return baseModels
	}
	// Look for YAML section between --- markers
	yamlPattern := regexp.MustCompile(`(?s)---\s*(.*?)\s*---`)
	if matches := yamlPattern.FindSubmatch(fileContent); len(matches) > 1 {
		var metadata map[string]interface{}
		if err := yaml.Unmarshal(matches[1], &metadata); err == nil {
			if baseModel, ok := metadata["base_model"]; ok {
				switch v := baseModel.(type) {
				case string:
					baseModels = append(baseModels, strings.ToLower(v))
				case []interface{}:
					for _, model := range v {
						if modelStr, ok := model.(string); ok {
							baseModels = append(baseModels, strings.ToLower(modelStr))
						}
					}
				}
			}
		}
	}

	return baseModels
}

// createBaseModelPackage creates a package for a base model
func createBaseModelPackage(artifactory string, baseModel string, version string, location file.Location) pkg.Package {
	purl := getAIModelPurl(artifactory, baseModel, version)
	return pkg.Package{
		Name:      baseModel,
		Version:   version,
		Type:      pkg.ModelArtifactPkg,
		Locations: file.NewLocationSet(location),
		PURL:      purl,
		Metadata: pkg.ModelArtifact{
			Name:        baseModel,
			Artifactory: artifactory,
		},
	}
}

// getModelName extracts a clean model name from the model artifact
func getModelName(modelInfo *pkg.ModelArtifact) string {
	if modelInfo.Name != "" {
		// If it's a path-like name (e.g., "microsoft/DialoGPT-medium"), extract the last part
		if strings.Contains(modelInfo.Name, "/") {
			parts := strings.Split(modelInfo.Name, "/")
			return parts[len(parts)-1]
		}
		return modelInfo.Name
	}

	// Fallback to directory name from config path
	if modelInfo.ConfigPath != "" {
		dir := filepath.Dir(modelInfo.ConfigPath)
		return filepath.Base(dir)
	}

	// Final fallback
	return "unknown-model"
}

// getAIModelPurl returns the PURL for an AI model
func getAIModelPurl(modelartifactory string, modelName string, version string) string {
	// The PURL specification for AI models is pkg:aimodel/<modelartifactory>/<modelowner>/<modelname>@<version>
	// Model Artifactory can be huggingface, local_model, tensorflowhub etc. Thus can locate unique weights and tokenizers used for the model
	// <modelowner>/<modelname> uniquely identify the model in artifactory
	// <version> is the artifactories version for the model like branch name or commit id for huggingface.

	if modelartifactory == HuggingFace && version == "" {
		// Huggingface models have default branch as "main"
		version = "main"
	}
	return fmt.Sprintf("pkg:aimodel/%s/%s@%s", modelartifactory, modelName, version)
}
