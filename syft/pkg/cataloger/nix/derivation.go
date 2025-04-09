package nix

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/log"
)

// NixDerivation represents a parsed Nix derivation file
type NixDerivation struct {
	Path        string
	Name        string
	PName       string
	Version     string
	System      string
	Builder     string
	Args        []string
	EnvVars     map[string]string
	Outputs     map[string]string
	InputDrvs   map[string][]string
	InputSrcs   []string
	License     string
	Homepage    string
	Description string
	OutputHash  string
}

// ParseDerivation attempts to parse a Nix derivation file without external commands
func ParseDerivation(path string) (*NixDerivation, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	derivation := &NixDerivation{
		Path:      path,
		EnvVars:   make(map[string]string),
		Outputs:   make(map[string]string),
		InputDrvs: make(map[string][]string),
	}

	// Simple parser for .drv files
	scanner := bufio.NewScanner(file)
	inEnvVars := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Process environment variables section
		if strings.Contains(line, "envVars = {") {
			inEnvVars = true
			continue
		} else if inEnvVars && strings.Contains(line, "};") {
			inEnvVars = false
			continue
		} else if inEnvVars && strings.Contains(line, " = ") {
			// Parse environment variables
			parts := strings.SplitN(line, " = ", 2)
			if len(parts) == 2 {
				key := strings.Trim(parts[0], " \"")
				value := strings.Trim(parts[1], " \";")
				derivation.EnvVars[key] = value
			}
		}
	}

	// Extract package information from environment variables
	derivation.Name = derivation.EnvVars["name"]
	derivation.PName = derivation.EnvVars["pname"]
	derivation.Version = derivation.EnvVars["version"]
	derivation.System = derivation.EnvVars["system"]
	derivation.License = derivation.EnvVars["license"]
	derivation.Homepage = derivation.EnvVars["homepage"]
	derivation.Description = derivation.EnvVars["description"]

	// If pname is not set but name follows pname-version pattern, extract it
	if derivation.PName == "" && derivation.Name != "" {
		re := regexp.MustCompile(`^(.*?)-([0-9].*)$`)
		if matches := re.FindStringSubmatch(derivation.Name); len(matches) == 3 {
			derivation.PName = matches[1]
			if derivation.Version == "" {
				derivation.Version = matches[2]
			}
		} else {
			derivation.PName = derivation.Name
		}
	}

	// Check if this is a patched package with security fixes
	for key := range derivation.EnvVars {
		if strings.HasPrefix(key, "patches") {
			value := derivation.EnvVars[key]
			if strings.Contains(value, "CVE-") {
				log.Debugf("Found security patch in %s: %s", derivation.Name, value)
			}
		}
	}

	return derivation, nil
}

// findDeriverPath attempts to find the derivation file for a store path
func findDeriverPath(storePath string) string {
	// If the path is already a derivation, return it
	if strings.HasSuffix(storePath, ".drv") {
		return storePath
	}

	// Look for a .drv file with a similar name
	drvPathGuess := storePath + ".drv"
	if _, err := os.Stat(drvPathGuess); err == nil {
		return drvPathGuess
	}

	// Fall back strategy using string manipulation
	// This is an approximation without running nix-store commands
	parts := strings.Split(storePath, "-")
	if len(parts) >= 2 {
		// Try to find the derivation file using the hash part
		hash := strings.Split(filepath.Base(storePath), "-")[0]
		if matched, _ := regexp.MatchString(`^[a-z0-9]{32}$`, hash); matched {
			drvDir := filepath.Join("/nix/store", hash+"-*.drv")
			matches, err := filepath.Glob(drvDir)
			if err == nil && len(matches) > 0 {
				return matches[0]
			}
		}
	}

	return ""
}
