// this is the entry point for regenerating the cataloger/*/capabilities.yaml files, which orchestrates discovery, merging, and validation of cataloger capabilities.
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/charmbracelet/lipgloss"

	"github.com/anchore/syft/internal/capabilities"
	"github.com/anchore/syft/internal/capabilities/internal"
)

var (
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true) // green
	warningStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Bold(true) // yellow
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)  // red
	infoStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))            // cyan
	dimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))           // lighter grey (256-color)
)

func main() {
	repoRoot, err := internal.RepoRoot()
	if err != nil {
		log.Fatalf("failed to find repo root: %v", err)
	}

	catalogerDir := internal.CatalogerDir(repoRoot)

	fmt.Println("Regenerating capabilities files...")
	fmt.Println()
	stats, err := RegenerateCapabilities(catalogerDir, repoRoot)
	if err != nil {
		log.Fatalf("failed to regenerate capabilities: %v", err)
	}

	printSummary(stats)
	checkIncompleteCapabilities(catalogerDir, repoRoot)
	printMetadataTypeCoverageWarning(catalogerDir, repoRoot)
	printPackageTypeCoverageWarning(catalogerDir, repoRoot)
}

func printSummary(stats *Statistics) {
	fmt.Println()
	fmt.Println(infoStyle.Bold(true).Render("Summary:"))
	fmt.Printf("  • Total catalogers: %s (%s generic, %s custom)\n",
		infoStyle.Render(fmt.Sprintf("%d", stats.TotalGenericCatalogers+stats.TotalCustomCatalogers)),
		infoStyle.Render(fmt.Sprintf("%d", stats.TotalGenericCatalogers)),
		infoStyle.Render(fmt.Sprintf("%d", stats.TotalCustomCatalogers)))
	fmt.Printf("  • Total parser functions: %s\n", infoStyle.Render(fmt.Sprintf("%d", stats.TotalParserFunctions)))

	if len(stats.NewCatalogers) > 0 {
		fmt.Printf("  • New catalogers: %s\n", successStyle.Render(fmt.Sprintf("%d", len(stats.NewCatalogers))))
		for _, name := range stats.NewCatalogers {
			fmt.Printf("    - %s\n", successStyle.Render(name))
		}
	}

	if len(stats.NewParserFunctions) > 0 {
		fmt.Printf("  • New parser functions: %s\n", successStyle.Render(fmt.Sprintf("%d", len(stats.NewParserFunctions))))
		for _, name := range stats.NewParserFunctions {
			fmt.Printf("    - %s\n", successStyle.Render(name))
		}
	}

	if len(stats.UpdatedCatalogers) > 0 {
		fmt.Printf("  • Updated catalogers: %s\n", infoStyle.Render(fmt.Sprintf("%d", len(stats.UpdatedCatalogers))))
	}

	fmt.Println()
	fmt.Println(successStyle.Render("✓ Updated capabilities files successfully"))
}

func checkIncompleteCapabilities(catalogerDir, repoRoot string) {
	doc, _, err := internal.LoadCapabilities(catalogerDir, repoRoot)
	if err != nil {
		log.Fatalf("failed to load updated capabilities: %v", err)
	}

	var needsAttentionGeneric []string
	var needsAttentionCustom []string
	for _, cataloger := range doc.Catalogers {
		switch cataloger.Type {
		case genericCatalogerType:
			for _, parser := range cataloger.Parsers {
				if hasEmptyCapabilities(parser.Capabilities) {
					needsAttentionGeneric = append(needsAttentionGeneric, fmt.Sprintf("%s/%s", cataloger.Name, parser.ParserFunction))
				}
			}
		case "custom":
			if hasEmptyCapabilities(cataloger.Capabilities) {
				needsAttentionCustom = append(needsAttentionCustom, cataloger.Name)
			}
		}
	}

	if len(needsAttentionGeneric) > 0 || len(needsAttentionCustom) > 0 {
		fmt.Println()
		printFailureASCII()
		fmt.Println(warningStyle.Render("⚠ WARNING:") + " The following entries have incomplete capabilities:")

		if len(needsAttentionGeneric) > 0 {
			fmt.Printf("  • %s generic cataloger parser functions need capabilities:\n", errorStyle.Render(fmt.Sprintf("%d", len(needsAttentionGeneric))))
			for _, name := range needsAttentionGeneric {
				fmt.Printf("    - %s\n", dimStyle.Render(name))
			}
		}

		if len(needsAttentionCustom) > 0 {
			fmt.Printf("  • %s custom catalogers need capabilities:\n", errorStyle.Render(fmt.Sprintf("%d", len(needsAttentionCustom))))
			for _, name := range needsAttentionCustom {
				fmt.Printf("    - %s\n", dimStyle.Render(name))
			}
		}

		fmt.Println()
		fmt.Println(dimStyle.Render("Please update these entries in the capabilities files before running tests."))
		fmt.Println()
		fmt.Println(dimStyle.Render("Exit code: 1"))
		os.Exit(1)
	}
	// show success ASCII art when all validations pass
	printSuccessASCII()
}

func hasEmptyCapabilities(caps capabilities.CapabilitySet) bool {
	// only flag if capabilities are completely missing (empty array)
	// if someone filled out the capabilities section (even with all false/empty values), that's intentional
	return len(caps) == 0
}

func printSuccessASCII() {
	fmt.Println()
	fmt.Println(successStyle.Render("✓ All validations passed!") + " 🎉")
	fmt.Println()
	fmt.Println(successStyle.Render("  ░█▀▀░█░█░█▀▀░█▀▀░█▀▀░█▀▀░█▀▀"))
	fmt.Println(successStyle.Render("  ░▀▀█░█░█░█░░░█░░░█▀▀░▀▀█░▀▀█"))
	fmt.Println(successStyle.Render("  ░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀"))
	fmt.Println()
}

func printFailureASCII() {
	fmt.Println(errorStyle.Render("✗ Validation failed") + " 😢")
	fmt.Println()
	fmt.Println(errorStyle.Render("  ░█▀▀░█▀█░▀█▀░█░░░█▀▀░█▀▄"))
	fmt.Println(errorStyle.Render("  ░█▀▀░█▀█░░█░░█░░░█▀▀░█░█"))
	fmt.Println(errorStyle.Render("  ░▀░░░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀▀░"))
	fmt.Println()
}
