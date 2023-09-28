.DEFAULT_GOAL := validate-schema
.PHONY: validate-schema
validate-schema:
	@echo "Generating CycloneDX SBOMs..."
	go run ../../cmd/syft/main.go ubuntu:latest -v -o cyclonedx=bom.xml -o cyclonedx-json=bom.json

	@echo "\nValidating CycloneDX XML..."
	xmllint --noout --schema ./cyclonedx.xsd bom.xml

	@echo "\nValidating CycloneDX JSON..."
	../../.tmp/yajsv -s cyclonedx.json bom.json
