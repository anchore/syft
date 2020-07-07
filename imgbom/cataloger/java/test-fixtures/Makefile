all: packages/example-app-maven-0.1.0.jar packages/example-app-gradle-0.1.0.jar packages/example-jenkins-plugin.hpi

clean: clean-examples
	rm -f packages/*

clean-examples: clean-gradle clean-maven clean-jenkins

.PHONY: maven gradle clean clean-gradle clean-maven clean-jenkins clean-examples

# Maven...
packages/example-app-maven-0.1.0.jar:
	./run-example-app-maven.sh

clean-maven:
	rm -rf example-app/target example-app/dependency-reduced-pom.xml

# Gradle...
packages/example-app-gradle-0.1.0.jar:
	./run-example-app-gradle.sh

clean-gradle:
	rm -rf example-app/.gradle example-app/build

# Jenkins plugin
packages/example-jenkins-plugin.hpi, packages/example-jenkins-plugin.jar:
	./run-example-jenkins-plugin-maven.sh

clean-jenkins:
	rm -rf example-jenkins-plugin/target example-jenkins-plugin/dependency-reduced-pom.xml example-jenkins-plugin/*.exploding

# we need a way to determine if CI should bust the test cache based on the source material
packages.fingerprint: clean-examples
	@mkdir -p packages
	find example-* -type f -exec sha256sum {} \; > packages.fingerprint
	sha256sum packages.fingerprint
