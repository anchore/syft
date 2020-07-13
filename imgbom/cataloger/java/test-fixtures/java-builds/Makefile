PKGSDIR=packages

ifndef PKGSDIR
    $(error PKGSDIR is not set)
endif

all: $(PKGSDIR)/example-java-app-maven-0.1.0.jar $(PKGSDIR)/example-java-app-gradle-0.1.0.jar $(PKGSDIR)/example-jenkins-plugin.hpi

clean: clean-examples
	rm -f $(PKGSDIR)/*

clean-examples: clean-gradle clean-maven clean-jenkins

.PHONY: maven gradle clean clean-gradle clean-maven clean-jenkins clean-examples

# Maven...
$(PKGSDIR)/example-java-app-maven-0.1.0.jar:
	./build-example-java-app-maven.sh $(PKGSDIR)

clean-maven:
	rm -rf	example-java-app/\? \
			example-java-app/target \
			example-java-app/dependency-reduced-pom.xml

# Gradle...
$(PKGSDIR)/example-java-app-gradle-0.1.0.jar:
	./build-example-java-app-gradle.sh $(PKGSDIR)

clean-gradle:
	rm -rf	example-java-app/.gradle \
			example-java-app/build

# Jenkins plugin
$(PKGSDIR)/example-jenkins-plugin.hpi , $(PKGSDIR)/example-jenkins-plugin.jar:
	./build-example-jenkins-plugin.sh $(PKGSDIR)

clean-jenkins:
	rm -rf	example-jenkins-plugin/target \
			example-jenkins-plugin/dependency-reduced-pom.xml \
			example-jenkins-plugin/*.exploding

# we need a way to determine if CI should bust the test cache based on the source material
$(PKGSDIR).fingerprint: clean-examples
	mkdir -p $(PKGSDIR)
	find example-* -type f -exec sha256sum {} \; | sort | tee $(PKGSDIR).fingerprint
	sha256sum $(PKGSDIR).fingerprint
