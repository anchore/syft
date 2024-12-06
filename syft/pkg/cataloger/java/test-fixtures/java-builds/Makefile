PKGSDIR=packages
FINGERPRINT_FILE=$(PKGSDIR).fingerprint

ifndef PKGSDIR
    $(error PKGSDIR is not set)
endif


.DEFAULT_GOAL := fixtures

# requirement 1: 'fixtures' goal to generate any and all test fixtures
fixtures: jars archives native-image

# requirement 2: 'fingerprint' goal to determine if the fixture input that indicates any existing cache should be busted
fingerprint: $(FINGERPRINT_FILE)

jars: $(PKGSDIR)/example-java-app-maven-0.1.0.jar $(PKGSDIR)/example-java-app-gradle-0.1.0.jar $(PKGSDIR)/example-jenkins-plugin.hpi $(PKGSDIR)/spring-boot-0.0.1-SNAPSHOT.jar

archives: $(PKGSDIR)/example-java-app-maven-0.1.0.zip $(PKGSDIR)/example-java-app-maven-0.1.0.tar $(PKGSDIR)/example-java-app-maven-0.1.0.tar.gz

native-image: $(PKGSDIR)/example-java-app $(PKGSDIR)/gcc-amd64-darwin-exec-debug

# jars within archives...

$(PKGSDIR)/example-java-app-maven-0.1.0.zip: $(PKGSDIR)/example-java-app-maven-0.1.0.jar
	zip $(PKGSDIR)/example-java-app-maven-0.1.0.zip $(PKGSDIR)/example-java-app-maven-0.1.0.jar

$(PKGSDIR)/example-java-app-maven-0.1.0.tar: $(PKGSDIR)/example-java-app-maven-0.1.0.jar
	tar -cvf $(PKGSDIR)/example-java-app-maven-0.1.0.tar $(PKGSDIR)/example-java-app-maven-0.1.0.jar

$(PKGSDIR)/example-java-app-maven-0.1.0.tar.gz: $(PKGSDIR)/example-java-app-maven-0.1.0.jar
	tar -czvf $(PKGSDIR)/example-java-app-maven-0.1.0.tar.gz $(PKGSDIR)/example-java-app-maven-0.1.0.jar

# Nested jar...

$(PKGSDIR)/spring-boot-0.0.1-SNAPSHOT.jar:
	./build-example-sb-app-nestedjar.sh $(PKGSDIR)

clean-nestedjar:
	rm -rf	example-sb-app/target

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

# Native Image...
$(PKGSDIR)/example-java-app: $(PKGSDIR)/example-java-app-maven-0.1.0.jar
	./build-example-java-app-native-image.sh $(PKGSDIR)

$(PKGSDIR)/gcc-amd64-darwin-exec-debug:
	./build-example-macho-binary.sh $(PKGSDIR)

# requirement 3: we always need to recalculate the fingerprint based on source regardless of any existing fingerprint
.PHONY: $(FINGERPRINT_FILE)
$(FINGERPRINT_FILE):
	@find example-* build-* Makefile -type f -exec sha256sum {} \; | sort -k2 > $(FINGERPRINT_FILE)
	@#cat $(FINGERPRINT_FILE) | sha256sum | awk '{print $$1}'

# requirement 4: 'clean' goal to remove all generated test fixtures
clean: clean-examples
	rm -rf $(PKGSDIR) $(FINGERPRINT_FILE)

clean-examples: clean-gradle clean-maven clean-jenkins clean-nestedjar

.PHONY: maven gradle clean clean-gradle clean-maven clean-jenkins clean-examples clean-nestedjar jars archives
