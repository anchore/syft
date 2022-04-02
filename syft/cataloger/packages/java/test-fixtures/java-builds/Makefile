PKGSDIR=packages

ifndef PKGSDIR
    $(error PKGSDIR is not set)
endif

all: jars archives

clean: clean-examples
	rm -f $(PKGSDIR)/*

clean-examples: clean-gradle clean-maven clean-jenkins clean-nestedjar

.PHONY: maven gradle clean clean-gradle clean-maven clean-jenkins clean-examples clean-nestedjar jars archives

jars: $(PKGSDIR)/example-java-app-maven-0.1.0.jar $(PKGSDIR)/example-java-app-gradle-0.1.0.jar $(PKGSDIR)/example-jenkins-plugin.hpi $(PKGSDIR)/spring-boot-0.0.1-SNAPSHOT.jar

archives: $(PKGSDIR)/example-java-app-maven-0.1.0.zip $(PKGSDIR)/example-java-app-maven-0.1.0.tar $(PKGSDIR)/example-java-app-maven-0.1.0.tar.gz

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

# we need a way to determine if CI should bust the test cache based on the source material
$(PKGSDIR).fingerprint: clean-examples
	mkdir -p $(PKGSDIR)
	find example-* -type f -exec sha256sum {} \; | sort | tee /dev/stderr | tee $(PKGSDIR).fingerprint
	sha256sum $(PKGSDIR).fingerprint
