FROM cgr.dev/chainguard/jdk

# Not committed to repository - can be found here: https://github.com/spdx/tools-java/releases
ADD tools-java-1.1.3-jar-with-dependencies.jar /usr/local/bin/tools-java.jar

ENTRYPOINT ["java", "-jar", "/usr/local/bin/tools-java.jar"]

