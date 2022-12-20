FROM cgr.dev/chainguard/jdk

RUN wget https://github.com/spdx/tools-java/releases/download/v1.1.3/tools-java-1.1.3.zip && \
	unzip tools-java-1.1.3.zip && \
	rm tools-java-1.1.3.zip

ENTRYPOINT ["java", "-jar", "tools-java-1.1.3-jar-with-dependencies.jar"]
