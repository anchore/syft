FROM openjdk:11@sha256:e81b7f317654b0f26d3993e014b04bcb29250339b11b9de41e130feecd4cd43c

RUN wget --no-verbose https://github.com/spdx/tools-java/releases/download/v1.1.3/tools-java-1.1.3.zip && \
	unzip tools-java-1.1.3.zip && \
	rm tools-java-1.1.3.zip

ENTRYPOINT ["java", "-jar", "tools-java-1.1.3-jar-with-dependencies.jar"]
