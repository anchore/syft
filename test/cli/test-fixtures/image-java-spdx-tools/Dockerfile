FROM openjdk:11@sha256:99bac5bf83633e3c7399aed725c8415e7b569b54e03e4599e580fc9cdb7c21ab

RUN wget --no-verbose https://github.com/spdx/tools-java/releases/download/v1.1.3/tools-java-1.1.3.zip && \
	unzip tools-java-1.1.3.zip && \
	rm tools-java-1.1.3.zip

ENTRYPOINT ["java", "-jar", "tools-java-1.1.3-jar-with-dependencies.jar"]
