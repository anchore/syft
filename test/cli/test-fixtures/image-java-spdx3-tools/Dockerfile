FROM amazoncorretto:25-jdk@sha256:fc1e15685008173644a62253459a10100803d4b7cbac1f5fcfa46d5fbec29250 AS build

WORKDIR /

RUN curl --verbose -LO https://github.com/spdx/tools-java/releases/download/v2.0.4/tools-java-2.0.4.zip
RUN jar -xf /tools-java-2.0.4.zip
RUN ls -l /usr/lib/jvm/java-25-amazon-corretto
RUN ls -l /etc/alternatives/java-25-amazon-corretto

FROM amazoncorretto:25-headless@sha256:8492d0c9d92edc54f0eb6aa5f9d0bba348d01143deb41834f7f15b0f25905001

COPY --from=build /tools-java-2.0.4-jar-with-dependencies.jar /

ENTRYPOINT ["java", "-jar", "/tools-java-2.0.4-jar-with-dependencies.jar"]
