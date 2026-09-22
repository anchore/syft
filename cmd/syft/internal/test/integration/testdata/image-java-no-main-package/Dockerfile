FROM jenkins/jenkins:2.346.3-slim-jdk17@sha256:028fbbd9112c60ed086f5197fcba71992317864d27644e5949cf9c52ff4b65f0 AS base

USER root

WORKDIR /usr/share/jenkins

RUN mkdir tmp

WORKDIR /usr/share/jenkins/tmp

RUN unzip ../jenkins.war 2>&1 > /dev/null

RUN rm -rf ./META-INF/MANIFEST.MF ./WEB-INF ./jsbundles ./scripts ./css

WORKDIR /usr/share/jenkins

RUN rm -rf jenkins.war

# use jar (from the JDK in the base image) to rezip -- M keeps it manifest-less, which is the point of this fixture
RUN cd ./tmp && jar cfM ../jenkins.war . && cd ..

RUN rm -rf ./tmp

FROM scratch

COPY --from=base /usr/share/jenkins/jenkins.war /jenkins.war
