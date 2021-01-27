FROM jenkins:2.60.3

USER root

WORKDIR /usr/share/jenkins

RUN mkdir tmp

WORKDIR /usr/share/jenkins/tmp

RUN apt-get update 2>&1 > /dev/null && apt-get install -y less zip 2>&1 > /dev/null

RUN unzip ../jenkins.war 2>&1 > /dev/null

RUN rm -f ./META-INF/MANIFEST.MF

WORKDIR /usr/share/jenkins

RUN rm -rf jenkins.war

RUN cd ./tmp && zip -r ../jenkins.war . && cd ..

RUN rm -rf ./tmp
