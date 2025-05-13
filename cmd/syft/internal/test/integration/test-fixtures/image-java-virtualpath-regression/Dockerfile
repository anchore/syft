FROM alpine:3.18.3@sha256:7144f7bab3d4c2648d7e59409f15ec52a18006a128c733fcff20d3a4a54ba44a AS base

RUN wget https://repo1.maven.org/maven2/org/jvnet/hudson/main/hudson-war/2.2.1/hudson-war-2.2.1.war

RUN mv hudson-war-2.2.1.war hudson.war

# let's make this image a little smaller as to not take up so much disk space
# we'll only keep the jar metadata files (pom data + manifest) and throw away the rest
RUN apk add --no-cache python3 py3-pip
COPY extract.py /extract.py
RUN python extract.py

FROM scratch

COPY --from=base /slim /
