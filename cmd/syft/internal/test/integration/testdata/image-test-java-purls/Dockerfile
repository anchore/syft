FROM docker.io/anchore/test_images:java-88948cc@sha256:dea0e6c24636937f53bdc997d9960c2a18966d1e38bcd8ebd0c395d4e169b806 AS base

# not covered in testing...
RUN rm /packages/gradle-7.1.1-bin.zip

RUN apk add --no-cache python3 py3-pip

COPY extract.py /extract.py

WORKDIR /

# let's make this image a little smaller as to not take up so much disk space
# we'll only keep the jar metadata files (pom data + manifest) and throw away the rest
RUN python extract.py

FROM scratch

COPY --from=base /slim/packages /packages
