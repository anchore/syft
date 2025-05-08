FROM ubuntu:20.04@sha256:33a5cc25d22c45900796a1aca487ad7a7cb09f09ea00b779e3b2026b4fc2faba AS base
# this covers rpm-python
RUN apt-get update && apt-get install -y python-pil=6.2.1-3

# let's save some space...
FROM scratch

COPY --from=base /var/lib/dpkg/status /var/lib/dpkg/status
