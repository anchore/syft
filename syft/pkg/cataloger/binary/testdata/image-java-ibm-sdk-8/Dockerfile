FROM ibmjava:8-sdk-alpine@sha256:4f8ad2029e78f7b91721745a77fc6011a7c0e09b9edeffb6b20b6ec34a6e63cd AS builder

FROM scratch

COPY --from=builder /opt/ibm/java/bin/jdb /opt/ibm/java/bin/
COPY --from=builder /opt/ibm/java/lib/amd64/jli/libjli.so /opt/ibm/java/lib/amd64/jli/
