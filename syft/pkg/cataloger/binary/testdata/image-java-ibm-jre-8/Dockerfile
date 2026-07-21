FROM ibmjava:8-jre@sha256:3588cd1cc9b8646fe03b3b15210e69b1b520f1321f8518b69c0e7013d702fd23 AS builder

FROM scratch

COPY --from=builder /opt/ibm/java/jre/bin/java /opt/ibm/java/jre/bin/
COPY --from=builder /opt/ibm/java/jre/lib/amd64/jli/libjli.so /opt/ibm/java/jre/lib/amd64/jli/
