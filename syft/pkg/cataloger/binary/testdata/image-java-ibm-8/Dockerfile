FROM ibmjava:8@sha256:05ef6b0f754aa3a8cebcec36260a70c234a217b21240a998604f33459037bc08 AS builder

FROM scratch

COPY --from=builder /opt/ibm/java/jre/bin/java /opt/ibm/java/jre/bin/
COPY --from=builder /opt/ibm/java/jre/lib/amd64/jli/libjli.so /opt/ibm/java/jre/lib/amd64/jli/
