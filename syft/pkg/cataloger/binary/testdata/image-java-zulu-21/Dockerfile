FROM azul/zulu-openjdk:21-jre-headless@sha256:581ebc852fcd9b52a5979b9b90dbe7cca2736bc1ecf1b9bd08ec41212d6675a4 AS builder

FROM scratch

COPY --from=builder /usr/lib/jvm/zulu21-ca-amd64/bin/java /usr/lib/jvm/zulu21-ca-amd64/bin/
