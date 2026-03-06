FROM azul/zulu-openjdk:8-latest@sha256:7e3116bf36566e046b763b4a33f410f07f591bc84c391aae4f7891f5ecbb6764 AS builder

FROM scratch

COPY --from=builder /usr/lib/jvm/zulu8-ca-amd64/bin/jdb /usr/lib/jvm/zulu8-ca-amd64/bin/
