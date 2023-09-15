FROM golang:1.21.1@sha256:cffaba795c36f07e372c7191b35ceaae114d74c31c3763d442982e3a4df3b39e as builder
WORKDIR /app
COPY go.sum go.mod app.go ./

RUN GOOS=linux go build -o elf .
RUN GOOS=windows go build -o win .
RUN GOOS=darwin go build -o macos .

FROM scratch

WORKDIR /tmp
COPY --from=builder /app/elf /
COPY --from=builder /app/win /
COPY --from=builder /app/macos /

ENTRYPOINT ["/elf"]
