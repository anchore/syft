FROM golang:latest as builder
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
