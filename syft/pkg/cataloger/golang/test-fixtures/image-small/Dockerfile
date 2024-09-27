FROM --platform=linux/amd64 golang:1.22.4 AS builder

RUN mkdir /app
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download
COPY main.go main.go

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-X main.Version=1.0.0" -o run-me .

FROM scratch

COPY --from=builder /app/run-me /run-me
ENTRYPOINT ["/run-me"]