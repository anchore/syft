# Stage 1: Build binaries for multiple platforms
FROM golang:1.24 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./

# build ELF (Linux)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o hello_linux .

# build Mach-O (macOS)
RUN CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o hello_mac .

# build PE (Windows)
RUN CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o hello.exe .

# Stage 2: Minimal image with just the binaries
FROM scratch

COPY --from=builder /app/hello_linux /
COPY --from=builder /app/hello_mac /
COPY --from=builder /app/hello.exe /
