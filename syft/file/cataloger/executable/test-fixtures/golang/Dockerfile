FROM golang:1.24

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY main.go cgo_main.go ./

# pure Go builds (no CGO)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /hello_linux .

RUN CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o /hello_mac .

RUN CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o /hello.exe .

# CGO-enabled build (Linux only, uses gcc)
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o /hello_linux_cgo ./cgo_main.go
