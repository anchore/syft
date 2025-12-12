FROM golang:1.24

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /hello_linux .

RUN CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o /hello_mac .

RUN CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o /hello.exe .
