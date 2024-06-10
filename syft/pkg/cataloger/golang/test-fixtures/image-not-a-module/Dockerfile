FROM --platform=linux/amd64 golang:1.22.4 AS builder

RUN mkdir /app
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download
COPY main.go main.go

# building with "." vs "main.go" is a difference in the buildinfo section
# specifically with main.go the buildinfo section will contain the following:
#
#   path command-line-arguments
#
# instead of
#
#  mod anchore.io/not/real
#
RUN CGO_ENABLED=0 GOOS=linux go build -o run-me main.go


FROM scratch

COPY --from=builder /app/run-me /run-me
ENTRYPOINT ["/run-me"]