GO_1_17 = /Users/jonas/.gvm/gos/go1.17.8/bin/go

build:
	GOARCH=arm64 GOOS=darwin $(GO_1_17) build -o hello-mach-o-arm64 main.go
	GOARCH=ppc64le GOOS=linux $(GO_1_17) build -o hello-linux-ppc64el main.go

clean:
	rm hello-*
