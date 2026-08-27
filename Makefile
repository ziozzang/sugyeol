.PHONY: all build test release clean

VERSION ?= 1.4.2

all: build

build:
	CGO_ENABLED=0 go build -buildvcs=false -trimpath -tags='netgo,osusergo' -ldflags='-s -w -buildid= -X main.version=$(VERSION)' -o sugyeol .

test:
	CGO_ENABLED=0 go test ./...

release:
	VERSION=$(VERSION) ./scripts/build-release.sh

clean:
	rm -f sugyeol
