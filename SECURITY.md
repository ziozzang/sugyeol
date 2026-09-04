# Security policy

Report suspected vulnerabilities privately through GitHub Security Advisories for
`ziozzang/sugyeol`. Do not include private keys, passwords, registry credentials,
tokens, or sensitive package contents in a public issue.

The latest release receives security fixes. Release builds use the Go toolchain
version declared in `go.mod`, set `CGO_ENABLED=0`, and are checked as static
binaries. Before release, maintainers should run:

```sh
go get -u ./...
go mod tidy
go test -race ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
make release
```

An advisory that exists only in an unimported package of a required module is
documented in the release notes and reassessed on every dependency update.
