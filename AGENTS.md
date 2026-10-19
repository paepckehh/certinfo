# AGENTS.md

## What this is

`paepcke.de/certinfo`: a pure-Go tool (app + library) that decodes and analyzes x.509 certificates, SSH keys/certs, and CSRs from any mixed ASCII input (PEM, openssl dumps, concatenated trust stores, pipes). Sibling project of `tlsinfo`/`dnsinfo` by the same author, sharing output conventions and the `paepcke.de/reportstyle` styling library.

## Commands

```bash
make check            # gofmt -w -s + go vet + go fix (repo root and cmd/certinfo)
make all              # runs: go run cmd/certinfo/main.go cmd/certinfo/example.txt
make deps             # regenerates go.mod (module paepcke.de/certinfo)

go run ./cmd/certinfo cmd/certinfo/example.txt   # manual run
cat file.pem | go run ./cmd/certinfo             # pipe input works too
```

- **There is no test suite.** `make check` (gofmt -s, vet, fix) is the quality gate; CI (`.github/workflows/golang.yml`) only does `go build ./...` + `go vet ./...` with `CGO_ENABLED=0`. Do not invent `go test` expectations.
- Build must stay `CGO_ENABLED=0` and cross-platform (goreleaser targets linux/freebsd/darwin/windows, amd64+arm64).
- staticcheck/golangci-lint are deliberately commented out in the Makefiles: the code intentionally uses deprecated `crypto/dsa` to parse old/broken certs (see `//lint:ignore SA41019` markers in x509.go, ssh.go).

## Release process (author convention)

- SemVer tags are `v0.1.N` (current: v0.1.58). **Bump the patch only, N+1**, push tag; `.github/workflows/release.yml` runs goreleaser on tags.
- Dependency bumps come via Dependabot (PRs titled `build(deps): bump ...`).

## Architecture

Root package `certinfo` is the library API; `cmd/certinfo` is a thin CLI on top.

Data flow (input → output):
1. `Decode(asciiBlock, *Report)` (api.go:93) is the universal entry point.
2. `decodeBlock` (generic.go:44) sanitizes input (strips everything outside `-----` PEM markers, but keeps `ssh-` authorized-key lines) and dispatches: SSH private key → `SshDecode`, `ssh-` authorized key/cert → `SshDecodeCert`, anything else with `BEGIN` → `multipartDecodeParallel`.
3. `multipartDecodeParallel` (generic.go:67) loops `pem.Decode` over the whole input and decodes each block concurrently (WaitGroup + channel), so concatenated/multipart PEM and noisy truststore dumps work.
4. x509 analysis lives in x509.go (`certSummary`, `certOpenSSL`, `certPem`), SSH in ssh.go.
5. Output is rendered entirely through the `paepcke.de/reportstyle` `*Style` struct (StyleText/Ansi/HTML/Markdown/Plain; fields like `Style.Start`, `.End`, `.L1`, `.L3`, `.LE`, `SaniFunc`). All formatting goes through `strings.Builder` + that struct; report sections are selected by the `Report` flags (Summary, OpenSSL, PEM, PINOnly, PEMLink).

The CLI (cmd/certinfo/main.go) has **no flags** - behavior is controlled purely by environment variables: `NO_COLOR`, `HTML`, `VERBOSE` (adds openssl dump), `PEMONLY` (re-encode only), `PINONLY` (keypin only). It prefers pipe input over file args.

## Conventions (project-specific)

- Minimal-dependency philosophy is a stated goal ("100% pure go, minimal imports"). Don't add new deps casually; the dep list is deliberately tiny (x/crypto, certificate-transparency-go, reportstyle).
- Repeated literal strings are hoisted into unexported const blocks prefixed with `_` (e.g. `_linefeed`, `_expired` in generic.go:18). Follow this when adding repeated literals.
- Output line labels are space-padded to a fixed column (e.g. `"X509 Cert Subject           "`) to keep summary tables aligned; keep padding consistent when editing labels.
- Public API functions are documented with the `// FuncName\n// In : ...\n// Out: ...` comment style (see api.go).
- Output is meant to be grep-parseable (`NO_COLOR` mode); errors print as `[certinfo] <msg>`, not via `log` (only the CLI uses `log.Fatal`).

## Gotchas

- The whole tree emits **nix LSP diagnostics** in this workspace (files parsed as Nix). Ignore them; they are false positives for Go/Makefile/YAML/markdown.
- `go vet`/`gofmt -s` are the only gates; the code style is deliberately compact (one-liner helpers at the bottom of each file).
- Don't "fix" the DSA warnings, deprecated crypto usage, or the commented-out linters - they are intentional for parsing legacy certs.
- The README's download link points at the tlsinfo repo (stale); releases for this project are at paepckehh/certinfo.
- Keep the input sanitizer's 32-byte minimum and first-32-char content sniffing (generic.go:97) in mind when changing input handling; dispatch keys off substring matches on the sanitized text.
