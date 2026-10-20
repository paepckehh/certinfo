# AGENTS.md

## What this is

`paepcke.de/certinfo`: a pure-Go tool (app + library) that decodes and analyzes x.509 certificates, SSH keys/certs, and CSRs from any mixed ASCII input (PEM, openssl dumps, concatenated trust stores, pipes). Sibling project of `tlsinfo`/`dnsinfo` by the same author, sharing output conventions and the `paepcke.de/reportstyle` styling library.

## Commands

```bash
make check            # gofmt -w -s + go vet + go fix + go test ./... (repo root and cmd/certinfo)
make all              # runs: go run cmd/certinfo/main.go cmd/certinfo/example.txt
make deps             # regenerates go.mod (module paepcke.de/certinfo)

go test ./...                                    # unit tests, self-contained (generates its own certs/keys)
go run ./cmd/certinfo cmd/certinfo/example.txt   # manual run
cat file.pem | go run ./cmd/certinfo             # pipe input works too
```

- **Tests live in `certinfo_test.go`** (root package, stdlib `testing` only, no fixtures, no network, no host files). `make check` (gofmt -s, vet, fix, test) is the quality gate; CI (`.github/workflows/golang.yml`) does `go build ./...` + `go vet ./...` + `go test ./...` with `CGO_ENABLED=0`.
- Build must stay `CGO_ENABLED=0` and cross-platform (goreleaser targets linux/freebsd/darwin/windows, amd64+arm64).
- staticcheck/golangci-lint are deliberately commented out in the Makefiles: the code intentionally uses deprecated `crypto/dsa` to parse old/broken certs (see `//lint:ignore SA41019` markers in x509.go, ssh.go).

## Release process (author convention)

- SemVer tags are `v0.1.N` (current: v0.1.61). **Bump the patch only, N+1**, push tag; `.github/workflows/release.yml` runs goreleaser on tags.
- Dependency bumps come via Dependabot (PRs titled `build(deps): bump ...`).
- `go.mod` requires **Go 1.27.2** (code uses modern idioms like `sync.WaitGroup.Go`); keep the CI matrix Go version (`.github/workflows/golang.yml`) in sync with it.

## Architecture

Root package `certinfo` is the library API; `cmd/certinfo` is a thin CLI on top.

Data flow (input → output):
1. `Decode(asciiBlock, *Report)` (api.go:93) is the universal entry point.
2. `decodeBlock` (generic.go:45) sanitizes input (whitespace-trims every line, so indented PEM/YAML dumps work; keeps only `-----` PEM blocks and any line that `ssh.ParseAuthorizedKey` accepts, e.g. `ssh-*`, `ecdsa-sha2-*`, `sk-*`, keys with options) and dispatches off the first 32 chars of the sanitized text (`eval` from `sanitizer`): `BEGIN`+`SSH` → `SshDecode` (SSH private key), any other `BEGIN` → `multipartDecodeParallel`, everything else → `decodeAuthorizedKeys` (every authorized key line, options included, one report each via `SshDecodeCert`). The sanitizer scans lines up to `_maxLine` (1 MiB) and reports scanner errors instead of silently truncating.
3. `multipartDecodeParallel` (generic.go:68) collects all `pem.Decode` blocks in input order, decodes them concurrently (`WaitGroup.Go` writing into an indexed result slice) via `decodePemBlock`, then joins the results in input order (a `\n` is added when a result does not end with one). Output is therefore deterministic, not scheduler dependent.
4. x509 analysis lives in x509.go (`decodePemBlock`, `certSummary`, `certOpenSSL`, `certPem`, `certRequestSummary`), SSH in ssh.go. `decodePemBlock` is also exposed as public `DecodePem` (api.go:88) for single `pem.Block` input. It recovers parser panics in band (returns `[certinfo] [ASN|X509] parser crash`), never writes to stdout, accepts `TRUSTED CERTIFICATE` blocks (openssl trust structure stripped via `asn1.RawValue`), `NEW CERTIFICATE REQUEST` and `RSA PUBLIC KEY` (PKCS#1) blocks, and reports encrypted PEM keys explicitly.
5. Output is rendered entirely through the `paepcke.de/reportstyle` `*Style` struct (StyleText/Ansi/HTML/Markdown/Plain; fields like `Style.Start`, `.End`, `.L1`, `.L3`, `.LE`, `SaniFunc`). All formatting goes through `strings.Builder` + that struct; report sections are selected by the `Report` flags (Summary, OpenSSL, PEM, PINOnly, PEMLink).

The CLI (cmd/certinfo/main.go) has **no flags** - behavior is controlled purely by environment variables: `NO_COLOR`, `HTML`, `VERBOSE` (adds openssl dump), `PEMONLY` (re-encode only), `PINONLY` (keypin only). It prefers pipe input over file args.

## Conventions (project-specific)

- Minimal-dependency philosophy is a stated goal ("100% pure go, minimal imports"). Don't add new deps casually; the dep list is deliberately tiny (x/crypto, certificate-transparency-go, reportstyle).
- Repeated literal strings are hoisted into unexported const blocks prefixed with `_` (e.g. `_linefeed`, `_expired` in generic.go:18). Follow this when adding repeated literals.
- Output line labels are space-padded to a fixed column (e.g. `"X509 Cert Subject           "`) to keep summary tables aligned; keep padding consistent when editing labels.
- Public API functions are documented with the `// FuncName\n// In : ...\n// Out: ...` comment style (see api.go).
- Output is meant to be grep-parseable (`NO_COLOR` mode); errors print as `[certinfo] <msg>`, not via `log` (only the CLI uses `log.Fatal`). The library never writes to stdout itself.
- Report lines are truncated by `short` (generic.go) at `_shortLen` (80) bytes on a UTF-8 rune boundary; keep that property so `HTML`/`Markdown` output stays valid.

## Gotchas

- The whole tree emits **nix LSP diagnostics** in this workspace (files parsed as Nix). Ignore them; they are false positives for Go/Makefile/YAML/markdown.
- `go vet`/`gofmt -s`/`go test ./...` are the gates; the code style is deliberately compact (one-liner helpers at the bottom of each file).
- Don't "fix" the DSA warnings, deprecated crypto usage, or the commented-out linters - they are intentional for parsing legacy certs.
- The README is a modern GitHub-style repo README (centered hero + badges, feature list, env-var mode table, library example, roadmap). Keep its install/release links pointing at paepckehh/certinfo, never the tlsinfo repo.
- Keep the input sanitizer's 32-byte minimum and first-32-char content sniffing (`sanitizer`, generic.go:98) in mind when changing input handling; dispatch keys off substring matches on the sanitized text, so the authorized-key path must stay the last (default) branch.
- Certificate validity is rendered by `duration` (x509.go): minutes below one hour, hours up to 72h, days above (rounded, not truncated), so short-lived certs never read "0 hours".
