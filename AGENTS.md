# AGENTS.md

## What this is

`paepcke.de/certinfo`: a pure-Go tool (app + library) that decodes and analyzes x.509 certificates, SSH keys/certs, and CSRs from any mixed ASCII input (PEM, openssl dumps, concatenated trust stores, pipes). Sibling project of `tlsinfo`/`dnsinfo` by the same author, sharing output conventions and the `paepcke.de/reportstyle` styling library.

## Commands

```bash
make check            # gofmt -w -s + go vet + go fix + go test ./... (repo root and cmd/certinfo)
make build            # CGO_ENABLED=0 build with the git tag injected as the version
make all              # runs: go run cmd/certinfo/main.go cmd/certinfo/example.txt
make deps             # regenerates go.mod (module paepcke.de/certinfo)

go test ./...                                    # unit tests, self-contained (generates its own certs/keys)
go run ./cmd/certinfo cmd/certinfo/example.txt   # manual run
cat file.pem | go run ./cmd/certinfo             # pipe input works too
```

- **Tests live in `certinfo_test.go`** (root package, stdlib `testing` only, no fixtures, no network, no host files); `cmd/certinfo/main_test.go` covers the CLI helpers. Regression coverage includes mixed authorized-key/PEM/OpenSSH-private-key streams and their order, BOM and CRLF input, legacy/encrypted PEM types, HTML escaping and balanced span markup, and the legacy OpenSSL view of an unparsable certificate. Helper-level tests cover keypins, store aggregation, CSR/self-signed states, key-usage and curve mapping, PEM private-key types, DBAA structure and overflow clamping, and the CLI env/arg/stdout helpers; statement coverage is ~94% (`main`, `log.Fatal` paths and system-trust success are deliberately not exercised). `make check` (gofmt -s, vet, fix, test) is the quality gate; CI (`.github/workflows/golang.yml`) does `go build ./...` + `go vet ./...` + `go test ./...` with `CGO_ENABLED=0`.
- Build must stay `CGO_ENABLED=0` and cross-platform (goreleaser targets linux/freebsd/darwin/windows, amd64+arm64).
- staticcheck/golangci-lint are deliberately commented out in the Makefiles: the code intentionally uses deprecated `crypto/dsa` to parse old/broken certs (see `//lint:ignore SA41019` markers in x509.go, ssh.go).

## Release process (author convention)

- SemVer tags are `v0.1.N` (current: v0.1.77). **Bump the patch only, N+1**, push tag; `.github/workflows/release.yml` runs goreleaser on tags.
- Keep the fallback `version` var (cmd/certinfo/main.go) equal to the tag. `make build` injects `git describe --tags --dirty` via ldflags and goreleaser injects `{{.Version}}`, so release binaries and source builds agree. When `git describe` is empty (source archive), `make build` omits the ldflags and the source fallback is used, never an empty version. The CLI prints `certinfo vX.Y.Z` as the first line of human-readable reports.
- Dependency bumps come via Dependabot (PRs titled `build(deps): bump ...`). `make deps` currently resolves certificate-transparency-go v1.4.0, which pulls in `k8s.io/klog/v2` as an indirect dependency.
- `go.mod` requires **Go 1.27.2** (code uses modern idioms like `sync.WaitGroup.Go`); keep the CI matrix Go version (`.github/workflows/golang.yml`) in sync with it.

## Architecture

Root package `certinfo` is the library API; `cmd/certinfo` is a thin CLI on top.

Data flow (input → output):
1. `Decode(asciiBlock, *Report)` (api.go) is the universal entry point; it and `DecodePem` (api.go) default a nil `Report`/`Style` to plain text via `report(r)`/`style(e)`.
2. `decodeBlock` (generic.go) sanitizes input (whitespace-trims every line and drops a UTF-8 BOM, so indented PEM/YAML dumps and Windows editors work; keeps only `-----` marker blocks and any line that `ssh.ParseAuthorizedKey` accepts, e.g. `ssh-*`, `ecdsa-sha2-*`, `sk-*`, keys with options) and always hands the result to `multipartDecodeParallel`. There is no global content sniff any more: every sanitized segment is dispatched on its own, so mixed inputs (authorized keys + PEM blocks + SSH private keys in one stream) are fully decoded. The sanitizer scans lines up to `_maxLine` (1 MiB) and reports scanner errors instead of silently truncating; input below 32 bytes reports `too short`.
3. `multipartDecodeParallel` (generic.go) splits the sanitized text at every `_pemBegin` into jobs: PEM block -> `decodePemBlock`, text segment -> `decodeAuthorizedKeysText` (quiet mode, so segments without a key do not produce an error line; every authorized key line gets one report via `SshDecodeCert`, options included). Jobs decode concurrently (`WaitGroup.Go` writing into an indexed result slice) and are joined in input order (a newline is added when a result does not end with one, empty results are skipped). Output is therefore deterministic, not scheduler dependent. Input without any PEM block falls back to the single `decodeAuthorizedKeys` call so its error messages stay as before.
4. x509 analysis lives in x509.go (`decodePemBlock`, `certSummary`, `certOpenSSL`, `certPem`, `certRequestSummary`), SSH in ssh.go. `decodePemBlock` is also exposed as public `DecodePem` (api.go) for single `pem.Block` input. It recovers parser panics in band (returns `[certinfo] [ASN|X509] parser crash`), never writes to stdout, accepts `CERTIFICATE`, `X509 CERTIFICATE`, `TRUSTED CERTIFICATE` (openssl trust structure stripped via `asn1.RawValue`), `NEW CERTIFICATE REQUEST`, `RSA PUBLIC KEY` (PKCS#1) and `OPENSSH PRIVATE KEY` (routed to `SshDecode`) blocks, and reports legacy and PKCS#8 encrypted PEM keys explicitly. `certOpenSSL` renders a `[FAIL]` line instead of panicking when the legacy ct-go parser cannot re-parse a certificate.
5. Output is rendered entirely through the `paepcke.de/reportstyle` `*Style` struct (StyleText/Ansi/HTML/Markdown/Plain; fields like `Style.Start`, `.End`, `.L1`, `.L3`, `.LE`, `SaniFunc`). All formatting goes through `strings.Builder` + that struct; report sections are selected by the `Report` flags (Summary, OpenSSL, PEM, PINOnly, PEMLink).

The CLI (cmd/certinfo/main.go) has **no flags** - behavior is controlled purely by environment variables: `NO_COLOR`, `HTML`, `VERBOSE` (adds openssl dump), `PEMONLY` (re-encode only), `PINONLY` (keypin only). It prefers pipe input over file args.

## Conventions (project-specific)

- `getKey` (ssh.go, PEM key path) and `pubKey` (x509.go, certificate path) carry a case for every stdlib key type: RSA, DSA, ECDSA, Ed25519, ECDH (`crypto/ecdh`, labeled via `curveName`, since `ecdh.Curve` has no name/String method), ML-DSA (`crypto/mldsa`, labeled via `Parameters().String()`). A missing case makes a valid stdlib key print "unsupported keytype"/`[FAIL][UNKNOWN]` — add the case, not a fallback catch-all.
- `certPubKey` (x509.go): the stdlib certificate parse path leaves `cert.PublicKey == nil` for SPKI types unknown to its `PublicKeyAlgorithm` enum (eg. X25519 KEM certs, RFC 8410), so the cert summary falls back to `x509.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)` before giving up as `[UNKNOWN]`.
- `sigAlgo` (x509.go): modern signature algorithms (SHA2-RSA/ECDSA, Ed25519, ML-DSA-44/65/87) render as `[VALID]`, broken legacy hashes as `[FAIL]`.
- Tests that generate ML-DSA material must skip (`t.Skipf`) when `mldsa.GenerateKey` returns errUnavailable (FIPS builds), so the suite stays green on all toolchains.
- Minimal-dependency philosophy is a stated goal ("100% pure go, minimal imports"). Don't add new deps casually; the direct dep list is deliberately tiny (x/crypto, certificate-transparency-go, reportstyle). `make deps` may add transitive indirect modules (eg. klog via certificate-transparency-go); that is expected.
- Repeated literal strings are hoisted into unexported const blocks prefixed with `_` (e.g. `_linefeed`, `_expired` in generic.go:18). Follow this when adding repeated literals.
- Output line labels are space-padded to a fixed column (e.g. `"X509 Cert Subject           "`) to keep summary tables aligned; keep padding consistent when editing labels.
- Public API functions are documented with the `// FuncName\n// In : ...\n// Out: ...` comment style (see api.go).
- The CLI prints `certinfo vX.Y.Z` at startup for human-readable reports (default ANSI and `NO_COLOR` text). `PEMONLY`, `PINONLY` and `HTML` stay banner-free so machine output and embedded reports remain clean (`isHumanReport`).
- `getDBAA` (ssh.go) renders the Drunken Bishop art from `_dbaaSymbols`; cells visited 15+ times clamp to the last symbol `^` like OpenSSH, otherwise they would print a border `|` and corrupt the frame.
- Report lines are truncated by `short` (generic.go) at `_shortLen` (80) bytes on a UTF-8 rune boundary; keep that property so `HTML`/`Markdown` output stays valid.
- Free form values (certificate subject/issuer/SANs/URLs/OCSP, SSH options/comment/rest, error text) go through `sani(e, ...)` (generic.go) which applies `Style.SaniFunc` (eg. `html.EscapeString`). Never write certificate or SSH field data into a line without it, otherwise `HTML` reports can be injected. Generated/constant strings and style tokens are not escaped.
- Error lines use `errString(err, style)` (generic.go), never string concatenation with `err.Error()`: parser errors can echo attacker-controlled input (eg. an unknown PEM type or a malformed SAN) and must be escaped for `HTML`. `CertRequest` renders its summary directly and only sanitizes the error text, so style tokens (`e.Valid`/`e.Fail`) are never passed through `SaniFunc`.
- Multiline blocks (openssl dump, PEM, ascii art, CSR) end with `lineEnd(e)` (generic.go) instead of `e.LE`: those lines use `e.L3`, which already closes the value span in HTML, so appending `e.LE` emits a dangling `</span>`. Text/ANSI/Markdown styles are unaffected (`lineEnd` only trims a leading `</span>`).
- Public entry points accept a zero value: `report(r)` / `style(e)` (api.go) default a nil `Report`/`Style` to plain text, so library users cannot end up with a recovered `parser crash` from a nil style.
- `extKeyUsageToString` (x509.go) needs an explicit case per `x509.ExtKeyUsage` constant; anything unmapped prints `[Unknown]`, so add Microsoft/Netscape variants rather than relying on a default.

## Gotchas

- The whole tree emits **nix LSP diagnostics** in this workspace (files parsed as Nix). Ignore them; they are false positives for Go/Makefile/YAML/markdown.
- `go vet`/`gofmt -s`/`go test ./...` are the gates; the code style is deliberately compact (one-liner helpers at the bottom of each file).
- Don't "fix" the DSA warnings, deprecated crypto usage, or the commented-out linters - they are intentional for parsing legacy certs.
- The README is a modern GitHub-style repo README (centered hero + badges, feature list, env-var mode table, library example, roadmap). Keep its install/release links pointing at paepckehh/certinfo, never the tlsinfo repo.
- The README hero is theme-aware: a `<picture>` with `prefers-color-scheme` picks `docs/hero-dark.svg` or `docs/hero-light.svg`, falling back to the light variant. Both are hand-built, self-contained SVG dashboards (no external assets, system font stacks only). Edit them as a pair so the variants stay in sync. The `docs/established-{dark,light}.svg` pair uses the same pattern for the "established 2022, 3+ years on GitHub" banner; keep its release count and year range a true snapshot when editing.
- The Showtime screenshots (`docs/screenshot-truststore.svg`, `docs/screenshot-ssh.svg`) are rendered from **real ANSI output** (not hand-colored) by [docs/render_ansi_svg.py](docs/render_ansi_svg.py), including the startup version banner. Regenerate after report or version changes:
  `certinfo input > /tmp/out.ansi && python3 docs/render_ansi_svg.py /tmp/out.ansi docs/screenshot-truststore.svg "certinfo vX.Y.Z - title" "command"`.
- Input dispatch is per sanitized segment (`multipartDecodeParallel`, generic.go): a PEM block goes to `decodePemBlock`, everything else to the authorized-key decoder. Do not reintroduce a global first-32-char sniff - that silently dropped the rest of mixed inputs. Keep the sanitizer's 32-byte minimum so tiny junk reports `too short` instead of a parser error.
- Certificate validity is rendered by `duration` (x509.go): minutes below one hour, hours up to 72h, days above (rounded, not truncated), so short-lived certs never read "0 hours".
- `isSelfSigned` (x509.go) reports a self-issued CA even when its signature does not verify: it returns `ok=true` with an `e.Fail` line. The caller must print the line whenever `ok` is true, otherwise a broken root silently loses its `SelfSigned` row.
