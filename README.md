# OVERVIEW
[![Go Reference](https://pkg.go.dev/badge/paepcke.de/certinfo.svg)](https://pkg.go.dev/paepcke.de/certinfo)
[![Go Report Card](https://goreportcard.com/badge/paepcke.de/certinfo)](https://goreportcard.com/report/paepcke.de/certinfo)
[![Go Build](https://github.com/paepckehh/certinfo/actions/workflows/golang.yml/badge.svg)](https://github.com/paepckehh/certinfo/actions/workflows/golang.yml)
[![License](https://img.shields.io/github/license/paepckehh/certinfo)](https://github.com/paepckehh/certinfo/blob/master/LICENSE)
[![SemVer](https://img.shields.io/github/v/release/paepckehh/certinfo)](https://github.com/paepckehh/certinfo/releases/latest)
<br>[![built with nix](https://builtwithnix.org/badge.svg)](https://search.nixos.org/packages?channel=unstable&show=certinfo-go&from=0&size=50&sort=relevance&type=packages&query=certinfo-go)

[paepcke.de/certinfo](https://paepcke.de/certinfo/)

-   Tired of guess all the cmd switches for [openssl|certutil|...] to decode certificates ?
-   100% pure go, minimal imports, use as app or api (see api.go), compatible with tlsinfo, dnsinfo

# ⚡️HOW TO RUN VIA GO
```
go run paepcke.de/certinfo/cmd/certinfo@latest
```

# ⚡️HOW TO INSTALL VIA GO
```
go install paepcke.de/certinfo/cmd/certinfo@latest
```

# ⚡️PRE-BUILD BINARIES (DOWNLOAD)
[https://github.com/paepckehh/tlsinfo/releases](https://github.com/paepckehh/tlsinfo/releases)

# ⚡️HOW TO RUN ON NIXOS
```
nix-shell -p certinfo-go
```

# ⚡️HOW TO INSTALL ON NIXOS
```
environment.systemPackages = [
  pkgs.certinfo-go
];
```

# ⚡️SHOWTIME

## Summary of all certificates (multipart-pem-decode)

``` Shell
certinfo cert.pem
X509 Cert Subject           : [CN=ISRG Root X1,O=Internet Security Research Group,C=US] 
X509 Cert Status            : [VALID] [for the next 4554 days]
X509 Cert Signature Algo    : [VALID] [SHA256-RSA] 
X509 Cert Public Key        : [VALID] [RSA] [4096] [e:65537]
X509 Cert KeyPin [base64]   : [C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=] 
X509 Cert Key Usage         : [CRITICAL] [Certificate Signing] [CRL Signing] 
X509 CA Authority           : [YES]
X509 CA SelfSigned          : [VALID] [RootCA]
X509 CA Allows SubCAs       : [YES] [ALERT] [PathLen:NotDefined]
X509 Issuer Signature By    : [CN=ISRG Root X1,O=Internet Security Research Group,C=US] 
X509 Issuer Signature State : [VALID] [trusted via system trust store]
```

## Need more details (incl. openssl-compatible-dump) ?

``` Shell
VERBOSE=true certinfo certs.txt
[...]
```

## Need to parse the output?

``` Shell
NO_COLOR=true certinfo certs.txt | grep ... 
[...]
```

## Need only the keypin?

``` Shell
PINONLY=true certinfo certs.txt
[...]
```

## Need to review your unix system trust store?

``` Shell
cat /etc/ssl/* | certinfo 
[...]
```

## Need to clean re-encode, sanitize your truststore in one file?

``` Shell
PEMONLY=true cat /etc/ssl/* | certinfo > truststore.pem
[..]
```

## PlainText, ColorAnsi Console, and HTML output.
``` Shell
HTML=true certinfo certs.txt
[...]
```

# TODO:

[] optional SCT log verification (online/leaky)

# DOCS

[pkg.go.dev/paepcke.de/certinfo](https://pkg.go.dev/paepcke.de/certinfo)

# 🛡 License

[![License](https://img.shields.io/github/license/paepckehh/certinfo)](https://github.com/paepckehh/certinfo/blob/master/LICENSE)

This project is licensed under the terms of the `BSD 3-Clause License` license. See [LICENSE](https://github.com/paepckehh/certinfo/blob/master/LICENSE) for more details.

# 📃 Citation

```bibtex
@misc{certinfo,
  author = {Michael Paepcke},
  title = {Tool to analyze and troubleshoot x.509 & ssh certificates, encoded keys, ... (app/lib/api)},
  year = {2022},
  publisher = {GitHub},
  journal = {GitHub repository},
  howpublished = {\url{https://paepcke.de/certinfo}}
}
```

# CONTRIBUTION

Yes, Please! PRs Welcome! 

