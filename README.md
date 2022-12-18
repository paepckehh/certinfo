# Overview

-   Tired of guess all the cmd switches for [openssl|certutil|...] to decode an simple certificate ?
-   100% pure go, minimal(internal-only) imports, use as app or api (see api.go), compatible with tlsinfo, dnsinfo ...

# Showtime

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
