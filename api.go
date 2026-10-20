// package certinfo analyzes encoded keys and certificates
package certinfo

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"
	"paepcke.de/reportstyle"
)

//
// SIMPLE API
//

// ReportAsText
// In : Parse any mixed ascii input.
// Out: Report any decodeable certificate details and clean re-encoded pem as Plain ASCII Text Output.
func ReportAsText(asciiBlock string) string {
	return Decode(asciiBlock, &Report{
		Summary: true,
		Style:   reportstyle.StyleText(),
	})
}

// ReportAsAnsi
// In : Parse any mixed ascii input.
// Out: Report any decodeable certificate details and clean re-encoded pem as Color Terminal Console Output
func ReportAsAnsi(asciiBlock string) string {
	return Decode(asciiBlock, &Report{
		Summary: true,
		Style:   reportstyle.StyleAnsi(),
	})
}

// ReportAsMarkdown
// In : Parse any mixed ascii input.
// Out: Report any decodeable certificate details as Markdown Code.
func ReportAsMarkdown(asciiBlock string) string {
	return Decode(asciiBlock, &Report{
		Summary: true,
		Style:   reportstyle.StyleMarkdown(),
	})
}

// ReportAsHTML
// In : Parse any mixed ascii input.
// Out: Report any decodeable certificate details as HTML Code.
func ReportAsHTML(asciiBlock string) string {
	return Decode(asciiBlock, &Report{
		Summary: true,
		Style:   reportstyle.StyleHTML(),
	})
}

// SanitizePEM
// In : Parse any mixed ascii input.
// Out: Sanitizes and clean re-encode any decodable certificate as new pem container.
func SanitizePEM(asciiBlock string) string {
	return Decode(asciiBlock, &Report{
		PEM:   true,
		Style: reportstyle.StylePlain(),
	})
}

//
// UNIVERSAL BACKEND
//

// Report structure
type Report struct {
	Summary    bool               // add summary view to report
	OpenSSL    bool               // add openssl view to report
	PEM        bool               // add clean re-encoded pem to report (pem sanitizer)
	PINOnly    bool               // output the base64 encoded keypin only
	PEMLink    bool               // add an URL link that posts the PEM to an external resource (eg. any pastebin clone)
	PEMPostURL string             // the URL for PEMLink, if PEMLink = false, PEMURL will be ignored
	Style      *reportstyle.Style // output report style (text,html,ansi-color-console, custom ...)
}

// DecodePem a pem block
func DecodePem(block *pem.Block, r *Report) string {
	return decodePemBlock(block, report(r))
}

// Decode an ascii block
func Decode(asciiBlock string, r *Report) string {
	return decodeBlock(asciiBlock, report(r))
}

// report returns a usable report, an unset style defaults to plain text
func report(r *Report) *Report {
	if r == nil {
		r = &Report{}
	}
	if r.Style == nil {
		sane := *r
		sane.Style = style(nil)
		return &sane
	}
	return r
}

// style returns a usable style, nil defaults to plain text
func style(e *reportstyle.Style) *reportstyle.Style {
	if e == nil {
		return reportstyle.StyleText()
	}
	return e
}

//
// X509 CERT
//

// KeyPinBase64 generates an base64 encoded keypin
func KeyPinBase64(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString([]byte(keyPin(cert)))
}

// KeyPinRaw generates an hex encoded keypin
func KeyPinRaw(cert *x509.Certificate) string {
	return hex.EncodeToString(keyPin(cert))
}

// Cert analyzes an x509 certificate
func Cert(cert *x509.Certificate, r *Report) string {
	r = report(r)
	if r.PINOnly {
		return KeyPinBase64(cert)
	}
	var s strings.Builder
	s.WriteString(r.Style.Start)
	if r.Summary {
		s.WriteString(certSummary(cert, r.Style))
	}
	if r.OpenSSL {
		s.WriteString(certOpenSSL(cert, r.Style))
	}
	if r.PEM {
		s.WriteString(certPem(cert, r.Style))
		s.WriteString(_linefeed)
	}
	s.WriteString(r.Style.End)
	return s.String()
}

// CertStore analyzes one x509 cert store
func CertStore(store []*x509.Certificate, r *Report) string {
	var s strings.Builder
	for _, cert := range store {
		s.WriteString(Cert(cert, r) + _linefeed)
	}
	return s.String()
}

// CertStores analyzes an array of x509 cert stores
func CertStores(stores [][]*x509.Certificate, r *Report) string {
	var s strings.Builder
	for _, store := range stores {
		s.WriteString(CertStore(store, r))
	}
	return s.String()
}

// CertRequest analyzses an x509 csr
func CertRequest(csr *x509.CertificateRequest, e *reportstyle.Style) string {
	e = style(e)
	cr := certRequestSummary(csr, e)
	if e.SaniFunc != nil {
		cr = e.PS + e.SaniFunc(cr) + e.PE
	}
	var s strings.Builder
	s.WriteString(e.L1 + "X509 Certificate Request" + e.L3 + cr + lineEnd(e))
	return s.String()
}

//
// KEYS SECTION
//

// PublicKey reports an PublicKey struct
func PublicKey(k any, e *reportstyle.Style) string {
	e = style(e)
	var s strings.Builder
	s.WriteString(e.L1 + "KEY Public Key             " + e.L3 + getKey(k) + lineEnd(e))
	return s.String()
}

// PrivateKey reports an PrivateKey struct
func PrivateKey(k any, e *reportstyle.Style) string {
	e = style(e)
	var s strings.Builder
	s.WriteString(e.L1 + "KEY Private Key            " + e.L3 + getKey(k) + lineEnd(e))
	return s.String()
}

//
// SSH SECTION
//

// SshDecode decodes an ascii block ssh key
func SshDecode(asciiBlock, eval string, e *reportstyle.Style) string {
	e = style(e)
	if strings.Contains(eval, "PRIVATE") {
		key, err := ssh.ParseRawPrivateKey([]byte(asciiBlock))
		if err != nil {
			return errString(err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return errString(errors.New("unsupported ssh keytype"))
		}
		pub, err := ssh.NewPublicKey(signer.Public())
		if err != nil {
			return errString(err)
		}
		digest := sha256.Sum256(pub.Marshal())
		dbaa := getDBAA(string(digest[:]))
		block, _ := pem.Decode([]byte(asciiBlock))
		keytype := parseRawPrivateKey(block)
		return SshDecodePk(keytype, ssh.FingerprintSHA256(pub), dbaa, e)
	}
	return errString(errors.New("unsupported ssh keytype"))
}

// SshDecodeCert decodes an ssh certificate
func SshDecodeCert(key ssh.PublicKey, comment string, options []string, rest []byte, e *reportstyle.Style) string {
	e = style(e)
	digest := sha256.Sum256(key.Marshal())
	dbaa := getDBAA(string(digest[:]))
	if e.SaniFunc != nil {
		dbaa = e.PS + e.SaniFunc(dbaa) + e.PE
	}
	var s strings.Builder
	s.WriteString(e.L1 + "SSH Certificate" + e.LE)
	s.WriteString(e.L1 + "SSH Options                " + e.L2 + sani(e, strings.Join(options, ", ")) + e.LE)
	s.WriteString(e.L1 + "SSH Other                  " + e.L2 + sani(e, string(rest)) + e.LE)
	s.WriteString(e.L1 + "SSH Comment                " + e.L2 + sani(e, comment) + e.LE)
	s.WriteString(e.L1 + "SSH Key Sig Algo           " + e.L2 + strings.TrimPrefix(key.Type(), "ssh-") + e.LE)
	s.WriteString(e.L1 + "SSH Key Finger Print       " + e.L2 + ssh.FingerprintSHA256(key) + e.LE)
	s.WriteString(e.L1 + "SSH Key Ascii Art DBAA     " + e.L3 + dbaa + lineEnd(e))
	return s.String()
}

// SshDecodePk decodes ssh key for <any> keytype
func SshDecodePk(keytype, fingerprint, dbaa string, e *reportstyle.Style) string {
	e = style(e)
	if e.SaniFunc != nil {
		dbaa = e.PS + e.SaniFunc(dbaa) + e.PE
	}
	var s strings.Builder
	s.WriteString(e.L1 + "SSH Private Key" + e.LE)
	s.WriteString(e.L1 + "SSH Key Type               " + e.L2 + keytype + e.LE)
	s.WriteString(e.L1 + "SSH Key Fingerprint        " + e.L2 + fingerprint + e.LE)
	s.WriteString(e.L1 + "SSH Key Ascii Art DBAA     " + e.L3 + dbaa + lineEnd(e))
	return s.String()
}
