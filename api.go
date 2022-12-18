// package certinfo
package certinfo

// import
import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
	"paepcke.de/reportstyle"
)

//
// SIMPLE API
//

// ReportAsText ...
// In : Parse any mixed ascii input.
// Out: Report any decodeable certificate details and clean re-encoded pem as Plain ASCII Text Output.
func ReportAsText(asciiBlock string) string {
	return Decode(asciiBlock, &Report{
		Summary: true,
		Style:   reportstyle.StyleText(),
	})
}

// ReportAsAnsi ...
// In : Parse any mixed ascii input.
// Out: Report any decodeable certificate details and clean re-encoded pem as Color Terminal Console Output
func ReportAsAnsi(asciiBlock string) string {
	return Decode(asciiBlock, &Report{
		Summary: true,
		Style:   reportstyle.StyleAnsi(),
	})
}

// ReportAsMarkdown ...
// In : Parse any mixed ascii input.
// Out: Report any decodeable certificate details as Markdown Code and a clean re-encoded sanitized pem as post URL.
func ReportAsMarkdown(asciiBlock string) string {
	return Decode(asciiBlock, &Report{
		Summary: true,
		Style:   reportstyle.StyleMarkdown(),
	})
}

// ReportAsHTML ...
// In : Parse any mixed ascii input.
// Out: Report any decodeable certificate details as HTML Code and a clean re-encoded sanitized pem as post URL.
func ReportAsHTML(asciiBlock string) string {
	return Decode(asciiBlock, &Report{
		Summary: true,
		Style:   reportstyle.StyleHTML(),
	})
}

// SanitizePEM ...
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

// Report ...
type Report struct {
	Summary    bool               // add summary view to report
	OpenSSL    bool               // add openssl view to report
	PEM        bool               // add clean re-encoded pem to report (pem sanitizer)
	PINOnly    bool               // output the base64 encoded keypin only
	PEMLink    bool               // add an URL link that posts the PEM to an external resource (eg. any pastebin clone)
	PEMPostURL string             // the URL for PEMLink, if PEMLink = false, PEMURL will be ignored
	Style      *reportstyle.Style // output report style (text,html,ansi-color-console, custom ...)
}

// Decode ...
func Decode(asciiBlock string, r *Report) string {
	return decodeBlock(asciiBlock, r)
}

// DecodePem ..
func DecodePem(block *pem.Block, r *Report) string {
	return decodePemBlock(block, r)
}

//
// X509 CERT
//

// Cert ...
func Cert(cert *x509.Certificate, r *Report) string {
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

// CertStore ...
func CertStore(store []*x509.Certificate, r *Report) string {
	var s strings.Builder
	for _, cert := range store {
		s.WriteString(Cert(cert, r) + _linefeed)
	}
	return s.String()
}

// CertStores ...
func CertStores(stores [][]*x509.Certificate, r *Report) string {
	var s strings.Builder
	for _, store := range stores {
		s.WriteString(CertStore(store, r))
	}
	return s.String()
}

// CertRequest ...
func CertRequest(csr *x509.CertificateRequest, e *reportstyle.Style) string {
	cr := certRequestSummary(csr, e)
	if e.SaniFunc != nil {
		cr = e.PS + e.SaniFunc(cr) + e.PE
	}
	var s strings.Builder
	s.WriteString(e.L1 + "X509 Certificate Request" + e.L3 + cr + e.LE)
	return s.String()
}

// KeyPinBase64 ...
func KeyPinBase64(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString([]byte(keyPin(cert)))
}

// KeyPinRaw ...
func KeyPinRaw(cert *x509.Certificate) string {
	return hex.EncodeToString(keyPin(cert))
}

//
// KEYS SECTION
//

// PublicKey ...
func PublicKey(k any, e *reportstyle.Style) string {
	var s strings.Builder
	s.WriteString(e.L1 + "KEY Public Key             " + e.L3 + getKey(k) + e.LE)
	return s.String()
}

// PrivateKey ...
func PrivateKey(k any, e *reportstyle.Style) string {
	var s strings.Builder
	s.WriteString(e.L1 + "KEY Private Key            " + e.L3 + getKey(k) + e.LE)
	return s.String()
}

//
// SSH SECTION
//

// SshDecodeCert ...
func SshDecodeCert(key ssh.PublicKey, comment string, options []string, rest []byte, e *reportstyle.Style) string {
	k := strings.Split(string(ssh.MarshalAuthorizedKey(key)), " ")
	digest := sha256.Sum256([]byte(k[1])) // todo: fix key decoding
	dbaa := getDBAA(string(digest[:]))
	if e.SaniFunc != nil {
		dbaa = e.PS + e.SaniFunc(dbaa) + e.PE
	}
	var s strings.Builder
	s.WriteString(e.L1 + "SSH Certificate" + e.LE)
	s.WriteString(e.L1 + "SSH Options                " + e.L2 + strings.Join(options, ", ") + e.LE)
	s.WriteString(e.L1 + "SSH Other                  " + e.L2 + string(rest) + e.LE)
	s.WriteString(e.L1 + "SSH Comment                " + e.L2 + comment + e.LE)
	s.WriteString(e.L1 + "SSH Key Sig Algo           " + e.L2 + k[0][4:] + e.LE)
	s.WriteString(e.L1 + "SSH Key Finger Print       " + e.L2 + k[1] + e.LE)
	s.WriteString(e.L1 + "SSH Key Ascii Art DBAA     " + e.L3 + dbaa + e.LE)
	return s.String()
}

// SshDecode ...
func SshDecode(asciiBlock, eval string, e *reportstyle.Style) string {
	if strings.Contains(eval, "PRIVATE") {
		key, err := ssh.ParseRawPrivateKey([]byte(asciiBlock))
		if err != nil {
			return errString(err)
		}
		digest := sha256.Sum256([]byte(fmt.Sprintf("%v", key))) // replace fmt via encoding/hex
		dbaa := getDBAA(fmt.Sprintf(string(digest[:])))
		block, _ := pem.Decode([]byte(asciiBlock))
		keytype := parseRawPrivateKey(block)
		return SshDecodePk(keytype, dbaa, e)
	}
	return errString(errors.New("unsupported ssh keytype"))
}

// SshDecodePk ...
func SshDecodePk(keytype, dbaa string, e *reportstyle.Style) string {
	if e.SaniFunc != nil {
		dbaa = e.PS + e.SaniFunc(dbaa) + e.PE
	}
	var s strings.Builder
	s.WriteString(e.L1 + "SSH Private Key" + e.LE)
	s.WriteString(e.L1 + "SSH Key Type               " + e.L2 + keytype + e.LE)
	s.WriteString(e.L2 + "SSH Key Fingerprint        " + e.L2 + e.LE)
	s.WriteString(e.L1 + "SSH Key Ascii Art DBAA     " + e.L3 + dbaa + e.LE)
	return s.String()
}
