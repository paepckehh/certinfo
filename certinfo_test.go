package certinfo

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
	"paepcke.de/reportstyle"
)

func testCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func testCertPem(t *testing.T, cn string) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testCert(t, cn).Raw}))
}

func testPin(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(digest[:])
}

func testStyle() *reportstyle.Style { return reportstyle.StyleText() }

func testReport() *Report { return &Report{Summary: true, Style: testStyle()} }

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestShortTruncatesOnRuneBoundary(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"ascii", strings.Repeat("a", 200)},
		{"two-byte", strings.Repeat("a", 74) + strings.Repeat("ü", 20)},
		{"three-byte", strings.Repeat("a", 73) + strings.Repeat("中", 20)},
		{"four-byte", strings.Repeat("a", 72) + strings.Repeat("😀", 20)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := short(tc.in)
			if len(got) > 80 {
				t.Fatalf("short() returned %d bytes, want <= 80", len(got))
			}
			if !utf8.ValidString(got) {
				t.Fatalf("short() returned invalid utf8: %q", got)
			}
		})
	}
}

func TestEd25519CertSummary(t *testing.T) {
	out := Decode(testCertPem(t, "ed25519.example"), testReport())
	if !strings.Contains(out, "[Ed25519]") {
		t.Fatalf("ed25519 certificate reports an unsupported public key: %q", out)
	}
	if strings.Contains(out, "[UNKNOWN]") {
		t.Fatalf("ed25519 certificate reports an unknown public key: %q", out)
	}
}

func TestMultipartOrder(t *testing.T) {
	const certs = 6
	var in strings.Builder
	var want []string
	for i := range certs {
		cert := testCert(t, "order"+itoa(i)+".example")
		in.WriteString(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
		want = append(want, testPin(cert))
	}
	report := &Report{PINOnly: true, Style: reportstyle.StylePlain()}
	for i := range 5 {
		out := Decode(in.String(), report)
		got := strings.Split(strings.TrimSuffix(out, _linefeed), _linefeed)
		if len(got) != len(want) {
			t.Fatalf("run %d: got %d results, want %d: %q", i, len(got), len(want), out)
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("run %d: result %d out of input order", i, j)
			}
		}
	}
}

func TestMultipartSeparatesResults(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte("not a decoder input"))
	block := func(kind string) string {
		return "-----BEGIN " + kind + "-----\n" + payload + "\n-----END " + kind + "-----\n"
	}
	out := Decode(block("FOO")+block("BAR"), testReport())
	lines := strings.Split(strings.TrimSuffix(out, _linefeed), _linefeed)
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want one result per block: %q", len(lines), out)
	}
	if !strings.Contains(lines[0], "FOO") || !strings.Contains(lines[1], "BAR") {
		t.Fatalf("results are not separated in input order: %q", out)
	}

	certs := testCertPem(t, "sep1.example") + testCertPem(t, "sep2.example")
	pins := Decode(certs, &Report{PINOnly: true, Style: reportstyle.StylePlain()})
	if n := len(strings.Split(strings.TrimSuffix(pins, _linefeed), _linefeed)); n != 2 {
		t.Fatalf("got %d keypin lines, want 2: %q", n, pins)
	}
}

func TestTrustedCertificate(t *testing.T) {
	cert := testCert(t, "trusted.example")
	aux, err := asn1.Marshal(asn1.ObjectIdentifier{2, 5, 29, 1})
	if err != nil {
		t.Fatal(err)
	}
	in := string(pem.EncodeToMemory(&pem.Block{Type: "TRUSTED CERTIFICATE", Bytes: append(cert.Raw, aux...)}))
	out := Decode(in, testReport())
	if !strings.Contains(out, "trusted.example") {
		t.Fatalf("TRUSTED CERTIFICATE block was not decoded: %q", out)
	}
}

func TestAuthorizedKeyVariants(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaPub, err := ssh.NewPublicKey(&ecdsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edKey, err := ssh.NewPublicKey(edPub)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		line string
		want string
	}{
		{"ed25519", string(ssh.MarshalAuthorizedKey(edKey)), ssh.FingerprintSHA256(edKey)},
		{"ecdsa", string(ssh.MarshalAuthorizedKey(ecdsaPub)), ssh.FingerprintSHA256(ecdsaPub)},
		{"options", `no-pty,command="/bin/date" ` + string(ssh.MarshalAuthorizedKey(edKey)), ssh.FingerprintSHA256(edKey)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := Decode(tc.line, testReport())
			if !strings.Contains(out, tc.want) {
				t.Fatalf("authorized key not decoded: %q", out)
			}
		})
	}
}

func TestLongLineInput(t *testing.T) {
	in := strings.Repeat("A", 70_000) + _linefeed + testCertPem(t, "longline.example")
	out := Decode(in, testReport())
	if !strings.Contains(out, "longline.example") {
		t.Fatalf("certificate after a long line was dropped: %q", short(out))
	}
}

func TestOverlongLineReportsError(t *testing.T) {
	in := strings.Repeat("A", 2<<20) + _linefeed + testCertPem(t, "overlong.example")
	out := Decode(in, testReport())
	if !strings.Contains(out, "token too long") {
		t.Fatalf("overlong line was silently dropped, want an explicit error: %q", short(out))
	}
}

func TestDecodePemRecoversInBand(t *testing.T) {
	var got string
	stdout := captureStdout(t, func() {
		got = DecodePem(nil, testReport())
	})
	if stdout != _empty {
		t.Fatalf("library wrote to stdout: %q", stdout)
	}
	if !strings.Contains(got, "parser crash") {
		t.Fatalf("recovered panic is not part of the report: %q", got)
	}
}

func TestEncryptedPrivateKey(t *testing.T) {
	block := &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,0123456789ABCDEF0123456789ABCDEF"},
		Bytes:   []byte("not a decodable key"),
	}
	out := Decode(string(pem.EncodeToMemory(block)), testReport())
	if !strings.Contains(out, "ncrypted") {
		t.Fatalf("encrypted key is not reported as encrypted: %q", out)
	}
}

func TestSanitizePEMRoundTrip(t *testing.T) {
	in := testCertPem(t, "rt1.example") + "noise\n" + testCertPem(t, "rt2.example")
	once := SanitizePEM(in)
	if strings.Contains(once, "noise") {
		t.Fatalf("sanitizer did not strip noise: %q", once)
	}
	if twice := SanitizePEM(once); twice != once {
		t.Fatalf("sanitized pem is not stable:\nfirst:  %q\nsecond: %q", once, twice)
	}
}
