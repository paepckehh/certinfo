package certinfo

import (
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
	"paepcke.de/reportstyle"
)

func testCertWith(t *testing.T, tmpl *x509.Certificate) *x509.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber = big.NewInt(1)
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(time.Hour)
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

func testCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	return testCertWith(t, &x509.Certificate{Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn}})
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

func TestIndentedPemInput(t *testing.T) {
	cert := testCertPem(t, "indented.example")
	var in strings.Builder
	for line := range strings.SplitSeq(strings.TrimSuffix(cert, _linefeed), _linefeed) {
		in.WriteString("    " + line + _linefeed)
	}
	in.WriteString("  tls.key: |" + _linefeed)
	out := Decode(in.String(), testReport())
	if !strings.Contains(out, "indented.example") {
		t.Fatalf("indented pem block was not decoded: %q", short(out))
	}
}

func TestAuthorizedKeysMultiple(t *testing.T) {
	var in strings.Builder
	var want []string
	for range 3 {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		in.WriteString(string(ssh.MarshalAuthorizedKey(key)))
		want = append(want, ssh.FingerprintSHA256(key))
	}
	out := Decode(in.String(), testReport())
	for i, fingerprint := range want {
		if !strings.Contains(out, fingerprint) {
			t.Fatalf("key %d of %d was not decoded: %q", i+1, len(want), short(out))
		}
	}
}

func TestCertificateRequestVariants(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "csr.example"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"} {
		t.Run(kind, func(t *testing.T) {
			in := string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}))
			out := Decode(in, testReport())
			if !strings.Contains(out, "X509 Certificate Request") || !strings.Contains(out, "[VALID]") {
				t.Fatalf("%s block was not decoded: %q", kind, out)
			}
		})
	}
}

func TestRSAPublicKeyPem(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	in := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)}))
	out := Decode(in, testReport())
	if !strings.Contains(out, "RSA Public Key [2048]") {
		t.Fatalf("pkcs1 rsa public key was not decoded: %q", out)
	}
}

func TestValidityFormatting(t *testing.T) {
	for _, tc := range []struct {
		name      string
		notBefore time.Duration
		notAfter  time.Duration
		want      string
	}{
		{"minutes left", -time.Hour, 30 * time.Minute, "[for the next 30 minutes]"},
		{"minutes ago", -time.Hour, -30 * time.Minute, "[expired since 30 minutes]"},
		{"hours left", -time.Hour, 10 * time.Hour, "[for the next 10 hours]"},
		{"days left", -time.Hour, 10 * 24 * time.Hour, "[for the next 10 days]"},
		{"not yet valid", 30 * time.Minute, 24 * time.Hour, "[for the next 30 minutes]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := &x509.Certificate{NotBefore: time.Now().Add(tc.notBefore), NotAfter: time.Now().Add(tc.notAfter)}
			got := validFor(cert, testStyle())
			if !strings.Contains(got, tc.want) {
				t.Fatalf("validFor() = %q, want it to contain %q", got, tc.want)
			}
		})
	}
}

func TestExtendedKeyUsageMicrosoft(t *testing.T) {
	cert := testCertWith(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "eku.example"},
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
			x509.ExtKeyUsageMicrosoftKernelCodeSigning,
		},
	})
	out := Cert(cert, testReport())
	for _, want := range []string{"[Microsoft commercial code signing]", "[Microsoft kernel code signing]"} {
		if !strings.Contains(out, want) {
			t.Fatalf("known extension usage %q not reported: %q", want, short(out))
		}
	}
	if strings.Contains(out, "[Unknown]") {
		t.Fatalf("known extension usage reported as unknown: %q", short(out))
	}
}

func TestECDHKeyPem(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		kind string
		der  []byte
		want string
	}{
		{"public", "PUBLIC KEY", pubDER, "ECDH Public Key [X25519]"},
		{"private", "PRIVATE KEY", privDER, "ECDH Private Key [X25519]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := string(pem.EncodeToMemory(&pem.Block{Type: tc.kind, Bytes: tc.der}))
			out := Decode(in, testReport())
			if !strings.Contains(out, tc.want) {
				t.Fatalf("%s key not reported as %q: %q", tc.name, tc.want, short(out))
			}
		})
	}
}

func TestMLDSAKeyPem(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Skipf("mldsa unavailable: %v", err)
	}
	pub := key.Public()
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		kind string
		der  []byte
		want string
	}{
		{"public", "PUBLIC KEY", pubDER, "ML-DSA-44 Public Key"},
		{"private", "PRIVATE KEY", privDER, "ML-DSA-44 Private Key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := string(pem.EncodeToMemory(&pem.Block{Type: tc.kind, Bytes: tc.der}))
			out := Decode(in, testReport())
			if !strings.Contains(out, tc.want) {
				t.Fatalf("%s mldsa key pem not reported as %q: %q", tc.name, tc.want, short(out))
			}
			if strings.Contains(out, "unsupported keytype") {
				t.Fatalf("%s mldsa key pem reported as unsupported: %q", tc.name, short(out))
			}
		})
	}
}

func TestMLDSACert(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Skipf("mldsa unavailable: %v", err)
	}
	pub := key.Public()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mldsa.example"},
		DNSNames:     []string{"mldsa.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Skipf("mldsa certificate creation unavailable: %v", err)
	}
	in := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	out := Decode(in, testReport())
	if strings.Contains(out, "[UNKNOWN]") {
		t.Fatalf("mldsa certificate reported as unknown public key: %q", short(out))
	}
	for _, want := range []string{"[VALID] [ML-DSA-44]", "[ML-DSA-44]"} {
		if !strings.Contains(out, want) {
			t.Fatalf("mldsa certificate missing %q: %q", want, short(out))
		}
	}
}

func TestX25519Cert(t *testing.T) {
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xkey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "x25519.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	// [crypto/x509] cannot create KEM certs, so splice an X25519 SPKI into a regular cert TBS
	base, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, caPub, caPriv)
	if err != nil {
		t.Fatal(err)
	}
	baseCert, err := x509.ParseCertificate(base)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(baseCert.RawTBSCertificate), string(baseCert.RawSubjectPublicKeyInfo)) {
		t.Fatal("SPKI is not the suffix of TBS, cannot splice")
	}
	spkix := struct {
		Algo pkix.AlgorithmIdentifier
		Bits asn1.BitString
	}{
		Algo: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 101, 110}},
		Bits: asn1.BitString{Bytes: xkey.PublicKey().Bytes(), BitLength: 256},
	}
	spkixBytes, err := asn1.Marshal(spkix)
	if err != nil {
		t.Fatal(err)
	}
	tbs := append([]byte{}, baseCert.RawTBSCertificate[:len(baseCert.RawTBSCertificate)-len(baseCert.RawSubjectPublicKeyInfo)]...)
	tbs = append(tbs, spkixBytes...)
	sig := ed25519.Sign(caPriv, tbs)
	certDER := struct {
		TBS     asn1.RawValue
		SigAlgo asn1.RawValue
		Sig     asn1.BitString
	}{
		asn1.RawValue{FullBytes: tbs},
		asn1.RawValue{FullBytes: baseCert.RawSignatureAlgorithm},
		asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	}
	der, err := asn1.Marshal(certDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		t.Skipf("x25519 KEM certificate not parsable by stdlib: %v", err)
	}
	in := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	out := Decode(in, testReport())
	if strings.Contains(out, "[UNKNOWN]") {
		t.Fatalf("x25519 KEM certificate reported as unknown public key: %q", short(out))
	}
	if !strings.Contains(out, "[ECDH] X25519") {
		t.Fatalf("x25519 KEM certificate not reported as [ECDH] X25519: %q", short(out))
	}
}

func TestMixedAuthorizedKeyAndCertificate(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	in := string(ssh.MarshalAuthorizedKey(key)) + testCertPem(t, "mixed.example")
	out := Decode(in, testReport())
	for _, want := range []string{ssh.FingerprintSHA256(key), "mixed.example"} {
		if !strings.Contains(out, want) {
			t.Fatalf("mixed input lost %q: %q", want, short(out))
		}
	}
}

func TestMixedCertificateAndOpenSSHPrivateKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	in := testCertPem(t, "withkey.example") + string(pem.EncodeToMemory(block))
	out := Decode(in, testReport())
	for _, want := range []string{"withkey.example", "SSH Private Key", "OPENSSH PRIVATE KEY"} {
		if !strings.Contains(out, want) {
			t.Fatalf("mixed input lost %q: %q", want, short(out))
		}
	}
	if strings.Contains(out, "no decoder") {
		t.Fatalf("multipart input reported a decoder gap: %q", short(out))
	}
}

func TestDecodePemOpenSSHPrivateKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	out := DecodePem(block, testReport())
	if !strings.Contains(out, "SSH Private Key") {
		t.Fatalf("DecodePem did not decode an OpenSSH private key: %q", short(out))
	}
	if strings.Contains(out, "no decoder") {
		t.Fatalf("DecodePem reported a decoder gap: %q", short(out))
	}
}

func TestLegacyCertificatePEMType(t *testing.T) {
	in := string(pem.EncodeToMemory(&pem.Block{Type: "X509 CERTIFICATE", Bytes: testCert(t, "legacy.example").Raw}))
	out := Decode(in, testReport())
	if !strings.Contains(out, "legacy.example") {
		t.Fatalf("legacy X509 CERTIFICATE pem type not decoded: %q", short(out))
	}
}

func TestEncryptedPKCS8PrivateKey(t *testing.T) {
	in := string(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("not decodable without a passphrase")}))
	out := Decode(in, testReport())
	if !strings.Contains(out, "encrypted private key") {
		t.Fatalf("encrypted pkcs8 key is not reported as encrypted: %q", short(out))
	}
}

func TestBOMInput(t *testing.T) {
	in := "\ufeff" + testCertPem(t, "bom.example")
	out := Decode(in, testReport())
	if !strings.Contains(out, "bom.example") {
		t.Fatalf("certificate behind a UTF-8 BOM was dropped: %q", short(out))
	}
}

func TestOpenSSLViewOfUnparsableCert(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte{0x30, 0x00}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	out := Cert(cert, &Report{OpenSSL: true, Style: testStyle()})
	if !strings.Contains(out, "re-parse") {
		t.Fatalf("unparsable certificate is not reported cleanly: %q", short(out))
	}
}

func TestHTMLReportEscapesFields(t *testing.T) {
	cert := testCertWith(t, &x509.Certificate{
		Subject:  pkix.Name{CommonName: "html.example"},
		DNSNames: []string{"a<script>b.example"},
	})
	out := Cert(cert, &Report{Summary: true, Style: reportstyle.StyleHTML()})
	if strings.Contains(out, "<script>") {
		t.Fatalf("certificate field was not escaped for html output: %q", short(out))
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatalf("certificate field missing from escaped html output: %q", short(out))
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	sshOut := SshDecodeCert(key, "cmt<script>", []string{"a<b"}, []byte("rest<script>"), reportstyle.StyleHTML())
	if strings.Contains(sshOut, "<script>") {
		t.Fatalf("ssh key field was not escaped for html output: %q", short(sshOut))
	}
}

func TestHTMLSpansBalanced(t *testing.T) {
	out := Cert(testCert(t, "html.example"), &Report{Summary: true, OpenSSL: true, Style: reportstyle.StyleHTML()})
	if open, closed := strings.Count(out, "<span"), strings.Count(out, "</span>"); open != closed {
		t.Fatalf("html output is not balanced: %d span open tags, %d close tags", open, closed)
	}
}

func TestZeroValueReportDefaultsToText(t *testing.T) {
	out := Decode(testCertPem(t, "nostyle.example"), &Report{Summary: true})
	if strings.Contains(out, "parser crash") {
		t.Fatalf("a report without a style must not end in a recovered panic: %q", short(out))
	}
	if !strings.Contains(out, "nostyle.example") {
		t.Fatalf("a report without a style did not decode: %q", short(out))
	}
	if got := Decode(testCertPem(t, "nilreport.example"), nil); strings.Contains(got, "parser crash") {
		t.Fatalf("a nil report must not end in a recovered panic: %q", short(got))
	}
}

func TestHTMLKeyViewSpansBalanced(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	in := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)}))
	out := Decode(in, &Report{Style: reportstyle.StyleHTML()})
	if !strings.Contains(out, "RSA Public Key") {
		t.Fatalf("key view did not render: %q", short(out))
	}
	if open, closed := strings.Count(out, "<span"), strings.Count(out, "</span>"); open != closed {
		t.Fatalf("html key view is not balanced: %d span open tags, %d close tags: %q", open, closed, short(out))
	}
}

func TestMixedInputOrder(t *testing.T) {
	var in strings.Builder
	var want []string
	for i := range 3 {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		in.WriteString(string(ssh.MarshalAuthorizedKey(key)))
		want = append(want, ssh.FingerprintSHA256(key))
		in.WriteString(testCertPem(t, "order"+itoa(i)+".example"))
		want = append(want, "CN=order"+itoa(i)+".example")
	}
	for run := range 5 {
		out := Decode(in.String(), testReport())
		last := -1
		for _, marker := range want {
			i := strings.Index(out, marker)
			if i < 0 {
				t.Fatalf("run %d: %q missing from report: %q", run, marker, short(out))
			}
			if i < last {
				t.Fatalf("run %d: %q out of input order", run, marker)
			}
			last = i
		}
	}
}

func testSelfSignedCA(t *testing.T, cn string, broken bool) *x509.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := priv
	if broken {
		_, signer, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func testSubCA(t *testing.T) *x509.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parent := &x509.Certificate{
		SerialNumber:          big.NewInt(12),
		Subject:               pkix.Name{CommonName: "parent.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	child := &x509.Certificate{
		SerialNumber:          big.NewInt(13),
		Subject:               pkix.Name{CommonName: "child.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, child, parent, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestReportVariants(t *testing.T) {
	in := testCertPem(t, "variants.example")
	tests := []struct {
		name string
		fn   func(string) string
		want string
	}{
		{"text", ReportAsText, "[CN=variants.example]"},
		{"ansi", ReportAsAnsi, "\x1b["},
		{"markdown", ReportAsMarkdown, "[CN=variants.example]"},
		{"html", ReportAsHTML, "<pre"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := tt.fn(in)
			if !strings.Contains(out, tt.want) {
				t.Fatalf("%s report missing %q: %q", tt.name, tt.want, short(out))
			}
		})
	}
}

func TestKeyPinFormats(t *testing.T) {
	cert := testCert(t, "pin.example")
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if got, want := KeyPinBase64(cert), base64.StdEncoding.EncodeToString(digest[:]); got != want {
		t.Fatalf("KeyPinBase64() = %q, want %q", got, want)
	}
	if got, want := KeyPinRaw(cert), hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("KeyPinRaw() = %q, want %q", got, want)
	}
	if got, want := Cert(cert, &Report{PINOnly: true, Style: testStyle()}), KeyPinBase64(cert); got != want {
		t.Fatalf("Cert(PINOnly) = %q, want %q", got, want)
	}
}

func TestCertStoreVariants(t *testing.T) {
	first := testCert(t, "store1.example")
	second := testCert(t, "store2.example")
	pins := &Report{PINOnly: true, Style: reportstyle.StylePlain()}

	one := CertStore([]*x509.Certificate{first, second}, pins)
	for _, want := range []string{testPin(first), testPin(second)} {
		if !strings.Contains(one, want) {
			t.Fatalf("CertStore lost %q: %q", want, one)
		}
	}
	if got := CertStore(nil, pins); got != _empty {
		t.Fatalf("CertStore(nil) = %q, want empty", got)
	}

	stores := CertStores([][]*x509.Certificate{{first}, {second}}, pins)
	for _, want := range []string{testPin(first), testPin(second)} {
		if !strings.Contains(stores, want) {
			t.Fatalf("CertStores lost %q: %q", want, stores)
		}
	}
	if got := CertStores(nil, pins); got != _empty {
		t.Fatalf("CertStores(nil) = %q, want empty", got)
	}
}

func TestCertSummaryOptionalFields(t *testing.T) {
	uri, err := url.Parse("https://example.com/cert")
	if err != nil {
		t.Fatal(err)
	}
	cert := testCertWith(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "fields.example"},
		EmailAddresses:        []string{"admin@example.com"},
		IPAddresses:           []net.IP{net.ParseIP("192.0.2.10")},
		URIs:                  []*url.URL{uri},
		IssuingCertificateURL: []string{"https://example.com/issuer"},
		OCSPServer:            []string{"http://ocsp.example.com"},
	})
	out := Cert(cert, testReport())
	for _, want := range []string{
		"X509 Cert Valid for eMail", "[admin@example.com]",
		"X509 Cert Valid for IPs", "[192.0.2.10]",
		"X509 Cert Valid for URLs", "[https://example.com/cert]",
		"X509 Issuer URL", "[https://example.com/issuer]",
		"X509 Issuer OCSP", "[http://ocsp.example.com]",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("certificate report missing %q: %q", want, short(out))
		}
	}
}

func TestPrivateKeyPEMTypes(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		kind string
		der  []byte
		want string
	}{
		{"pkcs1", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey), "RSA Private Key [2048]"},
		{"sec1", "EC PRIVATE KEY", ecDER, "ECDSA Private Key"},
		{"pkcs8", "PRIVATE KEY", pkcs8DER, "RSA Private Key [2048]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := string(pem.EncodeToMemory(&pem.Block{Type: tt.kind, Bytes: tt.der}))
			out := Decode(in, testReport())
			if !strings.Contains(out, tt.want) {
				t.Fatalf("%s private key not reported as %q: %q", tt.name, tt.want, short(out))
			}
		})
	}
}

func TestCertPEMReport(t *testing.T) {
	cert := testCert(t, "pem.example")
	out := Cert(cert, &Report{PEM: true, Style: reportstyle.StylePlain()})
	for _, want := range []string{"-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"} {
		if !strings.Contains(out, want) {
			t.Fatalf("pem report missing %q: %q", want, short(out))
		}
	}
	html := Cert(cert, &Report{PEM: true, Style: reportstyle.StyleHTML()})
	if !strings.Contains(html, "BEGIN CERTIFICATE") || !strings.Contains(html, "<div") {
		t.Fatalf("html pem report is malformed: %q", short(html))
	}
}

func TestCorruptPEMBlocks(t *testing.T) {
	for _, kind := range []string{
		"CERTIFICATE", "CERTIFICATE REQUEST", "PUBLIC KEY", "RSA PUBLIC KEY",
		"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY",
	} {
		t.Run(kind, func(t *testing.T) {
			in := string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: []byte{0x30, 0x00}}))
			out := Decode(in, testReport())
			if !strings.Contains(out, "[certinfo]") {
				t.Fatalf("corrupt %s block did not report an error: %q", kind, short(out))
			}
		})
	}
}

func TestCertRequestFailure(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "bad-csr.example"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	der[len(der)-1] ^= 0xff
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	out := CertRequest(csr, reportstyle.StyleHTML())
	if !strings.Contains(out, "[FAIL]") {
		t.Fatalf("broken csr not reported as FAIL: %q", short(out))
	}
	if open, closed := strings.Count(out, "<span"), strings.Count(out, "</span>"); open != closed {
		t.Fatalf("broken csr html is not balanced: %d span open tags, %d close tags", open, closed)
	}
}

func TestSCTStates(t *testing.T) {
	cert := testCertWith(t, &x509.Certificate{
		Subject:  pkix.Name{CommonName: "sct.example"},
		DNSNames: []string{"sct.example"},
		ExtraExtensions: []pkix.Extension{
			{Id: oidExtensionCTPoison, Critical: true, Value: []byte{0x05, 0x00}},
			{Id: oidExtensionCTSCT, Value: []byte{0x04, 0x00}},
		},
	})
	out := Cert(cert, testReport())
	for _, want := range []string{"[CRITICAL] [RFC6962 Pre-Certificate Poison]", "[YES] [RFC6962 SCT]"} {
		if !strings.Contains(out, want) {
			t.Fatalf("sct report missing %q: %q", want, short(out))
		}
	}
}

func TestExtendedKeyUsageUnknownCritical(t *testing.T) {
	value, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 2, 3, 4}})
	if err != nil {
		t.Fatal(err)
	}
	cert := testCertWith(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "eku-critical.example"},
		ExtraExtensions: []pkix.Extension{
			{Id: oidExtensionExtendedKeyUsage, Critical: true, Value: value},
		},
	})
	out := Cert(cert, testReport())
	for _, want := range []string{"[CRITICAL]", "[1.2.3.4]"} {
		if !strings.Contains(out, want) {
			t.Fatalf("extended key usage report missing %q: %q", want, short(out))
		}
	}
}

func TestKeyUsageAlert(t *testing.T) {
	cert := &x509.Certificate{
		KeyUsage:   x509.KeyUsageCertSign,
		Extensions: []pkix.Extension{{Id: oidExtensionKeyUsage, Critical: true}},
	}
	got := keyUsage(cert, testStyle())
	for _, want := range []string{"[CRITICAL]", "[ALERT] [Certificate Signing on nonCA]"} {
		if !strings.Contains(got, want) {
			t.Fatalf("keyUsage() missing %q: %q", want, got)
		}
	}
}

func TestIsCurveValid(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
		want  string
		ok    bool
	}{
		{"p256", elliptic.P256(), "[prime256v1] ", true},
		{"p384", elliptic.P384(), "[secp384r1] ", true},
		{"p521", elliptic.P521(), "[secp521r1] ", true},
		{"p224", elliptic.P224(), "[secp224r1] ", false},
		{"nil", nil, "[unsupported curve] ", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := isCurveValid(tt.curve)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("isCurveValid() = %q, %v, want %q, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestCertRequestHTMLReportEscapesMarkup(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "csr.example"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	in := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	out := Decode(in, &Report{Style: reportstyle.StyleHTML()})
	if strings.Contains(out, "&lt;a style") || strings.Contains(out, "&lt;strong") {
		t.Fatalf("csr style markup was escaped into visible text: %q", short(out))
	}
	if !strings.Contains(out, "[VALID]") {
		t.Fatalf("csr report misses the validity state: %q", short(out))
	}
	if open, closed := strings.Count(out, "<span"), strings.Count(out, "</span>"); open != closed {
		t.Fatalf("csr html is not balanced: %d span open tags, %d close tags", open, closed)
	}
}

func TestPEMTypeErrorEscapedInHTML(t *testing.T) {
	const bad = `<script>alert(1)</script>`
	in := "-----BEGIN " + bad + "-----\nAAAA\n-----END " + bad + "-----\n"
	out := Decode(in, &Report{Style: reportstyle.StyleHTML()})
	if strings.Contains(out, "<script>") {
		t.Fatalf("pem type ended up as raw html: %q", out)
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatalf("pem type error is not escaped for html: %q", out)
	}
}

func TestSelfSignedStates(t *testing.T) {
	valid := testSelfSignedCA(t, "root.example", false)
	if out := Cert(valid, testReport()); !strings.Contains(out, "[VALID] [RootCA]") {
		t.Fatalf("valid self-signed root not reported: %q", short(out))
	}

	broken := testSelfSignedCA(t, "broken-root.example", true)
	out := Cert(broken, testReport())
	var selfSignedLine string
	for line := range strings.SplitSeq(out, _linefeed) {
		if strings.HasPrefix(line, "X509 CA SelfSigned") {
			selfSignedLine = line
		}
	}
	if selfSignedLine == _empty {
		t.Fatalf("self-signed failure line is missing: %q", short(out))
	}
	if !strings.Contains(selfSignedLine, "[FAIL]") {
		t.Fatalf("self-signed failure not reported as FAIL: %q", selfSignedLine)
	}

	sub := testSubCA(t)
	if out := Cert(sub, testReport()); strings.Contains(out, "X509 CA SelfSigned") {
		t.Fatalf("sub-CA must not claim a self-signed state: %q", short(out))
	}
}

func TestIsCAStates(t *testing.T) {
	tests := []struct {
		name string
		cert x509.Certificate
		want string
	}{
		{"ca without pathlen", x509.Certificate{IsCA: true}, "[YES] [ALERT] [No PathLen set on CA]"},
		{"ca with pathlen", x509.Certificate{IsCA: true, MaxPathLen: 2}, "[YES]"},
		{"ca with pathlen zero", x509.Certificate{IsCA: true, MaxPathLenZero: true}, "[YES]"},
		{"nonca with pathlen", x509.Certificate{MaxPathLen: 2}, "[NO] [ALERT] [PathLen set on NonCA] [PathLen:2]"},
		{"nonca", x509.Certificate{}, "[NO]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isCA(&tt.cert, testStyle()); got != tt.want {
				t.Fatalf("isCA() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSubCAStates(t *testing.T) {
	tests := []struct {
		name string
		cert x509.Certificate
		want string
	}{
		{"pathlen", x509.Certificate{IsCA: true, MaxPathLen: 3}, "[YES] [PathLen:3]"},
		{"pathlen zero", x509.Certificate{IsCA: true, MaxPathLenZero: true}, "[NO] [PathLen:0]"},
		{"not defined", x509.Certificate{IsCA: true}, "[YES] [ALERT] [PathLen:NotDefined]"},
		{"not a ca", x509.Certificate{}, "[NO]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := subCA(&tt.cert, testStyle()); got != tt.want {
				t.Fatalf("subCA() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSigAlgoStates(t *testing.T) {
	e := testStyle()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"modern", "SHA256-RSA", e.Valid},
		{"ed25519", "Ed25519", e.Valid},
		{"mldsa", "ML-DSA-65", e.Valid},
		{"legacy", "MD5-RSA", e.Fail},
		{"unknown", "nonsense", "[unknown]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sigAlgo(tt.in, e)
			if !strings.Contains(got, tt.want) || !strings.Contains(got, tt.in) {
				t.Fatalf("sigAlgo(%q) = %q, want %q and %q", tt.in, got, tt.want, tt.in)
			}
		})
	}
}

func TestKeyUsageToString(t *testing.T) {
	all := x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign |
		x509.KeyUsageEncipherOnly |
		x509.KeyUsageDecipherOnly
	got, alert := keyUsageToString(all)
	if !alert {
		t.Fatal("keyUsageToString() did not flag certificate signing")
	}
	for _, want := range []string{
		"Digital Signature", "Content Commitment", "Key Encipherment",
		"Data Encipherment", "Key Agreement", "Certificate Signing",
		"CRL Signing", "Encipher Only", "Decipher Only",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("keyUsageToString() lost %q: %q", want, got)
		}
	}
	if empty, alert := keyUsageToString(0); empty != _empty || alert {
		t.Fatalf("keyUsageToString(0) = %q, %v, want empty,false", empty, alert)
	}
}

func TestExtKeyUsageToStringAll(t *testing.T) {
	e := testStyle()
	tests := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageServerAuth:                     "TLS Web server authentication",
		x509.ExtKeyUsageClientAuth:                     "TLS Web client authentication",
		x509.ExtKeyUsageCodeSigning:                    "Signing of executable code",
		x509.ExtKeyUsageEmailProtection:                "Email protection",
		x509.ExtKeyUsageIPSECEndSystem:                 "IPSEC end system",
		x509.ExtKeyUsageIPSECTunnel:                    "IPSEC tunnel",
		x509.ExtKeyUsageIPSECUser:                      "IPSEC user",
		x509.ExtKeyUsageTimeStamping:                   "Time stamping",
		x509.ExtKeyUsageOCSPSigning:                    "OCSP signing",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "Microsoft server gated cryptography",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      "Netscape server gated cryptography",
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "Microsoft commercial code signing",
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "Microsoft kernel code signing",
		x509.ExtKeyUsageAny:                            "Any",
	}
	for usage, want := range tests {
		if got := extKeyUsageToString(usage, e); !strings.Contains(got, want) {
			t.Fatalf("extKeyUsageToString(%d) = %q, want it to contain %q", usage, got, want)
		}
	}
	if got := extKeyUsageToString(x509.ExtKeyUsage(12345), e); !strings.Contains(got, "Unknown") {
		t.Fatalf("unknown extended key usage = %q, want Unknown", got)
	}
}

func TestOIDInExtensions(t *testing.T) {
	exts := []pkix.Extension{
		{Id: oidExtensionKeyUsage},
		{Id: asn1.ObjectIdentifier{1, 2, 3}, Critical: true},
		{Id: oidExtensionKeyUsage, Critical: true},
	}
	count, critical := oidInExtensions(oidExtensionKeyUsage, exts)
	if count != 2 || !critical {
		t.Fatalf("oidInExtensions() = %d, %v, want 2,true", count, critical)
	}
	count, critical = oidInExtensions(oidExtensionCTSCT, exts)
	if count != 0 || critical {
		t.Fatalf("oidInExtensions(absent) = %d, %v, want 0,false", count, critical)
	}
}

func TestEncryptedBlock(t *testing.T) {
	tests := []struct {
		name  string
		block *pem.Block
		want  bool
	}{
		{"pkcs8", &pem.Block{Type: "ENCRYPTED PRIVATE KEY"}, true},
		{"legacy", &pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}}, true},
		{"plain legacy", &pem.Block{Type: "RSA PRIVATE KEY"}, false},
		{"certificate", &pem.Block{Type: "CERTIFICATE"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := encryptedBlock(tt.block); got != tt.want {
				t.Fatalf("encryptedBlock() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseRawPrivateKey(t *testing.T) {
	for _, kind := range []string{"RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "OPENSSH PRIVATE KEY"} {
		if got := parseRawPrivateKey(&pem.Block{Type: kind}); got != kind {
			t.Fatalf("parseRawPrivateKey(%q) = %q, want %q", kind, got, kind)
		}
	}
	if got := parseRawPrivateKey(&pem.Block{Type: "PUBLIC KEY"}); !strings.Contains(got, "unsupported keytype") {
		t.Fatalf("unsupported pem type = %q, want unsupported keytype", got)
	}
}

func TestCurveName(t *testing.T) {
	tests := []struct {
		name  string
		curve ecdh.Curve
		want  string
	}{
		{"x25519", ecdh.X25519(), "X25519"},
		{"p256", ecdh.P256(), "NIST P-256"},
		{"p384", ecdh.P384(), "NIST P-384"},
		{"p521", ecdh.P521(), "NIST P-521"},
		{"nil", nil, "unknown curve"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := curveName(tt.curve); got != tt.want {
				t.Fatalf("curveName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetDBAA(t *testing.T) {
	const digest = "0123456789abcdef0123456789abcdef"
	out := getDBAA(digest)
	lines := strings.Split(strings.TrimSuffix(out, _linefeed), _linefeed)
	if len(lines) != 11 {
		t.Fatalf("getDBAA() returned %d lines, want 11", len(lines))
	}
	if lines[0] != "+-----------------+" || lines[10] != "+-----------------+" {
		t.Fatalf("getDBAA() borders are malformed: %q", lines[0])
	}
	for i := 1; i < 10; i++ {
		if len(lines[i]) != 19 || !strings.HasPrefix(lines[i], "|") || !strings.HasSuffix(lines[i], "|") {
			t.Fatalf("getDBAA() row %d is malformed: %q", i, lines[i])
		}
	}
	if n := strings.Count(out, "E"); n != 1 {
		t.Fatalf("getDBAA() marks %d end cells, want 1", n)
	}
	if n := strings.Count(out, "S"); n > 1 {
		t.Fatalf("getDBAA() marks %d start cells, want at most 1", n)
	}
}

func TestPubKeyVariants(t *testing.T) {
	e := testStyle()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xkey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		pub  any
		want string
	}{
		{"rsa2048", &key.PublicKey, e.Valid + " [RSA] [2048] [e:65537]"},
		{"rsa1024", &small.PublicKey, e.Fail + " [RSA] [1024] [e:65537]"},
		{"rsa small exponent", &rsa.PublicKey{N: key.N, E: 3}, e.Fail},
		{"ecdsa p256", &p256.PublicKey, e.Valid + " [ECDSA] [prime256v1]"},
		{"ecdsa p224", &p224.PublicKey, e.Fail + " [ECDSA] [secp224r1]"},
		{"ed25519", edPub, e.Valid + " [Ed25519]"},
		{"ecdh", xkey.PublicKey(), e.Valid + " [ECDH] X25519"},
		{"dsa", &dsa.PublicKey{}, e.Fail + " [DSA]"},
		{"unknown", 42, e.Fail + "[UNKNOWN]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pubKey(tt.pub, e); !strings.Contains(got, tt.want) {
				t.Fatalf("pubKey() = %q, want it to contain %q", got, tt.want)
			}
		})
	}
}

func TestGetKeyVariants(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	xkey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		key  any
		want string
	}{
		{"rsa public", &key.PublicKey, "RSA Public Key [2048]"},
		{"rsa private", key, "RSA Private Key [2048]"},
		{"dsa public", &dsa.PublicKey{}, "DSA Public Key"},
		{"dsa private", &dsa.PrivateKey{}, "DSA Private Key"},
		{"ecdsa public", &ecdsa.PublicKey{}, "ECDSA Public Key"},
		{"ecdsa private", &ecdsa.PrivateKey{}, "ECDSA Private Key"},
		{"ed25519 public", ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)), "Ed25519 Public Key"},
		{"ed25519 private", ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize)), "Ed25519 Private Key"},
		{"ecdh public", xkey.PublicKey(), "ECDH Public Key [X25519]"},
		{"ecdh private", xkey, "ECDH Private Key [X25519]"},
		{"unknown", 42, "unsupported keytype"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getKey(tt.key); !strings.Contains(got, tt.want) {
				t.Fatalf("getKey() = %q, want it to contain %q", got, tt.want)
			}
		})
	}
}

func TestSshDecodeVariants(t *testing.T) {
	e := testStyle()
	if got := SshDecode("garbage", "PUBLIC", e); !strings.Contains(got, "unsupported ssh keytype") {
		t.Fatalf("SshDecode(public) = %q, want unsupported keytype", got)
	}
	if got := SshDecode("garbage", "PRIVATE", e); !strings.Contains(got, "ssh:") {
		t.Fatalf("SshDecode(garbage) = %q, want an ssh parse error", got)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	in := string(pem.EncodeToMemory(block))
	if got := SshDecode(in, block.Type, e); !strings.Contains(got, "SSH Private Key") {
		t.Fatalf("SshDecode() did not decode an openssh private key: %q", short(got))
	}
}

func TestSshDecodePkHTMLReportEscapesMarkup(t *testing.T) {
	out := SshDecodePk("<script>alert(1)</script>", "<script>fingerprint</script>", "+---+\n", reportstyle.StyleHTML())
	if strings.Contains(out, "<script>") {
		t.Fatalf("ssh key type ended up as raw html: %q", short(out))
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatalf("ssh key type is not escaped for html: %q", short(out))
	}
}

func TestShortMsgArrayVariants(t *testing.T) {
	if got := shortMsgArray(nil); got != _empty {
		t.Fatalf("shortMsgArray(nil) = %q, want empty", got)
	}
	if got := shortMsgArray([]string{"a", "b"}); !strings.Contains(got, "[a] [b]") {
		t.Fatalf("shortMsgArray() = %q, want [a] [b]", got)
	}
	long := make([]string, 10)
	for i := range long {
		long[i] = strings.Repeat("x", 20)
	}
	if got := shortMsgArray(long); len(got) > 80 {
		t.Fatalf("shortMsgArray() returned %d bytes, want <= 80", len(got))
	}

	ips := shortMsgArrayIP([]net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")})
	for _, want := range []string{"[192.0.2.1]", "[2001:db8::1]"} {
		if !strings.Contains(ips, want) {
			t.Fatalf("shortMsgArrayIP() lost %q: %q", want, ips)
		}
	}
	if got := shortMsgArrayIP(nil); got != _empty {
		t.Fatalf("shortMsgArrayIP(nil) = %q, want empty", got)
	}

	u, err := url.Parse("https://example.com/a")
	if err != nil {
		t.Fatal(err)
	}
	urls := shortMsgArrayURL([]*url.URL{u})
	if !strings.Contains(urls, "[https://example.com/a]") {
		t.Fatalf("shortMsgArrayURL() = %q, want the url", urls)
	}
	if got := shortMsgArrayURL(nil); got != _empty {
		t.Fatalf("shortMsgArrayURL(nil) = %q, want empty", got)
	}
}

func TestDecodeErrorVariants(t *testing.T) {
	if got := Decode("short", testReport()); !strings.Contains(got, "too short") {
		t.Fatalf("Decode(short) = %q, want too short", got)
	}
	if got := decodeAuthorizedKeys("no key here", testReport()); !strings.Contains(got, "no key found") {
		t.Fatalf("decodeAuthorizedKeys() = %q, want no key found", got)
	}
}

func TestDuration(t *testing.T) {
	tests := []struct {
		name string
		in   time.Duration
		want string
	}{
		{"minutes", 30 * time.Minute, "30 minutes"},
		{"rounded hours", 90 * time.Minute, "2 hours"},
		{"72 hours", 72 * time.Hour, "72 hours"},
		{"rounded days", 73 * time.Hour, "3 days"},
		{"days", 96 * time.Hour, "4 days"},
		{"negative minutes", -30 * time.Minute, "30 minutes"},
		{"negative days", -96 * time.Hour, "4 days"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := duration(tt.in); got != tt.want {
				t.Fatalf("duration(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
