package certinfo

import (
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
