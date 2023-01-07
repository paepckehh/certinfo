package certinfo

import (
	//nolint:all yes, we must detect/analyze legecy
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	x509CT "github.com/google/certificate-transparency-go/x509"
	x509UT "github.com/google/certificate-transparency-go/x509util"
	"paepcke.de/reportstyle"
)

//
// INTERNAL LEGACY BACKEND
//

func certSummary(cert *x509.Certificate, e *reportstyle.Style) string {
	var s strings.Builder
	s.WriteString(e.L1 + "X509 Cert Subject          " + e.L2 + shortMsg(cert.Subject.String()) + e.LE)
	s.WriteString(e.L1 + "X509 Cert Status           " + e.L2 + validFor(cert, e) + e.LE)
	s.WriteString(e.L1 + "X509 Cert Signature Algo   " + e.L2 + sigAlgo(cert.SignatureAlgorithm.String(), e) + e.LE)
	s.WriteString(e.L1 + "X509 Cert Public Key       " + e.L2 + pubKey(cert.PublicKey, e) + e.LE)
	s.WriteString(e.L1 + "X509 Cert KeyPin [base64]  " + e.L2 + shortMsg(KeyPinBase64(cert)) + e.LE)
	if msg := shortMsgArray(cert.DNSNames); len(msg) > 0 {
		s.WriteString(e.L1 + "X509 Cert Valid for Host   " + e.L2 + msg + e.LE)
	}
	if msg := shortMsgArray(cert.EmailAddresses); len(msg) > 0 {
		s.WriteString(e.L1 + "X509 Cert Calid for eMai   " + e.L2 + msg + e.LE)
	}
	if msg := shortMsgArrayIP(cert.IPAddresses); len(msg) > 0 {
		s.WriteString(e.L1 + "X509 Cert Valid for IPs    " + e.L2 + msg + e.LE)
	}
	if msg := shortMsgArrayURL(cert.URIs); len(msg) > 0 {
		s.WriteString(e.L1 + "X509 Cert Valid for URLs   " + e.L2 + msg + e.LE)
	}
	if msg := keyUsage(cert, e); len(msg) > 0 {
		s.WriteString(e.L1 + "X509 Cert Key Usage        " + e.L2 + msg + e.LE)
	}
	if msg := extendedKeyUsage(cert, e); len(msg) > 0 {
		s.WriteString(e.L1 + "X509 Cert Key Usage Ext    " + e.L2 + msg + e.LE)
	}
	if msg := sct(cert, e); len(msg) > 0 {
		s.WriteString(e.L1 + "X509 Cert Transparency SCT " + e.L2 + msg + e.LE)
	}
	s.WriteString(e.L1 + "X509 CA Authority          " + e.L2 + isCA(cert, e) + e.LE)
	if cert.IsCA {
		if ss, ok := isSelfSigned(cert, e); ok {
			s.WriteString(e.L1 + "X509 CA SelfSigned         " + e.L2 + ss + e.LE)
		}
		s.WriteString(e.L1 + "X509 CA Allows SubCAs      " + e.L2 + subCA(cert, e) + e.LE)
	}
	s.WriteString(e.L1 + "X509 Issuer Signature By   " + e.L2 + shortMsg(cert.Issuer.String()) + e.LE)
	s.WriteString(e.L1 + "X509 Issuer Signature State" + e.L2 + signatureState(cert, e) + e.LE)
	if msg := shortMsgArray(cert.IssuingCertificateURL); len(msg) > 0 {
		s.WriteString(e.L1 + "X509 Issuer URL            " + e.L2 + msg + e.LE)
	}
	if msg := shortMsgArray(cert.OCSPServer); len(msg) > 0 {
		s.WriteString(e.L1 + "X509 Issuer OCSP           " + e.L2 + msg + e.LE)
	}
	return s.String()
}

func certOpenSSL(cert *x509.Certificate, e *reportstyle.Style) string {
	ossl := x509UT.CertificateToString(cert2CT(cert))
	if e.SaniFunc != nil {
		ossl = e.PS + e.SaniFunc(ossl) + e.PE
	}
	var s strings.Builder
	s.WriteString(e.L1 + "X509 OpenSSL compatible X509 Certificate Decoder Report" + e.L3)
	s.WriteString(ossl)
	s.WriteString(e.LE)
	return s.String()
}

func certPem(cert *x509.Certificate, e *reportstyle.Style) string {
	if e.SaniFunc != nil {
		return e.PS + e.SaniFunc(string(cert2pem(cert))) + e.PE
	}
	return string(cert2pem(cert))
}

func cert2pem(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func cert2CT(cert *x509.Certificate) *x509CT.Certificate {
	pct, _ := pem.Decode(cert2pem(cert))
	crt, _ := x509CT.ParseCertificate(pct.Bytes)
	return crt
}

func decodePemBlock(block *pem.Block, r *Report) string {
	defer func() {
		if err := recover(); err != nil {
			// [ASN1|X509] Parser are a little bit trigger happy
			out(_app + " [ASN|X509] parser crash")
		}
	}()
	switch block.Type {
	case "CERTIFICATE REQUEST":
		certRequest, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return errString(err)
		}
		return CertRequest(certRequest, r.Style)
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errString(err)
		}
		return Cert(cert, r)
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return errString(err)
		}
		return PublicKey(pub, r.Style)
	case "PRIVATE KEY":
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return errString(err)
		}
		return PrivateKey(priv, r.Style)
	}
	return errString(errors.New("no decoder for pem type: " + block.Type))
}

func sigAlgo(in string, e *reportstyle.Style) string {
	switch in {
	case "MD2-RSA", "MD5-RSA", "SHA1-RSA", "DSA-SHA1", "ECDSA-SHA1", "DSA-SHA256":
		return e.Fail + _space + shortMsg(in)
	case "SHA256-RSA", "SHA384-RSA", "SHA512-RSA", "SHA256-RSAPSS", "SHA384-RSAPSS", "SHA512-RSAPSS":
		return e.Valid + _space + shortMsg(in)
	case "ECDSA-SHA256", "ECDSA-SHA384", "ECDSA-SHA512", "Ed25519":
		return e.Valid + _space + shortMsg(in)
	}
	return e.Fail + _unknown + shortMsg(in)
}

func pubKey(pub any, e *reportstyle.Style) string {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		l := pub.N.BitLen()
		if l < 2048 || pub.E != 65537 {
			return e.Fail + " [RSA] [" + itoa(l) + "] [e:" + itoa(pub.E) + "]"
		}
		return e.Valid + " [RSA] [" + itoa(l) + "] [e:" + itoa(pub.E) + "]"
	case *dsa.PublicKey:
		return e.Fail + " [DSA] "
	case *ecdsa.PublicKey:
		curve, ok := isCurveValid(pub.Curve)
		if ok {
			return e.Valid + " [ECDSA] " + curve
		}
		return e.Fail + " [ECDSA] " + curve
	case *ed25519.PublicKey:
		return e.Valid + " [Ed25519]"
	}
	return e.Fail + "[UNKNOWN]"
}

func keyPin(cert *x509.Certificate) []byte {
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return digest[:]
}

func isSelfSigned(cert *x509.Certificate, e *reportstyle.Style) (string, bool) {
	selfsigned, status := _no, false
	if cert.IsCA && cert.Issuer.String() == cert.Subject.String() {
		selfsigned, status = e.Valid+_rootCA, true
		if err := cert.CheckSignatureFrom(cert); err != nil {
			selfsigned, status = e.Fail+_space+shortMsg(err.Error()), false
		}
	}
	return selfsigned, status
}

func subCA(cert *x509.Certificate, e *reportstyle.Style) string {
	if cert.IsCA {
		if cert.MaxPathLen > 0 {
			return _yes + _pathlen + strconv.Itoa(cert.MaxPathLen) + "]"
		}
		if cert.MaxPathLenZero {
			return _no + _pathlen + "0]"
		}
		return _yes + _space + e.Alert + _pathlen + "NotDefined]"
	}
	return _no
}

func isCA(cert *x509.Certificate, e *reportstyle.Style) string {
	state, alert := "", ""
	if cert.IsCA {
		state = _yes
		if cert.MaxPathLen == 0 && !cert.MaxPathLenZero {
			alert = _space + e.Alert + " [No PathLen set on CA]"
		}
	} else {
		state = _no
		if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
			alert = _space + e.Alert + " [PathLen set on NonCA]" + _pathlen + strconv.Itoa(cert.MaxPathLen) + "]"
		}
	}
	return state + alert
}

func signatureState(cert *x509.Certificate, e *reportstyle.Style) string {
	_, err := cert.Verify(x509.VerifyOptions{})
	if err != nil {
		return e.Fail + _space + shortMsg(err.Error())
	}
	return e.Valid + " [trusted via system trust store]"
}

func validFor(cert *x509.Certificate, e *reportstyle.Style) string {
	// result, t := e.Fail, cert.NotAfter.Sub(time.Now())
	t := time.Until(cert.NotAfter)
	h := t.Hours()
	var result, tss string
	if h > 72 || h < -72 {
		days := int(t.Hours() / 24)
		tss = ftoa64(math.Abs(float64(days))) + _days
	}
	if t > 0 {
		result = e.Valid + _forthenext + tss + _closebracket
	} else {
		result = e.Fail + _since + tss + _closebracket
	}
	// t = cert.NotBefore.Sub(time.Now())
	t = time.Until(cert.NotBefore)
	if t > 0 {
		tss = ftoa64(math.Abs(float64(t.Hours()))) + _hours
		if t.Hours() > 72 {
			days := int(t.Hours() / 24)
			tss = itoa(days) + _days
		}
		result = e.Fail + _forthenext + tss + _closebracket
	}
	return result
}

func encryptedBlock(block *pem.Block) bool {
	return strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED")
}

func certRequestSummary(csr *x509.CertificateRequest, e *reportstyle.Style) string {
	err := csr.CheckSignature()
	if err != nil {
		return e.Fail + _space + err.Error()
	}
	return e.Valid
}

func keyUsage(cert *x509.Certificate, e *reportstyle.Style) string {
	var s strings.Builder
	caAlert := false
	count, critical := oidInExtensions(oidExtensionKeyUsage, cert.Extensions)
	if critical {
		s.WriteString(_critical)
		s.WriteString(_space)
	}
	if count > 0 {
		r, alerter := keyUsageToString(cert.KeyUsage)
		if alerter {
			caAlert = true
		}
		s.WriteString(r)
	}
	if !cert.IsCA && caAlert {
		return e.Alert + " [Certificate Signing on nonCA] " + s.String()
	}
	return s.String()
}

func extendedKeyUsage(cert *x509.Certificate, e *reportstyle.Style) string {
	var s strings.Builder
	count, critical := oidInExtensions(oidExtensionExtendedKeyUsage, cert.Extensions)
	if critical {
		s.WriteString(_critical)
		s.WriteString(_space)
	}
	if count > 0 {
		for _, usage := range cert.ExtKeyUsage {
			s.WriteString(extKeyUsageToString(usage, e))
		}
		for _, oid := range cert.UnknownExtKeyUsage {
			s.WriteString(shortMsg(oid.String()))
		}
	}
	return s.String()
}

func sct(cert *x509.Certificate, _ *reportstyle.Style) string {
	var s strings.Builder
	count, critical := oidInExtensions(oidExtensionCTPoison, cert.Extensions)
	if critical {
		s.WriteString(_critical)
		s.WriteString(_space)
	}
	if count > 0 {
		s.WriteString(shortMsg("RFC6962 Pre-Certificate Poison"))
	}
	count, critical = oidInExtensions(oidExtensionCTSCT, cert.Extensions)
	if critical {
		s.WriteString(_critical)
		s.WriteString(_space)
	}
	if count > 0 {
		s.WriteString(_yes)
		s.WriteString(_space)
		s.WriteString(shortMsg("RFC6962 SCT"))
	}
	return s.String()
}

//
// LEGACY SECTION
//

// keywords from [github.com/google/certificate-transparency-go]
// forked from golang [crypto/x509], based on RFC / ASN spec keywords (!)
//
// Copyright 2016 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

var (
	oidExtensionKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtensionCTPoison         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	oidExtensionCTSCT            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

func oidInExtensions(oid asn1.ObjectIdentifier, extensions []pkix.Extension) (int, bool) {
	count := 0
	critical := false
	for _, ext := range extensions {
		if ext.Id.Equal(oid) {
			count++
			if ext.Critical {
				critical = true
			}
		}
	}
	return count, critical
}

func keyUsageToString(k x509.KeyUsage) (string, bool) {
	var s strings.Builder
	caAlert := false
	if k&x509.KeyUsageDigitalSignature != 0 {
		s.WriteString(shortMsg("Digital Signature"))
	}
	if k&x509.KeyUsageContentCommitment != 0 {
		s.WriteString(shortMsg("Content Commitment"))
	}
	if k&x509.KeyUsageKeyEncipherment != 0 {
		s.WriteString(shortMsg("Key Encipherment"))
	}
	if k&x509.KeyUsageDataEncipherment != 0 {
		s.WriteString(shortMsg("Data Encipherment"))
	}
	if k&x509.KeyUsageKeyAgreement != 0 {
		s.WriteString(shortMsg("Key Agreement"))
	}
	if k&x509.KeyUsageCertSign != 0 {
		caAlert = true
		s.WriteString(shortMsg("Certificate Signing"))
	}
	if k&x509.KeyUsageCRLSign != 0 {
		s.WriteString(shortMsg("CRL Signing"))
	}
	if k&x509.KeyUsageEncipherOnly != 0 {
		s.WriteString(shortMsg("Encipher Only"))
	}
	if k&x509.KeyUsageDecipherOnly != 0 {
		s.WriteString(shortMsg("Decipher Only"))
	}
	return s.String(), caAlert
}

func extKeyUsageToString(u x509.ExtKeyUsage, e *reportstyle.Style) string {
	var s strings.Builder
	switch u {
	case x509.ExtKeyUsageServerAuth:
		s.WriteString(shortMsg("TLS Web server authentication"))
	case x509.ExtKeyUsageClientAuth:
		s.WriteString(shortMsg("TLS Web client authentication"))
	case x509.ExtKeyUsageCodeSigning:
		s.WriteString(e.Alert + shortMsg("Signing of executable code"))
	case x509.ExtKeyUsageEmailProtection:
		s.WriteString(shortMsg("Email protection"))
	case x509.ExtKeyUsageIPSECEndSystem:
		s.WriteString(e.Alert)
		s.WriteString(shortMsg("IPSEC end system"))
	case x509.ExtKeyUsageIPSECTunnel:
		s.WriteString(e.Alert)
		s.WriteString(shortMsg("IPSEC tunnel"))
	case x509.ExtKeyUsageIPSECUser:
		s.WriteString(e.Alert)
		s.WriteString(shortMsg("IPSEC user"))
	case x509.ExtKeyUsageTimeStamping:
		s.WriteString(shortMsg("Time stamping"))
	case x509.ExtKeyUsageOCSPSigning:
		s.WriteString(shortMsg("OCSP signing"))
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		s.WriteString(shortMsg("Microsoft server gated cryptography"))
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		s.WriteString(shortMsg("Netscape server gated cryptography"))
	case x509.ExtKeyUsageAny:
		s.WriteString(e.Alert)
		s.WriteString(shortMsg("Any"))
	// todo: need update for crypto/x509 upstream
	// case x509.ExtKeyUsageCertificateTransparency:
	// 	return shortMsg("Certificate transparency")
	default:
		s.WriteString(shortMsg("Unknown"))
	}
	return s.String()
}

func isCurveValid(curve elliptic.Curve) (string, bool) {
	switch curve {
	case elliptic.P256():
		return shortMsg("prime256v1"), true
	case elliptic.P384():
		return shortMsg("secp384r1"), true
	case elliptic.P521():
		return shortMsg("secp521r1"), true
	case elliptic.P224():
		return shortMsg("secp224r1"), false
	}
	return shortMsg("unsupported curve"), false
}
