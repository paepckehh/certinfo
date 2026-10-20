package certinfo

import (
	//lint:ignore SA41019 we need to analyse old and broken certs as well
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
)

// parseRawPrivateKey ...
func parseRawPrivateKey(in *pem.Block) string {
	switch in.Type {
	case "RSA PRIVATE KEY":
		return "RSA PRIVATE KEY"
	case "PRIVATE KEY":
		return "PRIVATE KEY"
	case "EC PRIVATE KEY":
		return "EC PRIVATE KEY"
	case "DSA PRIVATE KEY":
		return "DSA PRIVATE KEY"
	case "OPENSSH PRIVATE KEY":
		return "OPENSSH PRIVATE KEY"
	}
	return errString(errors.New("unsupported keytype"))
}

// getKey ...
func getKey(k any) string {
	switch k := k.(type) {
	case *rsa.PublicKey:
		return "RSA Public Key [" + strconv.Itoa(k.N.BitLen()) + "]"
	case *rsa.PrivateKey:
		return "RSA Private Key [" + strconv.Itoa(k.N.BitLen()) + "]"
	case *dsa.PublicKey:
		return "DSA Public Key"
	case *dsa.PrivateKey:
		return "DSA Private Key"
	case *ecdsa.PublicKey:
		return "ECDSA Public Key"
	case *ecdsa.PrivateKey:
		return "ECDSA Private Key"
	case ed25519.PublicKey:
		return "Ed25519 Public Key"
	case ed25519.PrivateKey:
		return "Ed25519 Private Key"
	case *ecdh.PublicKey:
		return "ECDH Public Key [" + curveName(k.Curve()) + "]"
	case *ecdh.PrivateKey:
		return "ECDH Private Key [" + curveName(k.Curve()) + "]"
	case *mldsa.PublicKey:
		return k.Parameters().String() + " Public Key"
	case *mldsa.PrivateKey:
		return k.PublicKey().Parameters().String() + " Private Key"
	}
	return errString(errors.New("unsupported keytype"))
}

// curveName ...
func curveName(in ecdh.Curve) string {
	switch in {
	case ecdh.X25519():
		return "X25519"
	case ecdh.P256():
		return "NIST P-256"
	case ecdh.P384():
		return "NIST P-384"
	case ecdh.P521():
		return "NIST P-521"
	}
	return "unknown curve"
}

//
// SSH KEY ASCII REP
//

// dbapo ...
type dbapo struct{ Y, X int }

// getDBAA ...
func getDBAA(in string) (out string) {
	const sep = "+-----------------+\n"
	var bp []string
	for _, b := range []byte(in) {
		bb := fmt.Sprintf("%08b", b)
		bp = append(bp, bb[6:8], bb[4:6], bb[2:4], bb[0:2])
	}
	p := dbapo{4, 8}
	var r [9][17]int
	for _, bi := range bp {
		switch bi {
		case "00":
			p.Y--
			p.X--
		case "01":
			p.Y--
			p.X++
		case "10":
			p.Y++
			p.X--
		case "11":
			p.Y++
			p.X++
		}
		switch {
		case p.Y < 0:
			p.Y = 0
		case p.Y >= 9:
			p.Y = 9 - 1
		}
		switch {
		case p.X < 0:
			p.X = 0
		case p.X >= 17:
			p.X = 17 - 1
		}
		r[p.Y][p.X]++
	}
	r[4][8] = 1000
	r[p.Y][p.X] = 2000
	out += sep
	for _, ro := range r {
		var l []byte
		for _, co := range ro {
			c := byte('|')
			switch {
			case co == 1000:
				c = 'S'
			case co == 2000:
				c = 'E'
			case co < 15:
				c = " .o+=*BOX@%&#/^"[co]
			}
			l = append(l, c)
		}
		out += "|" + string(l) + "|\n"
	}
	return out + sep
}
