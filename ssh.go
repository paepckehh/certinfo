package certinfo

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
)

func parseRawPrivateKey(in *pem.Block) string {
	if encryptedBlock(in) {
		return "Encrypted KEY [PEM BLOCK]"
	}
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

func getKey(pub any) string {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return "RSA Public Key [" + strconv.Itoa(pub.Size()) + "]"
	case *dsa.PublicKey:
		return "DSA Public Key"
	case *ecdsa.PublicKey:
		return "ECDSA Public Key"
	case ed25519.PublicKey:
		return "Ed255519 Public Key"
	}
	return errString(errors.New("unsupported keytype"))
}

type dbapo struct{ Y, X int }

func getDBAA(in string) (out string) {
	const sep = "+-----------------+\n"
	var bp []string
	for _, byte := range []byte(in) {
		bb := fmt.Sprintf("%08b", byte)
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
			var c byte = '|'
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
