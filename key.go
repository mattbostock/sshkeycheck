package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/ssh"
)

type publicKey struct {
	key         ssh.PublicKey
	blacklisted bool
}

func (p *publicKey) BitLen() (int, error) {
	var (
		length int
		err    error
	)

	switch p.key.Type() {
	case ssh.KeyAlgoRSA:
		length, err = rsaKeyLength(p.key)
	case ssh.KeyAlgoDSA:
		length, err = dsaKeyLength(p.key)
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		length, err = ecdsaKeyLength(p.key)
	default:
		err = errors.New("Key type not supported: " + p.key.Type())
	}

	return length, err
}

func (p *publicKey) Fingerprint() string {
	return md5HexString(md5.Sum(p.key.Marshal()))
}

func rsaKeyLength(key ssh.PublicKey) (int, error) {
	var w struct {
		Name string
		E    *big.Int
		N    *big.Int
		Rest []byte `ssh:"rest"`
	}

	err := ssh.Unmarshal(key.Marshal(), &w)
	if err != nil {
		return 0, err
	}

	return w.N.BitLen(), nil
}

func dsaKeyLength(key ssh.PublicKey) (int, error) {
	var w struct {
		Name       string
		P, Q, G, Y *big.Int
		Rest       []byte `ssh:"rest"`
	}
	err := ssh.Unmarshal(key.Marshal(), &w)
	if err != nil {
		return 0, err
	}

	return w.P.BitLen(), nil
}

func ecdsaKeyLength(key ssh.PublicKey) (int, error) {
	var w struct {
		Name     string
		Curve    string
		KeyBytes []byte
		Rest     []byte `ssh:"rest"`
	}

	err := ssh.Unmarshal(key.Marshal(), &w)
	if err != nil {
		return 0, err
	}

	k := new(ecdsa.PublicKey)
	switch w.Curve {
	case "nistp256":
		k.Curve = elliptic.P256()
	case "nistp384":
		k.Curve = elliptic.P384()
	case "nistp521":
		k.Curve = elliptic.P521()
	default:
		return 0, fmt.Errorf("ECSDA curve not supported: %q", w.Curve)
	}

	k.X, k.Y = elliptic.Unmarshal(k.Curve, w.KeyBytes)
	if k.X == nil || k.Y == nil {
		return 0, fmt.Errorf("ECDSA X or Y points were nil: %q, %q", k.X, k.Y)
	}

	return k.Params().BitSize, nil
}

// md5HexString returns a formatted string representing the given md5 sum in hex
func md5HexString(md5 [16]byte) (s string) {
	s = fmt.Sprintf("% x", md5)
	s = strings.Replace(s, " ", ":", -1)
	return s
}
