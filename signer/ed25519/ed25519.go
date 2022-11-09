package ed25519

import (
	"fmt"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"github.com/UiCheonKim/go-verifiable/signer"
)

var ED25519 *Ed25519

func init () {
	fmt.Println("signer-ed25519-init")
	ED25519 = &Ed25519{}
}

var _ signer.Signer = &Ed25519{}

type Ed25519 struct {}

const (
	name      = "ED25519"
	proofType = "Ed25519Signature2018"
)

func (s *Ed25519) Name() string {
	fmt.Println("signer-ed25519-Name")
	return name
}

func (s *Ed25519) Type() string {
	fmt.Println("signer-ed25519-Type")
	return proofType
}

func (s *Ed25519) Sign(msg []byte, key interface{}) ([]byte, error) {
	fmt.Println("signer-ed25519-Sign")
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not ed25519 private key")
	}

	sign, err := privateKey.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		return nil, err
	}

	return sign, nil
}

func (s *Ed25519) Verify(msg []byte, signature []byte, key interface{}) bool {
	fmt.Println("signer-ed25519-Verify")
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return false
	}

	return ed25519.Verify(publicKey, msg, signature)
}
