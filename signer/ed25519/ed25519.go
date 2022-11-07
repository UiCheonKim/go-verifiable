package ed25519

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"github.com/UiCheonKim/go-verifiable/signer"
)

var ED25519 *Ed25519

func init () {
	ED25519 = &Ed25519{}
}

var _ signer.Signer = &Ed25519{}

type Ed25519 struct {}

const (
	name      = "ED25519"
	proofType = "Ed25519Signature2018"
)

func (s *Ed25519) Name() string {
	return name
}

func (s *Ed25519) Type() string {
	return proofType
}

func (s *Ed25519) Sign(msg []byte, key interface{}) ([]byte, error) {
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
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return false
	}

	return ed25519.Verify(publicKey, msg, signature)
}
