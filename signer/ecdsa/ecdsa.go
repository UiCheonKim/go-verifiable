package ecdsa

import (
	"fmt"
	"crypto"
	ec "crypto/ecdsa"
	"crypto/rand"
	"errors"
	"github.com/UiCheonKim/go-verifiable/signer"
	"log"
	"math/big"
)

type ECDSA struct {
	Hash      crypto.Hash
	AlgName   string
	ProofType string
}

var (
	ES256 *ECDSA
	ES384 *ECDSA
	ES512 *ECDSA
)

var _ signer.Signer = &ECDSA{}

func init() {
	fmt.Println("signer-ecdsa-ecdsa-init")
	ES256 = &ECDSA{Hash: crypto.SHA256, AlgName: "ES256", ProofType: "EcdsaSecp256r1Signature2019"}
	ES384 = &ECDSA{Hash: crypto.SHA384, AlgName: "ES384", ProofType: "EcdsaSecp384r1Signature2019"}
	ES512 = &ECDSA{Hash: crypto.SHA512, AlgName: "ES512", ProofType: "EcdsaSecp521r1Signature2019"}
}

func (e *ECDSA) Name() string {
	fmt.Println("signer-ecdsa-ecdsa-Name")
	return e.AlgName
}

func (e *ECDSA) Type() string {
	fmt.Println("signer-ecdsa-ecdsa-Type")
	return e.ProofType
}

func (e *ECDSA) Sign(msg []byte, key interface{}) ([]byte, error) {
	fmt.Println("signer-ecdsa-ecdsa-Sign")
	privateKey, ok := key.(*ec.PrivateKey)
	if !ok {
		return nil, errors.New("not ecdsa private key")
	}

	if !e.Hash.Available() {
		return nil, errors.New("need to import crypto/sha256 or sha512")
	}

	hasher := e.Hash.New()
	hasher.Write(msg)

	r, s, err := ec.Sign(rand.Reader, privateKey, hasher.Sum(nil))
	if err != nil {
		return nil, err
	}

	curveBits := privateKey.Curve.Params().BitSize

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes += 1
	}

	rBytes := r.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	out := append(rBytesPadded, sBytesPadded...)

	return out, nil
}

func (e *ECDSA) Verify(msg []byte, signature []byte, key interface{}) bool {
	fmt.Println("signer-ecdsa-ecdsa-Verify")
	publicKey, ok := key.(*ec.PublicKey)
	if !ok {
		return false
	}

	curveBits := publicKey.Curve.Params().BitSize

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes += 1
	}

	if len(signature) != 2*keyBytes {
		return false
	}

	r := big.NewInt(0).SetBytes(signature[:keyBytes])
	s := big.NewInt(0).SetBytes(signature[keyBytes:])

	if !e.Hash.Available() {
		log.Println("need to import crypto/sha256 or sha512")
		return false
	}

	hasher := e.Hash.New()
	hasher.Write(msg)

	return ec.Verify(publicKey, hasher.Sum(nil), r, s)
}
