package verifiable

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"github.com/UiCheonKim/go-verifiable/signer"
	"time"
)

const (
	VpContext      = "https://www.w3.org/2018/presentations/v1"
	ItsmeVpContext = "https://itsme.id/2020/presentations/v1"
)

type Presentation struct {
	Context              []string     `json:"@context"`
	Id                   string       `json:"id"`
	Type                 []string     `json:"type"`
	VerifiableCredential []Credential `json:"verifiableCredential"`
	Proof                *Proof       `json:"proof"`
}

func generateBaseVP() *Presentation {
	vp := &Presentation{
		Context: []string{VpContext, ItsmeVpContext},
		Type:    []string{VpType},
	}

	return vp
}

func newVpProof(signer signer.Signer, privateKey crypto.PrivateKey, issuerKeyId string, data []byte) (*Proof, error) {
	sig, err := signer.Sign(data, privateKey)
	if err != nil {
		return nil, err
	}
	proof := &Proof{
		Type:               signer.Type(),
		Created:            time.Now(),
		ProofPurpose:       "assertionMethod",
		VerificationMethod: issuerKeyId,
		Jws:                base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sig),
	}

	return proof, nil
}

func NewPresentation(signer signer.Signer, holderPrivateKey crypto.PrivateKey, holderDID, holderKeyId string, vcs []Credential) (*Presentation, error) {
	vp := generateBaseVP()

	vp.Id = holderDID
	vp.VerifiableCredential = vcs

	data, err := json.Marshal(vp)
	if err != nil {
		return nil, err
	}

	proof, err := newVpProof(signer, holderPrivateKey, holderKeyId, data)
	if err != nil {
		return nil, err
	}

	vp.Proof = proof

	return vp, nil
}
