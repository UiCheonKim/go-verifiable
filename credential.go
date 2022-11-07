package verifiable

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/UiCheonKim/go-verifiable/signer"
	"time"
)

const (
	VcContext      = "https://www.w3.org/2018/credentials/v1"
	ItsmeVcContext = "https://itsme.id/2020/credentials/v1"
	VcType         = "VerifiableCredential"
	VpType         = "VerifiablePresentation"
)

type Credential struct {
	Context           []string               `json:"@context"`
	Id                string                 `json:"id"`
	Type              []string               `json:"type"`
	Issuer            string                 `json:"issuer"`
	IssuanceDate      time.Time              `json:"issuanceDate"`
	ExpirationDate    time.Time              `json:"expirationDate"`
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
	Proof             *Proof                 `json:"proof"`
}

type Proof struct {
	Type               string    `json:"type"`
	Created            time.Time `json:"created"`
	ProofPurpose       string    `json:"proofPurpose"`
	VerificationMethod string    `json:"verificationMethod"`
	Jws                string    `json:"jws"`
}

const credentialIdFormat = "https://itsme.id/credentials/%s"

func generateBaseVc() *Credential {
	cred := &Credential{
		Context:      []string{VcContext, ItsmeVcContext},
		Type:         []string{VcType},
		IssuanceDate: time.Now(),
	}

	return cred
}

func newVcProof(signer signer.Signer, issuerKeyID string, privateKey interface{}, data []byte) (*Proof, error) {
	sig, err := signer.Sign(data, privateKey)
	if err != nil {
		return nil, err
	}
	proof := &Proof{
		Type:               signer.Type(),
		Created:            time.Now(),
		ProofPurpose:       "assertionMethod",
		VerificationMethod: issuerKeyID,
		Jws:                base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sig),
	}

	return proof, nil
}

func NewCredential() {

}

func NewSingleClaimCredential(signer signer.Signer, privateKey interface{}, holderDID, issuerKeyId, issuerName, credType, credId, keyName string, value interface{}, expiresAt time.Time) (*Credential, error) {
	vc := generateBaseVc()
	vc.Id = fmt.Sprintf(credentialIdFormat, credId)
	vc.Type = append(vc.Type, credType)
	vc.Issuer = issuerName
	vc.ExpirationDate = expiresAt

	cred := make(map[string]interface{})
	cred["id"] = holderDID
	cred[keyName] = value

	vc.CredentialSubject = cred

	data, err := json.Marshal(vc)
	if err != nil {
		return nil, err
	}

	proof, err := newVcProof(signer, issuerKeyId, privateKey, data)
	if err != nil {
		return nil, err
	}

	vc.Proof = proof

	return vc, nil
}
