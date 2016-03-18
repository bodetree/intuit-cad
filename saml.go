package intuit

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/nu7hatch/gouuid"
)

// Constants for xmldsig
const (
	C14N      = "http://www.w3.org/2001/10/xml-exc-c14n#"
	RSASHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	XMLDSIGNS = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	SHA1      = "http://www.w3.org/2000/09/xmldsig#sha1"
)

// Constants for SAML 2.0
const (
	classUnspecified        = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
	nameIDFormatUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	bearerToken             = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
)

func samlRequestID() string {
	refID, err := uuid.NewV4()
	if err != nil {
		panic(err)
	}

	return fmt.Sprintf("_%s", strings.Replace(refID.String(), "-", "", -1))
}

// Assertion is a Go representation of a SAML 2.0 Assertion
type Assertion struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`

	RefID        string    `xml:"ID,attr"`
	IssueInstant time.Time `xml:"IssueInstant,attr"`
	Version      string    `xml:"Version,attr"`

	Issuer         string         `xml:"Issuer"`
	Signature      *signature     `xml:"http://www.w3.org/2000/09/xmldsig# Signature,omitempty"`
	Subject        subject        `xml:"Subject"`
	Conditions     conditions     `xml:"Conditions"`
	AuthnStatement authnStatement `xml:"AuthnStatement"`
}

// NewAssertion creates a new SAML assertion
func NewAssertion(issuer, customerID string, lifetime time.Duration) Assertion {
	now := time.Now()
	expiration := now.Add(lifetime)

	refID := samlRequestID()

	return Assertion{
		RefID:        refID,
		IssueInstant: now,
		Version:      "2.0",

		Issuer: issuer,

		Conditions: conditions{
			NotBefore:           now,
			NotOnOrAfter:        expiration,
			AudienceRestriction: issuer,
		},
		Subject: subject{
			NameID: nameID{
				Format: nameIDFormatUnspecified,
				Value:  customerID,
			},
			SubjectConfirmation: subjectConfirmation{bearerToken},
		},
		AuthnStatement: authnStatement{
			AuthnInstance: now,
			SessionIndex:  refID,
			Context:       authnContext{classUnspecified},
		},
	}
}

// Sign populates the assertion's xmldisg signature based on the assertion's
// current state.
func (a *Assertion) Sign(key *rsa.PrivateKey) error {
	assertionStr, err := xml.Marshal(a)
	if err != nil {
		return err
	}

	hash := sha1.New()
	hash.Write(assertionStr)

	si := signedInfo{
		CanonicalizationMethod: algorithm{C14N},
		SignatureMethod:        algorithm{RSASHA1},
		Reference: reference{
			URI:          fmt.Sprintf("#%s", a.RefID),
			Transforms:   []algorithm{{XMLDSIGNS}, {C14N}},
			DigestMethod: algorithm{SHA1},
			DigestValue:  base64.StdEncoding.EncodeToString(hash.Sum(nil)),
		},
	}

	sigStr, err := si.signatureValue(key)
	if err != nil {
		return err
	}

	signature := &signature{
		SignedInfo:     si,
		SignatureValue: sigStr,
	}

	a.Signature = signature

	return nil
}

type signedInfo struct {
	XMLName                xml.Name  `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
	CanonicalizationMethod algorithm `xml:"CanonicalizationMethod"`
	SignatureMethod        algorithm `xml:"SignatureMethod"`
	Reference              reference `xml:"Reference"`
}

func (si signedInfo) signatureValue(key *rsa.PrivateKey) (string, error) {
	signedInfoXML, err := xml.Marshal(si)
	if err != nil {
		return "", err
	}

	hash := sha1.New()
	hash.Write(signedInfoXML)
	digest := hash.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, digest)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

type signature struct {
	SignedInfo     signedInfo `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
	SignatureValue string     `xml:"SignatureValue"`
}

type algorithm struct {
	Algorithm string `xml:"Algorithm,attr"`
}

type authnContext struct {
	ClassRef string `xml:"AuthnContextClassRef"`
}

type authnStatement struct {
	AuthnInstance time.Time    `xml:"AuthnInstant,attr"`
	SessionIndex  string       `xml:"SessionIndex,attr"`
	Context       authnContext `xml:"AuthnContext"`
}

type conditions struct {
	NotBefore           time.Time `xml:"NotBefore,attr,omitempty"`
	NotOnOrAfter        time.Time `xml:"NotOnOrAfter,attr,omitempty"`
	AudienceRestriction string    `xml:"AudienceRestriction>Audience"`
}

type nameID struct {
	Format string `xml:"Format,attr"`
	Value  string `xml:",chardata"`
}

type subjectConfirmation struct {
	Method string `xml:"Method,attr"`
}

type subject struct {
	NameID              nameID              `xml:"NameID"`
	SubjectConfirmation subjectConfirmation `xml:"SubjectConfirmation"`
}

type reference struct {
	URI          string      `xml:"URI,attr"`
	Transforms   []algorithm `xml:"Transforms>Transform"`
	DigestMethod algorithm   `xml:"DigestMethod"`
	DigestValue  string      `xml:"DigestValue"`
}
