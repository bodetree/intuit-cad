package intuit

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sync"
)

// Intuit CAD API constants
const (
	AccessTokenEndpoint = "https://oauth.intuit.com/oauth/v1/get_access_token_by_saml"
	BaseURL             = "https://financialdatafeed.platform.intuit.com/v1"
)

var clientsMu sync.Mutex
var clients = map[string]*Client{}

// Default values for clients
var (
	DefaultHTTPClient     = http.DefaultClient
	DefaultConsumerKey    = ""
	DefaultConsumerSecret = ""
	DefaultSAMLProviderID = ""
	DefaultPrivateKey     *rsa.PrivateKey
)

// SetDefaultCredentials sets default for clients from the given arguments
func SetDefaultCredentials(consumerKey, consumerSecret, samlProviderID string) {
	DefaultConsumerKey = consumerKey
	DefaultConsumerSecret = consumerSecret
	DefaultSAMLProviderID = samlProviderID
}

// SetDefaultPrivateKeyFromPEM decodes a PEM-encoded RSA key from `pemData` and
// stores it in DefaultPrivateKey. Panics if any part of the process fails
func SetDefaultPrivateKeyFromPEM(pemData io.Reader) error {
	pemBytes, err := ioutil.ReadAll(pemData)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		panic(errors.New("unable to read PEM data"))
	}

	DefaultPrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(fmt.Sprintf("bad private key: %v", err))
	}

	return nil
}
