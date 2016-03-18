package intuit

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kurrik/oauth1a"
)

// Intuit CAD API constants
const (
	AccessTokenEndpoint = "https://oauth.intuit.com/oauth/v1/get_access_token_by_saml"
	BaseURL             = "https://financialdatafeed.platform.intuit.com/v1"
)

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

// Client is an interface for accessing the Intuit CAD API
type Client struct {
	CustomerID string

	ConsumerKey    string
	ConsumerSecret string

	SAMLProviderID string
	PrivateKey     *rsa.PrivateKey

	HTTPClient *http.Client

	initialized bool

	clientConfig *oauth1a.ClientConfig
	userConfig   *oauth1a.UserConfig
	signer       oauth1a.Signer
}

// NewClient returns a client that uses the default settings. The client will be
// initialized automatically.
func NewClient(customerID string) (*Client, error) {
	client := &Client{
		CustomerID: customerID,

		ConsumerKey:    DefaultConsumerKey,
		ConsumerSecret: DefaultConsumerSecret,

		SAMLProviderID: DefaultSAMLProviderID,
		PrivateKey:     DefaultPrivateKey,

		HTTPClient: DefaultHTTPClient,
	}

	err := client.Init()
	if err != nil {
		return nil, err
	}

	return client, nil
}

// Init prepares the client for use by loading OAuth tokens from the Intuit API.
// It should be only be called once per client, and it should be called before
// any other method.
func (c *Client) Init() error {
	if c.initialized {
		return nil
	}

	c.clientConfig = &oauth1a.ClientConfig{
		ConsumerKey:    DefaultConsumerKey,
		ConsumerSecret: DefaultConsumerSecret,
	}

	c.signer = oauth1a.Signer(&oauth1a.HmacSha1Signer{})

	if err := c.loadOAuthUserConfig(); err != nil {
		return err
	}

	c.initialized = true

	return nil
}

func (c *Client) request(method, endpoint string, body interface{}) (*http.Request, error) {
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(bodyJSON)

	req, err := http.NewRequest(method, fmt.Sprintf("%s%s", BaseURL, endpoint), buf)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")

	return req, nil
}

func (c *Client) sign(req *http.Request) error {
	if err := c.Init(); err != nil {
		return err
	}

	return c.signer.Sign(req, c.clientConfig, c.userConfig)
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	if err := c.sign(req); err != nil {
		return nil, err
	}

	return c.HTTPClient.Do(req)
}

func (c *Client) url(path string) string {
	return fmt.Sprintf("%s%s", BaseURL, path)
}

func (c *Client) loadOAuthUserConfig() error {
	if c.CustomerID == "" {
		panic("customer id must not be empty")
	}

	assertion := NewAssertion(c.SAMLProviderID, c.CustomerID, time.Minute*10)
	if err := assertion.Sign(c.PrivateKey); err != nil {
		return fmt.Errorf("unable to sign assertion: %v", err)
	}

	samlString, err := xml.Marshal(assertion)
	if err != nil {
		return fmt.Errorf("unable to marshal assertion: %v", err)
	}

	values := make(url.Values)
	values.Set("saml_assertion", base64.URLEncoding.EncodeToString(samlString))
	values.Set("oauth_consumer_key", c.ConsumerKey)

	resp, err := http.PostForm(AccessTokenEndpoint, values)
	if err != nil {
		return fmt.Errorf("token request error: %s", err)
	}

	if resp.StatusCode != http.StatusOK {
		errmsg, _ := url.QueryUnescape(resp.Header.Get("Www-Authenticate"))
		return fmt.Errorf("authentication error: %s %s", resp.Status, errmsg)
	}

	body, _ := ioutil.ReadAll(resp.Body)
	respQuery, _ := url.ParseQuery(string(body))

	token, secret := respQuery.Get("oauth_token"), respQuery.Get("oauth_token_secret")
	c.userConfig = oauth1a.NewAuthorizedConfig(token, secret)

	return nil
}

type TransactionList map[string][]Transaction

func (t TransactionList) UnmarshalJSON(data []byte) error {
	var payload map[string]json.RawMessage

	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	for key, rawMessage := range payload {
		if !strings.HasSuffix(key, "Transactions") {
			continue
		}

		var txns []Transaction
		if err := json.Unmarshal(rawMessage, &txns); err != nil {
			return err
		}

		t[key] = txns
	}

	return nil
}

type Transaction struct {
	ID                       int64   `json:"id"`
	InstitutionTransactionID string  `json:"institutionTransactionId"`
	UserDate                 TxnTime `json:"userDate"`
	PostedDate               TxnTime `json:"postedDate"`
	CurrencyType             string  `json:"currencyType"`
	PayeeName                string  `json:"payeeName"`
	Amount                   float64 `json:"amount"`
	Pending                  bool    `json:"pending"`

	Context []TxnContext `json:"context"`
}

type TxnTime time.Time

func (t *TxnTime) UnmarshalJSON(strTime []byte) error {
	intTime, err := strconv.ParseInt(string(strTime), 10, 64)
	if err != nil {
		return err
	}

	*t = TxnTime(time.Unix(intTime/1000, 0))

	return nil
}

type TxnContext struct {
	Source       string `json:"source"`
	CategoryName string `json:"categoryName"`
	ScheduleC    string `json:"scheduleC"`
}

func (c *Client) AccountTransactions(accountID int64, startDate time.Time, endDate *time.Time) (TransactionList, error) {
	req, err := c.request("GET", fmt.Sprintf("/accounts/%d/transactions", accountID), nil)
	if err != nil {
		return nil, err
	}

	const dateFormat = "2006-01-02"
	query := url.Values{}
	query.Set("txnStartDate", startDate.Format(dateFormat))
	if endDate != nil {
		query.Set("txnEndDate", endDate.Format(dateFormat))
	}
	req.URL.RawQuery = query.Encode()

	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	decoder.UseNumber()

	payload := make(TransactionList)
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}

	return payload, nil
}

type InstitutionKeys []InstitutionKey

type institutionKeys struct {
	Key []InstitutionKey `json:"Key"`
}

func (l *InstitutionKeys) UnmarshalJSON(data []byte) error {
	var intermediate institutionKeys
	if err := json.Unmarshal(data, &intermediate); err != nil {
		return err
	}

	*l = intermediate.Key

	return nil
}

type InstitutionKey struct {
	Name          string `json:"name"`
	Value         string `json:"val"`
	Status        string `json:"status"`
	MinLength     int    `json:"valueLengthMin"`
	MaxLength     int    `json:"valueLengthMax"`
	DisplayToUser bool   `json:"displayFlag"`
	DisplayOrder  int    `json:"displayOrder"`
	MaskValue     bool   `json:"mask"`
	Instructions  string `json:"instructions"`
	Description   string `json:"description"`
}

type InstitutionDetails struct {
	ID           int64  `json:"institutionId"`
	Name         string `json:"institutionName"`
	HomeURL      string `json:"homeUrl"`
	PhoneNumber  string `json:"phoneNumber"`
	EmailAddress string `json:"emailAddress"`
	SpecialText  string `json:"specialText"`
	CurrencyCode string `json:"currencyCode"`
	Virtual      bool   `json:"virtual"`

	Address struct {
		AddressLine1 string `json:"address1"`
		AddressLine2 string `json:"address2"`
		AddressLine3 string `json:"address3"`
		City         string `json:"city"`
		State        string `json:"state"`
		PostalCode   string `json:"postalCode"`
		Country      string `json:"country"`
	} `json:"address"`

	Keys InstitutionKeys `json:"keys"`
}

func (c *Client) InstitutionDetails(institutionID int64) (*InstitutionDetails, error) {
	req, err := c.request("GET", fmt.Sprintf("/institutions/%d", institutionID), nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	decoder.UseNumber()

	var payload InstitutionDetails
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}

	return &payload, nil
}
