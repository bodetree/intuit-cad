package intuit

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/kurrik/oauth1a"
)

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
// initialized automatically. Clients will be cached for 30 minutes using
// customerID as the key.
func NewClient(customerID string) (*Client, error) {
	clientsMu.Lock()
	defer clientsMu.Unlock()

	if client, ok := clients[customerID]; ok {
		return client, nil
	}

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

	clients[customerID] = client

	// spawn a new goroutine which will sleep for 30 minutes and then delete the
	// cached client (this process will re-acquire the lock)
	time.AfterFunc(time.Minute*30, func() {
		clientsMu.Lock()
		defer clientsMu.Unlock()

		delete(clients, customerID)
	})

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
		return errors.New("customer id must not be empty")
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
