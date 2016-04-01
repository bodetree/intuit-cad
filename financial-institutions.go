package intuit

import (
	"encoding/json"
	"fmt"
)

type institutionKeys []InstitutionKey

type _institutionKeys struct {
	Key []InstitutionKey `json:"Key"`
}

func (l *institutionKeys) UnmarshalJSON(data []byte) error {
	var intermediate _institutionKeys
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

	Keys institutionKeys `json:"keys"`
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
