package intuit

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Constants representing account status
const (
	AccountStatusActive   = "ACTIVE"
	AccountStatusInactive = "INACTIVE"
)

// Constants representing aggregation status codes.
// See https://developer.intuit.com/docs/0020_customeraccountdata/0000_api/0700_error_codes#/Error_Code_and_Messages_with_Resolution
const (
	AggrStatusOK                        string = "0"
	AggrStatusUnknown                          = "100"
	AggrStatusGeneralError                     = "101"
	AggrStatusAggrError                        = "102"
	AggrStatusLoginError                       = "103"
	AggrStatusJSONParsingError                 = "104"
	AggrStatusUnavailable                      = "105"
	AggrStatusAccountMismatch                  = "106"
	AggrStatusEndUserActionRequired            = "108"
	AggrStatusPasswordChangeRequired           = "109"
	AggrStatusFinancialInstitutionError        = "155"
	AggrStatusApplicationError                 = "163"
	AggrStatusMultipleLogins                   = "179"
	AggrStatusMFARequired                      = "185"
	AggrStatusIncorrectMFAAnswer               = "187"
	AggrStatusInvalidPersonalAccessCode        = "199"
	AggrStatusDuplicateAccount                 = "323"
	AggrStatusAccountNumberChanged             = "324"
)

type accountList struct {
	Accounts []Account `json:"accounts"`
}

// Account is an account at a financial institution
type Account struct {
	ID                     int64               `json:"accountId"`
	LoginID                int64               `json:"institutionLoginId"`
	Name                   string              `json:"accountNickname"`
	Balance                float64             `json:"balanceAmount"`
	BalanceDate            unixTimestampMillis `json:"balanceDate"`
	Status                 string              `json:"status"`
	AggrSuccessDate        unixTimestampMillis `json:"aggrSuccessDate"`
	AggrAttemptDate        unixTimestampMillis `json:"aggrAttemptDate"`
	AggrStatusCode         string              `json:"aggrStatusCode"`
	Currency               string              `json:"currencyCode"`
	FinancialInstitutionID int64               `json:"institutionId"`
}

// IsActive returns true if the account status is active
func (a Account) IsActive() bool {
	return a.Status == AccountStatusActive
}

// GetCustomerAccounts returns all accounts for a customer across all of their
// logins
func (c *Client) GetCustomerAccounts() ([]Account, error) {
	req, err := c.request("GET", "/accounts", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CAD API returned status code %d", resp.StatusCode)
	}

	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	decoder.UseNumber()

	payload := accountList{}
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}

	return payload.Accounts, nil
}

// GetLoginAccounts returns all accounts for a login
func (c *Client) GetLoginAccounts(loginID int64) ([]Account, error) {
	req, err := c.request("GET", fmt.Sprintf("/logins/%d/accounts", loginID), nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CAD API returned status code %d", resp.StatusCode)
	}

	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	decoder.UseNumber()

	payload := accountList{}
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}

	return payload.Accounts, nil
}
