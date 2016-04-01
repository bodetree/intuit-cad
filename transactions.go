package intuit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TransactionList is a map of transaction types to a slice of transactions
type TransactionList map[string][]Transaction

// UnmarshalJSON implements the json Unmarshaler interface. It will inspect all
// of the top-level JSON object keys in the object. If a key ends with "Transactions"
// (e.g. bankingTransactions), the key will be included in the TransactionList and
// its value will be unmarshaled into a []Transaction
//
// TODO: this payload can contain an error key. Providing this back to the user
// (without returning an error from UnmarshalJSON) will likely require breaking
// changes to the TransactionList type.
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

// Transaction represents an individual transaction in a financial institution
// account.
type Transaction struct {
	ID                       int64               `json:"id"`
	InstitutionTransactionID string              `json:"institutionTransactionId"`
	UserDate                 unixTimestampMillis `json:"userDate"`
	PostedDate               unixTimestampMillis `json:"postedDate"`
	CurrencyType             string              `json:"currencyType"`
	PayeeName                string              `json:"payeeName"`
	Amount                   float64             `json:"amount"`
	Pending                  bool                `json:"pending"`

	Categorization struct {
		Common struct {
			NormalizedPayeeName string `json:"normalizedPayeeName"`
		} `json:"common"`

		Context []struct {
			Source       string `json:"source"`
			CategoryName string `json:"categoryName"`
			ScheduleC    string `json:"scheduleC"`
		} `json:"context"`
	} `json:"categorization"`
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

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CAD API returned status code %d", resp.StatusCode)
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
