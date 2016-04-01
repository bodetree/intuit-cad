package intuit

import (
	"strconv"
	"time"
)

type unixTimestampMillis time.Time

func (t *unixTimestampMillis) UnmarshalJSON(strTime []byte) error {
	intTime, err := strconv.ParseInt(string(strTime), 10, 64)
	if err != nil {
		return err
	}

	*t = unixTimestampMillis(time.Unix(intTime/1000, 0))

	return nil
}
