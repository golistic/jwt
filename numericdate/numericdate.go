package numericdate

import (
	"encoding/json"
	"fmt"
	"time"
)

// NumericDate defines a JSON numeric value representing the number of seconds from
// 1970-01-01T00:00:00Z UTC (ignoring leap years).
type NumericDate struct {
	time.Time
}

func New(year int, month time.Month, day, hour, min, sec int) NumericDate {
	return NumericDate{
		Time: time.Date(year, month, day, hour, min, sec, 0, time.UTC),
	}
}

func NewNowDuration(d time.Duration) NumericDate {
	return NumericDate{
		Time: time.Now().UTC().Add(d),
	}
}

func (n *NumericDate) UnmarshalJSON(data []byte) error {
	var v float64
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("numeric date could not be unmarshalled (%s)", err)
	}

	n.Time = time.Unix(int64(v), 0).UTC()
	return nil
}

func (n NumericDate) MarshalJSON() ([]byte, error) {
	return json.Marshal(n.Time.Unix())
}
