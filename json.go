package jwt

import (
	"encoding/json"
	"fmt"
	"reflect"
	"time"
)

// NumericDate defines a JSON numeric value representing the number of seconds from
// 1970-01-01T00:00:00Z UTC (ignoring leap years).
type NumericDate struct {
	time.Time
}

func NewNumericDate(year int, month time.Month, day, hour, min, sec int) NumericDate {
	return NumericDate{
		Time: time.Date(year, month, day, hour, min, sec, 0, time.UTC),
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

type StringOrSlice []string

func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
	var value any

	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}

	var res StringOrSlice

	switch v := value.(type) {
	case string:
		res = []string{v}
	case []interface{}:
		for _, vs := range v {
			s, ok := vs.(string)
			if !ok {
				return &json.UnsupportedTypeError{Type: reflect.TypeOf(vs)}
			}
			res = append(res, s)
		}
	case []string:
		res = v
	}

	*s = res
	return nil
}

func (s StringOrSlice) MarshalJSON() ([]byte, error) {
	if len(s) == 1 {
		return json.Marshal(s[0])
	}

	return json.Marshal(s)
}
