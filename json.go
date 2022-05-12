package jwt

import (
	"encoding/json"
	"fmt"
	"reflect"
)

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

	return json.Marshal([]string(s))
}

func anyToStrings(values any) ([]string, error) {
	var anys []any
	switch v := values.(type) {
	case []any:
		anys = v
	case []string:
		return v, nil
	default:
		panic(fmt.Errorf("unsupported type %T", values))
	}

	res := make([]string, len(anys))
	for i, r := range anys {
		var ok bool
		if res[i], ok = r.(string); !ok {
			return nil, fmt.Errorf("element %d is not a string", i)
		}
	}
	return res, nil
}
