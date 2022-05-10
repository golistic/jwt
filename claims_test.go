package jwt

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/geertjanvdk/xkit/xt"
)

type MyClaims struct {
	RegisteredClaims
	OK     bool     `json:"ok,omitempty"`
	Labels []string `json:"labels,omitempty"`
}

func NewMyClaims() *MyClaims {
	reg, _ := NewRegisteredClaims()
	return &MyClaims{
		RegisteredClaims: *reg,
	}
}

func TestClaims_Marshall(t *testing.T) {
	expIssuedAt := time.Date(2022, 1, 9, 13, 44, 27, 0, time.UTC)
	expNotBefore := time.Date(2022, 1, 9, 14, 44, 27, 0, time.UTC)
	expExpirationTime := time.Date(2022, 1, 9, 16, 44, 27, 0, time.UTC)

	t.Run("basic", func(t *testing.T) {
		doc := `{"iss":"alice", "exp":1641746667, "ok":true}`

		claims := &MyClaims{}
		xt.OK(t, json.Unmarshal([]byte(doc), claims))
		xt.Eq(t, "alice", claims.Issuer)
		xt.Assert(t, expExpirationTime.Equal(claims.ExpiresAt.Time))
		xt.Eq(t, true, claims.OK)
	})

	t.Run("time stamps", func(t *testing.T) {
		doc := `{"iat": 1641735867, "exp": 1641746667, "nbf": 1641739467}`
		claims := NewMyClaims()

		xt.OK(t, json.Unmarshal([]byte(doc), claims))
		xt.Assert(t, expIssuedAt.Equal(claims.IssuedAt.Time))
		xt.Assert(t, expNotBefore.Equal(claims.NotBefore.Time))
		xt.Assert(t, expExpirationTime.Equal(claims.ExpiresAt.Time))
	})
}

func TestClaims_MarshalJSON(t *testing.T) {
	expIssuedAt := NewNumericDate(2022, 1, 9, 13, 44, 27)
	expNotBefore := NewNumericDate(2022, 1, 9, 14, 44, 27)
	expExpirationTime := NewNumericDate(2022, 1, 9, 16, 44, 27)

	t.Run("basic", func(t *testing.T) {
		expClaims := MyClaims{
			RegisteredClaims: RegisteredClaims{
				Issuer:    "alice",
				Subject:   "1234",
				Audience:  StringOrSlice{"world"},
				ExpiresAt: expExpirationTime,
				NotBefore: expNotBefore,
				IssuedAt:  expIssuedAt,
				JWTID:     "xaXaop",
			},
			OK:     true,
			Labels: []string{"tests", "private"},
		}

		data, err := json.Marshal(expClaims)
		xt.OK(t, err)
		haveClaims := NewMyClaims()
		xt.OK(t, err)
		xt.OK(t, json.Unmarshal(data, haveClaims))
		xt.Assert(t, reflect.DeepEqual(expClaims, *haveClaims))
	})
}
