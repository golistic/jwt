package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/golistic/xt"

	"github.com/golistic/jwt/numericdate"
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

func (clms *MyClaims) Encode() (string, error) {
	return EncodeClaims(clms)
}

var (
	expIssuedAt       = numericdate.New(2022, 1, 9, 13, 44, 27)
	expNotBefore      = numericdate.New(2022, 1, 9, 14, 44, 27)
	expExpirationTime = numericdate.New(2022, 1, 9, 16, 44, 27)
)

func TestClaims_MarshalJSON(t *testing.T) {

	t.Run("basic", func(t *testing.T) {
		expClaims := MyClaims{
			RegisteredClaims: RegisteredClaims{
				Issuer:    "alice",
				Subject:   "1234",
				Audience:  StringOrSlice{"world"},
				ExpiresAt: &expExpirationTime,
				NotBefore: &expNotBefore,
				IssuedAt:  &expIssuedAt,
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

	t.Run("audience is array of strings", func(t *testing.T) {
		expClaims := RegisteredClaims{
			Audience: StringOrSlice{"world", "https://api.example.com"},
		}

		data, err := json.Marshal(expClaims)
		xt.OK(t, err)
		var have map[string]interface{}
		xt.OK(t, json.Unmarshal(data, &have))

		haveAudience, err := anyToStrings(have["aud"])
		xt.OK(t, err)
		xt.Eq(t, expClaims.Audience, StringOrSlice(haveAudience))

		haveClaims, err := NewRegisteredClaims()
		xt.OK(t, err)
		xt.OK(t, json.Unmarshal(data, haveClaims))
		xt.Eq(t, expClaims.Audience, haveClaims.Audience)
	})

	t.Run("audience is single string", func(t *testing.T) {
		expClaims := RegisteredClaims{
			Audience: StringOrSlice{"https://api.example.com"},
		}

		data, err := json.Marshal(expClaims)
		xt.OK(t, err)
		var have map[string]interface{}
		xt.OK(t, json.Unmarshal(data, &have))

		_, ok := have["aud"].(string)
		xt.Assert(t, ok, "expected aud to be string")

		haveClaims, err := NewRegisteredClaims()
		xt.OK(t, err)
		xt.OK(t, json.Unmarshal(data, haveClaims))
		xt.Eq(t, expClaims.Audience, haveClaims.Audience)
	})

	t.Run("numeric date fields are optional", func(t *testing.T) {
		claims := RegisteredClaims{
			Issuer: "no other claims set",
		}

		data, err := json.Marshal(claims)
		xt.OK(t, err)
		var doc map[string]interface{}
		xt.OK(t, json.Unmarshal(data, &doc))

		for _, name := range []string{"exp", "iat", "nbf"} {
			_, have := doc[name]
			xt.Assert(t, !have, fmt.Sprintf("expected %s not in claims payload", name))
		}
	})
}

func TestRegisteredClaims_Encode(t *testing.T) {
	t.Run("base64 encoded", func(t *testing.T) {
		var cases = []struct {
			exp string
			clm Claimer
		}{
			{
				exp: "eyJpc3MiOiJhbGljZSIsImV4cCI6MTY0MTc0NjY2N30",
				clm: &RegisteredClaims{
					Issuer:    "alice",
					ExpiresAt: &expExpirationTime,
				},
			},
			{
				exp: "eyJpc3MiOiJhbGljZSIsImF1ZCI6WyJhcGkiLCJleHRlcm5hbCJdLCJpYXQiOjE2NDE3MzU4Njd9",
				clm: &MyClaims{
					RegisteredClaims: RegisteredClaims{
						Issuer:   "alice",
						Audience: StringOrSlice{"api", "external"},
						IssuedAt: &expIssuedAt,
					},
				},
			},
		}

		for _, c := range cases {
			t.Run("", func(t *testing.T) {
				header, err := c.clm.Encode()
				xt.OK(t, err)
				xt.Eq(t, c.exp, header)

				decoded, err := base64.RawStdEncoding.DecodeString(c.exp)
				xt.OK(t, err)

				doc, err := json.Marshal(c.clm)
				xt.OK(t, err)

				xt.Eq(t, decoded, string(doc))
			})
		}

	})
}
