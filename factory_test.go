package jwt

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/golistic/xt"
)

func TestFactory_New(t *testing.T) {
	t.Run("unsecured", func(t *testing.T) {
		exp := "eyJhbGciOiJub25lIn0.eyJpc3MiOiJhbGljZSIsImxhYmVscyI6WyJsYWJlbDEiLCJsYWJlbDIiXX0"

		factory, err := NewFactory(AlgNone, nil, nil)
		xt.OK(t, err)

		j, err := factory.New(&MyClaims{
			RegisteredClaims: RegisteredClaims{Issuer: "alice"},
			Labels:           []string{"label1", "label2"},
		})
		xt.OK(t, err)

		encoded, err := j.Encode()
		xt.Eq(t, exp, encoded)
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		_, err := NewFactory("foo", nil, nil)
		xt.KO(t, err)
	})

	t.Run("signing", func(t *testing.T) {
		var cases = []struct {
			alg Algorithm
			jwk *JWK
			exp string
		}{
			{
				alg: AlgHS256,
				jwk: JWKeyHMAC("mysupersecret"),
				exp: "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJhbGljZSIsImxhYmVscyI6WyJsYWJlbDEiLCJsYWJlbDIiXX0.4JS0xGv_Y7b8s2pUbhXOTZUQuDCMkndL4OcQf_VCKUs",
			},
			{
				alg: AlgHS384,
				jwk: JWKeyHMAC("mysupersecret"),
				exp: "eyJhbGciOiJIUzM4NCJ9.eyJpc3MiOiJhbGljZSIsImxhYmVscyI6WyJsYWJlbDEiLCJsYWJlbDIiXX0.3RMTL_dPZNXQN1KMkAAe3EK6ihGA7qjEKgLRgFFrH_or71h2PlNQbPkXjq3vsbpE",
			},
			{
				alg: AlgHS512,
				jwk: JWKeyHMAC("mysupersecret"),
				exp: "eyJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJhbGljZSIsImxhYmVscyI6WyJsYWJlbDEiLCJsYWJlbDIiXX0.CFiczPbbONEQ-X7i2FF7NtZtpzKVjaTRhdqvqEY7Q8DPszUWMrm3KwfVtOPUla2-FoM05N5vNmJr0r1_JpS0Bw",
			},
		}

		claims := &MyClaims{
			RegisteredClaims: RegisteredClaims{Issuer: "alice"},
			Labels:           []string{"label1", "label2"},
		}

		for _, c := range cases {
			t.Run("JWS using "+string(c.alg), func(t *testing.T) {
				factory, err := NewFactory(c.alg, c.jwk, &MyClaims{})
				xt.OK(t, err)

				j, err := factory.New(claims)
				xt.OK(t, err)

				encoded, err := j.Encode()
				xt.Eq(t, c.exp, encoded)

				vj, err := factory.Decode(encoded)
				xt.OK(t, err)
				xt.Assert(t, reflect.DeepEqual(j.header, vj.header))
				xt.Assert(t, reflect.DeepEqual(claims, vj.claims))
			})
		}
	})

	t.Run("algorithm cannot be AlgNone if key is supplied", func(t *testing.T) {
		_, err := NewFactory(AlgNone, JWKeyHMAC("mysupersecret"), nil)
		xt.KO(t, err)
		xt.Assert(t, errors.Is(err, errAlgNoneWithKey))
	})

	t.Run("forged tokens fail verification", func(t *testing.T) {
		factory, err := NewFactory(AlgHS256, JWKeyHMAC("mysupersecret"), &MyClaims{})
		xt.OK(t, err)

		j, err := factory.New(&MyClaims{
			RegisteredClaims: RegisteredClaims{Subject: "trudy"},
			OK:               false,
			Labels:           nil,
		})
		xt.OK(t, err)

		original, err := j.Encode()
		xt.OK(t, err)
		origParts := strings.Split(original, ".")

		data, err := decodePart(origParts[1])
		xt.OK(t, err)
		forgedClaims := &MyClaims{}
		xt.OK(t, json.Unmarshal(data, forgedClaims))

		forgedClaims.Labels = []string{"admin"}
		data, err = json.Marshal(forgedClaims)
		xt.OK(t, err)

		_, err = factory.Decode(origParts[0] + "." + encodePart(data) + "." + origParts[2])
		xt.KO(t, err)
		xt.Eq(t, ErrVerifyFail, err)
	})
}

func TestFactory_Verify(t *testing.T) {
	t.Run("algorithm in header does not match factory", func(t *testing.T) {
		factory, err := NewFactory(AlgHS256, nil, nil)
		xt.OK(t, err)

		_, err = factory.Verify("eyJhbGciOiJub25lIn0.eyJpc3MiOiJhbGljZSIsImxhYmVscyI6WyJsYWJlbDEiLCJsYWJlbDIiXX0")
		xt.KO(t, err)
	})
}
