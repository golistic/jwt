package jwt

import (
	"errors"
	"testing"

	"github.com/geertjanvdk/xkit/xt"
)

func TestFactory_New(t *testing.T) {
	t.Run("unsecured", func(t *testing.T) {
		exp := "eyJhbGciOiJub25lIn0.eyJpc3MiOiJhbGljZSIsImxhYmVscyI6WyJsYWJlbDEiLCJsYWJlbDIiXX0"

		factory, err := NewFactory(AlgNone, nil)
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
		_, err := NewFactory("foo", nil)
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
				factory, err := NewFactory(c.alg, c.jwk)
				xt.OK(t, err)

				j, err := factory.New(claims)
				xt.OK(t, err)

				encoded, err := j.Encode()
				xt.Eq(t, c.exp, encoded)
			})
		}
	})

	t.Run("algorithm cannot be AlgNone if key is supplied", func(t *testing.T) {
		_, err := NewFactory(AlgNone, JWKeyHMAC("mysupersecret"))
		xt.KO(t, err)
		xt.Assert(t, errors.Is(err, errAlgNoneWithKey))
	})
}
