package jwt

import (
	"testing"

	"github.com/geertjanvdk/xkit/xt"
)

func TestJWT_Encode(t *testing.T) {
	t.Run("unsecured", func(t *testing.T) {
		exp := "eyJhbGciOiJub25lIn0.eyJpc3MiOiJhbGljZSIsInN1YiI6ImJvYiJ9"

		j := &jsonWebToken{
			algorithm: "none",
			claims: &RegisteredClaims{
				Issuer:  "alice",
				Subject: "bob",
			},
		}

		encoded, err := j.Encode()
		xt.OK(t, err)
		xt.Eq(t, exp, encoded)
	})

}
