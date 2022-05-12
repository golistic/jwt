package jwt

import (
	"testing"

	"github.com/geertjanvdk/xkit/xt"
)

func TestFactory_New(t *testing.T) {
	t.Run("unsecured", func(t *testing.T) {
		exp := "eyJhbGciOiJub25lIn0.eyJpc3MiOiJhbGljZSIsImxhYmVscyI6WyJsYWJlbDEiLCJsYWJlbDIiXX0"

		factory, err := NewFactory(AlgNone)
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
		_, err := NewFactory("foo")
		xt.KO(t, err)
	})
}
