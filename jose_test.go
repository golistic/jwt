package jwt

import (
	"testing"

	"github.com/geertjanvdk/xkit/xt"
)

func TestJOSEHeader_Encode(t *testing.T) {
	t.Run("base64 encoded", func(t *testing.T) {
		var cases = []struct {
			exp string
			jh  JOSEHeader
		}{
			{
				exp: "eyJhbGciOiJub25lIn0",
				jh: JOSEHeader{
					Algorithm: AlgorithmNone,
				},
			},
			{
				exp: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
				jh: JOSEHeader{
					Algorithm: AlgorithmHS256,
					Type:      JOSETypeJWT,
				},
			},
			{
				exp: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
				jh: JOSEHeader{
					Algorithm: AlgorithmRS256,
					Type:      JOSETypeJWT,
				},
			},
		}

		for _, c := range cases {
			t.Run("", func(t *testing.T) {
				header, err := c.jh.Encode()
				xt.OK(t, err)
				xt.Eq(t, c.exp, header)
			})
		}

	})
}
