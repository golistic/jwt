package jwt

import (
	"encoding/json"

	"github.com/golistic/jwt/numericdate"
)

type Claimer interface {
	Encode() (string, error)
}

// RegisteredClaims defines the registered JWT claims according to RFC7519, section 4.1.
// It also holds any public claims.
type RegisteredClaims struct {
	Issuer    string                   `json:"iss,omitempty"`
	Subject   string                   `json:"sub,omitempty"`
	Audience  StringOrSlice            `json:"aud,omitempty"`
	ExpiresAt *numericdate.NumericDate `json:"exp,omitempty"`
	NotBefore *numericdate.NumericDate `json:"nbf,omitempty"`
	IssuedAt  *numericdate.NumericDate `json:"iat,omitempty"`
	JWTID     string                   `json:"jti,omitempty"`
}

func NewRegisteredClaims() (*RegisteredClaims, error) {
	return &RegisteredClaims{}, nil
}

func (clms *RegisteredClaims) Encode() (string, error) {
	return EncodeClaims(clms)
}

func EncodeClaims(claims Claimer) (string, error) {
	data, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	return encodePart(data), nil
}
