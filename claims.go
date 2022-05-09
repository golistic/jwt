package jwt

type PrivateClaimer interface {
	Equal(other PrivateClaimer) error
}

type Claim struct {
	Name     string
	Value    any
	Required bool
}

// RegisteredClaims defines the registered JWT claims according to RFC7519, section 4.1.
// It also holds any public claims.
type RegisteredClaims struct {
	Issuer         string      `json:"iss,omitempty"`
	Subject        string      `json:"sub,omitempty"`
	Audience       string      `json:"aud,omitempty"`
	ExpirationTime NumericDate `json:"exp,omitempty"`
	NotBefore      NumericDate `json:"nbf,omitempty"`
	IssuedAt       NumericDate `json:"iat,omitempty"`
	JWTID          string      `json:"jti,omitempty"`
}

func NewRegisteredClaims() (*RegisteredClaims, error) {
	return &RegisteredClaims{}, nil
}
