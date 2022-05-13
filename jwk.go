package jwt

type JWKType string

const (
	JWKOct JWKType = "oct"
)

type JWK struct {
	KeyType JWKType
	key     []byte
}

func JWKeyHMAC(key string) *JWK {
	return &JWK{
		KeyType: JWKOct,
		key:     []byte(key),
	}
}
