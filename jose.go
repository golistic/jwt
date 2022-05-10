package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

type Algorithm string

const (
	AlgorithmNone  Algorithm = "none"
	AlgorithmHS256 Algorithm = "HS256"
	AlgorithmRS256 Algorithm = "RS256"
)

const (
	JOSETypeJWT = "JWT"
)

// JOSEHeader defines a JOSE (JSON Object Singing and Encryption) header
// specified in RFC 7515.
type JOSEHeader struct {
	Algorithm   Algorithm `json:"alg,omitempty"`
	Type        string    `json:"typ,omitempty"`
	ContentType string    `json:"cty,omitempty"`
	KeyID       string    `json:"kid,omitempty"`
}

func (jh JOSEHeader) Encode() (string, error) {
	data, err := json.Marshal(jh)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(base64.StdEncoding.EncodeToString(data), "="), nil
}
