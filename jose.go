package jwt

import (
	"encoding/base64"
	"encoding/json"
)

type Algorithm string

const (
	AlgNone  Algorithm = "none"
	AlgHS256 Algorithm = "HS256"
	AlgRS256 Algorithm = "RS256"
)

var supportedAlgorithms = []Algorithm{AlgNone, AlgHS256, AlgRS256}

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
	return base64.RawStdEncoding.EncodeToString(data), nil
}

func CheckAlgorithm(alg Algorithm) error {
	if !SliceHasString(supportedAlgorithms, alg) {
		return &ErrAlgorithmNotSupported{Algorithm: string(alg)}
	}
	return nil
}

func SliceHasString[T ~string](haystack []T, needle T) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
