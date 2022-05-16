package jwt

import (
	"encoding/json"
)

type Algorithm string

const (
	AlgNone  Algorithm = "none"
	AlgHS256 Algorithm = "HS256"
	AlgHS384 Algorithm = "HS384"
	AlgHS512 Algorithm = "HS512"
	AlgRS256 Algorithm = "RS256"
)

var hmacAlgorithms = []Algorithm{AlgHS256, AlgHS384, AlgHS512}

var supportedAlgorithms = append([]Algorithm{AlgNone, AlgRS256}, hmacAlgorithms...)

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
	return encodePart(data), nil
}

func CheckAlgorithm(alg Algorithm) error {
	if !SliceHasString(supportedAlgorithms, alg) {
		return &ErrAlgorithmNotSupported{Algorithm: string(alg)}
	}
	return nil
}

func isHMACAlgorithm(alg Algorithm) bool {
	return SliceHasString(hmacAlgorithms, alg)
}

func SliceHasString[T ~string](haystack []T, needle T) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
