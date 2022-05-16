package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"hash"
	"reflect"
)

type jsonWebToken struct {
	header  *JOSEHeader
	claims  Claimer
	factory *Factory
}

func (j *jsonWebToken) Encode() (string, error) {
	return j.encode(j.factory.algorithm, j.factory.jwk)
}

func (j *jsonWebToken) encode(alg Algorithm, key *JWK) (string, error) {
	j.header = &JOSEHeader{
		Algorithm: alg,
	}
	header, err := j.header.Encode()
	if err != nil {
		return "", &ErrEncoding{
			Part: "header",
			Err:  err,
		}
	}

	payload, err := j.claims.Encode()
	if err != nil {
		return "", &ErrEncoding{
			Part: "payload",
			Err:  err,
		}
	}

	switch {
	case alg == AlgNone:
		return header + "." + payload, nil
	case isHMACAlgorithm(alg):
		hp := header + "." + payload
		if signature, err := j.hmacSign(alg, key, hp); err != nil {
			return "", err
		} else {
			return hp + "." + signature, nil
		}
	default:
		return "", &ErrAlgorithmNotSupported{Algorithm: string(alg)}
	}
}

func (j *jsonWebToken) decodeParts(encHeader, encPayload string) error {
	h, err := base64.RawURLEncoding.DecodeString(encHeader)
	if err != nil {
		return err
	}

	p, err := base64.RawURLEncoding.DecodeString(encPayload)
	if err != nil {
		return err
	}

	if j.header == nil {
		j.header = &JOSEHeader{}
	}

	if err := json.Unmarshal(h, &j.header); err != nil {
		return &ErrDecoding{Part: "header", Err: err}
	}

	if j.claims == nil {
		j.claims = reflect.New(reflect.TypeOf(j.factory.claimType).Elem()).Interface().(Claimer)
	}

	if err := json.Unmarshal(p, &j.claims); err != nil {
		return &ErrDecoding{Part: "claims", Err: err}
	}

	return nil
}

func (j jsonWebToken) hmacSign(alg Algorithm, key *JWK, toSign string) (string, error) {
	if key == nil {
		return "", errAlgRequiresKey
	}
	var hf func() hash.Hash
	switch j.factory.algorithm {
	case AlgHS256:
		hf = sha256.New
	case AlgHS384:
		hf = sha512.New384
	case AlgHS512:
		hf = sha512.New
	default:
		return "", &ErrAlgorithmNotSupported{Algorithm: string(alg)}
	}

	mac := hmac.New(hf, key.key)
	mac.Write([]byte(toSign))
	return encodePart(mac.Sum(nil)), nil
}

func encodePart(p []byte) string {
	return base64.RawURLEncoding.EncodeToString(p)
}

func decodePart[T []byte | ~string](p T) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(string(p))
}
