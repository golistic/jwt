package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"hash"
	"strings"
)

type jsonWebToken struct {
	header  JOSEHeader
	claims  Claimer
	factory *Factory
}

func newFromEncoded(token string) (*jsonWebToken, error) {
	parts := strings.Split(token, ".")

	switch {
	case len(parts) < 2:
		return nil, &ErrDecoding{Part: "encoded token", Err: errNotEnoughParts}
	case len(parts) > 3:
		return nil, &ErrDecoding{Part: "encoded token", Err: errTooManyParts}
	}

	j := &jsonWebToken{}

	if err := j.decodeUnsecured(parts[0], parts[1]); err != nil {
		return nil, err
	}

	return j, nil
}

func (j *jsonWebToken) Encode() (string, error) {
	return j.encode(j.factory.algorithm, j.factory.jwk)
}

func (j *jsonWebToken) encode(alg Algorithm, key *JWK) (string, error) {
	header, err := JOSEHeader{
		Algorithm: alg,
	}.Encode()
	if err != nil {
		return "", &ErrEncoding{
			Segment: "header",
			Err:     err,
		}
	}

	payload, err := j.claims.Encode()
	if err != nil {
		return "", &ErrEncoding{
			Segment: "payload",
			Err:     err,
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

func (j *jsonWebToken) decodeUnsecured(encHeader, encPayload string) error {
	h, err := base64.RawURLEncoding.DecodeString(encHeader)
	if err != nil {
		return err
	}

	p, err := base64.RawURLEncoding.DecodeString(encPayload)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(h, &j.header); err != nil {
		return &ErrDecoding{Part: "header", Err: err}
	}

	if err := json.Unmarshal(p, &j.claims); err != nil {
		return &ErrDecoding{Part: "header", Err: err}
	}

	return nil
}

func (j *jsonWebToken) decodeSecured(token string) error {
	return nil
}

func (j jsonWebToken) hmacSign(alg Algorithm, key *JWK, toSign string) (string, error) {
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
	return encodeSegment(mac.Sum(nil)), nil
}

func encodeSegment(seg []byte) string {
	return base64.RawURLEncoding.EncodeToString(seg)
}
