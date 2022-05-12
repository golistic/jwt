package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

type jsonWebToken struct {
	algorithm Algorithm
	header    JOSEHeader
	claims    Claimer
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
	header, err := JOSEHeader{
		Algorithm: AlgNone,
	}.Encode()
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

	switch j.algorithm {
	case AlgNone:
		return header + "." + payload, nil
	default:
		return "", &ErrAlgorithmNotSupported{Algorithm: string(j.algorithm)}
	}
}

func (j *jsonWebToken) decodeUnsecured(encHeader, encPayload string) error {
	h, err := base64.RawStdEncoding.DecodeString(encHeader)
	if err != nil {
		return err
	}

	p, err := base64.RawStdEncoding.DecodeString(encPayload)
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
