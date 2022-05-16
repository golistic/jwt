package jwt

import "strings"

type Factory struct {
	algorithm Algorithm
	jwk       *JWK
	claimType Claimer
}

func NewFactory(alg Algorithm, jwk *JWK, claimType Claimer) (*Factory, error) {
	if err := CheckAlgorithm(alg); err != nil {
		return nil, err
	}

	if alg == AlgNone && jwk != nil {
		return nil, errAlgNoneWithKey
	}

	f := &Factory{
		algorithm: alg,
		jwk:       jwk,
	}

	if claimType == nil {
		f.claimType = &RegisteredClaims{}
	} else {
		f.claimType = claimType
	}

	return f, nil
}

func (f *Factory) New(claims Claimer) (*jsonWebToken, error) {
	return &jsonWebToken{
		claims:  claims,
		factory: f,
	}, nil
}

func (f *Factory) Verify(token string) (*jsonWebToken, error) {
	j, err := f.Decode(token)
	if err != nil {
		return nil, err
	}

	return j, nil
}

func (f *Factory) Decode(token string) (*jsonWebToken, error) {
	parts := strings.Split(token, ".")

	switch {
	case len(parts) < 2:
		return nil, &ErrDecoding{Part: "encoded token", Err: errNotEnoughParts}
	case len(parts) > 3:
		return nil, &ErrDecoding{Part: "encoded token", Err: errTooManyParts}
	}

	j := &jsonWebToken{
		factory: f,
	}

	if err := j.decodeParts(parts[0], parts[1]); err != nil {
		return nil, err
	}

	verifier, err := j.factory.New(j.claims)
	if err != nil {
		return nil, err
	}
	if vt, err := verifier.Encode(); err != nil {
		return nil, err
	} else if vt != token {
		return nil, ErrVerifyFail
	}

	return j, nil
}
