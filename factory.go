package jwt

type Factory struct {
	algorithm Algorithm
	jwk       *JWK
}

func NewFactory(alg Algorithm, jwk *JWK) (*Factory, error) {
	if err := CheckAlgorithm(alg); err != nil {
		return nil, err
	}

	if alg == AlgNone && jwk != nil {
		return nil, errAlgNoneWithKey
	}

	return &Factory{algorithm: alg, jwk: jwk}, nil
}

func (f *Factory) New(claims Claimer) (*jsonWebToken, error) {
	return &jsonWebToken{
		claims:  claims,
		factory: f,
	}, nil
}
