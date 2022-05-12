package jwt

type Factory struct {
	algorithm Algorithm
}

func NewFactory(alg Algorithm) (*Factory, error) {
	if err := CheckAlgorithm(alg); err != nil {
		return nil, err
	}
	return &Factory{algorithm: alg}, nil
}

func (f *Factory) New(claims Claimer) (*jsonWebToken, error) {
	return &jsonWebToken{
		algorithm: AlgNone,
		claims:    claims,
	}, nil
}
