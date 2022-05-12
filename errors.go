package jwt

import (
	"errors"
	"fmt"
)

type ErrEncoding struct {
	Part string
	Err  error
}

func (e *ErrEncoding) Error() string {
	return fmt.Sprintf("failed encoding %s (%s)", e.Part, e.Err)
}

type ErrAlgorithmNotSupported struct {
	Algorithm string
}

func (e *ErrAlgorithmNotSupported) Error() string {
	return fmt.Sprintf("algorithm '%s' is not supported", e.Algorithm)
}

type ErrDecoding struct {
	Part string
	Err  error
}

func (e *ErrDecoding) Error() string {
	return fmt.Sprintf("failed decoding %s (%s)", e.Part, e.Err)
}

var (
	errNotEnoughParts = errors.New("not enough encoded parts")
	errTooManyParts   = errors.New("too many encoded parts")
)
