package erdle

import (
	"errors"
	"fmt"
)

var ErrSkip = errors.New("skip")

var (
	Word  = []byte{0xf8, 0x2e, 0x35, 0x53}
	Stuff = []byte{0xf8, 0x2e, 0x35, 0xaa}
)

type MissingCaduError struct {
	From, To uint32
}

func (e MissingCaduError) Error() string {
	return fmt.Sprintf("%d missing cadus (%d - %d)", ((e.To-e.From)&caduCounterMask)-1, e.From, e.To)
}

type LengthError struct {
	Want int
	Got  int
}

func (e LengthError) Error() string {
	return fmt.Sprintf("invalid length: want %d, got %d", e.Want, e.Got)
}

type ChecksumError struct {
	Want uint32
	Got  uint32
}

func (e ChecksumError) Error() string {
	return fmt.Sprintf("invalid checksum: want %04x, got %04x", e.Want, e.Got)
}

func IsInvalidLength(err error) bool {
	_, ok := err.(LengthError)
	return ok
}

func IsMissingCadu(err error) bool {
	_, ok := err.(MissingCaduError)
	return ok
}

func IsInvalidSum(err error) bool {
	_, ok := err.(ChecksumError)
	return ok
}

func IsErdleError(err error) bool {
	if err == nil {
		return false
	}
	if err == ErrFull {
		return true
	}
	switch err.(type) {
	default:
		return false
	case LengthError, ChecksumError, MissingCaduError:
		return true
	}
}
