package erdle

import (
	"errors"
	"fmt"
)

var ErrMagic = errors.New("cadu: invalid magic")

type MissingCaduError struct {
	From, To uint32
}

func (e MissingCaduError) Error() string {
	return fmt.Sprintf("%d missing cadus (%d - %d)", ((e.To-e.From)&0xFFFFFF)-1, e.From, e.To)
}

type CRCError struct {
	Want, Got uint16
}

func (c CRCError) Error() string {
	return fmt.Sprintf("invalid crc: want %04x, got %04x", c.Want, c.Got)
}

func IsMissingCadu(err error) (int, bool) {
	e, ok := err.(MissingCaduError)
	return int((e.To - e.From) & 0xFFFFFF), ok
}

func IsCRCError(err error) bool {
	_, ok := err.(CRCError)
	return ok
}

func IsCaduError(err error) bool {
	_, ok := IsMissingCadu(err)
	return ok || IsCRCError(err) || err == ErrMagic
}
