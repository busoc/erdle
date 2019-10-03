package erdle

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	Word  = []byte{0xf8, 0x2e, 0x35, 0x53}
	Stuff = []byte{0xf8, 0x2e, 0x35, 0xaa}
	Magic = []byte{0x1a, 0xcf, 0xfc, 0x1d}
)

const (
	WordLen  = 4
	MagicLen = 4
)

const (
	CaduBodyLen      = 1008
	CaduLen          = 1024
	CaduHeaderLen    = 14
	CaduTrailerLen   = 2
	CaduTrailerIndex = CaduHeaderLen + CaduBodyLen
	CaduCounterMask  = 0xFFFFFF
	CaduCounterMax   = CaduCounterMask
)

func StuffBytes(bs []byte) []byte {
	offset := WordLen * 2

	xs := make([]byte, 0, len(bs))
	xs = append(xs, bs[:offset]...)
	for {
		if ix := bytes.Index(bs[offset:], Word); ix < 0 {
			break
		} else {
			xs = append(xs, bs[offset:offset+ix]...)
			xs = append(xs, Stuff...)

			offset += ix + WordLen - 1
		}
	}
	return append(xs, bs[offset:]...)
}

func Unstuff(bs []byte) (int, []byte) {
	xs := make([]byte, len(bs))
	return UnstuffBytes(bs, xs), xs
}

func UnstuffBytes(src, dst []byte) int {
	if len(src) <= 4 {
		return 0
	}
	z, n := int(binary.LittleEndian.Uint32(src[4:]))+12, len(src)
	if d := n - z; d > 0 && d%CaduBodyLen == 0 {
		n -= d
		src = src[:n]
	}
	var nn, offset int
	if n > z {
		for {
			if ix := bytes.Index(src[offset:], Stuff); ix < 0 {
				break
			} else {
				nn += copy(dst[nn:], src[offset:offset+ix+3])
				offset += ix + len(Stuff)
			}
		}
	}
	return nn + copy(dst[nn:], src[offset:])
}

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
