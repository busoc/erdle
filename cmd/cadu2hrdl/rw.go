package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/adler32"
	"io"
	"os"
	"sort"
)

var zh uint32

func init() {
	zh = adler32.Checksum(make([]byte, 1008))
}

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
	return ok || IsCRCError(err)
}

type multiReader struct {
	file  *os.File
	files []string
}

func MultiReader(ps []string) (io.Reader, error) {
	if len(ps) == 0 {
		return nil, fmt.Errorf("no files given")
	}
	sort.Strings(ps)
	f, err := os.Open(ps[0])
	if err != nil {
		return nil, err
	}
	m := multiReader{file: f}
	if len(ps) > 1 {
		m.files = ps[1:]
	} else {
		m.files = ps[:0]
	}
	return &m, nil
}

func (m *multiReader) Read(bs []byte) (int, error) {
	if len(m.files) == 0 && m.file == nil {
		return 0, io.EOF
	}
	n, err := m.file.Read(bs)
	if err == io.EOF {
		m.file.Close()
		if len(m.files) > 0 {
			if m.file, err = os.Open(m.files[0]); err != nil {
				return 0, err
			}
			if len(m.files) == 1 {
				m.files = m.files[:0]
			} else {
				m.files = m.files[1:]
			}
			return 0, nil
		} else {
			m.file = nil
		}
	}
	return n, err
}

type vcduReader struct {
	skip    int
	inner   io.Reader
	counter uint32
	body    bool
	digest  hash.Hash32
}

func CaduReader(r io.Reader, skip int) io.Reader {
	return &vcduReader{
		skip:   skip,
		inner:  r,
		body:   true,
		digest: SumVCDU(),
	}
}

func VCDUReader(r io.Reader, skip int) io.Reader {
	return &vcduReader{
		skip:   skip,
		inner:  r,
		digest: SumVCDU(),
	}
}

func (r *vcduReader) Read(bs []byte) (int, error) {
	defer r.digest.Reset()
	xs := make([]byte, r.skip+1024)
	n, err := r.inner.Read(xs)
	if err != nil {
		return n, err
	}
	if n == 0 {
		return r.Read(bs)
	}
	if s := r.digest.Sum(xs[r.skip+4 : r.skip+1022]); !bytes.Equal(s[2:], xs[r.skip+1022:r.skip+1024]) {
		w := binary.BigEndian.Uint16(xs[r.skip+1022:])
		g := binary.BigEndian.Uint16(s[2:])
		err = CRCError{Want: w, Got: g}
	}

	curr := binary.BigEndian.Uint32(xs[r.skip+6:]) >> 8
	if diff := (curr - r.counter) & 0xFFFFFF; diff != curr && diff > 1 {
		if err == nil {
			err = MissingCaduError{From: r.counter, To: curr}
		}
	}
	r.counter = curr
	if r.body {
		n = copy(bs, xs[r.skip+14:r.skip+1022])
	} else {
		n = copy(bs, xs[r.skip:])
	}
	return n, err
}

type hrdlReader struct {
	inner io.Reader
	rest  []byte
}

func HRDLReader(r io.Reader, skip int) io.Reader {
	return &hrdlReader{inner: CaduReader(r, skip)}
}

func (r *hrdlReader) Read(bs []byte) (int, error) {
	buffer, rest, err := nextPacket(r.inner, r.rest)
	r.rest = r.rest[:0]
	switch err {
	case nil:
		r.rest = rest

		return UnstuffBytes(buffer, bs), err
	case ErrSkip:
		return r.Read(bs)
	default:
		return 0, err
	}
}

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
	z, n := int(binary.LittleEndian.Uint32(src[4:]))+12, len(src)
	if d := n - z; d > 0 && d%1008 == 0 {
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

func nextPacket(r io.Reader, rest []byte) ([]byte, []byte, error) {
	var (
		offset int
		buffer []byte
	)

	if len(rest) > 0 {
		buffer = append(buffer, rest...)
	}
	block := make([]byte, 1008)
	for {
		n, err := r.Read(block)
		if err != nil {
			return nil, nil, err
		}
		buffer = append(buffer, block[:n]...)
		if bytes.Equal(buffer[:WordLen], Word) {
			break
		}
		if len(buffer[offset:]) > WordLen {
			if ix := bytes.Index(buffer[offset:], Word); ix >= 0 {
				buffer = buffer[offset+ix:]
				break
			}
		}
		offset += n - WordLen
	}
	offset = WordLen
	for {
		n, err := r.Read(block)
		if err != nil {
			return nil, nil, err
		}
		buffer = append(buffer, block[:n]...)
		if ix := bytes.Index(buffer[offset:], Word); ix >= 0 {
			buffer, rest = buffer[:offset+ix], buffer[offset+ix:]
			break
		}
		offset += n - WordLen
	}
	return buffer, rest, nil
}
