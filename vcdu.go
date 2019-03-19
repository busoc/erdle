package erdle

import (
	"bytes"
	"encoding/binary"
	"hash"
	"io"
)

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
	xs := make([]byte, r.skip+CaduLen)

	n, err := io.ReadFull(r.inner, xs)
	if err != nil {
		return n, err
	}
	if n == 0 {
		return r.Read(bs)
	}
	if !bytes.HasPrefix(xs[r.skip:], Magic) {
		return 0, ErrMagic
	}
	if s := r.digest.Sum(xs[r.skip+4 : r.skip+CaduTrailerIndex]); !bytes.Equal(s[2:], xs[r.skip+CaduTrailerIndex:r.skip+CaduLen]) {
		err = CRCError{
			Want: binary.BigEndian.Uint16(xs[r.skip+CaduTrailerIndex:]),
			Got:  binary.BigEndian.Uint16(s[2:]),
		}
	}

	curr := binary.BigEndian.Uint32(xs[r.skip+6:]) >> 8
	if curr < r.counter {
		if err == nil {
			err = MissingCaduError{From: curr, To: r.counter}
		}
	}
	if diff := (curr - r.counter) & CaduCounterMask; diff != curr && diff > 1 {
		if err == nil {
			err = MissingCaduError{From: r.counter, To: curr}
		}
	}
	r.counter = curr
	if r.body {
		n = copy(bs, xs[r.skip+CaduHeaderLen:r.skip+CaduTrailerIndex])
	} else {
		n = copy(bs, xs[r.skip:])
	}
	return n, err
}
