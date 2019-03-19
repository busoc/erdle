package main

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/busoc/erdle"
)

// type vcduReader struct {
// 	skip    int
// 	inner   io.Reader
// 	counter uint32
// 	body    bool
// 	digest  hash.Hash32
// }
//
// func CaduReader(r io.Reader, skip int) io.Reader {
// 	return &vcduReader{
// 		skip:   skip,
// 		inner:  r,
// 		body:   true,
// 		digest: erdle.SumVCDU(),
// 	}
// }
//
// func VCDUReader(r io.Reader, skip int) io.Reader {
// 	return &vcduReader{
// 		skip:   skip,
// 		inner:  r,
// 		digest: erdle.SumVCDU(),
// 	}
// }

const (
	CaduBodyLen      = 1008
	CaduLen          = 1024
	CaduHeaderLen    = 14
	CaduTrailerLen   = 2
	CaduTrailerIndex = CaduHeaderLen + CaduBodyLen
	CaduCounterMask  = 0xFFFFFF
)

// func (r *vcduReader) Read(bs []byte) (int, error) {
// 	defer r.digest.Reset()
// 	xs := make([]byte, r.skip+CaduLen)
// 	// n, err := r.inner.Read(xs)
// 	n, err := io.ReadFull(r.inner, xs)
// 	if err != nil {
// 		return n, err
// 	}
// 	if n == 0 {
// 		return r.Read(bs)
// 	}
// 	if !bytes.HasPrefix(xs[r.skip:], Magic) {
// 		return 0, erdle.ErrMagic
// 	}
// 	if s := r.digest.Sum(xs[r.skip+4 : r.skip+CaduTrailerIndex]); !bytes.Equal(s[2:], xs[r.skip+CaduTrailerIndex:r.skip+CaduLen]) {
// 		w := binary.BigEndian.Uint16(xs[r.skip+CaduTrailerIndex:])
// 		g := binary.BigEndian.Uint16(s[2:])
// 		err = erdle.CRCError{Want: w, Got: g}
// 	}
//
// 	curr := binary.BigEndian.Uint32(xs[r.skip+6:]) >> 8
// 	if curr < r.counter {
// 		if err == nil {
// 			err = erdle.MissingCaduError{From: curr, To: r.counter}
// 		}
// 	}
// 	if diff := (curr - r.counter) & CaduCounterMask; diff != curr && diff > 1 {
// 		if err == nil {
// 			err = erdle.MissingCaduError{From: r.counter, To: curr}
// 		}
// 	}
// 	r.counter = curr
// 	if r.body {
// 		n = copy(bs, xs[r.skip+CaduHeaderLen:r.skip+CaduTrailerIndex])
// 	} else {
// 		n = copy(bs, xs[r.skip:])
// 	}
// 	return n, err
// }

type hrdlReader struct {
	inner io.Reader
	rest  []byte
}

func HRDLReader(r io.Reader, skip int) io.Reader {
	return &hrdlReader{inner: erdle.CaduReader(r, skip)}
}

func (r *hrdlReader) Read(bs []byte) (int, error) {
	buffer, rest, err := nextPacket(r.inner, r.rest)
	r.rest = r.rest[:0]
	switch err {
	case nil:
		r.rest = rest

		return erdle.UnstuffBytes(buffer, bs), err
	case ErrSkip:
		return r.Read(bs)
	default:
		return 0, err
	}
}

func nextPacket(r io.Reader, rest []byte) ([]byte, []byte, error) {
	buffer := make([]byte, 0, 256<<10)
	if len(rest) > 0 {
		buffer = append(buffer, rest...)
	}
	block := make([]byte, CaduBodyLen)

	var offset int
	for {
		n, err := r.Read(block)
		if err != nil {
			return nil, nil, err
		}
		buffer = append(buffer, block[:n]...)
		if bytes.Equal(buffer[:erdle.WordLen], erdle.Word) {
			break
		}
		if len(buffer[offset:]) > erdle.WordLen {
			if ix := bytes.Index(buffer[offset:], erdle.Word); ix >= 0 {
				buffer = buffer[offset+ix:]
				break
			}
		}
		offset += n - erdle.WordLen
	}
	offset = erdle.WordLen
	for {
		n, err := r.Read(block)
		if err != nil {
			// verify the length of the buffer
			// we've maybe a full HRDL packet and the loss of cadu happens when, at least, one filler has been received
			// if we've enough bytes, we know that we've a full "valid" HRDL packet
			if z := binary.LittleEndian.Uint32(buffer[erdle.WordLen:]) + 12; len(buffer) >= int(z) {
				return buffer, nil, nil
			} else {
				return nil, nil, err
			}
		}
		buffer = append(buffer, block[:n]...)
		if ix := bytes.Index(buffer[offset:], erdle.Word); ix >= 0 {
			buffer, rest = buffer[:offset+ix], buffer[offset+ix:]
			break
		}
		offset += n - erdle.WordLen
	}
	return buffer, rest, nil
}
