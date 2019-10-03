package main

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/busoc/erdle"
)

const (
	CaduBodyLen      = 1008
	CaduLen          = 1024
	CaduHeaderLen    = 14
	CaduTrailerLen   = 2
	CaduTrailerIndex = CaduHeaderLen + CaduBodyLen
	CaduCounterMask  = 0xFFFFFF
)

type hrdlReader struct {
	inner io.Reader
	rest  []byte
	keep  bool
}

func HRDLReader(r io.Reader, skip int, keep bool) io.Reader {
	return &hrdlReader{
		inner: erdle.CaduReader(r, skip),
		keep:  keep,
	}
}

func (r *hrdlReader) Read(bs []byte) (int, error) {
	buffer, rest, err := nextPacket(r.inner, r.rest)
	if r.keep && err != nil && err != io.EOF {
		err = nil
	}
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
				err = nil
			}
			return buffer, nil, err
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
