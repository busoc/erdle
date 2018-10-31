package erdle

import (
	"bytes"
	"encoding/binary"
	"hash"
	"io"
	"time"
)

const (
	vcduCITT = uint16(0xFFFF)
	vcduPOLY = uint16(0x1021)
)

const (
	caduHeaderLen = 14
	caduCheckLen  = 2
	caduPacketLen = 1024
	caduBodyLen   = caduPacketLen - caduHeaderLen - caduCheckLen
)

type VCDUHeader struct {
	Word     uint32
	Version  uint8
	Space    uint8
	Channel  uint8
	Sequence uint32
	Replay   bool
	Control  uint16
	Data     uint16
}

type Cadu struct {
	*VCDUHeader
	Reception time.Time
	Payload   []byte
	Control   uint16
	Error     error
}

type vcduReader struct {
	inner io.Reader
	skip  int
	body  bool
}

func NewReader(r io.Reader, hrdfe bool) io.Reader {
	var skip int
	if hrdfe {
		skip = 8
	}
	return &vcduReader{inner: r, skip: skip}
}

func (r *vcduReader) Read(bs []byte) (int, error) {
	var n int
	for n+caduBodyLen <= len(bs) {
		nn, err := r.readSingle(bs[n:])
		if err != nil {
			return n, err
		}
		n += nn
	}
	return n, nil
}

func (r *vcduReader) readSingle(bs []byte) (int, error) {
	vs := make([]byte, caduPacketLen+r.skip)
	n, err := r.inner.Read(vs)
	if err != nil {
		return n, err
	}
	vs = vs[r.skip:]
	if r.body {
		vs = vs[caduHeaderLen : caduPacketLen-caduCheckLen]
	}
	return copy(bs, vs), nil
}

func DecodeCadu(r io.Reader) (*Cadu, error) {
	bs := make([]byte, caduPacketLen)
	if _, err := io.ReadFull(r, bs); err != nil {
		return nil, err
	}
	r = bytes.NewReader(bs)

	var (
		h   VCDUHeader
		pid uint16
		seq uint32
	)
	if err := binary.Read(r, binary.BigEndian, &h.Word); err != nil {
		return nil, err
	}

	sum := SumVCDU()
	rs := io.TeeReader(r, sum)

	binary.Read(rs, binary.BigEndian, &pid)
	h.Version = uint8((pid & 0xC000) >> 14)
	h.Space = uint8((pid & 0x3FC0) >> 6)
	h.Channel = uint8(pid & 0x003F)

	binary.Read(rs, binary.BigEndian, &seq)
	h.Sequence = seq >> 8
	h.Replay = (seq >> 7) == 1

	binary.Read(rs, binary.BigEndian, &h.Control)
	binary.Read(rs, binary.BigEndian, &h.Data)

	c := Cadu{
		VCDUHeader: &h,
		Payload:    make([]byte, caduBodyLen),
	}
	if _, err := io.ReadFull(rs, c.Payload); err != nil {
		return nil, err
	}
	binary.Read(r, binary.BigEndian, &c.Control)
	if s := sum.Sum32(); s != uint32(c.Control) {
		c.Error = ChecksumError{Want: uint32(c.Control), Got: s}
	}

	return &c, nil
}

func (c *Cadu) Missing(p *Cadu) uint32 {
	if p == nil {
		return 0
	}
	if p.Sequence > c.Sequence {
		return p.Missing(c)
	}
	if delta := (c.Sequence - p.Sequence) & 0xFFFFFF; delta > 1 {
		return delta
	}
	return 0
}

func (c *Cadu) Elapsed(p *Cadu) time.Duration {
	if p == nil {
		return 0
	}
	if p.Reception.After(c.Reception) {
		return p.Elapsed(c)
	}
	return c.Reception.Sub(p.Reception)
}

type vcduSum struct {
	sum uint16
}

func SumVCDU() hash.Hash32 {
	var v vcduSum
	v.Reset()
	return &v
}

func (v *vcduSum) Size() int      { return 2 }
func (v *vcduSum) BlockSize() int { return 32 }
func (v *vcduSum) Reset()         { v.sum = vcduCITT }

func (v *vcduSum) Sum(bs []byte) []byte {
	v.Write(bs)
	vs := make([]byte, v.Size()*2)
	binary.LittleEndian.PutUint32(vs, uint32(v.sum))

	return vs
}

func (v *vcduSum) Sum32() uint32 {
	return uint32(v.sum)
}

func (v *vcduSum) Write(bs []byte) (int, error) {
	for i := 0; i < len(bs); i++ {
		v.sum ^= uint16(bs[i]) << 8
		for j := 0; j < 8; j++ {
			if (v.sum & 0x8000) > 0 {
				v.sum = (v.sum << 1) ^ vcduPOLY
			} else {
				v.sum = v.sum << 1
			}
		}
	}
	return len(bs), nil
}
