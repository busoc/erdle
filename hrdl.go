package erdle

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"time"
)

var ErrFull = errors.New("complete")

const (
	hrdlHeaderLen  = 8
	hrdlTrailerLen = 4
	hrdlMetaLen    = hrdlHeaderLen + hrdlTrailerLen
)

type Builder struct {
	Word        []byte
	Order       binary.ByteOrder
	KeepHeader  bool
	KeepTrailer bool

	inner  io.Reader
	buffer []byte

	digest hash.Hash32

	count   int
	size    int
	written int
}

func NewBuilder(r io.Reader, hrdfe bool) *Builder {
	if _, ok := r.(*vcduReader); !ok {
		x := &vcduReader{
			inner: r,
			body:  true,
		}
		if hrdfe {
			x.skip = 8
		}
		r = x
	}
	b := Builder{
		inner:       r,
		Order:       binary.LittleEndian,
		Word:        Word,
		KeepTrailer: true,
		KeepHeader:  true,
	}
	return &b
}

func (b *Builder) Read(bs []byte) (int, error) {
	var (
		offset  int
		written int
	)

	written = copy(bs, b.buffer)
	b.buffer = b.buffer[:0]
	if b.size == 0 {
		for {
			if offset > len(b.Word) {
				offset -= len(b.Word)
			}
			offset = 0
			if ix := bytes.Index(bs[offset:written], b.Word); ix >= 0 {
				written = copy(bs, bs[offset+ix:written])
				offset = written
				b.count++
				break
			}
			if written+caduBodyLen > len(bs) {
				written = copy(bs, bs[written-len(b.Word):written])
			}
			n, err := b.inner.Read(bs[written : written+caduBodyLen])
			if err != nil {
				return 0, err
			}
			offset = written
			written += n
		}
		if written < hrdlHeaderLen+16 {
			n, err := b.inner.Read(bs[written : written+caduBodyLen])
			if err != nil {
				return 0, err
			}
			written += n
			offset = written
		}
		b.written = written
		b.size = int(b.Order.Uint32(bs[4:])) + hrdlMetaLen
		if ix, err := b.isFull(bs[len(b.Word):written]); ix >= 0 {
			return len(b.Word) + ix, err
		}
	}

	for written+caduBodyLen < len(bs) {
		if offset >= len(b.Word) {
			offset -= len(b.Word)
		}
		if ix, err := b.isFull(bs[offset:written]); ix >= 0 {
			return offset + ix, err
		}
		n, err := b.inner.Read(bs[written : written+caduBodyLen])
		if err != nil {
			return 0, err
		}
		offset = written
		written += n
		b.written += n
		if diff := b.written - b.size; b.written >= b.size {
			b.reset(bs[written-diff : written])
			return written - diff, ErrFull
		}
	}
	if ix, err := b.isFull(bs[offset:written]); ix >= 0 {
		return offset + ix, err
	}
	if diff := b.written - b.size; b.written >= b.size {
		b.reset(bs[written-diff : written])
		return written - diff, ErrFull
	}
	return written, nil
}

var null = []byte{0x00}

func (b *Builder) isFull(bs []byte) (int, error) {
	ix := bytes.Index(bs, b.Word)
	if ix < 0 {
		return ix, nil
	}
	b.reset(bs[ix:])
	return ix, ErrFull
}

func (b *Builder) reset(bs []byte) {
	b.size, b.written = 0, 0
	if len(bs) > 0 {
		b.buffer = append(b.buffer[:0], bs...)
	}
}

type Decoder struct {
	inner  io.Reader
	buffer []byte
}

func HRDL(r io.Reader) *Decoder {
	if _, ok := r.(*Builder); !ok {
		b := Builder{
			inner:       r,
			Order:       binary.LittleEndian,
			Word:        Word,
			KeepTrailer: true,
			KeepHeader:  true,
		}
		r = &b
	}
	return &Decoder{
		inner:  r,
		buffer: make([]byte, 8<<20),
	}
}

func NewDecoder(r io.Reader, hrdfe bool) *Decoder {
	if _, ok := r.(*Builder); !ok {
		r = NewBuilder(r, hrdfe)
	}
	return HRDL(r)
}

func (d *Decoder) Decode() (*Erdle, error) {
	n, err := d.inner.Read(d.buffer)
	switch err {
	case ErrFull, nil:
		err = nil
	default:
		return nil, err
	}
	rs := bytes.NewReader(d.buffer[:n])
	h := decodeHRDLHeader(rs)

	e := Erdle{
		HRDLHeader: h,
		Payload:    make([]byte, rs.Len()-hrdlMetaLen),
	}
	if _, err := io.ReadFull(rs, e.Payload); err != nil {
		return nil, err
	}
	binary.Read(rs, binary.LittleEndian, &e.Control)
	if uint32(n) != h.Size+hrdlMetaLen {
		err = LengthError{Want: int(h.Size), Got: int(n)}
	}
	return &e, err
}

func decodeHRDLHeader(rs io.Reader) *HRDLHeader {
	var h HRDLHeader

	var (
		spare  uint16
		fine   uint16
		coarse uint32
	)
	binary.Read(rs, binary.LittleEndian, &h.Sync)
	binary.Read(rs, binary.LittleEndian, &h.Size)

	binary.Read(rs, binary.LittleEndian, &h.Channel)
	binary.Read(rs, binary.LittleEndian, &h.Source)
	binary.Read(rs, binary.LittleEndian, &spare)
	binary.Read(rs, binary.LittleEndian, &h.Sequence)
	binary.Read(rs, binary.LittleEndian, &coarse)
	binary.Read(rs, binary.LittleEndian, &fine)
	binary.Read(rs, binary.LittleEndian, &spare)

	h.When = readTime6(coarse, fine)

	binary.Read(rs, binary.LittleEndian, &h.Property)
	binary.Read(rs, binary.LittleEndian, &h.Stream)
	binary.Read(rs, binary.LittleEndian, &h.Counter)
	binary.Read(rs, binary.LittleEndian, &h.Acqtime)
	binary.Read(rs, binary.LittleEndian, &h.Auxtime)
	binary.Read(rs, binary.LittleEndian, &h.Origin)

	switch h.Property >> 4 {
	case 1:
		h.UPI = "SCIENCE"
		bs := make([]byte, 32)
		if _, err := rs.Read(bs); err != nil {
			// return nil, err
		}
		if u := string(bytes.Trim(bs, "\x00")); len(u) > 0 {
			h.UPI = u
		}
	case 2:
		h.UPI = "IMAGE"
		bs := make([]byte, 52)
		if _, err := rs.Read(bs); err != nil {
			// return nil, err
		}
		if u := string(bytes.Trim(bs[20:], "\x00")); len(u) > 0 {
			h.UPI = u
		}
	default:
		h.UPI = "UNKNOWN"
	}
	return &h
}

type HRDLHeader struct {
	// HRDL Header Fields
	Sync uint32
	Size uint32

	// VMU Header Fields
	Channel  uint8
	Source   uint8
	Sequence uint32
	When     time.Time

	// HRD Common Header Fields
	Property uint8
	Stream   uint16
	Counter  uint32
	Acqtime  time.Duration
	Auxtime  time.Duration
	Origin   uint8
	UPI      string
}

type Erdle struct {
	*HRDLHeader
	Payload []byte
	Control uint32
}

func DecodeHRDL(r io.Reader) (*Erdle, error) {
	var (
		h  HRDLHeader
		rs *bytes.Buffer
		xs []byte
	)

	if a, ok := r.(*assembler); ok {
		xs = make([]byte, 8<<20)
		n, err := a.Read(xs)
		if err != nil {
			return nil, err
		}
		rs = bytes.NewBuffer(xs[:n])
		binary.Read(rs, binary.LittleEndian, &h.Sync)
		binary.Read(rs, binary.LittleEndian, &h.Size)
	} else {
		xs = make([]byte, 8)
		if _, err := io.ReadFull(r, xs); err != nil {
			return nil, err
		}
		rs = bytes.NewBuffer(xs)
		binary.Read(rs, binary.LittleEndian, &h.Sync)
		binary.Read(rs, binary.LittleEndian, &h.Size)

		if _, err := io.CopyN(rs, r, int64(h.Size)+4); err != nil {
			return nil, err
		}
	}

	var (
		spare  uint16
		fine   uint16
		coarse uint32
	)

	binary.Read(rs, binary.LittleEndian, &h.Channel)
	binary.Read(rs, binary.LittleEndian, &h.Source)
	binary.Read(rs, binary.LittleEndian, &spare)
	binary.Read(rs, binary.LittleEndian, &h.Sequence)
	binary.Read(rs, binary.LittleEndian, &coarse)
	binary.Read(rs, binary.LittleEndian, &fine)
	binary.Read(rs, binary.LittleEndian, &spare)

	h.When = readTime6(coarse, fine)

	binary.Read(rs, binary.LittleEndian, &h.Property)
	binary.Read(rs, binary.LittleEndian, &h.Stream)
	binary.Read(rs, binary.LittleEndian, &h.Counter)
	binary.Read(rs, binary.LittleEndian, &h.Acqtime)
	binary.Read(rs, binary.LittleEndian, &h.Auxtime)
	binary.Read(rs, binary.LittleEndian, &h.Origin)

	switch h.Property >> 4 {
	case 1:
		h.UPI = "SCIENCE"
		bs := make([]byte, 32)
		if _, err := rs.Read(bs); err != nil {
			return nil, err
		}
		if u := string(bytes.Trim(bs, "\x00")); len(u) > 0 {
			h.UPI = u
		}
	case 2:
		h.UPI = "IMAGE"
		bs := make([]byte, 52)
		if _, err := rs.Read(bs); err != nil {
			return nil, err
		}
		if u := string(bytes.Trim(bs[20:], "\x00")); len(u) > 0 {
			h.UPI = u
		}
	default:
		h.UPI = "UNKNOWN"
	}

	e := Erdle{
		HRDLHeader: &h,
		Payload:    make([]byte, rs.Len()-4),
	}
	if _, err := io.ReadFull(rs, e.Payload); err != nil {
		return nil, err
	}
	binary.Read(rs, binary.LittleEndian, &e.Control)
	return &e, nil
}

func readTime6(coarse uint32, fine uint16) time.Time {
	t := time.Unix(int64(coarse), 0).UTC()

	fs := float64(fine) / 65536.0 * 1000.0
	ms := time.Duration(fs) * time.Millisecond
	return t.Add(ms).UTC()
}

const defaultOffset = caduBodyLen + 4

type assembler struct {
	inner *bufio.Reader
	rest  *bytes.Buffer
	skip  int

	counter uint32
	total   uint64
}

const (
	caduCounterLim  = 1 << 24
	caduCounterMask = 0x0FFF
)

func Reassemble(r io.Reader, hrdfe bool) io.Reader {
	rs := &assembler{
		inner:   bufio.NewReaderSize(r, 8<<20),
		rest:    new(bytes.Buffer),
		counter: caduCounterLim,
	}
	if hrdfe {
		rs.skip = 8
	}
	return rs
}

func (r *assembler) Read(bs []byte) (int, error) {
	var written int
	if n, err := io.ReadAtLeast(r.rest, bs, r.rest.Len()); err != nil {
		return 0, err
	} else {
		written = n
	}
	if n, err := r.copyHRDL(bs[:written]); n > 0 {
		return n, err
	}
	for {
		vs, err := r.readCadu()
		if err != nil {
			return 0, err
		}
		written += copy(bs[written:], vs)
		if ix := bytes.Index(bs[:written], Word); ix >= 0 {
			written = copy(bs[0:], stuffBytes(bs[ix:written]))
			break
		}
	}
	for {
		if n, err := r.copyHRDL(bs[:written]); n > 0 {
			return n, err
		}
		vs, err := r.readCadu()
		if err != nil {
			return 0, err
		}
		z := copy(bs[written:], vs)
		copy(bs[written-4:], stuffBytes(bs[written-4:written+z]))
		written += z
	}
}

func (r *assembler) copyHRDL(bs []byte) (int, error) {
	if len(bs) < 8 || !bytes.Equal(bs[:len(Word)], Word) {
		return 0, nil
	}
	offset := len(bs) - 2048
	if offset <= 0 {
		offset = len(Word)
	}
	z := bytes.Index(bs[offset:], Word)
	if z < 0 {
		return 0, nil
	}
	z += offset
	r.rest.Write(bs[z:])

	size := int(binary.LittleEndian.Uint32(bs[len(Word):]))
	if s := size + hrdlMetaLen; s > z {
		return z, LengthError{Want: s, Got: z}
	}
	if err := verifyHRDL(bs[:size+hrdlMetaLen]); err != nil {
		return z, err
	}
	return size + hrdlMetaLen, nil
}

func verifyHRDL(bs []byte) error {
	var h hrdlSum
	h.Write(bs[8 : len(bs)-4])
	if g, w := h.Sum32(), binary.LittleEndian.Uint32(bs[len(bs)-4:]); g != w {
		return ChecksumError{Want: w, Got: g}
	}
	return nil
}

func (r *assembler) readCadu() ([]byte, error) {
	r.total++
	vs := make([]byte, caduPacketLen+r.skip)
	if _, err := io.ReadFull(r.inner, vs); err != nil {
		return nil, err
	}
	seq := binary.BigEndian.Uint32(vs[r.skip+6:]) >> 8

	var err error
	if r.counter != caduCounterLim {
		if diff := (seq - r.counter) & caduCounterMask; diff > 1 {
			// err = MissingCaduError(int(diff))
		}
	}
	r.counter = seq
	return vs[r.skip+caduHeaderLen : r.skip+caduPacketLen-caduCheckLen], err
}

func stuffBytes(bs []byte) []byte {
	return bytes.Replace(bs, Stuff, Stuff[:3], -1)
}

type hrdlSum struct {
	sum uint32
}

func SumHRDL() hash.Hash32 {
	return &hrdlSum{}
}

func (v *hrdlSum) Size() int      { return 4 }
func (v *hrdlSum) BlockSize() int { return 32 }
func (v *hrdlSum) Reset()         { v.sum = 0 }

func (v *hrdlSum) Sum(bs []byte) []byte {
	v.Write(bs)
	vs := make([]byte, v.Size())
	binary.LittleEndian.PutUint32(vs, v.sum)

	return vs
}

func (v *hrdlSum) Sum32() uint32 {
	return v.sum
}

func (v *hrdlSum) Write(bs []byte) (int, error) {
	for i := 0; i < len(bs); i++ {
		v.sum += uint32(bs[i])
	}
	return len(bs), nil
}
