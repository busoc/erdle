package erdle

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"hash"
	"io"
	"time"
)

const hrdlHeaderSize = 12

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
}

const caduLimCounter = 1<<24

func Reassemble(r io.Reader, hrdfe bool) io.Reader {
	rs := &assembler{
		inner: bufio.NewReaderSize(r, 8<<20),
		rest:  new(bytes.Buffer),
		counter: caduLimCounter,
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
	if s := size + hrdlHeaderSize; s > z {
		return z, LengthError{Want: s, Got: z}
	}
	if err := verifyHRDL(bs[:size+hrdlHeaderSize]); err != nil {
		return z, err
	}
	return size + hrdlHeaderSize, nil
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
	var err error
	vs := make([]byte, caduPacketLen+r.skip)
	if _, err = io.ReadFull(r.inner, vs); err != nil {
		return nil, err
	}
	// seq := binary.BigEndian.Uint32(vs[r.skip+6:])
	// if r.counter != 1<<24 {
	// 	if diff := (seq - r.counter) & 0xFFF; diff > 1 {
	// 		err = MissingCaduError(int(delta))
	// 	}
	// }
	// r.counter = seq
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
