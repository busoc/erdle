package erdle

import (
	// "bufio"
	"bytes"
	"fmt"
	"encoding/binary"
	"hash"
	"io"
	"time"
)

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
	xs := make([]byte, 8<<20)

	n, err := r.Read(xs)
	if err != nil {
		return nil, err
	}
	r = bytes.NewReader(xs[:n])

	var h HRDLHeader
	binary.Read(r, binary.BigEndian, &h.Sync)
	binary.Read(r, binary.LittleEndian, &h.Size)

	bs := make([]byte, h.Size+4)
	if _, err := io.ReadFull(r, bs); err != nil {
		return nil, err
	}

	var (
		spare  uint16
		fine   uint16
		coarse uint32
	)
	rs := bytes.NewReader(bs)
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
			fmt.Println("oups something wrong happens science")
			return nil, err
		}
		if u := string(bytes.Trim(bs, "\x00")); len(u) > 0 {
			h.UPI = u
		}
	case 2:
		h.UPI = "IMAGE"
		bs := make([]byte, 52)
		if _, err := rs.Read(bs); err != nil {
			fmt.Println("oups something wrong happens here - image")
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
	return &e, err
}

func readTime6(coarse uint32, fine uint16) time.Time {
	t := time.Unix(int64(coarse), 0).UTC()

	fs := float64(fine) / 65536.0 * 1000.0
	ms := time.Duration(fs) * time.Millisecond
	return t.Add(ms).UTC()
}

const defaultOffset = caduBodyLen + 4

type assembler struct {
	// queue  <-chan []byte
	inner  io.Reader
	rest   *bytes.Buffer
	skip   int
	digest hash.Hash32
}

func Reassemble(r io.Reader, hrdfe bool) io.Reader {
	rs := &assembler{
		// queue:  readCadus(NewReader(r, hrdfe)),
		inner:  NewReader(r, hrdfe),
		rest:   new(bytes.Buffer),
		digest: SumHRDL(),
	}
	if hrdfe {
		rs.skip = 8
	}
	return rs
}

func (r *assembler) Read(bs []byte) (int, error) {
	z := len(bs)
	if len(bs) < r.rest.Len() {
		z = r.rest.Len()
	}
	xs := make([]byte, r.rest.Len(), z)
	if _, err := io.ReadFull(r.rest, xs); err != nil {
		return 0, err
	}
	if n, err := r.copyHRDL(xs, bs); n > 0 {
		return n, err
	}
	for {
		vs, err := r.readCadu()
		if err != nil {
			return 0, err
		}
		xs = append(xs, vs...)
		if ix := bytes.Index(xs, Word); ix >= 0 {
			xs = bytes.Replace(xs[ix:], Stuff, Word[:3], -1)
			// xs = xs[ix:]
			break
		}
	}
	for {
		if n, err := r.copyHRDL(xs, bs); n > 0 {
			return n, err
		}
		vs, err := r.readCadu()
		if err != nil {
			return 0, err
		}
		xs = append(xs, vs...)
		offset := len(xs) - caduPacketLen
		if offset < 0 {
			offset = 0
		}
		copy(xs[offset:], bytes.Replace(xs[offset:], Stuff, Word[:3], -1))
	}
}

func (r *assembler) copyHRDL(xs, bs []byte) (int, error) {
	if len(xs) < 8 || !bytes.Equal(xs[:len(Word)], Word) {
		return 0, nil
	}
	offset := len(xs) - defaultOffset
	if offset <= 0 {
		offset = len(Word)
	}
	ix := bytes.Index(xs[offset:], Word)
	if ix < 0 {
		return 0, nil
	}
	z := ix + offset
	s := int(binary.LittleEndian.Uint32(xs[len(Word):])) + 12
	if s > z {
		s = z
	}
	r.digest.Write(xs[8 : s-4])
	defer r.digest.Reset()

	n := copy(bs, xs[:s])
	r.rest.Write(xs[z:])

	if g, w := s-12, int(binary.LittleEndian.Uint32(xs[4:])); g != w {
		return n, LengthError{Got: g, Want: w}
	}
	if g, w := r.digest.Sum32(), binary.LittleEndian.Uint32(xs[s-4:]); g != w {
		return n, ChecksumError{Got: g, Want: w}
	}
	return n, nil
}

func (r *assembler) readCadu() ([]byte, error) {
	// bs, ok := <-r.queue
	// if !ok {
	// 	return nil, io.EOF
	// }
	// return bs, nil
	vs := make([]byte, caduPacketLen)
	if _, err := io.ReadFull(r.inner, vs); err != nil {
		return nil, err
	}
	return vs, nil
}

func readCadus(r io.Reader) <-chan []byte {
	q := make(chan []byte, 1000)
	go func() {
		defer close(q)
		for {
			vs := make([]byte, caduPacketLen)
			if _, err := io.ReadFull(r, vs); err != nil {
				return
			}
			q <- vs
		}
	}()
	return q
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
