package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"hash"
	"hash/adler32"
	"io"
	"os"
	"path/filepath"
)

var sumEmpty uint32

func init() {
	sumEmpty = adler32.Checksum(make([]byte, 1008))
}

func main() {
	datadir := flag.String("d", os.TempDir(), "")
	skip := flag.Int("s", 0, "strip N bytes before")
	filler := flag.Bool("k", false, "keep filler")
	repeat := flag.Int("n", 0, "repeat")
	body := flag.Bool("b", false, "body only")
	flag.Parse()

	if flag.NArg() == 0 {
		os.Exit(2)
	}
	var files []string
	if *repeat > 0 {
		files = make([]string, *repeat*flag.NArg())
		var j int
		for i := 0; i < *repeat; i++ {
			j += copy(files[j:], flag.Args())
		}
	} else {
		files = flag.Args()
	}
	if err := os.MkdirAll(*datadir, 0755); err != nil {
		os.Exit(3)
	}
	wc, err := NewWriter(filepath.Join(*datadir, "merge.dat"), *body)
	if err != nil {
		os.Exit(4)
	}
	defer wc.Close()

	for i, f := range files {
		if s, err := copyFile(wc, f, *skip, *filler); err != nil {
			os.Exit(5)
		} else {
			fmt.Printf("%4d: %s: %d cadus (%dKB), %4d skipped\n", i+1, filepath.Base(f), s.Count, s.Size>>10, s.Skip)
		}
	}
}

type copyStat struct {
	Count int
	Size  int
	Skip  int
}

func copyFile(w io.Writer, file string, skip int, fill bool) (copyStat, error) {
	var stat copyStat
	r, err := os.Open(file)
	if err != nil {
		return stat, err
	}
	defer r.Close()

	body := make([]byte, 1024+skip)
	for {
		_, err := r.Read(body)
		if err == io.EOF {
			break
		}
		if err != nil {
			return stat, err
		}
		if s := adler32.Checksum(body[skip+14 : skip+1022]); !fill && s == sumEmpty {
			stat.Skip++
			continue
		}
		if n, err := w.Write(body[skip:]); err != nil {
			return stat, err
		} else {
			stat.Size += n
			stat.Count++
		}
	}
	return stat, nil
}

type writer struct {
	body  bool
	next  uint32
	inner *bufio.Writer
	io.WriteCloser
}

func NewWriter(file string, body bool) (io.WriteCloser, error) {
	w, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	return &writer{WriteCloser: w, inner: bufio.NewWriter(w), body: body}, nil
}

func (w *writer) Close() error {
	if err := w.inner.Flush(); err != nil {
		return err
	}
	return w.WriteCloser.Close()
}

func (w *writer) Write(bs []byte) (int, error) {
	if !w.body {
		if n := (w.next & 0xFF000000) >> 8; n > 0 {
			w.next = 0
		}
		binary.BigEndian.PutUint32(bs[6:], w.next<<8)
		binary.BigEndian.PutUint16(bs[1022:], Sum(bs[4:1022]))
		w.next++
	} else {
		bs = bs[14:1022]
	}
	return w.inner.Write(bs)
}

const (
	vcduCITT = uint16(0xFFFF)
	vcduPOLY = uint16(0x1021)
)

type vcduSum struct {
	sum uint16
}

func Sum(bs []byte) uint16 {
	s := SumVCDU()
	s.Write(bs)
	return uint16(s.Sum32())
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
	binary.BigEndian.PutUint32(vs, uint32(v.sum))

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
