package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"hash/adler32"
	"io"
	"os"
	"path/filepath"

	"github.com/busoc/erdle"
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

	body := make([]byte, erdle.CaduLen+skip)
	for {
		_, err := r.Read(body)
		if err == io.EOF {
			break
		}
		if err != nil {
			return stat, err
		}
		if s := adler32.Checksum(body[skip+erdle.CaduHeaderLen : skip+erdle.CaduBodyLen]); !fill && s == sumEmpty {
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
		binary.BigEndian.PutUint16(bs[erdle.CaduBodyLen:], erdle.Sum(bs[erdle.MagicLen:erdle.CaduBodyLen]))
		w.next++
	} else {
		bs = bs[14:1022]
	}
	return w.inner.Write(bs)
}
