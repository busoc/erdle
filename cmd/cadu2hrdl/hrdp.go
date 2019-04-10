package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/midbel/roll"
	"github.com/busoc/timutil"
)

type Writer interface {
	io.WriteCloser
	Filename() string
}

func NewWriter(dir string, payload uint8, options []roll.Option) (Writer, error) {
	if payload == 0 {
		return NewHRDFE(dir, options)
	} else {
		return NewHRDP(dir, payload, options)
	}
}

type hrdfe struct {
	datadir  string
	filename string

	io.WriteCloser
}

func NewHRDFE(dir string, options []roll.Option) (Writer, error) {
	err := os.MkdirAll(dir, 0755)
	if err != nil && !os.IsExist(err) {
		return nil, err
	}
	hr := hrdfe{
		datadir: dir,
	}
	if hr.WriteCloser, err = roll.Roll(hr.Open, options...); err != nil {
		return nil, err
	}
	return &hr, nil
}

func (h *hrdfe) Filename() string {
	return h.filename
}

func (h *hrdfe) Open(n int, w time.Time) (io.WriteCloser, []io.Closer, error) {
	datadir := h.datadir

	y := fmt.Sprintf("%04d", w.Year())
	d := fmt.Sprintf("%03d", w.YearDay())
	r := fmt.Sprintf("%02d", w.Hour())

	datadir = filepath.Join(datadir, y, d, r)
	if err := os.MkdirAll(datadir, 0755); err != nil {
		return nil, nil, err
	}
	file := filepath.Join(datadir, fmt.Sprintf("rt_%06d_%s.dat", n, w.Format("150405")))
	if file != h.filename {
		go func(f string) {
			i, err := os.Stat(f)
			if err != nil {
				return
			}
			if i.Size() == 0 {
				os.Remove(f)
			}
		}(h.filename)
	}
	h.filename = file
	wc, err := os.OpenFile(h.filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	return wc, nil, err
}

func (h *hrdfe) Write(bs []byte) (int, error) {
	var buf bytes.Buffer

	n := time.Now()
	binary.Write(&buf, binary.BigEndian, uint32(n.Unix()))
	binary.Write(&buf, binary.BigEndian, uint32(0))
	buf.Write(bs)

	if _, err := h.WriteCloser.Write(buf.Bytes()); err != nil {
		return 0, err
	}
	return len(bs), nil
}

type hrdp struct {
	datadir  string
	filename string
	payload  uint8

	io.WriteCloser
}

func NewHRDP(dir string, payload uint8, options []roll.Option) (Writer, error) {
	err := os.MkdirAll(dir, 0755)
	if err != nil && !os.IsExist(err) {
		return nil, err
	}
	hr := hrdp{
		payload: payload,
		datadir: dir,
	}

	hr.WriteCloser, err = roll.Roll(hr.Open, options...)
	if err != nil {
		return nil, err
	}
	return &hr, nil
}

func (h *hrdp) Filename() string {
	return h.filename
}

func (h *hrdp) Open(n int, w time.Time) (io.WriteCloser, []io.Closer, error) {
	datadir := h.datadir

	y := fmt.Sprintf("%04d", w.Year())
	d := fmt.Sprintf("%03d", w.YearDay())
	r := fmt.Sprintf("%02d", w.Hour())

	datadir = filepath.Join(datadir, y, d, r)
	if err := os.MkdirAll(datadir, 0755); err != nil {
		return nil, nil, err
	}
	file := filepath.Join(datadir, fmt.Sprintf("rt_%06d_%s.dat", n, w.Format("150405")))
	if file != h.filename {
		go func(f string) {
			i, err := os.Stat(f)
			if err != nil {
				return
			}
			if i.Size() == 0 {
				os.Remove(f)
			}
		}(h.filename)
	}
	h.filename = file
	wc, err := os.OpenFile(h.filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	return wc, nil, err
}

func (h *hrdp) Write(bs []byte) (int, error) {
	var (
		f uint32
		c uint8
	)
	var buf bytes.Buffer

	binary.Write(&buf, binary.LittleEndian, uint32(len(bs)+14))
	binary.Write(&buf, binary.BigEndian, uint16(0))
	binary.Write(&buf, binary.BigEndian, h.payload)
	binary.Write(&buf, binary.BigEndian, bs[8])
	// set acquisition timestamp
	coarse := binary.LittleEndian.Uint32(bs[16:])
	fine := binary.LittleEndian.Uint16(bs[20:])
	acq := timutil.Join6(coarse, fine)
	f, c = timutil.Split5(timutil.GPSTime(acq, true))

	binary.Write(&buf, binary.BigEndian, f)
	binary.Write(&buf, binary.BigEndian, c)
	//set reception timestamp
	f, c = timutil.Split5(timutil.GPSTime(time.Now(), true))
	binary.Write(&buf, binary.BigEndian, f)
	binary.Write(&buf, binary.BigEndian, c)

	buf.Write(bs)

	if _, err := h.WriteCloser.Write(buf.Bytes()); err != nil {
		return 0, err
	}
	return len(bs), nil
}
