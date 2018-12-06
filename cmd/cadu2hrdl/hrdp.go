package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type hrdp struct {
	datadir string
	payload uint8

	file   *os.File
	writer *bufio.Writer
	tick   <-chan time.Time
}

func NewHRDP(dir string) (*hrdp, error) {
	err := os.MkdirAll(dir, 0755)
	if err != nil && !os.IsExist(err) {
		return nil, err
	}
	hr := hrdp{
		payload: 2,
		datadir: dir,
		tick:    time.Tick(time.Minute * 5),
	}

	hr.file, err = createHRDPFile(dir, time.Now())
	if err != nil {
		return nil, err
	}
	hr.writer = bufio.NewWriter(hr.file)
	return &hr, nil
}

func (h *hrdp) Filename() string {
	return h.file.Name()
}

func (h *hrdp) Write(bs []byte) (int, error) {
	select {
	case t := <-h.tick:
		if err := h.writer.Flush(); err != nil {
			return 0, err
		}
		err := h.file.Close()
		if err != nil {
			return 0, err
		}
		h.file, err = createHRDPFile(h.datadir, t)
		h.writer.Reset(h.file)
	default:
	}
	n, c := time.Now().Unix(), bs[8]

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint32(len(bs)+14))
	binary.Write(&buf, binary.BigEndian, uint16(0))
	binary.Write(&buf, binary.BigEndian, h.payload)
	binary.Write(&buf, binary.BigEndian, uint8(c))
	binary.Write(&buf, binary.BigEndian, uint32(n))
	binary.Write(&buf, binary.BigEndian, uint8(0))
	binary.Write(&buf, binary.BigEndian, uint32(n))
	binary.Write(&buf, binary.BigEndian, uint8(0))
	buf.Write(bs)

	if _, err := io.Copy(h.writer, &buf); err != nil {
		return 0, err
	}
	return len(bs), nil
}

func createHRDPFile(dir string, t time.Time) (*os.File, error) {
	y, d, h := t.Year(), t.YearDay(), t.Hour()
	dir = filepath.Join(dir, fmt.Sprintf("%4d", y), fmt.Sprintf("%03d", d), fmt.Sprintf("%02d", h))
	if err := os.MkdirAll(dir, 0755); err != nil && !os.IsExist(err) {
		return nil, err
	}
	min := t.Truncate(time.Minute * 5).Minute()
	n := fmt.Sprintf("rt_%02d_%02d.dat", min, min+4)
	return os.Create(filepath.Join(dir, n))
}
