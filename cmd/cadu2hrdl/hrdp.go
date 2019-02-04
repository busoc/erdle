package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"math"
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

	hr.file, err = createHRDPFile(dir, time.Now().UTC())
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
		h.file, err = createHRDPFile(h.datadir, t.UTC())
		h.writer.Reset(h.file)
	default:
	}

	var (
		f uint32
		c uint8
	)

	binary.Write(h.writer, binary.LittleEndian, uint32(len(bs)+14))
	binary.Write(h.writer, binary.BigEndian, uint16(0))
	binary.Write(h.writer, binary.BigEndian, h.payload)
	binary.Write(h.writer, binary.BigEndian, bs[8])
	// set acquisition timestamp
	coarse := binary.LittleEndian.Uint32(bs[16:])
	fine := binary.LittleEndian.Uint16(bs[20:])
	f, c = splitTime5(joinTime6(coarse, fine))

	binary.Write(h.writer, binary.BigEndian, f)
	binary.Write(h.writer, binary.BigEndian, c)
	//set reception timestamp
	f, c = splitTime5(time.Now())
	binary.Write(h.writer, binary.BigEndian, f)
	binary.Write(h.writer, binary.BigEndian, c)

	if _, err := h.writer.Write(bs); err != nil {
		return 0, err
	}
	return len(bs), nil
}

func splitTime5(t time.Time) (uint32, uint8) {
	t = t.UTC().Add(-deltaGPS)

	ms := t.Nanosecond() / int(time.Millisecond)
	c := math.Ceil(float64(ms) / 1000 * 256)
	return uint32(t.Unix()), uint8(c)
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
