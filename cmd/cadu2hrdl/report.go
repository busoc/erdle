package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/busoc/erdle"
	"github.com/busoc/vmu"
)

type coze struct {
	Count   int
	Size    int
	Invalid int
	Missing uint32
}

func (c *coze) Update(z *coze) {
	c.Count += z.Count
	c.Size += z.Size
	c.Missing += z.Missing
}

func countCadus(r io.Reader) error {
	body := make([]byte, 1024)
	var z coze
	for {
		n, err := r.Read(body)
		if err == io.EOF {
			break
		}
		if n, ok := erdle.IsMissingCadu(err); ok {
			z.Missing += uint32(n)
			continue
		}
		if erdle.IsCRCError(err) {
			z.Invalid++
			continue
		}
		if err != nil {
			return err
		}
		z.Count++
		z.Size += n
	}
	fmt.Printf("%d cadus, missing: %d, invalid: %d (%dKB)", z.Count, z.Missing, z.Invalid, z.Size>>10)
	fmt.Println()
	return nil
}

func countHRDL(r io.Reader, by string) error {
	var byFunc func(bs []byte) (byte, uint32)
	switch by {
	case "origin", "source":
		byFunc = byOrigin
	case "channel", "":
		byFunc = byChannel
	default:
		return fmt.Errorf("unrecognized value %s", by)
	}

	zs := make(map[byte]*coze)
	ps := make(map[byte]uint32)

	body := make([]byte, 8<<20)
	for i := 1; ; i++ {
		n, err := r.Read(body)
		if err != nil {
			if err == io.EOF {
				break
			}
			if _, ok := erdle.IsMissingCadu(err); ok {
				continue
			}
			return err
		}

		i, s := byFunc(body[8:])
		if _, ok := zs[i]; !ok {
			zs[i] = &coze{}
		}
		if z := binary.LittleEndian.Uint32(body[4:]) + 12; int(z) != n {
			zs[i].Invalid++
		} else if s := vmu.Sum(body[8 : n-4]); s != binary.LittleEndian.Uint32(body[n-4:]) {
			zs[i].Invalid++
		}

		zs[i].Count++
		zs[i].Size += n - 12
		if diff := s - ps[i]; diff != s && diff > 1 {
			zs[i].Missing += diff - 1
		}
	}
	for i, e := range zs {
		fmt.Printf("%02x: %7d packets, %7d missing, %4d invalid, %7dMB", i, e.Count, e.Missing, e.Invalid, e.Size>>20)
		fmt.Println()
	}
	return nil
}

func listHRDL(r io.Reader, raw bool) error {
	body := make([]byte, vmu.BufferSize)
	var total, size, errCRC, errMissing, errInvalid, errLength int

	d := vmu.Dump(os.Stdout, false)
	for i := 1; ; i++ {
		n, err := r.Read(body)

		size += n
		if err != nil {
			if err == io.EOF {
				break
			}
			if n, ok := erdle.IsMissingCadu(err); ok {
				errMissing += n
			} else if erdle.IsCRCError(err) {
				errCRC++
			} else {
				return err
			}
		}
		total++
		if err := d.Dump(body[:n], true, raw); err != nil {
			if err == vmu.ErrInvalid {
				errInvalid++
			} else {
				errLength++
			}
		}
	}
	fmt.Printf("%d HRDL packets, %d invalid cks, %d invalid len (%d KB, %d missing cadus, %d corrupted)", total, errInvalid, errLength, size>>10, errMissing, errCRC)
	fmt.Println()
	return nil
}
