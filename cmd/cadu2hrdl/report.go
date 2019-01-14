package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"time"
)

var (
	leap       = time.Second * 18
	gpsEpoch   = time.Date(1980, 1, 6, 0, 0, 0, 0, time.UTC)
	unixEpoch  = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	deltaEpoch = gpsEpoch.Sub(unixEpoch) + leap
)

const deltaGPS = time.Duration(315964800) * time.Second

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
		if n, ok := IsMissingCadu(err); ok {
			z.Missing += uint32(n)
			continue
		}
		if IsCRCError(err) {
			z.Invalid++
			continue
		}
		if err != nil {
			return err
		}
		z.Count++
		z.Size += n
	}
	log.Printf("%d cadus, missing: %d, invalid: %d (%dKB)", z.Count, z.Missing, z.Invalid, z.Size>>10)
	return nil
}

func countHRDL(r io.Reader, by string) error {
	var byFunc func(bs []byte) (byte, uint32)
	switch by {
	case "origin":
		byFunc = func(bs []byte) (byte, uint32) {
			return bs[39], binary.LittleEndian.Uint32(bs[19:])
		}
	case "channel", "":
		byFunc = func(bs []byte) (byte, uint32) {
			return bs[0], binary.LittleEndian.Uint32(bs[4:])
		}
	default:
		return fmt.Errorf("unrecognized value %s", by)
	}

	zs := make(map[byte]*coze)
	ps := make(map[byte]uint32)

	body := make([]byte, 8<<20)
	for i := 1; ; i++ {
		_, err := r.Read(body)
		if err != nil {
			if err == io.EOF {
				break
			}
			if _, ok := IsMissingCadu(err); ok {
				continue
			}
			return err
		}
		i, s := byFunc(body[8:])
		if _, ok := zs[i]; !ok {
			zs[i] = &coze{}
		}

		zs[i].Count++
		zs[i].Size += len(body) - 12
		if diff := s - ps[i]; diff != s && diff > 1 {
			zs[i].Missing += diff - 1
		}
	}
	for i, e := range zs {
		log.Printf("%02x: %7d packets, %7d missing, %7dMB", i, e.Count, e.Missing, e.Size>>20)
	}
	return nil
}

func listHRDL(r io.Reader, raw bool) error {
	body := make([]byte, 8<<20)
	var total, size, errCRC, errMissing int
	for i := 1; ; i++ {
		if n, err := r.Read(body); err == nil {
			total++
			size += n
			if raw {
				log.Printf("%6d | %x | %x | %x", i, body[:8], body[8:24], body[24:48])
			} else {
				dumpErdle(i, bytes.NewReader(body[:n]))
			}
		} else if err == io.EOF {
			break
		} else if n, ok := IsMissingCadu(err); ok {
			size += n
			errMissing += n
		} else if IsCRCError(err) {
			size += n
			errCRC++
		} else {
			break
		}
	}
	log.Printf("%d HRDL packets (%d KB, %d missing cadus, %d corrupted)", total, size>>10, errMissing, errCRC)
	return nil
}

func dumpErdle(i int, r io.Reader) {
	var (
		sync     uint32
		size     uint32
		spare    uint16
		channel  uint8
		source   uint8
		origin   uint8
		sequence uint32
		coarse   uint32
		fine     uint16
		property uint8
		stream   uint16
		counter  uint32
		acqtime  time.Duration
		auxtime  time.Duration
	)
	binary.Read(r, binary.LittleEndian, &sync)
	binary.Read(r, binary.LittleEndian, &size)
	binary.Read(r, binary.LittleEndian, &channel)
	binary.Read(r, binary.LittleEndian, &source)
	binary.Read(r, binary.LittleEndian, &spare)
	binary.Read(r, binary.LittleEndian, &sequence)
	binary.Read(r, binary.LittleEndian, &coarse)
	binary.Read(r, binary.LittleEndian, &fine)
	binary.Read(r, binary.LittleEndian, &spare)

	vt := joinTime6(coarse, fine).Format("2006-01-02 15:04:05.000")

	binary.Read(r, binary.LittleEndian, &property)
	binary.Read(r, binary.LittleEndian, &stream)
	binary.Read(r, binary.LittleEndian, &counter)
	binary.Read(r, binary.LittleEndian, &acqtime)
	binary.Read(r, binary.LittleEndian, &auxtime)
	binary.Read(r, binary.LittleEndian, &origin)

	at := gpsEpoch.Add(acqtime).Format("2006-01-02 15:04:05.000")

	var mode string
	if origin == source {
		mode = "realtime"
	} else {
		mode = "playback"
	}
	var upi string
	switch property >> 4 {
	case 1:
		bs := make([]byte, 32)
		if _, err := io.ReadFull(r, bs); err == nil {
			upi = string(bytes.Trim(bs, "\x00"))
		} else {
			upi = "SCIENCE"
		}
	case 2:
		bs := make([]byte, 52)
		if _, err := io.ReadFull(r, bs); err == nil {
			upi = string(bytes.Trim(bs[20:], "\x00"))
		} else {
			upi = "IMAGE"
		}
	}

	log.Printf("%7d | %8d || %02x | %8d | %s || %s | %02x | %8d | %s | %s", i, size, channel, sequence, vt, mode, origin, counter, at, upi)
}

func joinTime6(coarse uint32, fine uint16) time.Time {
	t := time.Unix(int64(coarse), 0).UTC()

	fs := float64(fine) / 65536.0 * 1000.0
	ms := time.Duration(fs) * time.Millisecond
	return t.Add(ms + deltaEpoch).UTC()
}