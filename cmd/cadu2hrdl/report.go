package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
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

func listCadus(r io.Reader) error {
	body := make([]byte, 1024)

	const row = "%9d | %s | %x | %x | %x | %12d | %12d | %3d | %7d | %9dKB | %s"

	var (
		count  uint64
		buffer []byte
	)
	for i := 0; ; i++ {
		_, err := r.Read(body)
		if err == io.EOF {
			break
		}
		var missing int
		if m, ok := IsMissingCadu(err); err != nil && !(ok || IsCRCError(err)) {
			return err
		} else {
			missing = m
			buffer = buffer[:0]
		}
		var (
			magic   uint32
			seq     uint32
			control uint32
			pid     uint16
			valid   string
			filler  string
		)
		var (
			hrdl uint64
			size uint64
		)
		rs := bytes.NewReader(body)
		binary.Read(rs, binary.BigEndian, &magic)
		binary.Read(rs, binary.BigEndian, &pid)
		binary.Read(rs, binary.BigEndian, &seq)
		binary.Read(rs, binary.BigEndian, &control)

		buffer = append(buffer, body[14:1022]...)
		var offset int
		for offset < len(buffer) {
			if ix := bytes.Index(buffer[offset:], Word); ix < 0 {
				break
			} else {
				cut := offset + ix + WordLen
				if len(buffer[cut:]) >= 4 {
					hrdl++
					size += uint64(binary.LittleEndian.Uint32(buffer[cut:]))
					offset = cut + WordLen
				} else {
					break
				}
			}
		}
		buffer = buffer[offset:]
		count += hrdl

		if err != nil {
			valid = err.Error()
		} else {
			valid = "-"
		}

		log.Printf(row, i, filler, magic, pid, control, seq>>8, missing, hrdl, count, size>>10, valid)
	}
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
		n, err := r.Read(body)
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
		zs[i].Size += n - 12
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
	var total, size, errCRC, errMissing, invalid int
	for i := 1; ; i++ {
		n, err := r.Read(body)

		size += n
		if err != nil {
			if err == io.EOF {
				break
			}
			if n, ok := IsMissingCadu(err); ok {
				errMissing += n
			} else if IsCRCError(err) {
				errCRC++
			} else {
				return err
			}
		}
		total++
		if raw {
			log.Printf("%6d | %x | %x | %x", i, body[:8], body[8:24], body[24:48])
		} else {
			if err := dumpErdle(i, bytes.NewReader(body[:n])); err != nil {
				if err == ErrInvalid {
					invalid++
				} else {
					return err
				}
			}
		}
	}
	log.Printf("%d HRDL packets, %d invalid HRDL (%d KB, %d missing cadus, %d corrupted)", total, invalid, size>>10, errMissing, errCRC)
	return nil
}

func dumpErdle(i int, r io.Reader) error {
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
		cksum    uint32
		acqtime  time.Duration
		auxtime  time.Duration
	)
	binary.Read(r, binary.LittleEndian, &sync)
	binary.Read(r, binary.LittleEndian, &size)

	digest := SumHRDL()
	rw := io.TeeReader(r, digest)
	binary.Read(rw, binary.LittleEndian, &channel)
	binary.Read(rw, binary.LittleEndian, &source)
	binary.Read(rw, binary.LittleEndian, &spare)
	binary.Read(rw, binary.LittleEndian, &sequence)
	binary.Read(rw, binary.LittleEndian, &coarse)
	binary.Read(rw, binary.LittleEndian, &fine)
	binary.Read(rw, binary.LittleEndian, &spare)

	vt := joinTime6(coarse, fine).Format("2006-01-02 15:04:05.000")

	binary.Read(rw, binary.LittleEndian, &property)
	binary.Read(rw, binary.LittleEndian, &stream)
	binary.Read(rw, binary.LittleEndian, &counter)
	binary.Read(rw, binary.LittleEndian, &acqtime)
	binary.Read(rw, binary.LittleEndian, &auxtime)
	binary.Read(rw, binary.LittleEndian, &origin)

	at := gpsEpoch.Add(acqtime).Format("2006-01-02 15:04:05.000")

	var mode string
	rest := int(size) - (16 + 24) //16(VMU header length) + 24(HRD common header length)
	if origin == source {
		mode = "realtime"
	} else {
		mode = "playback"
	}
	var upi string
	switch channel {
	case 3:
		bs := make([]byte, 32)
		if _, err := io.ReadFull(rw, bs); err == nil {
			upi = string(bytes.Trim(bs, "\x00"))
		} else {
			upi = "SCIENCE"
		}
		rest -= len(bs)
	case 1, 2:
		bs := make([]byte, 52)
		if _, err := io.ReadFull(rw, bs); err == nil {
			upi = string(bytes.Trim(bs[20:], "\x00"))
		} else {
			upi = "IMAGE"
		}
		rest -= len(bs)
	}
	var err error
	if _, err = io.CopyN(ioutil.Discard, rw, int64(rest)); err != nil {
		return ErrInvalid
	}
	if err = binary.Read(r, binary.LittleEndian, &cksum); err != nil {
		return ErrInvalid
	}

	const row = "%7d | %8d || %02x | %8d | %s || %s | %02x | %8d | %s | %s || %08x | %08x | %s"
	valid := "ok"
	if cksum != digest.Sum32() {
		err = ErrInvalid
		valid = "bad"
	}
	log.Printf(row, i, size, channel, sequence, vt, mode, origin, counter, at, upi, cksum, digest.Sum32(), valid)
	return err
}

func joinTime6(coarse uint32, fine uint16) time.Time {
	t := time.Unix(int64(coarse), 0).UTC()

	fs := float64(fine) / 65536.0 * 1000.0
	ms := time.Duration(fs) * time.Millisecond
	return t.Add(ms + deltaEpoch).UTC()
}
