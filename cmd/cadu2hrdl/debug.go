package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/juju/ratelimit"
	"github.com/midbel/ringbuffer"
)

func byChannel(bs []byte) (byte, uint32) {
	return bs[0], binary.LittleEndian.Uint32(bs[4:])
}

func byOrigin(bs []byte) (byte, uint32) {
	return bs[39], binary.LittleEndian.Uint32(bs[19:])
}

func indexPackets(r io.Reader, by string) error {
	var byFunc func(bs []byte) (byte, uint32, time.Time)

	hdrLen := WordLen + VMULen
	switch by {
	case "mix":
		byFunc = func(bs []byte) (byte, uint32, time.Time) {
			id, seq := byOrigin(bs)

			coarse := binary.LittleEndian.Uint32(bs[8:])
			fine := binary.LittleEndian.Uint16(bs[12:])

			return id, seq, joinTime6(coarse, fine)
		}
		hdrLen += HDRLen
	case "origin", "source":
		byFunc = func(bs []byte) (byte, uint32, time.Time) {
			id, seq := byOrigin(bs)
			e := binary.LittleEndian.Uint64(bs[23:])
			return id, seq, gpsEpoch.Add(time.Duration(e))
		}
		hdrLen += HDRLen
	case "channel", "":
		byFunc = func(bs []byte) (byte, uint32, time.Time) {
			id, seq := byChannel(bs)

			coarse := binary.LittleEndian.Uint32(bs[8:])
			fine := binary.LittleEndian.Uint16(bs[12:])

			return id, seq, joinTime6(coarse, fine)
		}
	default:
		return fmt.Errorf("unrecognized value %s", by)
	}
	body := make([]byte, 1024)
	sum := adler32.Checksum(body)

	var (
		buffer  []byte
		pid     int
		elapsed time.Duration
	)
	step := time.Second / 4096
	for j := 1; ; j++ {
		_, err := r.Read(body)
		if err == io.EOF {
			break
		}
		if s := adler32.Checksum(body); s == sum {
			buffer = buffer[:0]
			continue
		}
		var missing int
		if err != nil {
			if n, ok := IsMissingCadu(err); ok {
				missing = n
			} else if IsCRCError(err) {

			} else {
				return err
			}
		}
		elapsed += step
		cid := binary.BigEndian.Uint32(body[6:]) >> 8
		buffer = append(buffer, body[14:1022]...)
		var offset int
		for i := 1; offset < len(buffer); i++ {
			if ix := bytes.Index(buffer[offset:], Word); ix < 0 {
				break
			} else {
				cut := offset + ix + WordLen
				if len(buffer[cut:]) >= hdrLen {
					pid++
					size := uint64(binary.LittleEndian.Uint32(buffer[cut:]))

					id, seq, w := byFunc(buffer[cut+WordLen:])
					when := w.Format("2006-01-02 15:04:05.000")
					log.Printf("%9d || %16s | %9d | %9d | %9d || %8d | %02x | %8d | %s", pid, elapsed, j, cid, missing, size, id, seq, when)

					offset = cut + WordLen + VMULen
				} else {
					break
				}
			}
		}
		buffer = buffer[offset:]
	}
	return nil
}

func inspectCadus(rs io.Reader, skip int) error {
	var (
		size    uint64
		average uint64
		filler  uint64
		prefix  uint64
		missing uint64
		invalid uint64
		total   uint64
		hrdl    uint64
		buffer  []byte
	)

	r := CaduReader(rs, skip)
	body := make([]byte, 1008)
	sum := adler32.Checksum(body)
	for {
		n, err := r.Read(body)
		size += uint64(n)
		if n > 0 {
			total++
		}
		if err == io.EOF {
			break
		}
		if err == nil {
			if sum == adler32.Checksum(body) {
				filler++
				size -= uint64(n)
				continue
			}
			var offset int
			if bytes.HasPrefix(body, Word) {
				buffer = buffer[:0]
				offset += WordLen
				prefix++
				hrdl++

				average += uint64(binary.LittleEndian.Uint32(body[WordLen:]))
			}
			buffer = append(buffer, body...)
			for offset < len(buffer) {
				if ix := bytes.Index(buffer[offset:], Word); ix < 0 {
					buffer = buffer[offset:]
					break
				} else {
					hrdl++
					if len(buffer[offset+ix:]) >= 8 {
						average += uint64(binary.LittleEndian.Uint32(buffer[offset+ix+WordLen:]))
					}
					offset = offset + ix + WordLen
				}
			}
		} else if IsCRCError(err) {
			invalid++
		} else if n, ok := IsMissingCadu(err); ok {
			missing += uint64(n)
		} else {
			return err
		}
	}
	const row = "%7d cadus (%3dKB), %8d missing, %4d invalid, %4d filler, %7d packets (avg: %4dKB, sum: %6dKB)"
	var avg uint64
	if hrdl > 0 {
		avg = (average / hrdl) >> 10
	}
	log.Printf(row, total, size>>10, missing, invalid, filler, hrdl, avg, average>>10)
	return nil
}

func replayCadus(addr string, r io.Reader, rate int) (*coze, error) {
	c, err := net.Dial(protoFromAddr(addr))
	if err != nil {
		return nil, err
	}
	defer c.Close()

	var w io.Writer
	if rate > 0 {
		w = ratelimit.Writer(c, ratelimit.NewBucketWithRate(float64(rate), int64(rate)))
	} else {
		w = c
	}

	tick := time.Tick(time.Second)
	logger := log.New(os.Stderr, "[replay] ", 0)

	var (
		size, count int
		z           coze
	)
	for {
		if n, err := io.CopyN(w, r, 1024); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		} else {
			size += int(n)
			count++
		}
		select {
		case <-tick:
			logger.Printf("%6d packets, %dKB", count, size>>10)
			z.Count += count
			z.Size += size
			size, count = 0, 0
		default:
		}
	}
	z.Count += count
	z.Size += size
	return &z, nil
}

func traceCadus(addr string) error {
	a, err := net.ResolveUDPAddr(protoFromAddr(addr))
	if err != nil {
		return err
	}
	c, err := net.ListenUDP("udp", a)
	if err != nil {
		return err
	}
	if err := c.SetReadBuffer(16 << 20); err != nil {
		return err
	}
	tick := time.Tick(time.Second)
	logger := log.New(os.Stderr, "[debug] ", 0)

	rg := ringbuffer.NewRingSize(64<<20, 8<<20)
	go func() {
		io.CopyBuffer(rg, c, make([]byte, 1024))
	}()
	var (
		count    int
		size     int
		errSize  int
		errMagic int
		missing  uint32
		prev     uint32
	)
	body := make([]byte, 1024)
	for {
		n, err := c.Read(body)
		if err != nil {
			return err
		}

		switch {
		case n < len(body):
			errSize++
		case !bytes.Equal(body[:4], Magic):
			errMagic++
		}
		curr := binary.BigEndian.Uint32(body[6:]) >> 8
		if diff := (curr - prev) & 0xFFFFFF; curr != diff && diff > 1 {
			missing += diff
		}
		prev = curr

		count++
		size += n
		select {
		case <-tick:
			logger.Printf("%6d packets, %8d missing, %8d size error, %8d magic error, %6dKB", count, missing, errSize, errMagic, size)
			count, size, missing, errSize, errMagic = 0, 0, 0, 0, 0
		default:
		}
	}
	return nil
}

func dumpPackets(queue <-chan []byte, i int) error {
	var kind, instance string
	switch i {
	case 0, 1, 2, 255:
		kind = "HDK"
		switch i {
		case 0:
			instance = "TEST"
		case 1, 2:
			instance = fmt.Sprintf("SIM%d", i)
		case 255:
			instance = "OPS"
		}
	case -1:
		kind, instance = "HRDL", "-"
	default:
		return fmt.Errorf("unsupported instance %d", i)
	}
	ps := make(map[byte]uint32)

	for i := 1; ; i++ {
		bs, ok := <-queue
		if !ok {
			return nil
		}
		var missing uint32

		c := bs[0]
		curr := binary.LittleEndian.Uint32(bs[4:])
		if diff := curr - ps[c]; diff > 1 && diff < curr {
			missing = diff
		}
		ps[c] = curr
		var chk uint32
		for i := 0; i < len(bs)-4; i++ {
			chk += uint32(bs[i])
		}
		sum := binary.LittleEndian.Uint32(bs[len(bs)-4:])
		log.Printf("%5s | %5s | %7d | %8d | %7d | %12d | %x | %08x | %08x", kind, instance, i, len(bs)-4, curr, missing, bs[:16], sum, chk)
	}
	return nil
}

func debugHRDL(a string, n, i int) (<-chan []byte, error) {
	c, err := net.Listen(protoFromAddr(a))
	if err != nil {
		return nil, err
	}

	q := make(chan []byte, n)
	go func() {
		defer func() {
			close(q)
			c.Close()
		}()
		for {
			c, err := c.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReaderSize(c, 8<<20)

				var size uint32
				for {
					binary.Read(r, binary.LittleEndian, &size)
					binary.Read(r, binary.LittleEndian, &size)

					bs := make([]byte, size+4)
					if _, err := io.ReadFull(r, bs); err != nil {
						return
					}
					select {
					case q <- bs:
					default:
					}
				}
			}(c)
		}
	}()
	return q, nil
}
