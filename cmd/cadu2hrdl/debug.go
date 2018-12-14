package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/juju/ratelimit"
	"github.com/midbel/ringbuffer"
)

func replayCadus(addr string, r io.Reader, rate int) error {
	c, err := net.Dial(protoFromAddr(addr))
	if err != nil {
		return err
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

	var size, count int

	for {
		if n, err := io.CopyN(w, r, 1024); err != nil {
			if err == io.EOF {
				break
			}
			return err
		} else {
			size += int(n)
			count++
		}
		select {
		case <-tick:
			logger.Printf("%6d packets, %dKB", count, size>>10)
			size, count = 0, 0
		default:
		}
	}
	return nil
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
