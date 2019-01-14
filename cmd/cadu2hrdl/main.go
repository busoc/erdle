package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/midbel/ringbuffer"
	"golang.org/x/sync/errgroup"
)

var ErrSkip = errors.New("skip")

var (
	Word  = []byte{0xf8, 0x2e, 0x35, 0x53}
	Stuff = []byte{0xf8, 0x2e, 0x35, 0xaa, 0x53}
	Magic = []byte{0x1a, 0xcf, 0xfc, 0x1d}
)

const WordLen = 4

const (
	hdkInstance = 0
	hdkVersion  = 0
	vmuVersion  = 2
)

func protoFromAddr(a string) (string, string) {
	u, err := url.Parse(a)
	if err != nil {
		return "tcp", a
	}
	return strings.ToLower(u.Scheme), u.Host
}

func main() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	m := flag.String("m", "", "mode")
	b := flag.String("b", "", "by")
	t := flag.String("t", "", "packet type")
	q := flag.Int("q", 64, "queue size before dropping HRDL packets")
	c := flag.Int("c", 8, "number of connections to remote server")
	i := flag.Int("i", -1, "hadock instance used")
	k := flag.Bool("k", false, "keep invalid HRDL packets (bad sum only)")
	x := flag.String("x", "", "proxy incoming cadus to a remote address")
	flag.Parse()
	switch *m {
	default:
		log.Fatalf("unsupported mode %s", *m)
	case "replay":
		files := make([]string, flag.NArg()-1)
		for i := 1; i < flag.NArg(); i++ {
			files[i-1] = flag.Arg(i)
		}
		r, err := MultiReader(files)
		if err != nil {
			log.Fatalln(err)
		}
		if err := replayCadus(flag.Arg(0), VCDUReader(r, *c), *q); err != nil {
			log.Fatalln(err)
		}
	case "replay+pcap":
		r, err := PCAPReader(flag.Arg(1), *x)
		if err != nil {
			log.Println(err)
		}
		if err := replayCadus(flag.Arg(0), VCDUReader(r, 0), *q); err != nil {
			log.Fatalln(err)
		}
	case "list":
		r, err := MultiReader(flag.Args())
		if err != nil {
			log.Fatalln(err)
		}
		switch *t {
		case "", "hrdl":
			err = listHRDL(HRDLReader(r, *c), *k)
		case "cadu":
			err = fmt.Errorf("not yet implemented")
		default:
			log.Fatalln("unknown packet type %s", *t)
		}
		if err != nil {
			log.Fatalln(err)
		}
	case "list+pcap":
		r, err := PCAPReader(flag.Arg(0), *x)
		if err != nil {
			log.Fatalln(err)
		}
		switch *t {
		case "", "hrdl":
			err = listHRDL(HRDLReader(r, 0), *k)
		case "cadu":
			err = fmt.Errorf("not yet implemented")
		default:
			log.Fatalln("unknown packet type %s", *t)
		}
		if err != nil {
			log.Fatalln(err)
		}
	case "count":
		r, err := MultiReader(flag.Args())
		if err != nil {
			log.Fatalln(err)
		}
		switch *t {
		case "", "hrdl":
			err = countHRDL(HRDLReader(r, *c), *b)
		case "cadu":
			err = countCadus(VCDUReader(r, 0))
		default:
			log.Fatalln("unknown packet type %s", *t)
		}
		if err != nil {
			log.Fatalln(err)
		}
	case "count+pcap":
		r, err := PCAPReader(flag.Arg(0), *x)
		if err != nil {
			log.Fatalln(err)
		}
		switch *t {
		case "", "hrdl":
			err = countHRDL(HRDLReader(r, 0), *b)
		case "cadu":
			err = countCadus(VCDUReader(r, 0))
		default:
			log.Fatalln("unknown packet type %s", *t)
		}
		if err != nil {
			log.Fatalln(err)
		}
	case "debug":
		if err := traceCadus(flag.Arg(0)); err != nil {
			log.Fatalln(err)
		}
	case "hrdp":
		hr, err := NewHRDP(flag.Arg(1))
		if err != nil {
			log.Fatalln(err)
		}
		queue, err := reassemble(flag.Arg(0), "", *q)
		if err != nil {
			log.Fatalln(err)
		}
		tick := time.Tick(time.Second)
		var (
			count int
			size  int
			fail  int
		)
		logger := log.New(os.Stderr, "[hrdp] ", 0)
		for bs := range validate(queue, *q, *k) {
			if n, err := hr.Write(bs); err != nil {
				fail++
				log.Println(err)
			} else {
				count++
				size += n
			}
			select {
			case <-tick:
				logger.Printf("%6d packets (%s), %7dKB, %6d failures", count, hr.Filename(), size>>10, fail)
				count, size, fail = 0, 0, 0
			default:
			}
		}
	case "hrdl", "hadock":
		queue, err := debugHRDL(flag.Arg(0), *q, *i)
		if err != nil {
			log.Fatalln(err)
		}
		if err := dumpPackets(queue, *i); err != nil {
			log.Fatalln(err)
		}
	case "cadu", "vcdu":
		queue, err := reassemble(flag.Arg(0), "", *q)
		if err != nil {
			log.Fatalln(err)
		}
		if err := dumpPackets(validate(queue, *q, *k), *i); err != nil {
			log.Fatalln(err)
		}
	case "", "relay":
		p, err := NewPool(flag.Arg(1), *c, *i)
		if err != nil {
			log.Fatalln(err)
		}
		queue, err := reassemble(flag.Arg(0), *x, *q)
		if err != nil {
			log.Fatalln(err)
		}

		var gp errgroup.Group
		for bs := range validate(queue, *q, *k) {
			xs := bs
			gp.Go(func() error {
				_, err := p.Write(xs)
				return err
			})
		}
		if err := gp.Wait(); err != nil {
			log.Fatalln(err)
		}
	}
}

func validate(queue <-chan []byte, n int, keep bool) <-chan []byte {
	var (
		count     int64
		size      int64
		dropped   int64
		errLength int64
		errSum    int64
	)
	go func() {
		const row = "%6d packets, %4d dropped, %6dKB, %4d valid, %4d length error, %4d checksum error"
		logger := log.New(os.Stderr, "[validate] ", 0)

		tick := time.Tick(time.Second)
		for range tick {
			valid := count - errLength - errSum
			if count > 0 || dropped > 0 {
				logger.Printf(row, atomic.LoadInt64(&count), atomic.LoadInt64(&dropped), atomic.LoadInt64(&size)>>10, atomic.LoadInt64(&valid), atomic.LoadInt64(&errLength), atomic.LoadInt64(&errSum))

				atomic.StoreInt64(&count, 0)
				atomic.StoreInt64(&dropped, 0)
				atomic.StoreInt64(&errLength, 0)
				atomic.StoreInt64(&errSum, 0)
				atomic.StoreInt64(&size, 0)
			}
		}
	}()
	q := make(chan []byte, n)
	go func() {
		defer close(q)

		for bs := range queue {
			atomic.AddInt64(&size, int64(len(bs)))
			z := int(binary.LittleEndian.Uint32(bs[4:])) + 12
			switch {
			default:
			case z < len(bs):
				bs = bs[:z]
			case z > len(bs):
				atomic.AddInt64(&errLength, 1)
				continue
			}
			if keep {
				sum := binary.LittleEndian.Uint32(bs[z-4:])
				var chk uint32
				for i := 8; i < z-4; i++ {
					chk += uint32(bs[i])
				}
				if chk != sum {
					atomic.AddInt64(&errSum, 1)
				}
			}
			select {
			case q <- bytes.Replace(bs[8:], Stuff, Word, -1): //bs[8:]:
				atomic.AddInt64(&count, 1)
			default:
				atomic.AddInt64(&dropped, 1)
			}
		}
	}()
	return q
}

func reassemble(addr, proxy string, n int) (<-chan []byte, error) {
	a, err := net.ResolveUDPAddr(protoFromAddr(addr))
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", a)
	if err != nil {
		return nil, err
	}
	if err := c.SetReadBuffer(8 << 20); err != nil {
		return nil, err
	}
	q := make(chan []byte, n)

	rg := ringbuffer.NewRingSize(64<<20, 0)
	go func() {
		io.CopyBuffer(rg, c, make([]byte, 1024))
	}()

	var r io.Reader = rg
	switch x, err := net.Dial(protoFromAddr(proxy)); {
	case err == nil:
		r = io.TeeReader(r, x)
	case err != nil && proxy == "":
	default:
		return nil, err
	}

	var dropped, skipped, size, count, errCRC, errMissing int64
	go func() {
		const row = "%6d packets, %4d skipped, %4d dropped, %7d missing, %7d crc error, %7d bytes discarded"

		logger := log.New(os.Stderr, "[assemble] ", 0)
		tick := time.Tick(5 * time.Second)
		for range tick {
			if count > 0 || skipped > 0 {
				logger.Printf(row, atomic.LoadInt64(&count), atomic.LoadInt64(&skipped), atomic.LoadInt64(&dropped), atomic.LoadInt64(&errMissing), atomic.LoadInt64(&errCRC), atomic.LoadInt64(&size))

				atomic.StoreInt64(&size, 0)
				atomic.StoreInt64(&skipped, 0)
				atomic.StoreInt64(&errMissing, 0)
				atomic.StoreInt64(&errCRC, 0)
				atomic.StoreInt64(&dropped, 0)
				atomic.StoreInt64(&count, 0)
			}
		}
	}()

	go func() {
		defer func() {
			c.Close()
			close(q)
		}()
		var buffer, rest []byte
		r := CaduReader(r, 0)
		for {
			buffer, rest, err = nextPacket(r, rest)
			if err == nil {
				if len(buffer) == 0 {
					continue
				}
				select {
				case q <- buffer:
					atomic.AddInt64(&count, 1)
				default:
					atomic.AddInt64(&dropped, 1)
					atomic.AddInt64(&size, int64(len(buffer)))
				}
			} else if n, ok := IsMissingCadu(err); ok {
				atomic.AddInt64(&errMissing, int64(n))
				atomic.AddInt64(&skipped, 1)
				atomic.AddInt64(&size, int64(len(buffer)))
			} else if IsCRCError(err) {
				atomic.AddInt64(&errCRC, 1)
				atomic.AddInt64(&skipped, 1)
				atomic.AddInt64(&size, int64(len(buffer)))
			} else {
				log.Println(err)
				return
			}
		}
	}()
	return q, nil
}
