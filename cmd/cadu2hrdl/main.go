package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
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
		if err := replayCadus(flag.Arg(0), files, *q, *c); err != nil {
			log.Fatalln(err)
		}
	case "count":
		if err := countHRDL(flag.Args(), *b, *c); err != nil {
			log.Fatalln(err)
		}
	case "list":
		if err := listHRDL(flag.Args(), *c, *k); err != nil {
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
	const row = "%6d packets, %4d dropped, %6dKB, %4d valid, %4d length error, %4d checksum error"
	q := make(chan []byte, n)
	go func() {
		logger := log.New(os.Stderr, "[validate] ", 0)
		defer close(q)
		tick := time.Tick(time.Second)

		var (
			count     int
			size      int
			dropped   int
			errLength int
			errSum    int
		)
		for bs := range queue {
			size += len(bs)

			z := int(binary.LittleEndian.Uint32(bs[4:])) + 12
			switch {
			default:
			case z < len(bs):
				bs = bs[:z]
			case z > len(bs):
				errLength++
				continue
			}
			if keep {
				sum := binary.LittleEndian.Uint32(bs[z-4:])
				var chk uint32
				for i := 8; i < z-4; i++ {
					chk += uint32(bs[i])
				}
				if chk != sum {
					errSum++
				}
			}
			select {
			case q <- bs[8:]:
				count++
			default:
				dropped++
			}
			select {
			case <-tick:
				valid := count - errLength - errSum
				logger.Printf(row, count, dropped, size>>10, valid, errLength, errSum)
				count, dropped, errLength, errSum, size = 0, 0, 0, 0, 0
			default:
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

	rg := ringbuffer.NewRingSize(64<<20, 8<<20)
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

	go func() {
		const row = "%6d packets, %4d skipped, %4d dropped, %7d bytes discarded"
		defer func() {
			c.Close()
			close(q)
		}()
		logger := log.New(os.Stderr, "[assemble] ", 0)

		r := CaduReader(r, 0)
		tick := time.Tick(10 * time.Second)
		var (
			rest    []byte
			buffer  []byte
			skipped int
			dropped int
			size    int
			count   int
		)
		for {
			buffer, rest, err = nextPacket(r, rest)
			switch err {
			case nil:
				if len(buffer) == 0 {
					break
				}
				select {
				case q <- buffer:
					count++
				default:
					dropped++
					size += len(buffer)
				}
			case ErrSkip:
				skipped++
				size += len(buffer)
			default:
				log.Println(err)
				return
			}
			select {
			case <-tick:
				logger.Printf(row, count, skipped, dropped, size)
				size, skipped, dropped, count = 0, 0, 0, 0
			default:
			}
		}
	}()
	return q, nil
}
