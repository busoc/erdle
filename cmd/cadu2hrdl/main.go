package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
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
	"time"

	"github.com/busoc/erdle"
	"github.com/midbel/ringbuffer"
	"golang.org/x/sync/errgroup"
)

var ErrSkip = errors.New("skip")

var Word = []byte{0xf8, 0x2e, 0x35, 0x53}

const WordLen = 4

const (
	hdkInstance = 0
	hdkVersion  = 0
	vmuVersion  = 2
)

type conn struct {
	net.Conn
	next     uint16
	preamble uint16

	writePacket func(*conn, []byte) (int, error)
}

func client(a string, i int) (net.Conn, error) {
	var (
		preamble  uint16
		writeFunc func(*conn, []byte) (int, error)
	)
	switch i {
	case 0, 1, 2, 255:
		preamble = uint16(hdkVersion)<<12 | uint16(vmuVersion)<<8 | uint16(i)
		writeFunc = writeHadock
	case -1:
		writeFunc = writeHRDL
	default:
		return nil, fmt.Errorf("invalid instance (%d)", i)
	}
	c, err := net.Dial(protoFromAddr(a))
	if err != nil {
		return nil, err
	}
	return &conn{
		Conn:        c,
		preamble:    preamble,
		writePacket: writeFunc,
	}, nil
}

func (c *conn) Write(bs []byte) (int, error) {
	defer func() { c.next++ }()
	return c.writePacket(c, bs)
}

func writeHRDL(c *conn, bs []byte) (int, error) {
	var buf bytes.Buffer

	buf.Write(Word)
	binary.Write(&buf, binary.LittleEndian, uint32(len(bs))-4)
	buf.Write(bs)

	n, err := io.Copy(c.Conn, &buf)
	return int(n), err
}

func writeHadock(c *conn, bs []byte) (int, error) {
	var buf bytes.Buffer

	buf.Write(Word)
	binary.Write(&buf, binary.BigEndian, c.preamble)
	binary.Write(&buf, binary.BigEndian, c.next)
	binary.Write(&buf, binary.BigEndian, uint32(len(bs)))
	buf.Write(bs)
	binary.Write(&buf, binary.BigEndian, uint16(0xFFFF))

	n, err := io.Copy(c.Conn, &buf)
	return int(n), err
}

type pool struct {
	addr     string
	instance int
	queue    chan net.Conn
}

func protoFromAddr(a string) (string, string) {
	u, err := url.Parse(a)
	if err != nil {
		return "tcp", a
	}
	return strings.ToLower(u.Scheme), u.Host
}

func NewPool(a string, n, i int) (*pool, error) {
	if n <= 1 {
		return nil, fmt.Errorf("number of connections too small")
	}
	q := make(chan net.Conn, n)
	for j := 0; j < n; j++ {
		c, err := client(a, i)
		if err != nil {
			return nil, err
		}
		q <- c
	}
	p := pool{
		addr:     a,
		queue:    q,
		instance: i,
	}
	return &p, nil
}

func (p *pool) Write(bs []byte) (int, error) {
	c, err := p.pop()
	if err != nil {
		return 0, err
	}

	n, err := c.Write(bs)
	if err != nil {
		c.Close()
	} else {
		p.push(c)
	}
	return n, err
}

func (p *pool) pop() (net.Conn, error) {
	select {
	case c := <-p.queue:
		return c, nil
	default:
		return client(p.addr, p.instance)
	}
}

func (p *pool) push(c net.Conn) {
	select {
	case p.queue <- c:
	default:
		c.Close()
	}
}

func main() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	g := flag.String("g", "", "debug")
	q := flag.Int("q", 64, "queue size before dropping HRDL packets")
	c := flag.Int("c", 8, "number of connections to remote server")
	i := flag.Int("i", -1, "hadock instance used")
	k := flag.Bool("k", false, "keep invalid HRDL packets (bad sum only)")
	x := flag.String("x", "", "proxy incoming cadus to a remote address")
	flag.Parse()
	switch *g {
	default:
		log.Fatalf("unsupported debug mode %s", *g)
	case "hrdl":
		queue, err := debugHRDL(flag.Arg(0), *q)
		if err != nil {
			log.Fatalln(err)
		}
		dumpPackets(queue)
	case "cadu", "vcdu":
		queue, err := reassemble(flag.Arg(0), "", *q)
		if err != nil {
			log.Fatalln(err)
		}
		dumpPackets(validate(queue, *q, *k))
	case "":
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

func dumpPackets(queue <-chan []byte) {
	ps := make(map[byte]uint32)
	for i := 1; ; i++ {
		select {
		case bs, ok := <-queue:
			if !ok {
				return
			}
			var missing uint32

			c := bs[0]
			curr := binary.LittleEndian.Uint32(bs[4:])
			if diff := curr - ps[c]; diff > 1 {
				missing = diff
			}
			ps[c] = curr
			log.Printf("%7d | %8d | %7d | %12d | %x | %x | %x", i, len(bs)-4, curr, missing, bs[:16], bs[16:40], md5.Sum(bs[:len(bs)-4]))
		}
	}
}

func debugHRDL(a string, n int) (<-chan []byte, error) {
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
				if count == 0 {
					break
				}
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

	go func() {
		const row = "%6d packets, %4d skipped, %4d dropped, %7d bytes discarded"
		defer func() {
			c.Close()
			close(q)
		}()
		logger := log.New(os.Stderr, "[assemble] ", 0)

		r := erdle.NewReader(rg, false)
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
				return
			}
			select {
			case <-tick:
				if count == 0 && skipped == 0 && dropped == 0 {
					break
				}
				logger.Printf(row, count, skipped, dropped, size)
				size, skipped, dropped, count = 0, 0, 0, 0
			default:
			}
		}
	}()
	return q, nil
}

func nextPacket(r io.Reader, rest []byte) ([]byte, []byte, error) {
	var offset int

	block, buffer := make([]byte, 1008), rest
	rest = rest[:0]
	for {
		n, err := r.Read(block)
		if err != nil {
			if !erdle.IsMissingCadu(err) {
				return nil, nil, err
			}
			continue
		}
		buffer = append(buffer, block[:n]...)
		if bytes.Equal(buffer[:WordLen], Word) {
			break
		}
		if len(buffer[offset:]) > WordLen {
			if ix := bytes.Index(buffer[offset:], Word); ix >= 0 {
				buffer = buffer[offset+ix:]
				break
			}
		}
		offset += n - WordLen
	}
	offset = WordLen
	for {
		n, err := r.Read(block)
		if err != nil {
			if !erdle.IsMissingCadu(err) {
				return nil, nil, err
			} else {
				return nil, nil, ErrSkip
			}
		}
		buffer = append(buffer, block[:n]...)
		if ix := bytes.Index(buffer[offset:], Word); ix >= 0 {
			buffer, rest = buffer[:offset+ix], buffer[offset+ix:]
			break
		}
		offset += n - WordLen
	}
	return buffer, rest, nil
}
