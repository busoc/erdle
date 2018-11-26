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

type pool struct {
	addr  string
	queue chan net.Conn

	writePacket func(io.Writer, uint16, []byte) (int, error)

	sequence uint32
	preamble uint16
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
	var (
		f func(io.Writer, uint16, []byte) (int, error)
		p pool
	)
	switch i {
	case 0, 1, 2, 255:
		f = p.writeHadock
	case -1:
		f = p.writeHRDL
	default:
		return nil, fmt.Errorf("invalid instance")
	}
	q := make(chan net.Conn, n)
	for i := 0; i < n; i++ {
		c, err := net.Dial(protoFromAddr(a))
		if err != nil {
			return nil, err
		}
		q <- c
	}
	p = pool{
		addr:        a,
		queue:       q,
		writePacket: f,
		preamble:    uint16(hdkVersion)<<12 | uint16(vmuVersion)<<8 | uint16(i),
	}
	return &p, nil
}

func (p *pool) writeHRDL(w io.Writer, _ uint16, bs []byte) (int, error) {
	var buf bytes.Buffer

	buf.Write(Word)
	binary.Write(&buf, binary.LittleEndian, uint32(len(bs))-4)
	buf.Write(bs)

	n, err := io.Copy(w, &buf)
	return int(n), err
}

func (p *pool) writeHadock(w io.Writer, next uint16, bs []byte) (int, error) {
	var buf bytes.Buffer

	buf.Write(Word)
	binary.Write(&buf, binary.BigEndian, p.preamble)
	binary.Write(&buf, binary.BigEndian, next)
	binary.Write(&buf, binary.BigEndian, uint32(len(bs)))
	buf.Write(bs)
	binary.Write(&buf, binary.BigEndian, uint16(0xFFFF))

	n, err := io.Copy(w, &buf)
	return int(n), err
}

func (p *pool) Write(bs []byte) (int, error) {
	c, next, err := p.pop()
	if err != nil {
		return 0, err
	}

	n, err := p.writePacket(c, next, bs)
	if err != nil {
		c.Close()
	} else {
		p.push(c)
	}
	return n, err
}

func (p *pool) pop() (net.Conn, uint16, error) {
	var (
		n   uint16
		c   net.Conn
		err error
	)
	x := atomic.AddUint32(&p.sequence, 1)
	if v := x >> 16; v > 0 {
		x = v
	}
	n = uint16(x)
	select {
	case x := <-p.queue:
		c = x
	default:
		c, err = net.Dial("tcp", p.addr)
	}
	return c, n, err
}

func (p *pool) push(c net.Conn) {
	select {
	case p.queue <- c:
	default:
		c.Close()
	}
}

func main() {
	q := flag.Int("q", 64, "queue size before dropping HRDL packets")
	c := flag.Int("c", 8, "number of connections to remote server")
	i := flag.Int("i", -1, "hadock instance used")
	k := flag.Bool("k", false, "keep invalid HRDL packets (bad sum only)")
	// f := flag.Bool("f", false, "fill missing cadus with zeros (not recommended)")
	log.SetFlags(0)
	log.SetOutput(os.Stdout)
	flag.Parse()

	p, err := NewPool(flag.Arg(1), *c, *i)
	if err != nil {
		log.Fatalln(err)
	}
	queue, err := reassemble(flag.Arg(0), *q)
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
			count++
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

func reassemble(addr string, n int) (<-chan []byte, error) {
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
