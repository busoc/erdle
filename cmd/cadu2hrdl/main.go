package main

import (
	"bufio"
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
	"path/filepath"
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

	hr.file, err = openFile(dir, time.Now())
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
		h.file, err = openFile(h.datadir, t)
		h.writer.Reset(h.file)
	default:
	}
	n, c := time.Now().Unix(), bs[8]

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint32(len(bs)+14))
	binary.Write(&buf, binary.BigEndian, uint16(0))
	binary.Write(&buf, binary.BigEndian, h.payload)
	binary.Write(&buf, binary.BigEndian, uint8(c))
	binary.Write(&buf, binary.BigEndian, uint32(n))
	binary.Write(&buf, binary.BigEndian, uint8(0))
	binary.Write(&buf, binary.BigEndian, uint32(n))
	binary.Write(&buf, binary.BigEndian, uint8(0))
	buf.Write(bs)

	if _, err := io.Copy(h.writer, &buf); err != nil {
		return 0, err
	}
	return len(bs), nil
}

func openFile(dir string, t time.Time) (*os.File, error) {
	y, d, h := t.Year(), t.YearDay(), t.Hour()
	dir = filepath.Join(dir, fmt.Sprintf("%4d", y), fmt.Sprintf("%03d", d), fmt.Sprintf("%02d", h))
	if err := os.MkdirAll(dir, 0755); err != nil && !os.IsExist(err) {
		return nil, err
	}
	min := t.Truncate(time.Minute * 5).Minute()
	n := fmt.Sprintf("rt_%02d_%02d.dat", min, min+4)
	return os.Create(filepath.Join(dir, n))
}

func main() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	m := flag.String("m", "", "mode")
	q := flag.Int("q", 64, "queue size before dropping HRDL packets")
	c := flag.Int("c", 8, "number of connections to remote server")
	i := flag.Int("i", -1, "hadock instance used")
	k := flag.Bool("k", false, "keep invalid HRDL packets (bad sum only)")
	x := flag.String("x", "", "proxy incoming cadus to a remote address")
	flag.Parse()
	switch *m {
	default:
		log.Fatalf("unsupported mode %s", *m)
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

		r := erdle.NewReader(r, false)
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
