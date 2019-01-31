package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/midbel/cli"
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

const VCDUSize = 1024

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

var commands = []*cli.Command{
	{
		Usage: "list [-pcap] [-x filter] [-t type] [-c skip] [-k keep] <file...>",
		Short: "list cadus/HRDL packets contained in the given files",
		Run:   runList,
		Desc: `
options:

  -c COUNT   skip COUNT bytes between each packets
  -x FILTER  specify a predicate to filter packets from a capture file
  -t TYPE    specify the packet type (hrdl or cadu)
  -k         keep invalid HRDL packets
  -pcap      tell replay that the given files is a pcap file
`,
	},
	{
		Usage: "count [-pcap] [-x filter] [-t type] [-b by] [-c skip] <file...>",
		Short: "count cadus/HRDL packets contained in the given files",
		Run:   runCount,
		Desc: `
options:

  -b BY      report count by origin or by channel if type is hrdl
  -c COUNT   skip COUNT bytes between each packets
  -x FILTER  specify a predicate to filter packets from a capture file
  -t TYPE    specify the packet type (hrdl or cadu)
  -k         keep invalid HRDL packets
  -pcap      tell replay that the given files is a pcap file
`,
	},
	{
		Usage: "replay [-pcap] [-x filter] [-c skip] [-r rate] <host:port> <file...>",
		Short: "send cadus from a file to a remote host",
		Run:   runReplay,
		Desc: `
options:

  -c    COUNT   skip COUNT bytes between each packets
  -r    RATE    define the output bandwidth usage in bytes
  -x    FILTER  specify a predicate to filter packets from a capture file
  -pcap         tell replay that the given files is a pcap file
`,
	},
	{
		Usage: "store [-k keep] [-q queue] <host:port> <datadir>",
		Short: "create an archive of HRDL packets from a cadus stream",
		Run:   runStore,
		Desc: `
options:

  -q SIZE  size of the queue to store reassemble packets
  -k       store HRDL packets even if they are corrupted
`,
	},
	{
		Usage: "relay [-r rate] [-q queue] [-i instance] [-c conn] [-k keep] [-x proxy] <host:port> <host:port>",
		Short: "reassemble incoming cadus to HRDL packets",
		Run:   runRelay,
		Desc: `
options:

  -q SIZE      size of the queue to store reassembled HRDL packets
  -i INSTANCE  hadock instance
  -r RATE      outgoing bandwidth rate
  -c CONN      number of connections to open to remote host
  -x PROXY     host:port of a remote host
  -k           keep invalid HRDL packets
`,
	},
	{
		Usage: "dump [-q queue] [-i instance] [-k keep] <host:port>",
		Short: "print the raw bytes on incoming HRDL packets",
		Run:   runDump,
		Desc: `
options:

  -q SIZE      size of the queue to store reassembled HRDL packets
  -i INSTANCE  hadock instance
  -k           keep invalid HRDL packets
`,
	},
	{
		Usage: "debug [-q queue] [-i instance] <host:port>",
		Short: "print the raw bytes on incoming HRDL packets",
		Run:   runDebug,
		Desc: `
options:

  -q SIZE      size of the queue to store reassembled HRDL packets
  -i INSTANCE  hadock instance
`,
	},
	{
		Usage: "trace <host:port>",
		Short: "give statistics on incoming cadus stream",
		Run:   runTrace,
	},
	{
		Usage: "inspect [-c count] [-e every] [-p parallel] <file...>",
		Alias: []string{"dig"},
		Short: "try to analyse how HRDL are organized into cadus",
		Run:   runInspect,
		Desc: `
options:

  -c COUNT     skip COUNT bytes between each packets
  -e EVERY     create reports by slice of EVERY packets
  -p PARALLEL  create reports in parallel workers
`,
	},
	{
		Usage: "split [-d dir] <file...>",
		Short: "split packets from RT files into cadus",
		Run:   runSplit,
	},
}

const Program = "c2h"

func init() {
	cli.BuildTime = "2019-01-15 11:30:00"
	cli.Version = "0.0.1"
}

const helpText = `
{{.Name}} handles cadus from various sources (files, pcap files, network
connection(s)) to produce:

* stream of HRDL packets by reassembling them
* reports on the status of a stream

{{.Name}} can also be used to debug in realtime (or via a replay) a stream
of cadus and/or reassembled HRDL packets.

Usage:

  {{.Name}} command [arguments]

The commands are:

{{range .Commands}}{{printf "  %-9s %s" .String .Short}}
{{end}}
Use {{.Name}} [command] -h for more information about its usage.
`

func main() {
	log.SetFlags(0)
	usage := func() {
		data := struct {
			Name     string
			Commands []*cli.Command
		}{
			Name:     Program,
			Commands: commands,
		}
		t := template.Must(template.New("help").Parse(strings.TrimSpace(helpText) + "\n"))
		t.Execute(os.Stderr, data)

		os.Exit(2)
	}
	if err := cli.Run(commands, usage, nil); err != nil {
		log.Fatalln(err)
	}
}

func runSplit(cmd *cli.Command, args []string) error {
	file := cmd.Flag.String("f", filepath.Join(os.TempDir(), "cadus.dat"), "")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	w, err := os.Create(*file)
	if err != nil {
		return err
	}
	defer w.Close()

	body := make([]byte, VCDUSize)
	for _, p := range cmd.Flag.Args() {
		r, err := OpenRT(p)
		if err != nil {
			return err
		}
		_, err = io.CopyBuffer(w, r, body)
		r.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

type chunker struct {
	io.Closer

	counter uint32
	digest  hash.Hash32
	buffer  bytes.Buffer
	scanner *bufio.Scanner
}

func OpenRT(file string) (io.ReadCloser, error) {
	r, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 8<<20), 8<<20)
	s.Split(scanPackets)

	c := chunker{
		Closer:  r,
		scanner: s,
		digest:  SumVCDU(),
	}
	return &c, nil
}

func scanPackets(bs []byte, ateof bool) (int, []byte, error) {
	if ateof {
		return len(bs), bs, bufio.ErrFinalToken
	}
	if len(bs) < 4 {
		return 0, nil, nil
	}
	size := int(binary.LittleEndian.Uint32(bs)) + 4
	if len(bs) < size {
		return 0, nil, nil
	}
	vs := make([]byte, size-18)
	copy(vs, bs[18:])
	return size, vs, nil
}

func (c *chunker) Read(bs []byte) (int, error) {
	defer c.digest.Reset()

	if c.buffer.Len() == 0 {
		if !c.scanner.Scan() {
			err := c.scanner.Err()
			if err == nil {
				err = io.EOF
			}
			return 0, err
		}
		c.buffer.Write(c.scanner.Bytes())
	}
	var b bytes.Buffer
	b.Write(Magic)

	w := io.MultiWriter(&b, c.digest)

	binary.Write(w, binary.BigEndian, uint16(0x45c7))
	binary.Write(w, binary.BigEndian, c.counter<<8)
	binary.Write(w, binary.BigEndian, uint32(0xfdc33fff))
	if n, _ := io.CopyN(w, &c.buffer, 1008); n < 1008 {
		w.Write(make([]byte, 1008-n))
	}
	binary.Write(&b, binary.BigEndian, uint16(c.digest.Sum32()))

	c.counter++
	if c.counter > 0xFFFFFF {
		c.counter = 0
	}
	return io.ReadAtLeast(&b, bs, 1024)
}

func runInspect(cmd *cli.Command, args []string) error {
	count := cmd.Flag.Int("c", 0, "bytes to skip")
	every := cmd.Flag.Int("e", 4096, "stats every x packets")
	parallel := cmd.Flag.Int("p", 4, "parallel reader")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	if *every <= 0 {
		*every = 4096
	}
	if *parallel <= 0 || *parallel >= 64 {
		*parallel = 4
	}
	mr, err := MultiReader(cmd.Flag.Args())
	if err != nil {
		return err
	}
	fill := VCDUSize + *count

	var grp errgroup.Group
	sema := make(chan struct{}, *parallel)
	for {
		sema <- struct{}{}

		var b bytes.Buffer
		if _, err := io.CopyN(&b, mr, int64(*every*fill)); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		grp.Go(func() error {
			err := inspectCadus(&b, *count)
			<-sema
			return err
		})
	}
	return grp.Wait()
}

func runRelay(cmd *cli.Command, args []string) error {
	q := cmd.Flag.Int("q", 64, "queue size before dropping HRDL packets")
	c := cmd.Flag.Int("c", 8, "number of connections to remote server")
	i := cmd.Flag.Int("i", -1, "hadock instance used")
	r := cmd.Flag.Int("r", 0, "bandwidth rate")
	k := cmd.Flag.Bool("k", false, "keep invalid HRDL packets (bad sum only)")
	x := cmd.Flag.String("x", "", "proxy incoming cadus to a remote address")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	p, err := NewPool(cmd.Flag.Arg(1), *c, *i, *r)
	if err != nil {
		return err
	}
	queue, err := reassemble(cmd.Flag.Arg(0), *x, *q)
	if err != nil {
		return err
	}

	var gp errgroup.Group
	for bs := range validate(queue, *q, *k) {
		xs := bs
		gp.Go(func() error {
			_, err := p.Write(xs)
			return err
		})
	}
	return gp.Wait()
}

func runReplay(cmd *cli.Command, args []string) error {
	pcap := cmd.Flag.Bool("pcap", false, "")
	filter := cmd.Flag.String("x", "", "pcap filter")
	count := cmd.Flag.Int("c", 0, "bytes to skip before each packets")
	rate := cmd.Flag.Int("r", 8<<20, "output bandwith usage")
	inspect := cmd.Flag.Bool("i", false, "inspect vcdu stream")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	var (
		r   io.Reader
		err error
	)
	if *pcap {
		r, err = PCAPReader(cmd.Flag.Arg(1), *filter)
		*count = 0
	} else {
		files := make([]string, cmd.Flag.NArg()-1)
		for i := 1; i < cmd.Flag.NArg(); i++ {
			files[i-1] = cmd.Flag.Arg(i)
		}
		r, err = MultiReader(files)
	}
	if err != nil {
		return err
	}
	r = VCDUReader(r, *count)
	if *inspect {
		pr, pw := io.Pipe()
		defer pw.Close()
		go func() {
			defer pw.Close()
			for {
				var b bytes.Buffer
				if _, err := io.CopyN(&b, pr, int64(*rate)); err != nil {
					return
				}
				if err := inspectCadus(&b, 0); err != nil {
					return
				}
			}
			}()
		r = io.TeeReader(r, pw)
	}

	n := time.Now()
	z, err := replayCadus(cmd.Flag.Arg(0), r, *rate)
	if err == nil {
		log.Printf("%d packets (%dMB, %s)", z.Count, z.Size>>20, time.Since(n))
	}
	return err
}

func runCount(cmd *cli.Command, args []string) error {
	pcap := cmd.Flag.Bool("pcap", false, "")
	by := cmd.Flag.String("b", "", "by")
	filter := cmd.Flag.String("x", "", "pcap filter")
	kind := cmd.Flag.String("t", "", "packet type")
	count := cmd.Flag.Int("c", 0, "bytes to skip before each packets")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	var (
		r   io.Reader
		err error
	)
	if *pcap {
		r, err = PCAPReader(cmd.Flag.Arg(0), *filter)
		*count = 0
	} else {
		r, err = MultiReader(cmd.Flag.Args())
	}
	if err != nil {
		return err
	}
	switch strings.ToLower(*kind) {
	case "", "hrdl":
		return countHRDL(HRDLReader(r, *count), strings.ToLower(*by))
	case "cadu":
		return countCadus(VCDUReader(r, *count))
	default:
		return fmt.Errorf("unknown packet type %s", *kind)
	}
}

func runList(cmd *cli.Command, args []string) error {
	pcap := cmd.Flag.Bool("pcap", false, "")
	filter := cmd.Flag.String("x", "", "pcap filter")
	kind := cmd.Flag.String("t", "", "packet type")
	keep := cmd.Flag.Bool("k", false, "keep invalid HRDL packets (bad sum only)")
	count := cmd.Flag.Int("c", 0, "bytes to skip before each packets")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	var (
		r   io.Reader
		err error
	)
	if *pcap {
		r, err = PCAPReader(cmd.Flag.Arg(0), *filter)
		*count = 0
	} else {
		r, err = MultiReader(cmd.Flag.Args())
	}
	if err != nil {
		return err
	}
	switch strings.ToLower(*kind) {
	case "", "hrdl":
		return listHRDL(HRDLReader(r, *count), *keep)
	case "cadu", "vcdu":
		return listCadus(VCDUReader(r, *count))
	default:
		return fmt.Errorf("unknown packet type %s", *kind)
	}
}

func runStore(cmd *cli.Command, args []string) error {
	q := cmd.Flag.Int("q", 64, "queue size before dropping HRDL packets")
	k := cmd.Flag.Bool("k", false, "keep invalid HRDL packets (bad sum only)")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	hr, err := NewHRDP(cmd.Flag.Arg(1))
	if err != nil {
		return err
	}
	queue, err := reassemble(cmd.Flag.Arg(0), "", *q)
	if err != nil {
		return err
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
	return nil
}

func runDump(cmd *cli.Command, args []string) error {
	q := cmd.Flag.Int("q", 64, "queue size before dropping HRDL packets")
	i := cmd.Flag.Int("i", -1, "hadock instance used")
	k := cmd.Flag.Bool("k", false, "keep invalid HRDL packets (bad sum only)")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	queue, err := reassemble(cmd.Flag.Arg(0), "", *q)
	if err != nil {
		return err
	}
	return dumpPackets(validate(queue, *q, *k), *i)
}

func runDebug(cmd *cli.Command, args []string) error {
	q := cmd.Flag.Int("q", 64, "queue size before dropping HRDL packets")
	i := cmd.Flag.Int("i", -1, "hadock instance used")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	queue, err := debugHRDL(cmd.Flag.Arg(0), *q, *i)
	if err != nil {
		return err
	}
	return dumpPackets(queue, *i)
}

func runTrace(cmd *cli.Command, args []string) error {
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	return traceCadus(cmd.Flag.Arg(0))
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
					continue
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
