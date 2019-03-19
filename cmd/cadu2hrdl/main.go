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
	"text/template"
	"time"

	"github.com/busoc/erdle"
	"github.com/busoc/erdle/cmd/internal/multireader"
	"github.com/busoc/erdle/cmd/internal/roll"
	"github.com/midbel/cli"
	"github.com/midbel/ringbuffer"
	"github.com/midbel/toml"
	"golang.org/x/sync/errgroup"
)

var (
	ErrSkip    = errors.New("skip")
	ErrInvalid = errors.New("hrdl: invalid checksum")
	ErrLength  = errors.New("hrdl: invalid length")
)

var (
	Word  = []byte{0xf8, 0x2e, 0x35, 0x53}
	Stuff = []byte{0xf8, 0x2e, 0x35, 0xaa}
	Magic = []byte{0x1a, 0xcf, 0xfc, 0x1d}
)

const (
	WordLen = 4
	VMULen  = 16
	HDRLen  = 24
)

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
		Usage: "list [-c skip] [-k keep] <file...>",
		Short: "list HRDL packets contained in the given file(s)",
		Run:   runList,
		Desc: `
options:

  -c COUNT   skip COUNT bytes between each packets
  -k         keep invalid HRDL packets
`,
	},
	{
		Usage: "count [-t type] [-b by] [-c skip] <file...>",
		Short: "count cadus/HRDL packets contained in the given files",
		Run:   runCount,
		Desc: `
options:

  -b BY      report count by origin or by channel if type is hrdl
  -c COUNT   skip COUNT bytes between each packets
  -t TYPE    specify the packet type (hrdl or cadu)
  -k         keep invalid HRDL packets
`,
	},
	{
		Usage: "replay [-c skip] [-r rate] <host:port> <file...>",
		Short: "send cadus from a file to a remote host",
		Run:   runReplay,
		Desc: `
options:

  -c    COUNT   skip COUNT bytes between each packets
  -r    RATE    define the output bandwidth usage in bytes
`,
	},
	{
		Usage: "store [-k keep] [-q queue] <host:port> <datadir>",
		Short: "create an archive of HRDL packets from a cadus stream",
		Run:   runStore,
		Desc: `
options:

  -c          use given configuration file to load options
  -i INTERVAL time between automatic file rotation
  -t TIMEOUT  timeout before forcing file rotation
  -s SIZE     max size (in bytes) of a file before triggering a rotation
  -c COUNT    max number of packets in a file before triggering a rotation
  -b BUFFER   size of buffer between incoming cadus and reassembler
  -p PAYLOAD  identifier of source payload
  -q SIZE     size of the queue to store reassemble packets
  -k          store HRDL packets even if they are corrupted
`,
	},
	{
		Usage: "relay [-b buffer] [-c] [-r rate] [-q queue] [-i instance] [-c conn] [-k keep] <host:port> <host:port>",
		Short: "reassemble incoming cadus to HRDL packets",
		Run:   runRelay,
		Desc: `
options:

  -c           use given configuration file to load options
  -b BUFFER    size of buffer between incoming cadus and reassembler
  -q SIZE      size of the queue to store reassembled HRDL packets
  -i INSTANCE  hadock instance
  -r RATE      outgoing bandwidth rate
  -c CONN      number of connections to open to remote host
  -k           don't relay invalid HRDL packets
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
	{
		Usage: "index [-c skip] [-b by] <file...>",
		Short: "create an index of hrdl packets by cadus",
		Run:   runIndex,
		Desc: `
options:

  -c COUNT  skip COUNT bytes between each packets
  -b BY     report by origin or by channel
`,
	},
}

const Program = "c2h"

func init() {
	cli.BuildTime = "2019-02-04 12:45:00"
	cli.Version = "0.1.1"
}

const helpText = `
{{.Name}} handles cadus from various sources (files, network connection(s)) to
produce:

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

func runIndex(cmd *cli.Command, args []string) error {
	count := cmd.Flag.Int("c", 0, "skip count bytes")
	by := cmd.Flag.String("b", "", "")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	mr, err := multireader.New(cmd.Flag.Args())
	if err != nil {
		return err
	}
	return indexPackets(erdle.VCDUReader(mr, *count), strings.ToLower(*by))
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
		digest:  erdle.SumVCDU(),
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
		c.buffer.Write(StuffBytes(c.scanner.Bytes()))
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
	mr, err := multireader.New(cmd.Flag.Args())
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
	settings := struct {
		Config bool `toml:"-"`
		//incoming cadus settings
		Local  string `toml:"local"`
		Buffer int    `toml:"buffer"`
		Queue  int    `toml:"queue"`
		Keep   bool   `toml:"keep"`
		//outgoging vmu settings
		Remote   string `toml:"remote"`
		Instance int    `toml:"instance"`
		Rate     int    `toml:"rate"`
		Num      int    `toml:"connections"`
	}{}
	cmd.Flag.IntVar(&settings.Queue, "q", 64, "queue size before dropping HRDL packets")
	cmd.Flag.IntVar(&settings.Buffer, "b", 64<<20, "buffer size between socket and assembler")
	cmd.Flag.IntVar(&settings.Num, "n", 8, "number of connections to remote server")
	cmd.Flag.IntVar(&settings.Instance, "i", -1, "hadock instance used")
	cmd.Flag.IntVar(&settings.Rate, "r", 0, "bandwidth rate")
	cmd.Flag.BoolVar(&settings.Keep, "k", false, "keep invalid HRDL packets (bad sum only)")
	cmd.Flag.BoolVar(&settings.Config, "c", false, "use a configuration file")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	if settings.Config {
		r, err := os.Open(cmd.Flag.Arg(0))
		if err != nil {
			return err
		}
		defer r.Close()
		if err := toml.NewDecoder(r).Decode(&settings); err != nil {
			return err
		}
	} else {
		settings.Local = cmd.Flag.Arg(0)
		settings.Remote = cmd.Flag.Arg(1)
	}
	p, err := NewPool(settings.Remote, settings.Num, settings.Instance, settings.Rate)
	if err != nil {
		return err
	}
	queue, err := reassemble(settings.Local, settings.Queue, settings.Buffer)
	if err != nil {
		return err
	}

	var gp errgroup.Group
	for bs := range validate(queue, settings.Queue, settings.Keep, true) {
		xs := bs
		gp.Go(func() error {
			_, err := p.Write(xs)
			return err
		})
	}
	return gp.Wait()
}

func runReplay(cmd *cli.Command, args []string) error {
	count := cmd.Flag.Int("c", 0, "bytes to skip before each packets")
	rate := cmd.Flag.Int("r", 8<<20, "output bandwith usage")
	inspect := cmd.Flag.Bool("i", false, "inspect vcdu stream")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	files := make([]string, cmd.Flag.NArg()-1)
	for i := 1; i < cmd.Flag.NArg(); i++ {
		files[i-1] = cmd.Flag.Arg(i)
	}
	r, err := multireader.New(files)
	if err != nil {
		return err
	}
	r = erdle.VCDUReader(r, *count)
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
	by := cmd.Flag.String("b", "", "by")
	kind := cmd.Flag.String("t", "", "packet type")
	count := cmd.Flag.Int("c", 0, "bytes to skip before each packets")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	r, err := multireader.New(cmd.Flag.Args())
	if err != nil {
		return err
	}
	switch strings.ToLower(*kind) {
	case "", "hrdl":
		return countHRDL(HRDLReader(r, *count), strings.ToLower(*by))
	case "cadu":
		return countCadus(erdle.VCDUReader(r, *count))
	default:
		return fmt.Errorf("unknown packet type %s", *kind)
	}
}

func runList(cmd *cli.Command, args []string) error {
	keep := cmd.Flag.Bool("k", false, "keep invalid HRDL packets (bad sum only)")
	count := cmd.Flag.Int("c", 0, "bytes to skip before each packets")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	r, err := multireader.New(cmd.Flag.Args())
	if err != nil {
		return err
	}
	return listHRDL(HRDLReader(r, *count), *keep)
}

func runStore(cmd *cli.Command, args []string) error {
	settings := struct {
		Config  bool         `toml:"-"`
		Address string       `toml:"address"`
		Dir     string       `toml:"datadir"`
		Roll    roll.Options `toml:"storage"`
		Data    struct {
			Payload uint `toml:"payload"`
			Buffer  int  `toml:"buffer"`
			Queue   int  `toml:"queue"`
			Keep    bool `toml:"keep"`
		} `toml:"hrdl"`
	}{}
	cmd.Flag.DurationVar(&settings.Roll.Interval, "i", time.Minute*5, "rotation interval")
	cmd.Flag.DurationVar(&settings.Roll.Timeout, "t", time.Minute, "rotation timeout")
	cmd.Flag.UintVar(&settings.Data.Payload, "p", 0, "payload identifier")
	cmd.Flag.IntVar(&settings.Roll.MaxSize, "s", 0, "size threshold before rotation")
	cmd.Flag.IntVar(&settings.Roll.MaxCount, "z", 0, "packet threshold before rotation")
	cmd.Flag.IntVar(&settings.Data.Queue, "q", 64, "queue size before dropping HRDL packets")
	cmd.Flag.IntVar(&settings.Data.Buffer, "b", 64<<20, "buffer size")
	cmd.Flag.BoolVar(&settings.Data.Keep, "k", false, "keep invalid HRDL packets (bad sum only)")
	cmd.Flag.BoolVar(&settings.Config, "c", false, "use a configuration file")

	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	if settings.Config {
		r, err := os.Open(cmd.Flag.Arg(0))
		if err != nil {
			return err
		}
		defer r.Close()
		if err := toml.NewDecoder(r).Decode(&settings); err != nil {
			return err
		}
		settings.Roll.Interval = settings.Roll.Interval * time.Second
		settings.Roll.Timeout = settings.Roll.Timeout * time.Second
	} else {
		settings.Address = cmd.Flag.Arg(0)
		settings.Dir = cmd.Flag.Arg(1)
	}
	var (
		prefix string
		queue  <-chan []byte
	)
	hr, err := NewWriter(settings.Dir, settings.Roll, uint8(settings.Data.Payload))
	if err != nil {
		return err
	}
	defer hr.Close()
	if settings.Data.Payload == 0 {
		prefix = "[hrdfe]"
		queue, err = readPackets(settings.Address, settings.Data.Queue, settings.Data.Buffer)
		if err != nil {
			return err
		}
	} else {
		prefix = "[hrdp]"
		q, err := reassemble(settings.Address, settings.Data.Queue, settings.Data.Buffer)
		if err != nil {
			return err
		}
		queue = validate(q, settings.Data.Queue, settings.Data.Keep, false)
	}
	return storePackets(hr, queue, prefix)
}

func storePackets(hr Writer, queue <-chan []byte, prefix string) error {
	var (
		count int
		size  int
		fail  int
	)
	go func() {
		tick := time.Tick(time.Second * 5)
		logger := log.New(os.Stderr, prefix+" ", 0)
		for range tick {
			if count > 0 || fail > 0 {
				logger.Printf("%s: %6d packets, %7dKB, %6d failures", hr.Filename(), count, size>>10, fail)
				count, size, fail = 0, 0, 0
			}
		}
	}()
	for bs := range queue {
		if n, err := hr.Write(bs); err != nil {
			fail++
			log.Println(err)
		} else {
			count++
			size += n
		}
	}
	return nil
}

func runDump(cmd *cli.Command, args []string) error {
	q := cmd.Flag.Int("q", 64, "queue size before dropping HRDL packets")
	i := cmd.Flag.Int("i", -1, "hadock instance used")
	b := cmd.Flag.Int("b", 64<<20, "buffer size")
	k := cmd.Flag.Bool("k", false, "keep invalid HRDL packets (bad sum only)")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	queue, err := reassemble(cmd.Flag.Arg(0), *q, *b)
	if err != nil {
		return err
	}
	return dumpPackets(validate(queue, *q, *k, true), *i)
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

func validate(queue <-chan []byte, n int, keep, strip bool) <-chan []byte {
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
				logger.Printf(row, count, dropped, size>>10, valid, errLength, errSum)

				count = 0
				dropped = 0
				errLength = 0
				errSum = 0
				size = 0
			}
		}
	}()
	q := make(chan []byte, n)
	go func() {
		defer close(q)

		var offset int
		if strip {
			offset = 2 * WordLen
		}
		for bs := range queue {
			n, xs := Unstuff(bs)
			z := int(binary.LittleEndian.Uint32(xs[4:])) + 12
			if n < offset || len(xs) < z || len(xs) < 12 {
				errLength++
				continue
			}
			size += int64(z)
			if keep {
				sum := binary.LittleEndian.Uint32(xs[z-4:])
				var chk uint32
				for i := 8; i < z-4; i++ {
					chk += uint32(xs[i])
				}
				if chk != sum {
					errSum++
					continue
				}
			}
			select {
			case q <- xs[offset:z]:
				count++
			default:
				dropped++
			}
		}
	}()
	return q
}

func listenUDP(addr string) (net.Conn, error) {
	a, err := net.ResolveUDPAddr(protoFromAddr(addr))
	if err != nil {
		return nil, err
	}
	var c *net.UDPConn
	if a.IP.IsMulticast() {
		c, err = net.ListenMulticastUDP("udp", nil, a)
	} else {
		c, err = net.ListenUDP("udp", a)
	}
	if err != nil {
		return nil, err
	}
	if err := c.SetReadBuffer(16 << 20); err != nil {
		return nil, err
	}
	return c, nil
}

func reassemble(addr string, n, b int) (<-chan []byte, error) {
	c, err := listenUDP(addr)
	if err != nil {
		return nil, err
	}
	q := make(chan []byte, n)

	var r io.Reader = c
	if b > 0 {
		rw := ringbuffer.NewRingSize(b, 0)
		go func(r io.Reader) {
			io.CopyBuffer(rw, r, make([]byte, 1024))
		}(r)
		r = rw
	}

	var dropped, skipped, size, count, errCRC, errMissing int64
	go func() {
		const row = "%6d packets, %4d skipped, %4d dropped, %7d missing, %7d crc error, %7d bytes discarded"

		logger := log.New(os.Stderr, "[assemble] ", 0)
		tick := time.Tick(time.Second * 5)
		for range tick {
			err := errMissing + errCRC
			if count > 0 || skipped > 0 || err > 0 {
				logger.Printf(row, count, skipped, dropped, errMissing, errCRC, size)

				size = 0
				skipped = 0
				errMissing = 0
				errCRC = 0
				dropped = 0
				count = 0
			}
		}
	}()

	go func() {
		defer func() {
			c.Close()
			close(q)
		}()
		var buffer, rest []byte
		r := erdle.CaduReader(r, 0)
		for {
			buffer, rest, err = nextPacket(r, rest)
			if err == nil {
				if len(buffer) == 0 {
					continue
				}
				select {
				case q <- buffer:
					count++
				default:
					dropped += 1
					size += int64(len(buffer))
				}
			} else if n, ok := erdle.IsMissingCadu(err); ok {
				errMissing += int64(n)
				size += int64(len(buffer))
				skipped++
			} else if erdle.IsCRCError(err) {
				errCRC += int64(n)
				size += int64(len(buffer))
				skipped++
			} else {
				log.Println(err)
				return
			}
		}
	}()
	return q, nil
}

func readPackets(addr string, n, b int) (<-chan []byte, error) {
	c, err := listenUDP(addr)
	if err != nil {
		return nil, err
	}
	q := make(chan []byte, n)

	var r io.Reader = c
	if b > 0 {
		rw := ringbuffer.NewRingSize(b, 0)
		go func(r io.Reader) {
			io.CopyBuffer(rw, r, make([]byte, 1024))
		}(r)
		r = rw
	}
	go func() {
		defer func() {
			c.Close()
			close(q)
		}()
		r := erdle.VCDUReader(r, 0)
		for {
			body := make([]byte, 1024)
			n, err := r.Read(body)
			if n < len(body) {
				continue
			}
			if err != nil {
				if erdle.IsCaduError(err) {
					continue
				} else {
					return
				}
			}
			select {
			case q <- body:
			default:
			}
		}
	}()
	return q, nil
}
