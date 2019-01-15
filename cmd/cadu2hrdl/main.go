package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
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
	},
	{
		Usage: "count [-pcap] [-x filter] [-t type] [-b by] [-c skip] <file...>",
		Short: "count cadus/HRDL packets contained in the given files",
		Run:   runCount,
	},
	{
		Usage: "replay [-pcap] [-x filter] [-c skip] [-q queue] <host:port> <file...>",
		Short: "send cadus from a file to a remote host",
		Run:   runReplay,
	},
	{
		Usage: "store [-k keep] [-q queue] <host:port> <datadir>",
		Short: "create an archive of HRDL packets from a cadus stream",
		Run:   runStore,
	},
	{
		Usage: "relay [-q queue] [-i instance] [-c conn] [-i instance] [-k keep] [-x proxy] <host:port> <host:port>",
		Short: "reassemble incoming cadus to HRDL packets",
		Run:   runRelay,
	},
	{
		Usage: "dump [-q queue] [-i instance] [-k keep] <host:port>",
		Short: "print the raw bytes on incoming HRDL packets",
		Run:   runDump,
	},
	{
		Usage: "debug [-q queue] [-i instance] <host:port>",
		Short: "print the raw bytes on incoming HRDL packets",
		Run:   runDebug,
	},
	{
		Usage: "trace <local>",
		Short: "give statistics on incoming cadus stream",
		Run:   runTrace,
	},
}

const Program   = "c2h"

func init() {
	cli.BuildTime = "2019-01-15 11:30:00"
	cli.Version   = "0.0.1"
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
		t := template.Must(template.New("help").Parse(strings.TrimSpace(helpText)+"\n"))
		t.Execute(os.Stderr, data)

		os.Exit(2)
	}
	if err := cli.Run(commands, usage, nil); err != nil {
		log.Fatalln(err)
	}
}

func runRelay(cmd *cli.Command, args []string) error {
	q := cmd.Flag.Int("q", 64, "queue size before dropping HRDL packets")
	c := cmd.Flag.Int("c", 8, "number of connections to remote server")
	i := cmd.Flag.Int("i", -1, "hadock instance used")
	k := cmd.Flag.Bool("k", false, "keep invalid HRDL packets (bad sum only)")
	x := cmd.Flag.String("x", "", "proxy incoming cadus to a remote address")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	p, err := NewPool(cmd.Flag.Arg(1), *c, *i)
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
	x := cmd.Flag.String("x", "", "pcap filter")
	c := cmd.Flag.Int("c", 0, "bytes to skip before each packets")
	q := cmd.Flag.Int("q", 64, "queue size before dropping HRDL packets")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	var (
		r   io.Reader
		err error
	)
	if *pcap {
		r, err = PCAPReader(cmd.Flag.Arg(1), *x)
		*c = 0
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
	return replayCadus(cmd.Flag.Arg(0), VCDUReader(r, *c), *q)
}

func runCount(cmd *cli.Command, args []string) error {
	pcap := cmd.Flag.Bool("pcap", false, "")
	b := cmd.Flag.String("b", "", "by")
	x := cmd.Flag.String("x", "", "pcap filter")
	t := cmd.Flag.String("t", "", "packet type")
	c := cmd.Flag.Int("c", 0, "bytes to skip before each packets")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	var (
		r   io.Reader
		err error
	)
	if *pcap {
		r, err = PCAPReader(cmd.Flag.Arg(0), *x)
		*c = 0
	} else {
		r, err = MultiReader(cmd.Flag.Args())
	}
	if err != nil {
		return err
	}
	switch strings.ToLower(*t) {
	case "", "hrdl":
		return countHRDL(HRDLReader(r, *c), *b)
	case "cadu":
		return countCadus(VCDUReader(r, *c))
	default:
		return fmt.Errorf("unknown packet type %s", *t)
	}
}

func runList(cmd *cli.Command, args []string) error {
	pcap := cmd.Flag.Bool("pcap", false, "")
	x := cmd.Flag.String("x", "", "pcap filter")
	t := cmd.Flag.String("t", "", "packet type")
	k := cmd.Flag.Bool("k", false, "keep invalid HRDL packets (bad sum only)")
	c := cmd.Flag.Int("c", 0, "bytes to skip before each packets")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	var (
		r   io.Reader
		err error
	)
	if *pcap {
		r, err = PCAPReader(cmd.Flag.Arg(0), *x)
		*c = 0
	} else {
		r, err = MultiReader(cmd.Flag.Args())
	}
	if err != nil {
		return err
	}
	switch strings.ToLower(*t) {
	case "", "hrdl":
		return listHRDL(HRDLReader(r, *c), *k)
	case "cadu", "vcdu":
		return listCadus(VCDUReader(r, *c))
	default:
		return fmt.Errorf("unknown packet type %s", *t)
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
