package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/busoc/erdle"
	"github.com/midbel/cli"
	"golang.org/x/time/rate"
)

var (
	GPS   = time.Date(1980, 1, 6, 0, 0, 0, 0, time.UTC)
	UNIX  = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	Delta = GPS.Sub(UNIX)
)

var commands = []*cli.Command{
	{
		Usage: "replay [-r] <source,...>",
		Short: "",
		Run:   runReplay,
	},
	{
		Usage: "relay <local> <remote>",
		Short: "",
		Run:   runRelay,
	},
	{
		Usage: "count [-p] [-k] <source,...>",
		Short: "",
		Run:   runCount,
	},
	{
		Usage: "dump [-p] [-k] <source,...>",
		Short: "",
		Run:   runDump,
	},
}

const helpText = `{{.Name}} reports various information about vcdu and/or hrdl packets

Usage:

  {{.Name}} command [options] <arguments>

Available commands:

{{range .Commands}}{{if .Runnable}}{{printf "  %-12s %s" .String .Short}}{{if .Alias}} (alias: {{ join .Alias ", "}}){{end}}{{end}}
{{end}}
Use {{.Name}} [command] -h for more information about its usage.
`

func main() {
	defer func() {
		if err := recover(); err != nil {
			log.Fatalf("unexpected error: %s", err)
		}
	}()
	sort.Slice(commands, func(i, j int) bool { return commands[i].String() < commands[j].String() })
	usage := func() {
		data := struct {
			Name     string
			Commands []*cli.Command
		}{
			Name:     filepath.Base(os.Args[0]),
			Commands: commands,
		}
		fs := map[string]interface{}{
			"join": strings.Join,
		}
		sort.Slice(data.Commands, func(i, j int) bool { return data.Commands[i].String() < data.Commands[j].String() })
		t := template.Must(template.New("help").Funcs(fs).Parse(helpText))
		t.Execute(os.Stderr, data)

		os.Exit(2)
	}
	if err := cli.Run(commands, usage, nil); err != nil {
		log.Fatalln(err)
	}
}

func runDump(cmd *cli.Command, args []string) error {
	proto := cmd.Flag.String("p", "", "protocol")
	hrdfe := cmd.Flag.Bool("e", false, "hrdfe")
	kind := cmd.Flag.String("k", "", "dump packet type")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	var r io.Reader
	switch strings.ToLower(*proto) {
	case "", "file":
		var rs []io.Reader
		for _, p := range cmd.Flag.Args() {
			r, err := os.Open(p)
			if err != nil {
				return err
			}
			defer r.Close()
			rs = append(rs, r)
		}
		r = io.MultiReader(rs...)
	case "udp":
		a, err := net.ResolveUDPAddr("udp", cmd.Flag.Arg(0))
		if err != nil {
			return err
		}
		c, err := net.ListenUDP("udp", a)
		if err != nil {
			return err
		}
		defer c.Close()

		r = c
	default:
		return fmt.Errorf("unsupported protocol %s", *proto)
	}
	var err error
	switch *kind {
	case "", "hrdl":
		err = dumpHRDL(r, *hrdfe)
	case "vcdu", "cadu":
		err = dumpVCDU(r, *hrdfe)
	default:
		err = fmt.Errorf("unsupported packet type %s", *kind)
	}
	return err
}

func dumpVCDU(r io.Reader, hrdfe bool) error {
	const row = "%8d | %04x | %-3d | %-3d | %-3d | %-12d | %6t | %04x | %04x | %04x | %4d | %s"
	var (
		prev      *erdle.Cadu
		count     int
		corrupted int
		missing   int
	)
	logger := log.New(os.Stdout, "", 0)

	r = erdle.NewReader(r, hrdfe)
	for {
		c, err := erdle.DecodeCadu(r)
		if err != nil {
			return err
		}
		delta := c.Missing(prev)

		msg := "-"
		if c.Error != nil {
			msg = c.Error.Error()
			corrupted++
		}
		missing += int(delta)
		count++

		h := c.VCDUHeader
		logger.Printf(row, count, h.Word, h.Version, h.Space, h.Channel, h.Sequence, h.Replay, h.Control, h.Data, c.Control, delta, msg)
		prev = c
	}
	logger.Printf("%d cadus found (%d missing, %d corrupted)", count, missing, corrupted)
	return nil
}

func dumpHRDL(r io.Reader, hrdfe bool) error {
	const row = "%6d | %7d | %02x | %s | %9d | %s | %s | %02x | %s | %7d | %16s | %s"

	logger := log.New(os.Stdout, "", 0)
	r = erdle.Reassemble(r, hrdfe)
	for i := 1; ; i++ {
		e, err := erdle.DecodeHRDL(r)
		if err == io.EOF {
			return nil
		}
		if e == nil {
			return err
		}
		h := e.HRDLHeader
		at := GPS.Add(h.Acqtime).Format("2006-01-02 15:04:05.000")
		xt := GPS.Add(h.Auxtime).Format("15:04:05.000")
		vt := e.When.Add(Delta).Format("2006-01-02 15:04:05.000")

		errtype := "-"
		switch {
		case erdle.IsInvalidLength(err):
			errtype = "bad length"
		case erdle.IsInvalidSum(err):
			errtype = "bad sum"
		default:
		}
		mode := "realtime"
		if h.Source != h.Origin {
			mode = "playback"
		}

		logger.Printf(row, i, h.Size, h.Channel, vt, h.Sequence, at, xt, h.Origin, mode, h.Counter, h.UPI, errtype)
	}
	return nil
}

func runRelay(cmd *cli.Command, args []string) error {
	rate, _ := cli.ParseSize("32m")
	size := cmd.Flag.Uint("s", 1000, "queue size")
	cmd.Flag.Var(&rate, "r", "bandwidth")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	c, err := net.Dial("tcp", cmd.Flag.Arg(1))
	if err != nil {
		return err
	}
	defer c.Close()

	queue, err := reassemble(cmd.Flag.Arg(0), int(*size))
	if err != nil {
		return err
	}
	for bs := range queue {
		if _, err := c.Write(bs); err != nil {
			log.Println(err)
		}
	}
	return nil
}

func reassemble(addr string, size int) (<-chan []byte, error) {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", a)
	if err != nil {
		return nil, err
	}
	q := make(chan []byte, size)
	go func() {
		defer func() {
			close(q)
			c.Close()
		}()
		rs := erdle.Reassemble(c, false)

		var dropped uint64
		for {
			xs := make([]byte, 8<<20)
			switch n, err := rs.Read(xs); err {
			case nil:
				xs = xs[:n]
			case io.EOF:
				return
			default:
				log.Println(err)
				continue
			}
			select {
			case q <- xs:
			default:
				dropped++
				log.Printf("packet %d dropped (%d bytes)", dropped, len(xs))
			}
		}
	}()
	return q, nil
}

func runReplay(cmd *cli.Command, args []string) error {
	rate, _ := cli.ParseSize("32m")
	cmd.Flag.Var(&rate, "r", "bandwidth usage")
	hrdfe := cmd.Flag.Bool("e", false, "hrdfe")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	w, err := Replay(cmd.Flag.Arg(0), rate)
	if err != nil {
		return err
	}
	defer w.Close()

	var rs []io.Reader
	for i := 1; i < cmd.Flag.NArg(); i++ {
		r, err := os.Open(cmd.Flag.Arg(i))
		if err != nil {
			return err
		}
		defer r.Close()

		rs = append(rs, r)
	}
	r := erdle.NewReader(io.MultiReader(rs...), *hrdfe)

	_, err = io.CopyBuffer(w, r, make([]byte, 1024))
	return err
}

func Replay(addr string, z cli.Size) (net.Conn, error) {
	c, err := net.Dial("udp", addr)
	if z == 0 {
		return c, err
	}
	return &replay{
		Conn:    c,
		limiter: rate.NewLimiter(rate.Limit(z.Float()), int(z.Int())/10),
	}, nil
}

type replay struct {
	net.Conn
	limiter *rate.Limiter
}

func (r *replay) Write(bs []byte) (int, error) {
	v := r.limiter.ReserveN(time.Now(), len(bs))
	if !v.OK() {
		return 0, nil
	}
	time.Sleep(v.Delay())

	return r.Conn.Write(bs)
}

func runCount(cmd *cli.Command, args []string) error {
	return cmd.Flag.Parse(args)
}
