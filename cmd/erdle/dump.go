package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"github.com/busoc/erdle"
	"github.com/midbel/cli"
)

var dumpCommand = &cli.Command{
	Usage: "dump [-p] [-k] <source,...>",
	Short: "",
	Run:   runDump,
}

type dumpFunc func(io.Reader, bool) error

func runDump(cmd *cli.Command, args []string) error {
	proto := cmd.Flag.String("p", "", "protocol")
	hrdfe := cmd.Flag.Bool("e", false, "hrdfe")
	kind := cmd.Flag.String("k", "", "dump packet type")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	var dump dumpFunc
	switch *kind {
	case "", "hrdl":
		if *proto == "file" {
			dump = func(r io.Reader, hrdfe bool) error {
				return dumpHRDL(erdle.Reassemble(r, hrdfe), hrdfe)
			}
		} else {
			dump = dumpHRDL
		}
	case "vcdu", "cadu":
		dump = dumpVCDU
	default:
		return fmt.Errorf("unsupported packet type %s", *kind)
	}
	switch strings.ToLower(*proto) {
	case "", "file":
		return dumpFile(cmd.Flag.Args(), *hrdfe, dump)
	case "udp":
		return dumpUDP(cmd.Flag.Arg(0), false, dump)
	case "tcp":
		return dumpTCP(cmd.Flag.Arg(0), false, dump)
	default:
		return fmt.Errorf("unsupported protocol %s", *proto)
	}
}

func dumpFile(ps []string, hrdfe bool, dump dumpFunc) error {
	var rs []io.Reader
	for _, p := range ps {
		r, err := os.Open(p)
		if err != nil {
			return err
		}
		defer r.Close()
		rs = append(rs, r)
	}

	return dump(io.MultiReader(rs...), hrdfe)
}

func dumpUDP(a string, hrdfe bool, dump dumpFunc) error {
	addr, err := net.ResolveUDPAddr("udp", a)
	if err != nil {
		return err
	}
	var c net.Conn
	if addr.IP.IsMulticast() {
		c, err = net.ListenMulticastUDP("udp", nil, addr)
	} else {
		c, err = net.ListenUDP("udp", addr)
	}
	if err != nil {
		return err
	}
	defer c.Close()
	return dump(c, hrdfe)
}

func dumpTCP(a string, hrdfe bool, dump dumpFunc) error {
	c, err := net.Listen("tcp", a)
	if err != nil {
		return err
	}
	defer c.Close()

	for {
		r, err := c.Accept()
		if err != nil {
			return err
		}
		go func(r net.Conn) {
			defer r.Close()
			if err := dump(r, hrdfe); err != nil {
				log.Println(r.RemoteAddr(), err)
			}
		}(r)
	}
	return nil
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
	// r = erdle.Reassemble(r, hrdfe)
	for i := 1; ; i++ {
		e, err := erdle.DecodeHRDL(r)
		switch {
		case err == io.EOF:
			return nil
		case err != nil && erdle.IsErdleError(err):
			log.Println(err)
			continue
		case err != nil && !erdle.IsErdleError(err):
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
