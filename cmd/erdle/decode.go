package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/busoc/erdle"
	"github.com/midbel/cli"
)

var decodeCommand = &cli.Command{
	Usage: "decode [-s] [-e] <file,...>",
	Short: "",
	Run:   runDecode,
}

var debugCommand = &cli.Command{
	Usage: "debug [-k] [-e] <file,...>",
	Short: "",
	Run:   runDebug,
}

func runDebug(cmd *cli.Command, args []string) error {
	hrdfe := cmd.Flag.Bool("e", false, "hrdfe")
	size := cmd.Flag.Int("s", 8<<20, "size")
	// kind := cmd.Flag.String("k", "", "type")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	var count int
	for _, p := range cmd.Flag.Args() {
		r, err := os.Open(p)
		if err != nil {
			return err
		}
		if c, err := debugHRDLPackets(erdle.NewBuilder(r, *hrdfe), count, *size); err != nil {
			return err
		} else {
			count = c
		}
		r.Close()
	}
	return nil
}

func debugHRDLPackets(r io.Reader, sid, size int) (int, error) {
	hrdl := make([]byte, 8<<20)
	buffer := make([]byte, size)

	var n int

	digest := erdle.SumHRDL()
	for {
		nn, err := r.Read(buffer)
		if err == io.EOF {
			break
		}
		if err == erdle.ErrFull || err == nil {
			n += copy(hrdl[n:], buffer[:nn])
		}
		if err == erdle.ErrFull {
			sid++
			digest.Write(hrdl[8 : n-4])
			z := binary.LittleEndian.Uint32(hrdl[4:])
			x := binary.LittleEndian.Uint32(hrdl[n-4:])
			n -= 12

			var zok, xok string
			if n != int(z) {
				zok = "mismatch"
			}
			sum := digest.Sum32()
			if x != sum {
				xok = "mismatch"
			}

			fmt.Printf("%5d | %8d | %8d | %08x | %08x | %x | %x | %8s | %8s\n", sid, n, z, x, sum, hrdl[:8], hrdl[8:24], zok, xok)

			n = 0
			digest.Reset()

			continue
		}
		if err != nil {
			return 0, err
		}
	}
	return sid, nil
}

func runDecode(cmd *cli.Command, args []string) error {
	convert := cmd.Flag.Bool("c", false, "convert")
	summary := cmd.Flag.Bool("s", false, "summary")
	hrdfe := cmd.Flag.Bool("e", false, "hrdfe")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	switch proto, addr := protoFromAddr(cmd.Flag.Arg(0)); proto {
	case "udp", "UDP":
		return decodeFromUDP(addr, *convert)
	case "tcp", "TCP":
		return decodeFromTCP(addr, *convert)
	default:
		return decodeFromFiles(cmd.Flag.Args(), *summary, *hrdfe)
	}
}

func decodeFromTCP(addr string, convert bool) error {
	c, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	for {
		c, err := c.Accept()
		if err != nil {
			return err
		}
		go func(r io.ReadCloser) {
			defer r.Close()

			var d *erdle.Decoder
			if convert {
				d = erdle.NewDecoder(r, false)
			} else {
				d = erdle.HRDL(r)
			}
			if _, _, _, err := decodeHRDLPackets(d, os.Stdout, 0); err != nil {
				log.Fatalln(err)
			}
		}(c)
	}
	return nil
}

func decodeFromUDP(addr string, convert bool) error {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	c, err := net.ListenUDP("udp", a)
	if err != nil {
		return err
	}
	defer c.Close()

	var d *erdle.Decoder
	if convert {
		d = erdle.NewDecoder(c, false)
	} else {
		d = erdle.HRDL(c)
	}
	count, invalid, size, err := decodeHRDLPackets(d, os.Stdout, 0)
	fmt.Printf("%d HRDL packets (%dKB - %d invalid)", count, size>>10, invalid)
	fmt.Println()
	return err
}

func decodeFromFiles(ps []string, summary, hrdfe bool) error {
	var (
		count   int
		invalid int
		size    int
	)
	var w io.Writer = os.Stdout
	if summary {
		w = ioutil.Discard
	}
	for _, p := range ps {
		r, err := os.Open(p)
		if err != nil {
			return err
		}
		d := erdle.NewDecoder(r, hrdfe)
		if c, i, s, err := decodeHRDLPackets(d, w, count); err != nil {
			return err
		} else {
			count = c
			invalid += i
			size += s
		}
		r.Close()
	}
	if !summary {
		fmt.Println()
	}
	fmt.Printf("%d HRDL packets (%dKB - %d invalid)", count, size>>10, invalid)
	fmt.Println()
	return nil
}

func decodeHRDLPackets(d *erdle.Decoder, w io.Writer, sid int) (int, int, int, error) {
	const row = "%6d | %7d | %02x | %s | %9d | %8d | %s | %s | %02x | %s | %7d | %16s | %s\n"

	var size, invalid int
	cs := make(map[uint8]uint32)
	for {
		e, err := d.Decode()
		switch {
		case err == io.EOF:
			return sid, invalid, size, nil
		case err != nil && !erdle.IsErdleError(err):
			return sid, invalid, size, err
		case err != nil && erdle.IsErdleError(err):
			invalid++
			if erdle.IsMissingCadu(err) {
				continue
			}
		default:
		}
		size += int(e.HRDLHeader.Size)

		h := e.HRDLHeader
		at := GPS.Add(h.Acqtime).Format("2006-01-02 15:04:05.000")
		xt := GPS.Add(h.Auxtime).Format("15:04:05.000")
		vt := e.When.Add(Delta).Format("2006-01-02 15:04:05.000")

		diff := h.Sequence - cs[h.Channel]
		if diff == 1 || diff == h.Sequence {
			diff = 0
		}

		cs[h.Channel] = h.Sequence

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
		sid++
		fmt.Fprintf(w, row, sid, h.Size, h.Channel, vt, h.Sequence, diff, at, xt, h.Origin, mode, h.Counter, h.UPI, errtype)
	}
}
