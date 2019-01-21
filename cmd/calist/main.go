package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var Magic = []byte{0x1a, 0xcf, 0xfc, 0x1d}

type Coze struct {
	Count   int
	Size    int
	Gaps    int
	Missing int
	Elapsed time.Duration
}

const line = "%d cadus, %d gaps (%s), %d missing, %dKB"

func (z *Coze) Update(c *Coze) {
	z.Count += c.Count
	z.Size += c.Size
	z.Gaps += c.Gaps
	z.Missing += c.Missing
	z.Elapsed += c.Elapsed
}

func main() {
	defer func() {
		if err := recover(); err != nil {
			fmt.Fprintf(os.Stderr, "unexpected error: %s\n", err)
			os.Exit(3)
		}
	}()
	list := flag.Bool("l", false, "show cadus list")
	diff := flag.Bool("g", false, "show cadus gaps")
	flag.Parse()

	if *list && *diff {
		fmt.Fprintln(os.Stderr, "-l and -d flags can not be set together")
		os.Exit(1)
	}

	var z Coze
	for _, a := range flag.Args() {
		h, err := pcap.OpenOffline(a)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := listCadus(h, &z, *list, *diff); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	fmt.Fprintf(os.Stdout, line, z.Count, z.Gaps, z.Elapsed, z.Missing, z.Size>>10)
	fmt.Fprintln(os.Stdout)
}

func listCadus(h *pcap.Handle, c *Coze, list, gap bool) error {
	d := struct {
		Curr uint32
		When time.Time
	}{}

	defer h.Close()
	s := gopacket.NewPacketSource(h, h.LinkType())
	for {
		p, err := s.NextPacket()
		if err != nil {
			break
		}

		xs := p.ApplicationLayer().Payload()
		if !bytes.HasPrefix(xs, Magic) {
			continue
		}
		c.Count++
		c.Size += len(xs)

		var missing uint32

		curr := binary.BigEndian.Uint32(xs[6:]) >> 8
		md := p.Metadata()
		t := md.Timestamp.UTC()
		if diff := (curr - d.Curr) & 0xFFFFFF; diff != curr && diff > 1 {
			missing = diff - 1
			c.Missing += int(missing)
			c.Gaps++
			if !d.When.IsZero() {
				c.Elapsed += t.Sub(d.When)
			}
		}
		if !list && gap && missing > 0 {
			fmt.Fprintf(os.Stdout, "%5d | %s | %s | %7d | %7d | %d\n", c.Gaps, d.When.Format(time.RFC3339), t.Format(time.RFC3339), d.Curr, curr, missing)
		}
		if list && !gap {
			sn, dn := p.NetworkLayer().NetworkFlow().Endpoints()
			sp, dp := p.TransportLayer().TransportFlow().Endpoints()

			var proto string
			if i := p.Layer(layers.LayerTypeIPv4); i != nil {
				i := i.(*layers.IPv4)
				proto = i.Protocol.String()
			} else if i := p.Layer(layers.LayerTypeIPv6); i != nil {
				i := i.(*layers.IPv6)
				proto = i.NextHeader.String()
			} else {
				proto = "unknown"
			}
			var e time.Duration
			if !d.When.IsZero() {
				e = t.Sub(d.When)
			}
			fmt.Fprintf(os.Stdout, "%8d | %12s | %s | %s:%s | %s:%s | %s | %6d | %d\n", c.Count, e, t.Format(time.RFC3339), sn, sp, dn, dp, proto, len(xs), missing)
		}
		d.Curr, d.When = curr, t
	}
	return nil
}
