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

const line = "%d cadus (expected: %d cadus), %d gaps (%s), %d missing (%.2f%%), %dKB"

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
	ratio := float64(z.Missing) / float64(z.Count+z.Missing)
	fmt.Fprintf(os.Stdout, line, z.Count, z.Count+z.Missing, z.Gaps, z.Elapsed, z.Missing, ratio*100, z.Size>>10)
	fmt.Fprintln(os.Stdout)
}

func listCadus(h *pcap.Handle, c *Coze, list, gap bool) error {
	d := struct {
		Curr    uint32
		When    time.Time
		Elapsed time.Duration
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
			missing = diff
			c.Missing += int(missing)
			c.Gaps++
			if !d.When.IsZero() {
				c.Elapsed += t.Sub(d.When)
			}
		}
		if !list && gap && missing > 0 {
			fmt.Fprintf(os.Stdout, "%5d | %12s | %s | %s | %7d | %7d | %d\n", c.Gaps, d.Elapsed, d.When.Format(time.RFC3339), t.Format(time.RFC3339), d.Curr, curr, missing)
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
			fmt.Fprintf(os.Stdout, "%8d | %12s | %s | %s:%s | %s:%s | %s | %6d | %d\n", c.Count, d.Elapsed, t.Format(time.RFC3339), sn, sp, dn, dp, proto, len(xs), missing)
		}
		if !d.When.IsZero() {
			d.Elapsed += t.Sub(d.When)
			if d.Elapsed < 0 {
				d.Elapsed = 0
			}
		}
		d.Curr, d.When = curr, t
	}
	return nil
}
