package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/busoc/erdle"
	"github.com/midbel/cli"
)

type Coze struct {
	Count   uint64
	Size    uint64
	Missing uint64
	First   uint32
	Last    uint32
}

var countCommand = &cli.Command{
	Usage: "count [-b] [-k] <file,...>",
	Short: "",
	Run:   runCount,
}

type byFunc func(*erdle.Erdle) (uint16, uint32)

func runCount(cmd *cli.Command, args []string) error {
	kind := cmd.Flag.String("b", "channel", "report by channel or origin")
	hrdfe := cmd.Flag.Bool("e", false, "hrdfe packet")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	var by byFunc
	switch strings.ToLower(*kind) {
	case "channel":
		by = func(e *erdle.Erdle) (uint16, uint32) {
			return uint16(e.Channel), e.Sequence
		}
	case "origin":
		by = func(e *erdle.Erdle) (uint16, uint32) {
			return uint16(e.Source)<<8 | uint16(e.Origin), e.Counter
		}
	default:
		return fmt.Errorf("%s unsupported", *kind)
	}
	reports, errLen, errSum, errMiss, err := countPackets(cmd.Flag.Args(), *hrdfe, by)
	if err != nil {
		return err
	}
	const row = "%s(%s) %02x: total: %7d - first: %8d - last: %8d - missing: %8d - size: %dMB"
	var z Coze

	logger := log.New(os.Stdout, "", 0)
	for b, c := range reports {
		z.Count += c.Count
		z.Size += c.Size

		mode := "rt"
		if m := b >> 8; m >= 0x61 && m <= 0x66 {
			mode = "pb"
		}
		logger.Printf(row, *kind, mode, b&0xFF, c.Count, c.First, c.Last, c.Missing, c.Size>>20)
	}
	logger.Printf("%d VMU packets (%d cadu(s) missing, %d bad sum, %d bad length, %dKB)", z.Count, errMiss, errSum, errLen, z.Size>>10)
	return nil
}

func countPackets(ps []string, hrdfe bool, by byFunc) (map[uint16]*Coze, uint64, uint64, uint64, error) {
	var rs []io.Reader
	for _, p := range ps {
		r, err := os.Open(p)
		if err != nil {
			return nil, 0, 0, 0, err
		}
		defer r.Close()
		rs = append(rs, r)
	}
	r := erdle.Reassemble(io.MultiReader(rs...), hrdfe)

	zs := make(map[uint16]*Coze)
	var errSum, errLen, errMiss uint64

Loop:
	for {
		e, err := erdle.DecodeHRDL(r)
		switch {
		case err == io.EOF:
			break Loop
		case err != nil && erdle.IsInvalidLength(err):
			errLen++
			continue
		case err != nil && erdle.IsInvalidSum(err):
			errSum++
			continue
		case err != nil && erdle.IsMissingCadu(err):
			errMiss++
			continue
		case err != nil && !erdle.IsErdleError(err):
			return nil, 0, 0, 0, err
		}
		key, seq := by(e)
		curr, ok := zs[key]
		if !ok {
			zs[key] = &Coze{
				First: seq,
				Last:  seq,
				Count: 1,
				Size:  uint64(e.Size),
			}
			continue
		}
		curr.Count++
		curr.Size += uint64(e.Size)
		curr.Missing += sequenceDelta(seq, curr.Last)
		curr.Last = seq
	}
	return zs, errLen, errSum, errMiss, nil
}

func sequenceDelta(current, last uint32) uint64 {
	if current == last+1 {
		return 0
	}
	if current > last {
		return uint64(current) - uint64(last)
	}
	return 0
}
