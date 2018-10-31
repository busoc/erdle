package main

import (
	"io"
	"log"
	"os"

	"github.com/busoc/erdle"
	"github.com/midbel/cli"
)

var decodeCommand = &cli.Command{
	Usage: "decode [-e] <file,...>",
	Short: "",
	Run:   runDecode,
}

func runDecode(cmd *cli.Command, args []string) error {
	const row = "%6d | %7d | %02x | %s | %9d | %s | %s | %02x | %s | %7d | %16s | %s"

	hrdfe := cmd.Flag.Bool("e", false, "hrdfe")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	var sid int
	logger := log.New(os.Stdout, "", 0)
	for _, p := range cmd.Flag.Args() {
		r, err := os.Open(p)
		if err != nil {
			return err
		}
		d := erdle.NewDecoder(r, *hrdfe)
	Loop:
		for {
			e, err := d.Decode()
			switch {
			case err == io.EOF:
				break Loop
			// case err != nil && erdle.IsErdleError(err):
			case err != nil && !erdle.IsErdleError(err):
				return err
			default:
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
			sid++
			logger.Printf(row, sid, h.Size, h.Channel, vt, h.Sequence, at, xt, h.Origin, mode, h.Counter, h.UPI, errtype)
		}
		r.Close()
	}
	return nil
}
