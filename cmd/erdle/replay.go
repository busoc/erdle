package main

import (
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/busoc/erdle"
	"github.com/juju/ratelimit"
	"github.com/midbel/cli"
)

var replayCommand = &cli.Command{
	Usage: "replay [-r] <source,...>",
	Short: "",
	Run:   runReplay,
}

func runReplay(cmd *cli.Command, args []string) error {
	rate := cli.Size(0)
	cmd.Flag.Var(&rate, "r", "bandwidth usage")
	hrdfe := cmd.Flag.Bool("e", false, "hrdfe")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	c, err := net.Dial(protoFromAddr(cmd.Flag.Arg(0)))
	if err != nil {
		return err
	}
	defer c.Close()

	if c, ok := c.(interface{ SetWriteBuffer(int) error }); ok {
		if err := c.SetWriteBuffer(16 << 20); err != nil {
			return err
		}
	}

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

	var w io.Writer = c
	if rate.Int() > 0 {
		w = ratelimit.Writer(c, ratelimit.NewBucketWithRate(rate.Float(), rate.Int()))
	}
	cadu := make([]byte, 1024)
	tick := time.Tick(time.Second)
	var n, i int
	for {
		_, err := r.Read(cadu)
		if err != nil {
			if !erdle.IsMissingCadu(err) {
				return err
			}
			log.Println(err)
		}
		if nn, err := w.Write(cadu); err != nil {
			return err
		} else {
			n += nn
			i++
		}
		select {
		case <-tick:
			log.Printf("%d cadus send (%dKB)", i, n>>10)
			n, i = 0, 0
		default:
		}
		//
		// nn, err := io.CopyBuffer(w, r, vs)
		// if !erdle.IsErdleError(err) {
		// 	return err
		// } else {
		// 	n += nn
		// 	log.Printf("%s", err)
		// }
	}
	return nil
}
