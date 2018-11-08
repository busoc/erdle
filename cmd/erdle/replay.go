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
	rate, _ := cli.ParseSize("32m")
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

	when := time.Now()
	vs := make([]byte, 1024)

	w := ratelimit.Writer(c, ratelimit.NewBucketWithRate(rate.Float(), rate.Int()))
	var n int64
	for {
		nn, err := io.CopyBuffer(w, r, vs)
		if !erdle.IsErdleError(err) {
			return err
		} else {
			n += nn
			log.Printf("%s", err)
		}
	}
	log.Printf("%d KB sent in %s", n>>10, time.Since(when))
	return nil
}
