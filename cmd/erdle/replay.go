package main

import (
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/busoc/erdle"
	"github.com/midbel/cli"
	"golang.org/x/time/rate"
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

	when := time.Now()
	vs := make([]byte, 1024)
	n, err := io.CopyBuffer(w, r, vs)
	if err == nil {
		log.Printf("%d KB sent in %s", n>>10, time.Since(when))
	}
	return err
}

func Replay(addr string, z cli.Size) (net.Conn, error) {
	c, err := net.Dial(protoFromAddr(addr))
	if err != nil {
		return nil, err
	}
	return Replayer(c, z), nil
}

func Replayer(c net.Conn, z cli.Size) net.Conn {
	if z == 0 {
		return c
	}
	return &replay{
		Conn:    c,
		limiter: rate.NewLimiter(rate.Limit(z.Float()), int(z.Int())/10),
	}
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
