package main

import (
	"fmt"
	"io"
	"log"
	"net"

	"github.com/busoc/erdle"
	"github.com/midbel/cli"
)

var relayCommand = &cli.Command{
	Usage: "relay <local> <remote>",
	Short: "",
	Run:   runRelay,
}

type relayFunc func(string, string, int, bool) error

func runRelay(cmd *cli.Command, args []string) error {
	rate, _ := cli.ParseSize("32m")
	size := cmd.Flag.Uint("s", 64, "queue size")
	keep := cmd.Flag.Bool("k", false, "keep invalid")
	cmd.Flag.Var(&rate, "r", "bandwidth")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	var relay relayFunc
	proto, addr := protoFromAddr(cmd.Flag.Arg(0))
	switch proto {
	case "udp":
		relay = relayUDP
	case "tcp":
		relay = relayTCP
	default:
		return fmt.Errorf("unsupported protocol %s", proto)
	}

	return relay(addr, cmd.Flag.Arg(1), int(*size), *keep)
}

func relayTCP(local, remote string, size int, keep bool) error {
	c, err := net.Listen("tcp", local)
	if err != nil {
		return err
	}
	defer c.Close()

	for {
		r, err := c.Accept()
		if err != nil {
			return err
		}
		w, err := net.Dial(protoFromAddr(remote))
		if err != nil {
			continue
		}
		go func(r, w net.Conn) {
			defer func() {
				r.Close()
				w.Close()
			}()
			queue, err := reassemble(r, size, keep)
			if err != nil {
				return
			}
			if err := relayConn(w, queue); err != nil {
				log.Println(err)
			}
		}(r, w)
	}
}

func relayUDP(local, remote string, size int, keep bool) error {
	c, err := net.Dial(protoFromAddr(remote))
	if err != nil {
		return err
	}
	defer c.Close()

	a, err := net.ResolveUDPAddr("udp", local)
	if err != nil {
		return err
	}
	r, err := net.ListenUDP("udp", a)
	if err != nil {
		return err
	}
	defer c.Close()
	queue, err := reassemble(r, int(size), keep)
	if err != nil {
		return err
	}
	return relayConn(c, queue)
}

func relayConn(c net.Conn, queue <-chan []byte) error {
	for bs := range queue {
		if n, err := c.Write(bs); err != nil {
			if err, ok := err.(net.Error); ok && !err.Temporary() {
				return err
			}
			log.Printf("%s: write %d/%d bytes", err, n, len(bs))
		} else {
			log.Printf("packet %d bytes written to %s", n, c.RemoteAddr())
		}
	}
	return nil
}

func reassemble(r io.Reader, size int, keep bool) (<-chan []byte, error) {
	q := make(chan []byte, size)
	go func() {
		defer close(q)
		rs := erdle.Reassemble(r, false)

		var dropped uint64
		for i := 1; ; i++ {
			xs := make([]byte, 8<<20)
			switch n, err := rs.Read(xs); err {
			case nil:
				xs = xs[:n]
			case io.EOF:
				return
			default:
				if !erdle.IsErdleError(err) {
					return
				}
				log.Printf("skip packet (%d bytes): %s", n, err)
				if !keep {
					continue
				}
			}
			select {
			case q <- xs:
				log.Printf("packet %d sent (%d bytes)", i, len(xs))
			default:
				dropped++
				log.Printf("packet %d dropped (%d bytes)", dropped, len(xs))
			}
		}
	}()
	return q, nil
}
