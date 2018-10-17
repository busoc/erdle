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

func runRelay(cmd *cli.Command, args []string) error {
	rate, _ := cli.ParseSize("32m")
	size := cmd.Flag.Uint("s", 1000, "queue size")
	cmd.Flag.Var(&rate, "r", "bandwidth")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	var relay func(string, string, int) error
	proto, addr := protoFromAddr(cmd.Flag.Arg(0))
	switch proto {
	case "udp":
		relay = relayUDP
	case "tcp":
		relay = relayTCP
	default:
		return fmt.Errorf("unsupported protocol %s", proto)
	}

	return relay(addr, cmd.Flag.Arg(1), int(*size))
}

func relayTCP(local, remote string, size int) error {
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
			queue, err := reassemble(r, size)
			if err != nil {
				return
			}
			for bs := range queue {
				if n, err := w.Write(bs); err != nil {
					log.Printf("%s: write %d/%d bytes", err, n, len(bs))
				}
			}
		}(r, w)
	}
}

func relayUDP(local, remote string, size int) error {
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
	queue, err := reassemble(r, int(size))
	if err != nil {
		return err
	}
	for bs := range queue {
		if n, err := c.Write(bs); err != nil {
			log.Printf("%s: write %d/%d bytes", err, n, len(bs))
		}
	}
	return nil
}

func reassemble(r io.Reader, size int) (<-chan []byte, error) {
	q := make(chan []byte, size)
	go func() {
		defer close(q)
		rs := erdle.Reassemble(r, false)

		var dropped uint64
		for {
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
				log.Println(err)
				continue
			}
			select {
			case q <- xs:
			default:
				dropped++
				log.Printf("packet %d dropped (%d bytes)", dropped, len(xs))
			}
		}
	}()
	return q, nil
}
