package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/busoc/erdle"
	"github.com/midbel/cli"
	"github.com/midbel/rustine/sum"
)

var relayCommand = &cli.Command{
	Usage: "relay <local> <remote>",
	Short: "",
	Run:   runRelay,
}

type relayFunc func(string, string, int, int, bool) error

func runRelay(cmd *cli.Command, args []string) error {
	rate, _ := cli.ParseSize("32m")
	mode := cmd.Flag.Int("i", -1, "instance")
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
	switch *mode {
	case -1, 0, 1, 2, 255:
	default:
		return fmt.Errorf("unsupported instance")
	}

	return relay(addr, cmd.Flag.Arg(1), *mode, int(*size), *keep)
}

func relayTCP(local, remote string, mode, size int, keep bool) error {
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
			Relay(w, r)
		}(r, w)
	}
}

func relayUDP(local, remote string, mode, size int, keep bool) error {
	w, err := net.Dial(protoFromAddr(remote))
	if err != nil {
		return err
	}
	defer w.Close()

	a, err := net.ResolveUDPAddr("udp", local)
	if err != nil {
		return err
	}
	r, err := net.ListenUDP("udp", a)
	if err != nil {
		return err
	}
	defer r.Close()

	return Relay(w, r)
}

const (
	hdkVersion = 0
	vmuVersion = 2
)

func relayHadock(c net.Conn, queue <-chan []byte, mode int) error {
	if mode < 0 {
		return relayConn(c, queue)
	}
	var (
		seq uint16
		buf   bytes.Buffer
	)
	preamble := uint16(hdkVersion) << 12 | uint16(vmuVersion) << 8 | uint16(mode)

	addr := c.RemoteAddr().String()
	var counter uint64
	for bs := range queue {
		counter++

		buf.Write(bs[:4])
		binary.Write(&buf, binary.BigEndian, preamble)
		binary.Write(&buf, binary.BigEndian, seq)
		binary.Write(&buf, binary.BigEndian, uint32(len(bs[8:])))
		buf.Write(bs[8:])
		binary.Write(&buf, binary.BigEndian, sum.Sum1071(bs[8:]))

		seq++
		w := time.Now()
		if n, err := io.Copy(c, &buf); err != nil {
			if err, ok := err.(net.Error); ok && !err.Temporary() {
				return err
			}
			log.Printf("packet (%d): %s (%d bytes written)", counter, err, n)
		} else {
			log.Printf("packet (%d) %d bytes written to %s (%s)", counter, n, addr, time.Since(w))
		}
	}
	return nil
}

func relayConn(c net.Conn, queue <-chan []byte) error {
	addr := c.RemoteAddr().String()

	var counter uint64
	for bs := range queue {
		counter++
		w := time.Now()
		if n, err := c.Write(bs); err != nil {
			if err, ok := err.(net.Error); ok && !err.Temporary() {
				return err
			}
			log.Printf("packet (%d): %s (%d bytes written)", counter, err, n)
		} else {
			log.Printf("packet (%d) %d bytes written to %s (%s)", counter, n, addr, time.Since(w))
		}
	}
	return nil
}

func Relay(w io.Writer, r io.Reader) error {
	a := erdle.Reassemble(r, false)
	_, err := io.CopyBuffer(&relayWriter{w}, &relayReader{a}, make([]byte, 8<<20))
	return err
}

type relayWriter struct { w io.Writer }
func (c *conn) Write(bs []byte) (int, error) { return c.w.Write(bs) }

type relayReader struct { inner io.Reader }

func (r *relayReader) Read(bs []byte) (int, error) {
	if n, err := r.inner.Read(bs); erdle.IsErdleError(err) {
		return 0, nil
	} else {
		return n, err
	}
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
				log.Printf("invalid packet (%d bytes): %s", n, err)
				if !keep {
					continue
				}
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
