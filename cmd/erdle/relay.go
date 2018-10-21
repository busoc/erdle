package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/busoc/erdle"
	"github.com/midbel/cli"
	"github.com/midbel/rustine/sum"
)

const (
	hdkVersion = 0
	vmuVersion = 2
)

var relayCommand = &cli.Command{
	Usage: "relay <local> <remote>",
	Short: "",
	Run:   runRelay,
}

type relayFunc func(string, string, string, int) error

func runRelay(cmd *cli.Command, args []string) error {
	rate, _ := cli.ParseSize("32m")
	cmd.Flag.Var(&rate, "r", "bandwidth")
	mode := cmd.Flag.Int("i", -1, "instance")
	// proto := cmd.Flag.String("p", "tcp", "default protocol")
	proxy := cmd.Flag.String("d", "", "proxy packets to")
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

	return relay(addr, cmd.Flag.Arg(1), *proxy, *mode)
}

func relayTCP(local, remote, proxy string, mode int) error {
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
			if err := Relay(w, r, mode, proxy); err != nil {
				log.Println(err)
			}
		}(r, w)
	}
}

func relayUDP(local, remote, proxy string, mode int) error {
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

	return Relay(w, r, mode, proxy)
}

func Relay(w io.Writer, r io.Reader, mode int, proxy string) error {
	if x, err := net.Dial(protoFromAddr(proxy)); err == nil {
		defer x.Close()
		r = io.TeeReader(r, x)
	}
	a := erdle.Reassemble(r, false)
	var p uint16
	switch mode {
	case 0, 1, 2, 255:
		p = uint16(hdkVersion)<<12 | uint16(vmuVersion)<<8 | uint16(mode)
	default:
	}
	rs := &relayReader{a}
	ws := &relayWriter{w: w, version: p}
	_, err := io.CopyBuffer(ws, rs, make([]byte, 8<<20))
	return err
}

type relayWriter struct {
	w       io.Writer
	version uint16
	counter uint16
}

func (w *relayWriter) Write(bs []byte) (int, error) {
	if w.version != 0 {
		vs := make([]byte, len(bs)+14)
		// buf := bytes.NewBuffer(vs)
		// buf.Write(bs[:4])
		// binary.Write(buf, binary.BigEndian, w.version)
		// binary.Write(buf, binary.BigEndian, w.counter)
		// binary.Write(buf, binary.BigEndian, uint32(len(bs)-8))
		// buf.Write(bs[8:])
		// binary.Write(buf, binary.BigEndian, sum.Sum1071(bs[8:]))
		//
		// _, err := io.Copy(w.w, buf)
		copy(vs, bs[:4])
		binary.BigEndian.PutUint16(vs[4:], w.version)
		binary.BigEndian.PutUint16(vs[6:], w.counter)
		binary.BigEndian.PutUint32(vs[8:], uint32(len(bs)-8))
		n := copy(vs[12:], bs[8:])
		binary.BigEndian.PutUint16(vs[12+n:], sum.Sum1071(bs[8:]))

		w.counter++
		_, err := w.w.Write(vs)
		return len(bs), err
	} else {
		return w.w.Write(bs)
	}
}

type relayReader struct{ inner io.Reader }

func (r *relayReader) Read(bs []byte) (int, error) {
	if n, err := r.inner.Read(bs); erdle.IsErdleError(err) {
		log.Println("==>", err)
		return 0, nil
	} else {
		return n, err
	}
}
