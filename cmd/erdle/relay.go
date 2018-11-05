package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/busoc/erdle"
	"github.com/midbel/cli"
)

const (
	hdkInstance = 0
	hdkVersion  = 0
	vmuVersion  = 2
)

var relayCommand = &cli.Command{
	Usage: "relay [-d] <local> <remote>",
	Short: "",
	Run:   runRelay,
}

type relayFunc func(string, string, string, string, int) error

func runRelay(cmd *cli.Command, args []string) error {
	buffer := cmd.Flag.Int("b", 32<<10, "buffer size")
	mode := cmd.Flag.String("m", "", "mode")
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

	return relay(addr, cmd.Flag.Arg(1), *proxy, *mode, *buffer)
}

func relayTCP(local, remote, proxy, mode string, size int) error {
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
			if err := Relay(w, r, proxy, mode, size); err != nil {
				log.Println(err)
			}
		}(r, w)
	}
}

func relayUDP(local, remote, proxy, mode string, size int) error {
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

	return Relay(w, r, proxy, mode, size)
}

func Relay(w io.Writer, r io.Reader, proxy, mode string, size int) error {
	if x, err := net.Dial(protoFromAddr(proxy)); err == nil {
		defer x.Close()
		r = io.TeeReader(r, x)
	}
	rs := erdle.NewBuilder(r, false)
	switch mode {
	case "", "raw", "hrdl":
		ws := HRDL(w)
		buffer := make([]byte, size)
		for i := 1; ; i++ {
			n, err := io.CopyBuffer(ws, rs, buffer)
			if !erdle.IsErdleError(err) {
				return err
			}
			errmsg := "no error"
			if err != nil && err != erdle.ErrFull {
				errmsg = err.Error()
			}
			log.Printf("HRDL packet (%d) decoded (%d bytes): %s", i, n, errmsg)
		}
	case "hdk", "hadock":
		ws := Hadock(w, size)
		for i := 1; ; i++ {
			_, err := io.Copy(ws, rs)
			if !erdle.IsErdleError(err) {
				return err
			}
			log.Printf("error while decoding HRDL packet (%d): %s", i, err)
		}
	default:
		return fmt.Errorf("unsupported mode %s", mode)
	}
	return nil
}

type hadockRelayer struct {
	io.Writer
	buffer   []byte
	preamble uint16
	sequence uint16
}

func Hadock(w io.Writer, size int) io.Writer {
	return &hadockRelayer{
		Writer:   w,
		buffer:   make([]byte, size),
		preamble: uint16(hdkVersion)<<12 | uint16(vmuVersion)<<8 | uint16(hdkInstance),
	}
}

func (hr *hadockRelayer) ReadFrom(r io.Reader) (int64, error) {
	var n int64

	for {
		nn, err := r.Read(hr.buffer)
		switch err {
		case nil:
		case erdle.ErrFull:
			hr.sequence++
		default:
			return n, err
		}
		var buffer []byte
		if bytes.Equal(hr.buffer[:4], erdle.Word) {
			size := binary.LittleEndian.Uint32(hr.buffer[4:]) + 4

			var buf bytes.Buffer
			buf.Write(hr.buffer[:4])
			binary.Write(&buf, binary.BigEndian, hr.preamble)
			binary.Write(&buf, binary.BigEndian, hr.sequence)
			binary.Write(&buf, binary.BigEndian, size)
			buf.Write(hr.buffer[8:nn])

			buffer = buf.Bytes()
		} else {
			buffer = hr.buffer[:nn]
		}
		if err == erdle.ErrFull {
			buffer = append(buffer, 0xFF, 0xFF)
		}
		if nn, err := hr.Write(buffer); err != nil {
			return n, err
		} else {
			n += int64(nn)
		}
	}
	return n, nil
}

type hrdlRelayer struct {
	w io.Writer
}

func HRDL(w io.Writer) io.Writer {
	return &hrdlRelayer{w: w}
}

func (r *hrdlRelayer) Write(bs []byte) (int, error) {
	return r.w.Write(bs)
}
