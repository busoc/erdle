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
	// rs := erdle.NewBuilder(r, false)
	rs := Ring(4<<20, erdle.NewBuilder(r, false))
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
	sequence uint16
	size     int
}

const hdkHeaderLen = 12 // sync(4)+preamble(2)+sequence(2)+size(4)

func Hadock(w io.Writer, size int) io.Writer {
	preamble := uint16(hdkVersion)<<12 | uint16(vmuVersion)<<8 | uint16(hdkInstance)
	buffer := make([]byte, hdkHeaderLen+size+2)

	copy(buffer, erdle.Word)
	binary.BigEndian.PutUint16(buffer[4:], preamble)

	return &hadockRelayer{
		Writer: w,
		buffer: buffer,
		size:   len(buffer) - 2,
	}
}

func (hr *hadockRelayer) ReadFrom(r io.Reader) (int64, error) {
	var n int64

	for {
		nn, err := r.Read(hr.buffer[hdkHeaderLen:hr.size])
		switch err {
		case nil:
		case erdle.ErrFull:
			binary.BigEndian.PutUint16(hr.buffer[hdkHeaderLen+nn:], 0xFFFF)
			nn += 2
			hr.sequence++
		default:
			return n, err
		}

		var ix int
		if bytes.Equal(hr.buffer[hdkHeaderLen:hdkHeaderLen+4], erdle.Word) {
			size := binary.LittleEndian.Uint32(hr.buffer[hdkHeaderLen+4:]) + 4

			vs := make([]byte, 4)
			binary.BigEndian.PutUint32(vs, size)

			binary.BigEndian.PutUint16(hr.buffer[6:], hr.sequence)
			binary.BigEndian.PutUint32(hr.buffer[8:], size)

			nn = copy(hr.buffer[hdkHeaderLen:], hr.buffer[hdkHeaderLen+8:hdkHeaderLen+nn]) + hdkHeaderLen
		} else {
			ix = hdkHeaderLen
		}
		if nn, err := hr.Write(hr.buffer[ix : ix+nn]); err != nil {
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

type ring struct {
	buffer []byte

	rix   int
	rchan chan int

	wix   int
	wchan chan int
}

func Ring(s int, rs io.Reader) io.ReadWriter {
	r := ring{
		buffer: make([]byte, s),
		rchan:  make(chan int),
		wchan:  make(chan int),
	}
	go r.syncboth()
	go r.fill(rs)
	return &r
}

func (r *ring) Read(bs []byte) (int, error) {
	r.rchan <- len(bs)
	<-r.rchan
	n := copy(bs, r.buffer[r.rix:])
	if n < len(bs) {
		n, r.rix = copy(bs[n:], r.buffer), 0
	}
	r.rix += n
	return len(bs), nil
}

func (r *ring) Write(bs []byte) (int, error) {
	n := copy(r.buffer[r.wix:], bs)
	if n < len(bs) {
		n, r.wix = copy(r.buffer, bs[n:]), 0
	}
	r.wix += n
	r.wchan <- len(bs)
	return len(bs), nil
}

func (r *ring) fill(rs io.Reader) {
	for {
		_, err := io.Copy(r, rs)
		if !erdle.IsErdleError(err) {
			return
		}
	}
}

func (r *ring) syncboth() {
	var available int
	for {
		log.Println(available)
		select {
		case n, _ := <-r.wchan:
			available += n
		case n, _ := <-r.rchan:
			if n < available {
				available -= n
				r.rchan <- n
				break
			}
			for nn := range r.wchan {
				available += nn
				if n < available {
					available -= n
					r.rchan <- n
					break
				}
			}
		}
	}
}
