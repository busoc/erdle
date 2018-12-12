package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/midbel/rustine/sum"
)

type pool struct {
	addr     string
	instance int
	queue    chan net.Conn
}

func NewPool(a string, n, i int) (*pool, error) {
	if n <= 1 {
		return nil, fmt.Errorf("number of connections too small")
	}
	q := make(chan net.Conn, n)
	for j := 0; j < n; j++ {
		c, err := client(a, i)
		if err != nil {
			return nil, err
		}
		q <- c
	}
	p := pool{
		addr:     a,
		queue:    q,
		instance: i,
	}
	return &p, nil
}

func (p *pool) Write(bs []byte) (int, error) {
	c, err := p.pop()
	if err != nil {
		return 0, err
	}

	n, err := c.Write(bs)
	if err != nil {
		c.Close()
	} else {
		p.push(c)
	}
	return n, err
}

func (p *pool) pop() (net.Conn, error) {
	select {
	case c := <-p.queue:
		return c, nil
	default:
		return client(p.addr, p.instance)
	}
}

func (p *pool) push(c net.Conn) {
	select {
	case p.queue <- c:
	default:
		c.Close()
	}
}

type conn struct {
	net.Conn
	next     uint16
	preamble uint16

	writePacket func(*conn, []byte) (int, error)
}

func client(a string, i int) (net.Conn, error) {
	var (
		preamble  uint16
		writeFunc func(*conn, []byte) (int, error)
	)
	switch i {
	case 0, 1, 2, 255:
		preamble = uint16(hdkVersion)<<12 | uint16(vmuVersion)<<8 | uint16(i)
		writeFunc = writeHadock
	case -1:
		writeFunc = writeHRDL
	default:
		return nil, fmt.Errorf("invalid instance (%d)", i)
	}
	c, err := net.Dial(protoFromAddr(a))
	if err != nil {
		return nil, err
	}
	return &conn{
		Conn:        c,
		preamble:    preamble,
		writePacket: writeFunc,
	}, nil
}

func (c *conn) Write(bs []byte) (int, error) {
	defer func() { c.next++ }()
	return c.writePacket(c, bs)
}

func writeHRDL(c *conn, bs []byte) (int, error) {
	var buf bytes.Buffer

	buf.Write(Word)
	binary.Write(&buf, binary.LittleEndian, uint32(len(bs))-4)
	buf.Write(bs)

	n, err := io.Copy(c.Conn, &buf)
	return int(n), err
}

func writeHadock(c *conn, bs []byte) (int, error) {
	var buf bytes.Buffer

	buf.Write(Word)
	binary.Write(&buf, binary.BigEndian, c.preamble)
	binary.Write(&buf, binary.BigEndian, c.next)
	binary.Write(&buf, binary.BigEndian, uint32(len(bs)))
	buf.Write(bs)
	binary.Write(&buf, binary.BigEndian, sum.Sum1071Bis(buf.Bytes()))

	n, err := io.Copy(c.Conn, &buf)
	return int(n), err
}
