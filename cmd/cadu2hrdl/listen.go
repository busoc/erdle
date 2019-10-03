package main

import (
	"net"
)

func listenUDP(addr string) (net.Conn, error) {
	a, err := net.ResolveUDPAddr(protoFromAddr(addr))
	if err != nil {
		return nil, err
	}
	var c *net.UDPConn
	if a.IP.IsMulticast() {
		c, err = net.ListenMulticastUDP("udp", nil, a)
	} else {
		c, err = net.ListenUDP("udp", a)
	}
	if err != nil {
		return nil, err
	}
	if err := c.SetReadBuffer(16 << 20); err != nil {
		return nil, err
	}
	return c, nil
}
