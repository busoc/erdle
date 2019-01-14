package main

import (
	"bytes"
	"io"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type pcapReader struct {
	handler *pcap.Handle
	// bpf *pcap.BPF
}

func PCAPReader(f, e string) (io.Reader, error) {
	h, err := pcap.OpenOffline(f)
	if err != nil {
		return nil, err
	}
	if e != "" {
		if err := h.SetBPFFilter(e); err != nil {
			return nil, err
		}
	}
	return &pcapReader{handler: h}, nil
}

func (r *pcapReader) Read(bs []byte) (int, error) {
	for {
		xs, _, err := r.handler.ReadPacketData()
		if err != nil {
			if _, ok := err.(pcap.NextError); ok {
				return 0, io.EOF
			}
			return 0, err
		}
		p := gopacket.NewPacket(xs, layers.LayerTypeEthernet, gopacket.Default)

		if a := p.ApplicationLayer(); a != nil {
			xs = a.Payload()
			if !bytes.HasPrefix(xs, Magic) {
				continue
			}
		} else {
			continue
		}
		return copy(bs, xs), nil
	}
}
