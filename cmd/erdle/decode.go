package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"io"
	"log"
	"os"

	"github.com/busoc/erdle"
	"github.com/midbel/cli"
)

var decodeCommand = &cli.Command{
	Usage: "decode [-e] <file,...>",
	Short: "",
	Run:   runDecode,
}

func runDecode(cmd *cli.Command, args []string) error {
	size := cmd.Flag.Int("s", 8<<20, "size")
	hrdfe := cmd.Flag.Bool("e", false, "hrdfe")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	buffer := make([]byte, *size)
	var i int
	for _, p := range cmd.Flag.Args() {
		r, err := os.Open(p)
		if err != nil {
			return err
		}
		hr := erdle.NewBuilder(r, *hrdfe)
		for {
			n, err := hr.Read(buffer)
			if err == io.EOF {
				break
			}
			if err != nil && err != io.EOF {
				return err
			}
			if bytes.Equal(buffer[:4], erdle.Word) {
				i++
				xxx := md5.Sum(buffer[:n])
				s := binary.LittleEndian.Uint32(buffer[4:])
				log.Printf("got %7d ==> %7d (%d) %x %x %x", i, s, n, buffer[:8], buffer[8:24], xxx)
			}
		}
		r.Close()
	}
	return nil
}
