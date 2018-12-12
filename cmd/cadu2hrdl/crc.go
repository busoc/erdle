package main

import (
  "encoding/binary"
  "hash"
)

const (
	vcduCITT = uint16(0xFFFF)
	vcduPOLY = uint16(0x1021)
)

type vcduSum struct {
	sum uint16
}

func Sum(bs []byte) uint16 {
  s := SumVCDU()
  s.Write(bs)
  return uint16(s.Sum32())
}

func SumVCDU() hash.Hash32 {
	var v vcduSum
	v.Reset()
	return &v
}

func (v *vcduSum) Size() int      { return 2 }
func (v *vcduSum) BlockSize() int { return 32 }
func (v *vcduSum) Reset()         { v.sum = vcduCITT }

func (v *vcduSum) Sum(bs []byte) []byte {
	v.Write(bs)
	vs := make([]byte, v.Size()*2)
	binary.BigEndian.PutUint32(vs, uint32(v.sum))

	return vs
}

func (v *vcduSum) Sum32() uint32 {
	return uint32(v.sum)
}

func (v *vcduSum) Write(bs []byte) (int, error) {
	for i := 0; i < len(bs); i++ {
		v.sum ^= uint16(bs[i]) << 8
		for j := 0; j < 8; j++ {
			if (v.sum & 0x8000) > 0 {
				v.sum = (v.sum << 1) ^ vcduPOLY
			} else {
				v.sum = v.sum << 1
			}
		}
	}
	return len(bs), nil
}
