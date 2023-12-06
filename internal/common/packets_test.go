package common

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestPacketFromBytes(t *testing.T) {
	sid := [8]byte{255, 255, 255, 255, 255, 255, 255, 255}
	data := []byte{1, 0, 1}
	dataLength := len(data)

	want := Packet{
		Flag:       Request,
		Sync:       0,
		Data:       data,
		Sid:        sid,
		DataLength: uint32(dataLength),
	}

	bytes := []byte{0, 0, 0, 0, 0, 1, 0, 1}

	pck := PacketFromBytes(bytes, uint32(dataLength), sid)

	if !cmp.Equal(pck, want) {
		t.Fail()
	}
}
