package common

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestPacketFromBytes(t *testing.T) {
	sid := [8]byte{255, 255, 255, 255, 255, 255, 255, 255}
	data := []byte{1, 0, 1}
	dataLength := len(data)

	expect := Packet{
		Flag:       Request,
		Sync:       0,
		Data:       data,
		Sid:        sid,
		DataLength: uint32(dataLength),
	}

	bytes := []byte{0, 0, 0, 0, 0, 1, 0, 1}

	pck := PacketFromBytes(bytes, uint32(dataLength), sid)

	if !cmp.Equal(pck, expect) {
		t.Fail()
	}
}

func TestPacketToBytes(t *testing.T) {
	p := Packet{
		Flag:       Request,
		Sync:       0,
		Data:       []byte{101, 10, 1},
		Sid:        [8]byte{255, 255, 255, 255, 255, 255, 255, 255},
		DataLength: 3,
	}

	expect := []byte{0, 0, 0, 0, 0, 101, 10, 1}

	bytes := p.ToBytes()

	if !cmp.Equal(bytes, expect) {
		t.Fail()
	}
}

func TestSymetricSecurePacket(t *testing.T) {
	expect := Packet{
		Flag:       Request,
		Sync:       0,
		Data:       []byte{101, 10, 1},
		Sid:        [8]byte{255, 255, 255, 255, 255, 255, 255, 255},
		DataLength: 3,
	}

	key := [32]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}

	secPck := NewSymetricSecurePacket(key, &expect)

	packet, err := secPck.ExtractPacket(key)
	if err != nil {
		t.Fail()
	}

	if !cmp.Equal(packet, expect) {
		t.Fail()
	}
}

func TestSecurePacketFromBytes(t *testing.T) {
	bytes := []byte{
		//IsRsa
		0,
		// Nonce
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		// Sid
		255, 255, 255, 255, 255, 255, 255, 255,
		// Length
		3, 0, 0, 0,
		// Data
		101, 10, 1,
	}

	secPck := SecurePacketFromBytes(bytes)

	expect := SecurePacket{
		IsRsa:         0,
		Nonce:         [24]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		Sid:           [8]byte{255, 255, 255, 255, 255, 255, 255, 255},
		DataLength:    3,
		EncryptedData: []byte{101, 10, 1},
	}

	if !cmp.Equal(secPck, expect) {
		t.Fail()
	}
}

func TestSecurePacketToBytes(t *testing.T) {
	expect := []byte{
		//IsRsa
		0,
		// Nonce
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		// Sid
		255, 255, 255, 255, 255, 255, 255, 255,
		// Length
		3, 0, 0, 0,
		// Data
		101, 10, 1,
	}

	secPck := SecurePacket{
		IsRsa:         0,
		Nonce:         [24]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		Sid:           [8]byte{255, 255, 255, 255, 255, 255, 255, 255},
		DataLength:    3,
		EncryptedData: []byte{101, 10, 1},
	}

	bytes := secPck.ToBytes()

	if !cmp.Equal(bytes, expect) {
		t.Fail()
	}
}

func TestGetUint32Payload_Positive(t *testing.T) {
	pck := Packet{
		Flag:       Ack,
		Data:       []byte{40, 0, 0, 0},
		DataLength: 4,
	}

	var expect uint32 = 40

	payload, err := pck.GetUint32Payload()
	if err != nil {
		t.Fail()
	}

	if payload != expect {
		t.Fail()
	}
}

func TestGetUint32Payload_Negative(t *testing.T) {
	pck := Packet{
		Flag:       Request,
		Data:       []byte{40, 0, 0, 0},
		DataLength: 4,
	}

	_, err := pck.GetUint32Payload()
	if err == nil {
		t.Fail()
	}
}

func TestGetFilePath_Positive(t *testing.T) {
	expect := "Hello World!"
	b := []byte(expect)

	pck := Packet{
		Flag:       Request,
		Data:       b,
		DataLength: uint32(len(b)),
	}

	payload, err := pck.GetFilePath()
	if err != nil {
		t.Fail()
	}

	if payload != expect {
		t.Fail()
	}
}

func TestGetFilePath_Negative(t *testing.T) {
	pck := Packet{
		Flag:       Ack,
		Data:       []byte{40, 0, 0, 0},
		DataLength: 4,
	}

	_, err := pck.GetFilePath()
	if err == nil {
		t.Fail()
	}
}
