package common

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

type Packet struct {
	Flag HeaderFlag
	Sync uint32
	Data []byte

	// NOT IN BYTES THAT ARE SENT
	Sid        SessionID
	DataLength uint32
}

func PacketFromBytes(bytes []byte, dataLength uint32, sid SessionID) Packet {
	flag := HeaderFlag(bytes[0])
	sync := binary.LittleEndian.Uint32(bytes[1:5])
	pck := Packet{
		Sid:        sid,
		Flag:       flag,
		Sync:       sync,
		DataLength: dataLength,
		Data:       bytes[HeaderSize : HeaderSize+int(dataLength)],
	}
	return pck
}

func NewAck(pckToAck *Packet) *Packet {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, pckToAck.Sync)
	return &Packet{
		Sid:        pckToAck.Sid,
		Flag:       Ack,
		Sync:       pckToAck.Sync + 1,
		DataLength: uint32(4),
		Data:       data,
	}
}

func NewRequest(path string) *Packet {
	data := []byte(path)
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}

	return &Packet{
		Sid:        SessionID(buf),
		Flag:       Request,
		Sync:       0,
		DataLength: uint32(len(data)),
		Data:       data,
	}
}

func (pck *Packet) GetUint32Payload() (uint32, error) {
	flag := pck.Flag
	if flag != PTE && flag != Ack && flag != End && flag != Resend {
		return 0, errors.New(fmt.Sprintf("Can not get Sync from Packet Type with flag: %v", flag))
	}
	return binary.LittleEndian.Uint32(pck.Data), nil
}

func (pck *Packet) GetFilePath() (string, error) {
	if pck.Flag != Request {
		return "", errors.New("Can not get FilePath from Packet that is not Request")
	}
	return string(pck.Data), nil
}

func NewResendFile(resendPck *Packet, data []byte) *Packet {
	sync, _ := resendPck.GetUint32Payload()
	return &Packet{
		Sid:        resendPck.Sid,
		Flag:       File,
		Sync:       sync,
		DataLength: uint32(len(data)),
		Data:       data,
	}
}

func NewFile(lastPck *Packet, data []byte) *Packet {
	return &Packet{
		Sid:        lastPck.Sid,
		Flag:       File,
		Sync:       lastPck.Sync + 1,
		DataLength: uint32(len(data)),
		Data:       data,
	}
}

func NewEnd(lastFilePck *Packet) *Packet {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, lastFilePck.Sync)
	return &Packet{
		Sid:        lastFilePck.Sid,
		Flag:       End,
		Sync:       lastFilePck.Sync + 1,
		DataLength: uint32(4),
		Data:       data,
	}
}

func NewResend(sync uint32, lastPck *Packet) *Packet {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, sync)
	return &Packet{
		Sid:        lastPck.Sid,
		Flag:       Resend,
		Sync:       lastPck.Sync + 1,
		DataLength: uint32(4),
		Data:       data,
	}
}

func NewPte(fileSize uint32, lastPck *Packet) *Packet {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, fileSize)
	return &Packet{
		Sid:        lastPck.Sid,
		Flag:       PTE,
		Sync:       lastPck.Sync + 1,
		DataLength: uint32(4),
		Data:       data,
	}
}

func (pck *Packet) ToBytes() []byte {
	arr := make([]byte, HeaderSize+int(pck.DataLength))
	arr[0] = byte(pck.Flag)
	binary.LittleEndian.PutUint32(arr[1:5], pck.Sync)
	copy(arr[HeaderSize:HeaderSize+int(pck.DataLength)], pck.Data)

	return arr
}
