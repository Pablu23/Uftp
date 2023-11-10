package common

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const PacketSize = 504

const HeaderSize int = 32 + 1 + 4 + 4
const SecureHeaderSize int = 1 + 42 + 32 + 4

type SessionID [32]byte

type SecurePacket struct {
	IsRsa         byte // 0 = false everything else is true
	Nonce         [24]byte
	Sid           SessionID
	DataLength    uint32
	EncryptedData []byte
}

type Packet struct {
	// headerLength uint32
	Sid        SessionID
	Flag       HeaderFlag
	Sync       uint32
	DataLength uint32
	Data       []byte
}

func NewSymetricSecurePacket(key [32]byte, pck *Packet) *SecurePacket {
	sid := pck.Sid
	data := pck.ToBytes()
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, 24)
	if _, err = rand.Read(nonce); err != nil {
		panic(err)
	}

	encrypted := make([]byte, len(data)+aead.Overhead())
	encrypted = aead.Seal(nil, nonce, data, nil)

	return &SecurePacket{
		IsRsa:         0,
		Nonce:         [24]byte(nonce),
		Sid:           sid,
		DataLength:    uint32(len(encrypted)),
		EncryptedData: encrypted,
	}
}

func SecurePacketFromBytes(bytes []byte) SecurePacket {
	isRsa := bytes[0]
	nonce := bytes[1:25]
	sid := SessionID(bytes[25:57])
	length := binary.LittleEndian.Uint32(bytes[57:61])
	enc := bytes[61 : 61+length]

	return SecurePacket{
		IsRsa:         isRsa,
		Nonce:         [24]byte(nonce),
		Sid:           sid,
		DataLength:    length,
		EncryptedData: enc,
	}
}

func (secPck *SecurePacket) ToBytes() []byte {
	arr := make([]byte, SecureHeaderSize+len(secPck.EncryptedData))
	arr[0] = secPck.IsRsa
	copy(arr[1:25], secPck.Nonce[:])
	copy(arr[25:57], secPck.Sid[:])
	binary.LittleEndian.PutUint32(arr[57:61], secPck.DataLength)
	copy(arr[61:], secPck.EncryptedData)

	return arr
}

func (secPck *SecurePacket) ExtractPacket(key [32]byte) (Packet, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		panic(err)
	}
	data, err := aead.Open(nil, secPck.Nonce[:], secPck.EncryptedData, nil)
	if err != nil {
		return Packet{}, err
	}
	// fmt.Println(data)
	packet := PacketFromBytes(data)
	return packet, nil
}

func NewRsaPacket(sid SessionID, key [32]byte) *SecurePacket {
	return &SecurePacket{
		IsRsa:         1,
		Nonce:         [24]byte(make([]byte, 24)),
		Sid:           sid,
		EncryptedData: key[:],
	}
}

func (secPck *SecurePacket) ExtractKey( /*RSA HERE LATER*/ ) []byte {
	return secPck.EncryptedData[:32]
}

func PacketFromBytes(bytes []byte) Packet {
	flag := HeaderFlag(bytes[0])
	sid := SessionID(bytes[1:33])
	sync := binary.LittleEndian.Uint32(bytes[33:37])
	dataLength := binary.LittleEndian.Uint32(bytes[37:41])
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
	copy(arr[1:33], pck.Sid[:])
	binary.LittleEndian.PutUint32(arr[33:37], pck.Sync)
	binary.LittleEndian.PutUint32(arr[37:41], pck.DataLength)
	copy(arr[41:], pck.Data)

	return arr
}

type HeaderFlag uint8

const (
	Request HeaderFlag = iota
	PTE     HeaderFlag = iota
	Ack     HeaderFlag = iota
	File    HeaderFlag = iota
	End     HeaderFlag = iota
	Resend  HeaderFlag = iota
)