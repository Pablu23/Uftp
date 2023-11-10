package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const HeaderSize int = 32 + 1 + 4 + 4
const SecureHeaderSize int = 1 + 42 + 32 + 4

type SessionID [32]byte

type SecurePacket struct {
	isRsa         byte // 0 = false everything else is true
	nonce         [24]byte
	sid           SessionID
	dataLength    uint32
	encryptedData []byte
}

type Packet struct {
	// headerLength uint32
	sid        SessionID
	flag       HeaderFlag
	sync       uint32
	dataLength uint32
	data       []byte
}

func NewSymetricSecurePacket(key [32]byte, pck *Packet) *SecurePacket {
	sid := pck.sid
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
		isRsa:         0,
		nonce:         [24]byte(nonce),
		sid:           sid,
		dataLength:    uint32(len(encrypted)),
		encryptedData: encrypted,
	}
}

func SecurePacketFromBytes(bytes []byte) SecurePacket {
	isRsa := bytes[0]
	nonce := bytes[1:25]
	sid := SessionID(bytes[25:57])
	length := binary.LittleEndian.Uint32(bytes[57:61])
	enc := bytes[61 : 61+length]

	return SecurePacket{
		isRsa:         isRsa,
		nonce:         [24]byte(nonce),
		sid:           sid,
		encryptedData: enc,
		dataLength:    length,
	}
}

func (secPck *SecurePacket) ToBytes() []byte {
	arr := make([]byte, SecureHeaderSize+len(secPck.encryptedData))
	arr[0] = secPck.isRsa
	copy(arr[1:25], secPck.nonce[:])
	copy(arr[25:57], secPck.sid[:])
	binary.LittleEndian.PutUint32(arr[57:61], secPck.dataLength)
	copy(arr[61:], secPck.encryptedData)

	return arr
}

func (secPck *SecurePacket) ExtractPacket(key [32]byte) (*Packet, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		panic(err)
	}
	data, err := aead.Open(nil, secPck.nonce[:], secPck.encryptedData, nil)
	if err != nil {
		return nil, err
	}
	packet := PacketFromBytes(data)
	return &packet, nil
}

func NewRsaPacket(sid SessionID, key [32]byte) *SecurePacket {
	return &SecurePacket{
		isRsa:         1,
		nonce:         [24]byte(make([]byte, 24)),
		sid:           sid,
		encryptedData: key[:],
	}
}

func (secPck *SecurePacket) ExtractKey( /*RSA HERE LATER*/ ) []byte {
	return secPck.encryptedData[:32]
}

func PacketFromBytes(bytes []byte) Packet {
	flag := HeaderFlag(bytes[0])
	sid := SessionID(bytes[1:33])
	sync := binary.LittleEndian.Uint32(bytes[33:37])
	dataLength := binary.LittleEndian.Uint32(bytes[37:41])
	pck := Packet{
		sid:        sid,
		flag:       flag,
		sync:       sync,
		dataLength: dataLength,
		data:       bytes[HeaderSize : HeaderSize+int(dataLength)],
	}
	return pck
}

func NewAck(pckToAck *Packet) *Packet {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, pckToAck.sync)
	return &Packet{
		sid:        pckToAck.sid,
		flag:       Ack,
		sync:       pckToAck.sync + 1,
		dataLength: uint32(4),
		data:       data,
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
		sid:        SessionID(buf),
		flag:       Request,
		sync:       0,
		dataLength: uint32(len(data)),
		data:       data,
	}
}

func (pck *Packet) GetUint32Payload() (uint32, error) {
	flag := pck.flag
	if flag != PTE && flag != Ack && flag != End && flag != Resend {
		return 0, errors.New(fmt.Sprintf("Can not get Sync from Packet Type with flag: %v", flag))
	}
	return binary.LittleEndian.Uint32(pck.data), nil
}

func (pck *Packet) GetFilePath() (string, error) {
	if pck.flag != Request {
		return "", errors.New("Can not get FilePath from Packet that is not Request")
	}
	return string(pck.data), nil
}

func NewResendFile(resendPck *Packet, data []byte) *Packet {
	sync, _ := resendPck.GetUint32Payload()
	return &Packet{
		sid:        resendPck.sid,
		flag:       File,
		sync:       sync,
		dataLength: uint32(len(data)),
		data:       data,
	}
}

func NewFile(lastPck *Packet, data []byte) *Packet {
	return &Packet{
		sid:        lastPck.sid,
		flag:       File,
		sync:       lastPck.sync + 1,
		dataLength: uint32(len(data)),
		data:       data,
	}
}

func NewEnd(lastFilePck *Packet) *Packet {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, lastFilePck.sync)
	return &Packet{
		sid:        lastFilePck.sid,
		flag:       End,
		sync:       lastFilePck.sync + 1,
		dataLength: uint32(4),
		data:       data,
	}
}

func NewResend(sync uint32, lastPck *Packet) *Packet {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, sync)
	return &Packet{
		sid:        lastPck.sid,
		flag:       Resend,
		sync:       lastPck.sync + 1,
		dataLength: uint32(4),
		data:       data,
	}
}

func NewPte(fileSize uint32, lastPck *Packet) *Packet {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, fileSize)
	return &Packet{
		sid:        lastPck.sid,
		flag:       PTE,
		sync:       lastPck.sync + 1,
		dataLength: uint32(4),
		data:       data,
	}
}

func (pck *Packet) ToBytes() []byte {
	arr := make([]byte, HeaderSize+int(pck.dataLength))
	arr[0] = byte(pck.flag)
	copy(arr[1:33], pck.sid[:])
	binary.LittleEndian.PutUint32(arr[33:37], pck.sync)
	binary.LittleEndian.PutUint32(arr[37:41], pck.dataLength)
	copy(arr[41:], pck.data)

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
