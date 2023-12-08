package common

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

type SecurePacket struct {
	Nonce         [24]byte
	Sid           SessionID
	DataLength    uint32
	EncryptedData []byte
}

func NewSymmetricSecurePacket(key [32]byte, pck *Packet) *SecurePacket {
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
		Nonce:         [24]byte(nonce),
		Sid:           sid,
		DataLength:    uint32(len(encrypted)),
		EncryptedData: encrypted,
	}
}

func SecurePacketFromBytes(bytes []byte) (*SecurePacket, error) {
	nonce := bytes[:24]
	sid := SessionID(bytes[24:32])
	length := binary.LittleEndian.Uint32(bytes[32:36])
	if SecureHeaderSize+int(length) > PacketSize {
		return nil, errors.New("Packet too large")
	}
	enc := bytes[36 : SecureHeaderSize+int(length)]

	return &SecurePacket{
		Nonce:         [24]byte(nonce),
		Sid:           sid,
		DataLength:    length,
		EncryptedData: enc,
	}, nil
}

func (secPck *SecurePacket) ToBytes() []byte {
	encSize := int(secPck.DataLength)

	arr := make([]byte, SecureHeaderSize+encSize)
	copy(arr[0:24], secPck.Nonce[:])
	copy(arr[24:32], secPck.Sid[:])
	binary.LittleEndian.PutUint32(arr[32:36], secPck.DataLength)
	copy(arr[36:SecureHeaderSize+encSize], secPck.EncryptedData)

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
	packet := PacketFromBytes(
		data,
		secPck.DataLength-uint32(HeaderSize)-uint32(aead.Overhead()),
		secPck.Sid,
	)
	return packet, nil
}
