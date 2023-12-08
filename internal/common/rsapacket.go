package common

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
)

type RsaPacket struct {
	Sid          SessionID
	DataLength   uint32
	EncryptedKey []byte
}

func NewRsaPacket(pubKey *rsa.PublicKey, key [32]byte, sid SessionID) (*RsaPacket, error) {
	enc, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, key[:], nil)
	if err != nil {
		return nil, err
	}

	pck := RsaPacket{
		Sid:          sid,
		DataLength:   uint32(len(enc)),
		EncryptedKey: enc,
	}

	return &pck, nil
}

func (rsaPck *RsaPacket) ToBytes() []byte {
	bytes := make([]byte, rsaPck.DataLength+8+4)
	copy(bytes[0:8], rsaPck.Sid[:])
	binary.LittleEndian.PutUint32(bytes[8:12], rsaPck.DataLength)
	copy(bytes[12:], rsaPck.EncryptedKey[:])
	return bytes
}

func RsaPacketFromBytes(bytes []byte) *RsaPacket {
	sid := SessionID(bytes[0:8])
	dLen := binary.LittleEndian.Uint32(bytes[8:12])
	data := bytes[12 : 12+dLen]

	return &RsaPacket{
		Sid:          sid,
		DataLength:   dLen,
		EncryptedKey: data,
	}
}

func (rsaPck *RsaPacket) ExtractKey(priv *rsa.PrivateKey) ([32]byte, error) {
	// key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, rsaPck.EncryptedKey, nil)
	key, err := priv.Decrypt(
		rand.Reader,
		rsaPck.EncryptedKey,
		&rsa.OAEPOptions{Hash: crypto.SHA256},
	)
	if err != nil {
		return [32]byte{}, err
	}
	return [32]byte(key[0:32]), nil
}
