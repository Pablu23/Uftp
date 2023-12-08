package common

const PacketSize = 504

const (
	HeaderSize       int = 1 + 4
	SecureHeaderSize int = 24 + 8 + 4
)

const MaxDataSize = PacketSize - HeaderSize - SecureHeaderSize - 16 // AEAD Overhead

type SessionID [8]byte

type HeaderFlag uint8

const (
	Request HeaderFlag = iota
	PTE     HeaderFlag = iota
	Ack     HeaderFlag = iota
	File    HeaderFlag = iota
	End     HeaderFlag = iota
	Resend  HeaderFlag = iota
)
