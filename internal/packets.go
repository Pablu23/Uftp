package packets

type Packet struct {
	header Header
	data   Data
}

type Header struct {
	headerLength uint32
	flag         HeaderFlag
	sync         uint32
	dataLength   uint32
}

type Data interface {
	ToBytes() []byte
}

type StringData string

func (s StringData) ToBytes() []byte {
	return []byte(s)
}

type HeaderFlag uint32

const (
	Request HeaderFlag = iota
	PTE     HeaderFlag = iota
	Ack     HeaderFlag = iota
	File    HeaderFlag = iota
	End     HeaderFlag = iota
	Resend  HeaderFlag = iota
)
