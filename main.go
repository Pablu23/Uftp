package main

import (
	"os"
)

const PacketSize = 504

// type packet struct {
// 	syn uint32
// 	// Flag
// 	len  uint32
// 	data []byte
// }

// func (packet packet) ToBytes() []byte {
// 	arr := make([]byte, 4+4+len(packet.data))
// 	binary.LittleEndian.PutUint32(arr[0:4], packet.syn)
// 	binary.LittleEndian.PutUint32(arr[4:8], packet.len)
// 	for i := 0; i < len(packet.data); i++ {
// 		arr[8+i] = packet.data[i]
// 	}
// 	return arr
// }

// func makePacketFrombytes(bytes []byte) packet {
// 	syn := binary.LittleEndian.Uint32(bytes[0:4])
// 	len := binary.LittleEndian.Uint32(bytes[4:8])
// 	data := bytes[8:(8 + len)]
// 	return packet{syn: syn, len: len, data: data}
// }

// func check(e error) {
// 	if e != nil {
// 		panic(e)
// 	}
// }

// func sendFile(conn *net.UDPConn, addr *net.UDPAddr) {
// 	dat, err := os.ReadFile("testFile")
// 	check(err)

// 	offset := 0
// 	syn := 0

// 	for {
// 		fmt.Printf("Sending Syn %v to addr %v\n", syn, addr.IP.String())
// 		remaining := PacketSize
// 		if offset+PacketSize > len(dat) {
// 			remaining = len(dat) - offset
// 		}

// 		pck := packet{
// 			data: dat[offset : offset+remaining],
// 			len:  uint32(remaining),
// 			syn:  uint32(syn),
// 		}

// 		conn.WriteToUDP(pck.ToBytes(), addr)

// 		syn += 1
// 		offset = offset + remaining

// 		if offset >= len(dat) {
// 			break
// 		}
// 	}

// 	endPacket := packet{
// 		len: 0,
// 		syn: uint32(syn),
// 	}

// 	conn.WriteToUDP(endPacket.ToBytes(), addr)
// }

// func checkFileTest() {
// 	dat, err := os.ReadFile("testFile")
// 	check(err)

// 	offset := 0
// 	syn := 0

// 	for {
// 		remaining := PacketSize
// 		if offset+PacketSize > len(dat) {
// 			remaining = len(dat) - offset
// 		}

// 		pck := packet{
// 			data: dat[offset : offset+remaining],
// 			len:  uint32(remaining),
// 			syn:  uint32(syn),
// 		}

// 		str := hex.EncodeToString(pck.ToBytes())
// 		fmt.Println(pck)
// 		fmt.Println(str)

// 		// conn.WriteToUDP(pck.ToBytes(), addr)

// 		offset = offset + remaining
// 		syn += 1

// 		if offset >= len(dat) {
// 			break
// 		}
// 	}
// }

// func resend(conn *net.UDPConn, addr *net.UDPAddr, syn uint32) {
// 	dat, err := os.ReadFile("testFile")
// 	check(err)

// 	index := int((syn + 1) * PacketSize)
// 	remaining := PacketSize
// 	if index+PacketSize > len(dat) {
// 		remaining = len(dat) - index
// 	}

// 	pck := packet{
// 		data: dat[index : index+remaining],
// 		syn:  syn,
// 		len:  uint32(remaining),
// 	}

// 	conn.WriteToUDP(pck.ToBytes(), addr)
// }

// func server() {
// 	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:13374")

// 	if err != nil {
// 		fmt.Println(err)
// 		os.Exit(1)
// 	}

// 	conn, err := net.ListenUDP("udp", udpAddr)

// 	if err != nil {
// 		fmt.Println(err)
// 		os.Exit(1)
// 	}

// 	for {
// 		var buf [PacketSize]byte
// 		_, addr, err := conn.ReadFromUDP(buf[0:])
// 		if err != nil {
// 			fmt.Println(err)
// 			return
// 		}

// 		pck := makePacketFrombytes(buf[0:])

// 		if pck.len == 0 {
// 			sendFile(conn, addr)
// 		} else {
// 			resend(conn, addr, pck.syn)
// 		}
// 	}
// }

// func client() {
// 	// Resolve the string address to a UDP address
// 	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:13374")

// 	if err != nil {
// 		fmt.Println(err)
// 		os.Exit(1)
// 	}

// 	// Dial to the address with UDP
// 	conn, err := net.DialUDP("udp", nil, udpAddr)

// 	if err != nil {
// 		fmt.Println(err)
// 		os.Exit(1)
// 	}

// 	initPacket := packet{
// 		syn: 0,
// 		len: 0,
// 	}

// 	// Send a message to the server
// 	_, err = conn.Write(initPacket.ToBytes())
// 	fmt.Println("send...")
// 	if err != nil {
// 		fmt.Println(err)
// 		os.Exit(1)
// 	}

// 	bytes := make([]byte, 512)
// 	var syns []int
// 	var endSyn uint32 = 0

// 	for {
// 		_, _, err := conn.ReadFrom(bytes)
// 		check(err)

// 		pck := makePacketFrombytes(bytes)

// 		// if pck.syn != currSyn {
// 		// 	fmt.Println("Out of Sync")
// 		// 	r.PushFront(currSyn)
// 		// }

// 		syns = append(syns, int(pck.syn))
// 		fmt.Println(pck)

// 		// currSyn += 1

// 		if pck.len == 0 {
// 			endSyn = pck.syn
// 			break
// 		}
// 	}

// 	sort.Ints(syns)
// 	if len(syns) != int(endSyn+1) {

// 	}

// 	for i := 0; i < int(endSyn); i++ {
// 		if i < len(syns) {
// 			if syns[i] != i {
// 				fmt.Printf("Out of Sync on Packet %v\n", i)
// 			}
// 		} else {
// 			fmt.Printf("Out of Sync on Packet %v\n", i)
// 		}
// 	}
// }

func main() {
	if os.Args[1] == "server" {
		server := New()
		server.Serve()
	} else {
		GetFile(os.Args[2])
	}
}
