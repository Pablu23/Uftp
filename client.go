package main

import (
	"fmt"
	"net"
	"os"
	"sort"
)

func GetFile(path string) {
	request := NewRequest(path)

	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:13374")

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Dial to the address with UDP
	conn, err := net.DialUDP("udp", nil, udpAddr)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	_, err = conn.Write(request.ToBytes())
	if err != nil {
		panic(err)
	}

	bytes := make([]byte, PacketSize)
	file, err := os.Create(path + ".recv")
	if err != nil {
		panic(err)
	}

	_, _, err = conn.ReadFrom(bytes)
	if err != nil {
		panic(err)
	}

	pck := PacketFromBytes(bytes)
	if pck.flag != PTE {
		panic("Header flag was supposed to be PTE")
	}

	size, err := pck.GetUint32Payload()
	if err != nil {
		panic(err)
	}

	file.Truncate(int64(size))

	ackPck := NewAck(&pck)
	conn.Write(ackPck.ToBytes())

	recvPackets := make([]uint32, 0)
	var endPacket Packet

	for {
		_, _, err = conn.ReadFrom(bytes)
		if err != nil {
			panic(err)
		}

		pck := PacketFromBytes(bytes)
		if pck.flag == End {
			endPacket = pck
			break
		}
		recvPackets = append(recvPackets, pck.sync)

		offset := (int64(pck.sync) - int64(ackPck.sync+1)) * (PacketSize - int64(HeaderSize))
		fmt.Printf("Sync: %v, Offset: %v\n", pck.sync, offset)

		_, err = file.WriteAt(pck.data, offset)
		if err != nil {
			panic(err)
		}
	}

	sort.Slice(recvPackets, func(i, j int) bool {
		pckI := recvPackets[i]
		pckJ := recvPackets[j]
		return pckI < pckJ
	})

	lostPackets := make([]uint32, 0)
	lastSync := ackPck.sync
	needResend := false
	for _, i := range recvPackets {
		if lastSync+1 != i {
			lostPackets = append(lostPackets, i)
			needResend = true
		}
		lastSync = i
	}

	if !needResend {
		ack := NewAck(&endPacket)
		conn.Write(ack.ToBytes())
	}

	// sort.Slice(recvPackets, func(i, j int) bool {
	// 	pckI := recvPackets[i]
	// 	pckJ := recvPackets[j]
	// 	return pckI.sync < pckJ.sync
	// })

	// endPacketFound := false
	// needResend := false
	// lastSync := request.sync
	// fmt.Println(lastSync)
	// endPacketSync, err := endPacket.GetSync()
	// if err != nil {
	// 	panic(err)
	// }

	// for _, packet := range recvPackets {
	// 	// fmt.Println(packet.sync)
	// 	// offset := (int64(packet.sync)-1)*PacketSize - int64(HeaderSize)
	// 	// data := packet.data
	// 	// fmt.Printf("Data: %v Offset: %v\n", data, offset)

	// 	if lastSync+1 != packet.sync {
	// 		fmt.Printf("Need Packet %v resend\n", lastSync+1)
	// 		// Add to slice
	// 		needResend = true
	// 		continue
	// 	}

	// 	fmt.Printf("Writing Packet %v to file\n", packet.sync)

	// 	_, err = file.Write(packet.data)
	// 	if err != nil {
	// 		panic(err)
	// 	}

	// 	if packet.sync == endPacketSync {
	// 		endPacketFound = true
	// 	}

	// 	lastSync = packet.sync
	// }

}
