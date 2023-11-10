package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"time"
)

func SendPacket(pck *Packet, key [32]byte, conn *net.UDPConn) {
	secPck := NewSymetricSecurePacket(key, pck)
	fmt.Println(secPck)
	if _, err := conn.Write(secPck.ToBytes()); err != nil {
		panic(err)
	}
}

func GetFile(path string) {
	request := NewRequest(path)

	k := make([]byte, 32)
	_, err := rand.Read(k)
	if err != nil {
		panic(err)
	}
	key := [32]byte(k)
	keyExchangePck := NewRsaPacket(request.sid, key)

	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:13374")
	// udpAddr, err := net.ResolveUDPAddr("udp", "192.168.2.145:13374")

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

	_, err = conn.Write(keyExchangePck.ToBytes())
	if err != nil {
		panic(err)
	}

	SendPacket(request, key, conn)

	bytes := make([]byte, PacketSize)
	file, err := os.Create("out/" + hex.EncodeToString(request.sid[:]) + ".recv")
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
	SendPacket(ackPck, key, conn)

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

	for i := ackPck.sync + 1; i < endPacket.sync; i++ {
		if b, _ := contains(recvPackets, i); !b {
			lostPackets = append(lostPackets, i)
		}
	}

	for _, i := range lostPackets {
		fmt.Println(i)
	}

	lastPacket := ackPck

	for {
		if len(lostPackets) == 0 {
			break
		}

		for _, sync := range lostPackets {

			fmt.Printf("Request resend for %v\n", sync)
			resend := NewResend(uint32(sync), lastPacket)
			SendPacket(resend, key, conn)
			lastPacket = resend

			conn.SetReadDeadline(time.Now().Add(10 * time.Second))

			_, _, err = conn.ReadFrom(bytes)
			if err != nil {
				if e, ok := err.(net.Error); !ok || !e.Timeout() {
					// If it's not a timeout, log the error as usual
					panic(err)
				}
				continue
			}

			pck := PacketFromBytes(bytes)
			offset := (int64(pck.sync) - int64(ackPck.sync+1)) * (PacketSize - int64(HeaderSize))
			// fmt.Printf("Sync: %v, Offset: %v\n", pck.sync, offset)

			_, err = file.WriteAt(pck.data, offset)
			if err != nil {
				panic(err)
			}

			_, index := contains(lostPackets, pck.sync)
			fmt.Printf("Removing sync %v from LostPackets\n", pck.sync)
			lostPackets = remove(lostPackets, index)

		}
	}

	ack := NewAck(&endPacket)
	SendPacket(ack, key, conn)
}

func remove(s []uint32, i int) []uint32 {
	s[i] = s[len(s)-1]
	return s[:len(s)-1]
}

func contains(s []uint32, e uint32) (bool, int) {
	for i, a := range s {
		if a == e {
			return true, i
		}
	}
	return false, 0
}
