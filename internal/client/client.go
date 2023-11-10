package client

import (
	"common"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"time"
)

func SendPacket(pck *common.Packet, key [32]byte, conn *net.UDPConn) {
	secPck := common.NewSymetricSecurePacket(key, pck)
	if _, err := conn.Write(secPck.ToBytes()); err != nil {
		panic(err)
	}
}

func ReceivePacket(key [32]byte, conn *net.UDPConn) common.Packet {
	bytes := make([]byte, common.PacketSize+common.SecureHeaderSize)
	_, _, err := conn.ReadFrom(bytes)
	if err != nil {
		panic(err)
	}

	secPck := common.SecurePacketFromBytes(bytes)
	pck, err := secPck.ExtractPacket(key)

	if err != nil {
		panic(err)
	}

	fmt.Printf("Decrypted Packet, Sync: %v, Type: %v\n", pck.Sync, pck.Flag)

	return pck
}

func ReceivePacketWithTimeout(key [32]byte, conn *net.UDPConn) (common.Packet, bool) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	bytes := make([]byte, common.PacketSize)

	_, _, err := conn.ReadFrom(bytes)
	if err != nil {
		if e, ok := err.(net.Error); !ok || !e.Timeout() {
			// If it's not a timeout, log the error as usual
			panic(err)
		}

		return common.Packet{}, false
	}

	secPck := common.SecurePacketFromBytes(bytes)
	pck, err := secPck.ExtractPacket(key)
	if err != nil {
		panic(err)
	}

	return pck, true
}

func GetFile(path string) {
	request := common.NewRequest(path)

	k := make([]byte, 32)
	_, err := rand.Read(k)
	if err != nil {
		panic(err)
	}
	key := [32]byte(k)
	keyExchangePck := common.NewRsaPacket(request.Sid, key)

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

	file, err := os.Create("out/" + hex.EncodeToString(request.Sid[:]) + ".recv")
	if err != nil {
		panic(err)
	}

	pck := ReceivePacket(key, conn)
	if pck.Flag != common.PTE {
		panic("Header flag was supposed to be PTE")
	}

	size, err := pck.GetUint32Payload()
	if err != nil {
		panic(err)
	}

	file.Truncate(int64(size))

	ackPck := common.NewAck(&pck)
	SendPacket(ackPck, key, conn)

	recvPackets := make([]uint32, 0)
	var endPacket common.Packet

	for {
		pck := ReceivePacket(key, conn)
		if pck.Flag == common.End {
			endPacket = pck
			break
		}
		if pck.Flag != common.File {
			fmt.Printf("Received %v Packet, but expected File Packet\n", pck.Flag)
			continue
		}

		recvPackets = append(recvPackets, pck.Sync)

		offset := (int64(pck.Sync) - int64(ackPck.Sync+1)) * (common.PacketSize - int64(common.HeaderSize))
		// fmt.Printf("Sync: %v, Offset: %v\n", pck.Sync, offset)

		_, err = file.WriteAt(pck.Data, offset)
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

	for i := ackPck.Sync + 1; i < endPacket.Sync; i++ {
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
			resend := common.NewResend(uint32(sync), lastPacket)
			SendPacket(resend, key, conn)
			lastPacket = resend

			pck, received := ReceivePacketWithTimeout(key, conn)

			if !received {
				continue
			}

			offset := (int64(pck.Sync) - int64(ackPck.Sync+1)) * (common.PacketSize - int64(common.HeaderSize))
			// fmt.Printf("Sync: %v, Offset: %v\n", pck.sync, offset)

			_, err = file.WriteAt(pck.Data, offset)
			if err != nil {
				panic(err)
			}

			_, index := contains(lostPackets, pck.Sync)
			fmt.Printf("Removing sync %v from LostPackets\n", pck.Sync)
			lostPackets = remove(lostPackets, index)

		}
	}

	ack := common.NewAck(&endPacket)
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
