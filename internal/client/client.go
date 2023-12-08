package client

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/kelindar/bitmap"

	"github.com/Pablu23/Uftp/internal/common"
)

func SendPacket(pck *common.Packet, key [32]byte, conn *net.UDPConn) {
	secPck := common.NewSymmetricSecurePacket(key, pck)
	if _, err := conn.Write(secPck.ToBytes()); err != nil {
		panic(err)
	}
}

func ReceivePacket(key [32]byte, conn *net.UDPConn) common.Packet {
	bytes := make([]byte, common.PacketSize)
	_, _, err := conn.ReadFrom(bytes)
	if err != nil {
		panic(err)
	}

	secPck, err := common.SecurePacketFromBytes(bytes)
	if err != nil {
		panic(err)
	}
	pck, err := secPck.ExtractPacket(key)
	if err != nil {
		fmt.Println(bytes)
		panic(err)
	}

	// fmt.Printf("Decrypted Packet, Sync: %v, Type: %v\n", pck.Sync, pck.Flag)

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

	secPck, err := common.SecurePacketFromBytes(bytes)
	if err != nil {
		panic(err)
	}
	pck, err := secPck.ExtractPacket(key)
	if err != nil {
		panic(err)
	}

	return pck, true
}

func StartConnection(sid common.SessionID, key [32]byte, address string) {
	pubkey, err := os.ReadFile("pubkey.pem")
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(pubkey)
	pKey, _ := x509.ParsePKCS1PublicKey(block.Bytes)
	keyExchangePck, err := common.NewRsaPacket(pKey, key, sid)
	if err != nil {
		panic(err)
	}

	var d net.Dialer
	conn, err := d.Dial("tcp", address)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	conn.Write(keyExchangePck.ToBytes())

	var buf [1024]byte
	_, err = conn.Read(buf[:])
	if err != nil && !errors.Is(err, io.EOF) {
		panic(err)
	}
}

func GetFile(path string, address string) {
	request := common.NewRequest(path)

	k := make([]byte, 32)
	_, err := rand.Read(k)
	if err != nil {
		panic(err)
	}
	key := [32]byte(k)

	StartConnection(request.Sid, key, fmt.Sprintf("%v:13375", address))

	// udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:13374")
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%v:13374", address))
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

	var endPacket common.Packet

	var recvPackets bitmap.Bitmap

	dataReceived := 0

	go func() {
		last := 0

		fmt.Print("\033[s")

		for {
			fmt.Print("\033[u\033[K")
			fmt.Printf("Throughput: %v Mbit/s\n", ((dataReceived-last)*8)/1024/1024)
			last = dataReceived
			time.Sleep(1 * time.Second)
		}
	}()

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

		recvPackets.Set(pck.Sync)
		offset := (int64(pck.Sync) - int64(ackPck.Sync+1)) * int64(common.MaxDataSize)
		_, err = file.WriteAt(pck.Data, offset)
		if err != nil {
			panic(err)
		}

		dataReceived += int(pck.DataLength)
	}

	lostPackets := make([]uint32, 0)

	var reverse bitmap.Bitmap
	reverse.Grow(endPacket.Sync)
	reverse.Ones()

	for i := 0; i <= int(ackPck.Sync); i++ {
		recvPackets.Set(uint32(i))
	}

	recvPackets.Xor(reverse)

	recvPackets.Range(func(x uint32) {
		if x < endPacket.Sync {
			lostPackets = append(lostPackets, x)
		}
	})

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

			offset := (int64(pck.Sync) - int64(ackPck.Sync+1)) * int64(common.MaxDataSize)
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
