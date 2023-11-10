package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
)

type info struct {
	path        string
	lastSync    uint32
	lastPckSend HeaderFlag
	key         [32]byte
}

type Server struct {
	sessions map[SessionID]*info
	rsa      *rsa.PrivateKey
}

func New() (*Server, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)

	if err != nil {
		return nil, err
	}

	return &Server{
		sessions: make(map[SessionID]*info),
		rsa:      key,
	}, nil
}

func (server *Server) handlePacket(conn *net.UDPConn, addr *net.UDPAddr, rPacket *Packet) {
	switch rPacket.flag {
	case Request:
		server.sendPTE(conn, addr, rPacket)
		break
	case Ack:
		server.handleAck(conn, addr, rPacket)
		break
	case Resend:
		server.resend(conn, addr, rPacket)
	}
}

func (server *Server) resend(conn *net.UDPConn, addr *net.UDPAddr, pck *Packet) {
	resend, err := pck.GetUint32Payload()
	if err != nil {
		panic(err)
	}

	path := server.sessions[pck.sid].path
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// This should be different
	offset := (int64(resend) - 3) * (PacketSize - int64(HeaderSize))
	// fmt.Printf("Requested Sync: %v, Calculated Offset: %v\n", resend, offset)
	buf := make([]byte, PacketSize-HeaderSize)

	_, err = file.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		panic(err)
	}

	fmt.Printf("Resending Packet %v\n", resend)

	resendPck := NewResendFile(pck, buf)

	conn.WriteToUDP(resendPck.ToBytes(), addr)

}

func (server *Server) handleAck(conn *net.UDPConn, addr *net.UDPAddr, pck *Packet) {
	ack, err := pck.GetUint32Payload()
	if err != nil {
		panic(err)
	}
	session := server.sessions[pck.sid]
	if session == nil {
		panic(err)
	}
	if ack != session.lastSync {
		fmt.Printf("Wrong Ack %v, expected %v\n", ack, session.lastSync)
		return
	}

	if session.lastPckSend == End {
		fmt.Printf("Deleting Session %v\n", hex.EncodeToString(pck.sid[:]))
		delete(server.sessions, pck.sid)
	} else {
		fmt.Printf("Sending Data for Session %v\n", hex.EncodeToString(pck.sid[:]))
		server.sendData(conn, addr, pck)
	}
}

func (server *Server) sendPTE(conn *net.UDPConn, addr *net.UDPAddr, pck *Packet) {
	path, err := pck.GetFilePath()
	if err != nil {
		panic(err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		panic(err)
	}

	fileSize := fi.Size()

	ptePck := NewPte(uint32(fileSize), pck)
	conn.WriteToUDP(ptePck.ToBytes(), addr)

	server.sessions[pck.sid].path = path
	server.sessions[pck.sid].lastSync = ptePck.sync
	server.sessions[pck.sid].lastPckSend = ptePck.flag
}

func (server *Server) sendData(conn *net.UDPConn, addr *net.UDPAddr, pck *Packet) {
	path := server.sessions[pck.sid].path
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	buf := make([]byte, PacketSize-HeaderSize)
	filePck := pck
	for {
		r, err := file.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			panic(err)
		}
		if r == 0 {
			break
		}
		filePck = NewFile(filePck, buf[:r])
		fmt.Printf("Sending File Packet %v\n", filePck.sync)

		conn.WriteToUDP(filePck.ToBytes(), addr)
	}

	eodPck := NewEnd(filePck)
	server.sessions[pck.sid].lastSync = eodPck.sync
	server.sessions[pck.sid].lastPckSend = eodPck.flag

	fmt.Printf("Sending Eod Packet %v\n", eodPck.sync)
	conn.WriteToUDP(eodPck.ToBytes(), addr)
}

func (server *Server) Serve() {
	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:13374")

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	conn, err := net.ListenUDP("udp", udpAddr)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for {
		var buf [PacketSize]byte
		_, addr, err := conn.ReadFromUDP(buf[0:])
		if err != nil {
			fmt.Println(err)
			return
		}

		secPck := SecurePacketFromBytes(buf[:])

		fmt.Println(secPck)

		if secPck.isRsa == 0 {
			key := server.sessions[secPck.sid].key
			pck, err := secPck.ExtractPacket(key)
			if err != nil {
				fmt.Println(err)
				//fmt.Println("Could not establish secure connection")
			}
			go server.handlePacket(conn, addr, pck)
		} else {
			key := secPck.ExtractKey()
			fmt.Println(key)
			fmt.Println(secPck.sid)
			server.sessions[secPck.sid] = &info{
				key: [32]byte(key),
			}

		}
	}
}
