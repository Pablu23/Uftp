package main

import (
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
}

type Server struct {
	sessions map[SessionID]*info
}

func New() *Server {
	return &Server{
		sessions: make(map[SessionID]*info),
	}
}

func (server *Server) handlePacket(conn *net.UDPConn, addr *net.UDPAddr, rPacket *Packet) {
	switch rPacket.flag {
	case Request:
		server.sendPTE(conn, addr, rPacket)
		break
	case Ack:
		server.handleAck(conn, addr, rPacket)
		break
	}
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

	server.sessions[pck.sid] = &info{
		path:        path,
		lastSync:    ptePck.sync,
		lastPckSend: ptePck.flag,
	}
}

func (server *Server) sendData(conn *net.UDPConn, addr *net.UDPAddr, pck *Packet) {
	path := server.sessions[pck.sid].path
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}

	// // ONLY FOR TEST
	// firstPacket := true
	// var firstFilePckt Packet
	// // END TEST

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

		// // ONLY FOR TEST
		// if firstPacket {
		// 	firstPacket = false
		// 	firstFilePckt = Packet{
		// 		sid:        filePck.sid,
		// 		flag:       File,
		// 		sync:       filePck.sync,
		// 		dataLength: filePck.dataLength,
		// 		data:       make([]byte, filePck.dataLength),
		// 	}

		// 	copy(firstFilePckt.data, filePck.data)

		// } else {
		// 	// END
		conn.WriteToUDP(filePck.ToBytes(), addr)
		// }
	}

	// conn.WriteToUDP(firstFilePckt.ToBytes(), addr)

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
		pck := PacketFromBytes(buf[:])
		go server.handlePacket(conn, addr, &pck)
	}
}
