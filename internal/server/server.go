package server

import (
	"common"
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
	lastPckSend common.HeaderFlag
	key         [32]byte
}

type Server struct {
	sessions map[common.SessionID]*info
	rsa      *rsa.PrivateKey
}

func New() (*Server, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)

	if err != nil {
		return nil, err
	}

	return &Server{
		sessions: make(map[common.SessionID]*info),
		rsa:      key,
	}, nil
}

func (server *Server) sendPacket(conn *net.UDPConn, addr *net.UDPAddr, pck *common.Packet) {
	key := server.sessions[pck.Sid].key

	fmt.Printf("Sending Packet, Sync: %v, Type: %v\n", pck.Sync, pck.Flag)

	secPck := common.NewSymetricSecurePacket(key, pck)
	if _, err := conn.WriteToUDP(secPck.ToBytes(), addr); err != nil {
		panic(err)
	}
	conn.WriteToUDP(secPck.ToBytes(), addr)
}

func (server *Server) handlePacket(conn *net.UDPConn, addr *net.UDPAddr, rPacket *common.Packet) {
	switch rPacket.Flag {
	case common.Request:
		server.sendPTE(conn, addr, rPacket)
		break
	case common.Ack:
		server.handleAck(conn, addr, rPacket)
		break
	case common.Resend:
		server.resend(conn, addr, rPacket)
	}
}

func (server *Server) resend(conn *net.UDPConn, addr *net.UDPAddr, pck *common.Packet) {
	resend, err := pck.GetUint32Payload()
	if err != nil {
		panic(err)
	}

	path := server.sessions[pck.Sid].path
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// This should be different
	offset := (int64(resend) - 3) * (common.PacketSize - int64(common.HeaderSize))
	buf := make([]byte, common.PacketSize-common.HeaderSize)

	_, err = file.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		panic(err)
	}

	resendPck := common.NewResendFile(pck, buf)
	server.sendPacket(conn, addr, resendPck)
}

func (server *Server) handleAck(conn *net.UDPConn, addr *net.UDPAddr, pck *common.Packet) {
	ack, err := pck.GetUint32Payload()
	if err != nil {
		panic(err)
	}
	session := server.sessions[pck.Sid]
	if session == nil {
		panic(err)
	}
	if ack != session.lastSync {
		fmt.Printf("Wrong Ack %v, expected %v\n", ack, session.lastSync)
		return
	}

	if session.lastPckSend == common.End {
		fmt.Printf("Deleting Session %v\n", hex.EncodeToString(pck.Sid[:]))
		delete(server.sessions, pck.Sid)
	} else {
		server.sendData(conn, addr, pck)
	}
}

func (server *Server) sendPTE(conn *net.UDPConn, addr *net.UDPAddr, pck *common.Packet) {
	path, err := pck.GetFilePath()
	if err != nil {
		panic(err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		panic(err)
	}

	fileSize := fi.Size()

	ptePck := common.NewPte(uint32(fileSize), pck)
	server.sendPacket(conn, addr, ptePck)

	server.sessions[pck.Sid].path = path
	server.sessions[pck.Sid].lastSync = ptePck.Sync
	server.sessions[pck.Sid].lastPckSend = ptePck.Flag
}

func (server *Server) sendData(conn *net.UDPConn, addr *net.UDPAddr, pck *common.Packet) {
	path := server.sessions[pck.Sid].path
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	buf := make([]byte, common.PacketSize-common.HeaderSize)
	filePck := pck
	for {
		r, err := file.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			panic(err)
		}
		if r == 0 {
			break
		}
		filePck = common.NewFile(filePck, buf[:r])

		server.sendPacket(conn, addr, filePck)
	}

	eodPck := common.NewEnd(filePck)
	server.sessions[pck.Sid].lastSync = eodPck.Sync
	server.sessions[pck.Sid].lastPckSend = eodPck.Flag
	server.sendPacket(conn, addr, eodPck)
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
		var buf [common.PacketSize]byte
		_, addr, err := conn.ReadFromUDP(buf[0:])
		if err != nil {
			fmt.Println(err)
			return
		}

		secPck := common.SecurePacketFromBytes(buf[:])

		if secPck.IsRsa == 0 {
			key := server.sessions[secPck.Sid].key
			pck, err := secPck.ExtractPacket(key)
			if err != nil {
				fmt.Println(err)
			}
			go server.handlePacket(conn, addr, &pck)
		} else {
			key := secPck.ExtractKey()
			fmt.Printf("Session: %v, Key: %v\n", hex.EncodeToString(secPck.Sid[:]), hex.EncodeToString(key))
			server.sessions[secPck.Sid] = &info{
				key: [32]byte(key),
			}
		}
	}
}
