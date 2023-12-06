package server

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/Pablu23/Uftp/internal/common"

	log "github.com/sirupsen/logrus"
)

type info struct {
	path        string
	lastSync    uint32
	lastPckSend common.HeaderFlag
	key         [32]byte
	time        time.Time
}

type Server struct {
	sessions map[common.SessionID]*info
	mu       sync.Mutex
	rsa      *rsa.PrivateKey
}

func New() (*Server, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)

	if err != nil {
		return nil, err
	}

	log.SetFormatter(&log.TextFormatter{
		ForceColors: true,
	})

	return &Server{
		sessions: make(map[common.SessionID]*info),
		rsa:      key,
	}, nil
}

func (server *Server) sendPacket(conn *net.UDPConn, addr *net.UDPAddr, pck *common.Packet) {
	server.mu.Lock()
	var key [32]byte
	if info, ok := server.sessions[pck.Sid]; ok {
		key = info.key
		server.sessions[pck.Sid].time = time.Now()
		server.mu.Unlock()
	} else {
		log.WithField("SessionID", hex.EncodeToString(pck.Sid[:])).Warn("Invalid Session")
		server.mu.Unlock()
		return
	}

	secPck := common.NewSymetricSecurePacket(key, pck)
	if _, err := conn.WriteToUDP(secPck.ToBytes(), addr); err != nil {
		log.Error("Could not write Packet to UDP")
		return
	}
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
		break
	default:
		log.WithField("Packet Type", rPacket.Flag).Error("Unexpected Packet Type")
		break
	}
}

func (server *Server) resend(conn *net.UDPConn, addr *net.UDPAddr, pck *common.Packet) {
	resend, err := pck.GetUint32Payload()
	if err != nil {
		log.Error("Error getting Resend Sync from Packet")
		return
	}

	server.mu.Lock()
	var path string
	if info, ok := server.sessions[pck.Sid]; ok {
		path = info.path
		server.mu.Unlock()
	} else {
		log.WithField("SessionID", hex.EncodeToString(pck.Sid[:])).Warn("Invalid Session")
		server.mu.Unlock()
		return
	}

	file, err := os.Open(path)
	if err != nil {
		log.WithError(err).WithField("File Path", path).Error("Unable to open File")
		return
	}
	defer file.Close()

	// This should be different
	offset := (int64(resend) - 3) * (int64(common.MaxDataSize))
	buf := make([]byte, common.MaxDataSize)

	_, err = file.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).WithField("File Path", path).Error("Unable to read File")
		return
	}

	resendPck := common.NewResendFile(pck, buf)
	server.sendPacket(conn, addr, resendPck)
}

func (server *Server) handleAck(conn *net.UDPConn, addr *net.UDPAddr, pck *common.Packet) {
	ack, err := pck.GetUint32Payload()
	if err != nil {
		log.WithError(err).Error("Getting Acknowledge from Packet")
		return
	}

	server.mu.Lock()
	if session, ok := server.sessions[pck.Sid]; ok {
		if ack != session.lastSync {
			log.WithFields(log.Fields{
				"Expected": session.lastSync,
				"Received": ack,
			}).Warn("Received wrong Acknowledge")
			return
		}

		if session.lastPckSend == common.End {
			log.WithField("SessionID", hex.EncodeToString(pck.Sid[:])).Info("Closing Session")
			delete(server.sessions, pck.Sid)
			server.mu.Unlock()
		} else {
			server.mu.Unlock()
			server.sendData(conn, addr, pck)
		}
	} else {
		log.WithField("SessionID", hex.EncodeToString(pck.Sid[:])).Warn("Invalid Session")
		server.mu.Unlock()
		return
	}

}

func (server *Server) sendPTE(conn *net.UDPConn, addr *net.UDPAddr, pck *common.Packet) {
	path, err := pck.GetFilePath()
	if err != nil {
		log.WithError(err).Error("Unable to get File Path")
		return
	}

	fi, err := os.Stat(path)
	if err != nil {
		log.WithError(err).WithField("File Path", path).Error("Unable to open File")
		return
	}

	fileSize := fi.Size()

	ptePck := common.NewPte(uint32(fileSize), pck)
	server.sendPacket(conn, addr, ptePck)

	server.mu.Lock()
	if info, ok := server.sessions[pck.Sid]; ok {
		info.path = path
		info.lastSync = ptePck.Sync
		info.lastPckSend = ptePck.Flag
		server.mu.Unlock()
	} else {
		log.WithField("SessionID", hex.EncodeToString(pck.Sid[:])).Warn("Invalid Session")
		server.mu.Unlock()
		return
	}
}

func (server *Server) sendData(conn *net.UDPConn, addr *net.UDPAddr, pck *common.Packet) {

	var path string
	server.mu.Lock()
	if info, ok := server.sessions[pck.Sid]; ok {
		path = info.path
		server.mu.Unlock()
	} else {
		log.WithField("SessionID", hex.EncodeToString(pck.Sid[:])).Warn("Invalid Session")
		server.mu.Unlock()
		return
	}

	file, err := os.Open(path)
	if err != nil {
		log.WithError(err).WithField("File Path", path).Error("Unable to open File")
		return
	}
	defer file.Close()

	buf := make([]byte, common.MaxDataSize)
	filePck := pck
	for {
		r, err := file.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			log.WithError(err).WithField("File Path", path).Error("Unable to read File")
			return
		}
		if r == 0 {
			break
		}
		filePck = common.NewFile(filePck, buf[:r])

		server.sendPacket(conn, addr, filePck)
	}

	eodPck := common.NewEnd(filePck)

	server.mu.Lock()
	if info, ok := server.sessions[pck.Sid]; ok {
		info.lastSync = eodPck.Sync
		info.lastPckSend = eodPck.Flag
		server.mu.Unlock()
	} else {
		log.WithField("SessionID", hex.EncodeToString(pck.Sid[:])).Warn("Invalid Session")
		server.mu.Unlock()
		return
	}

	server.sendPacket(conn, addr, eodPck)
}

func (server *Server) startTimeout(interuptChan chan bool) {
	running := true
	for running {
		select {
		case c := <-interuptChan:
			if c {
				running = false
			}
			break
		case <-time.After(time.Second * 30):
			server.cleanup()
			break
		}
	}
}

func (server *Server) cleanup() {
	server.mu.Lock()

	for sid, info := range server.sessions {
		if time.Now().After(info.time.Add(30 * time.Second)) {
			delete(server.sessions, sid)
			log.WithField("SessionID", hex.EncodeToString(sid[:])).Info("Closed session")
		}
	}

	server.mu.Unlock()
}

func (server *Server) handleShutdown(stop chan bool) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	go func() {
		for range c {
			stop <- true
			log.Info("Server is shutting down")
			os.Exit(0)
		}
	}()
}

func (server *Server) Serve() {
	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:13374")

	if err != nil {
		log.Fatal("Could not resolve UDP Address")
	}

	log.Infof("Starting server on %v:%v", udpAddr.IP, udpAddr.Port)

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatal("Could not start listening")
	}

	log.Info("Started listening")

	c := make(chan bool)
	server.handleShutdown(c)
	go server.startTimeout(c)

	for {
		var buf [common.PacketSize]byte
		_, addr, err := conn.ReadFromUDP(buf[0:])
		if err != nil {
			log.Error("Could not retrieve UDP Packet")
			continue
		}

		secPck := common.SecurePacketFromBytes(buf[:])

		if secPck.IsRsa == 0 {
			var key [32]byte

			server.mu.Lock()
			if info, ok := server.sessions[secPck.Sid]; ok {
				key = info.key
			} else {
				log.WithField("SessionID", hex.EncodeToString(secPck.Sid[:])).Warn("Invalid Session")
				server.mu.Unlock()
				continue
			}
			server.mu.Unlock()
			pck, err := secPck.ExtractPacket(key)
			if err != nil {
				log.Error("Could not extract Packet from Secure Packet")
			}
			go server.handlePacket(conn, addr, &pck)
		} else {
			key := secPck.ExtractKey()
			log.WithField("SessionID", hex.EncodeToString(secPck.Sid[:])).Info("New Session")
			server.sessions[secPck.Sid] = &info{
				key: [32]byte(key),
			}
		}

	}
}
