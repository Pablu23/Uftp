package server

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/Pablu23/Uftp/internal/common"
)

type info struct {
	path        string
	lastSync    uint32
	lastPckSend common.HeaderFlag
	key         [32]byte
	time        time.Time
}

type Server struct {
	sessions       map[common.SessionID]*info
	mu             sync.Mutex
	rsa            *rsa.PrivateKey
	options        *Options
	parentFilePath string
}

func New(opts ...func(*Options)) (*Server, error) {
	options := NewDefaultOptions()

	for _, opt := range opts {
		opt(options)
	}

	var key *rsa.PrivateKey
	var err error
	if options.LoadPrivkey {
		privKey, err := os.ReadFile(options.PrivKeyPath)
		if err != nil {
			return nil, err
		}

		block, _ := pem.Decode(privKey)
		key, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else {
		key, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, err
		}
	}

	parentFilePath, err := filepath.Abs(options.Datapath)
	if err != nil {
		return nil, err
	}

	server := &Server{
		sessions:       make(map[common.SessionID]*info),
		rsa:            key,
		options:        options,
		parentFilePath: parentFilePath,
	}

	if options.SavePubKey {
		err = server.SavePublicKeyPem()
		if err != nil {
			return nil, err
		}
	}

	if options.SavePrivKey {
		err = server.SavePrivateKeyPem()
		if err != nil {
			return nil, err
		}
	}

	log.SetFormatter(&log.TextFormatter{
		ForceColors: true,
	})

	return server, nil
}

func (server *Server) SavePrivateKeyPem() error {
	file, err := os.Create(server.options.PrivKeyPath)
	if err != nil {
		return err
	}

	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.WithError(err).Error("Could not close File")
		}
	}(file)

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(server.rsa),
	}
	err = pem.Encode(file, privateKeyPEM)
	if err != nil {
		return err
	}
	return nil
}

func (server *Server) SavePublicKeyPem() error {
	file, err := os.Create(server.options.PubKeyPath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.WithError(err).Error("Could not close File")
		}
	}(file)
	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&server.rsa.PublicKey),
	}
	err = pem.Encode(file, publicKeyPEM)
	if err != nil {
		return err
	}
	return nil
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

	secPck := common.NewSymmetricSecurePacket(key, pck)
	if _, err := conn.WriteToUDP(secPck.ToBytes(), addr); err != nil { // && !errors.Is(err)
		log.WithError(err).Error("Could not write Packet to UDP")
		fmt.Println(err)
		return
	} else if err != nil && errors.Is(err, bufio.ErrBufferFull) {
		time.Sleep(time.Millisecond * 10)
		server.sendPacket(conn, addr, pck)
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
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.WithError(err).Error("Could not close File")
		}
	}(file)

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

	file := filepath.Join(server.parentFilePath, path)
	file = filepath.Clean(file)

	matched, err := filepath.Match(filepath.Join(server.parentFilePath, "*"), file)

	if err != nil || !matched {
		log.WithFields(log.Fields{
			"ParentFilePath":    server.parentFilePath,
			"RequestedFilePath": path,
			"CleanedFilePath":   file,
		}).WithError(err).Warn("Requesting File out of Path")
		return
	}

	fi, err := os.Stat(file)
	if err != nil {
		log.WithError(err).WithField("File Path", file).Error("Unable to open File")
		return
	}

	fileSize := fi.Size()

	ptePck := common.NewPte(uint32(fileSize), pck)
	server.sendPacket(conn, addr, ptePck)

	server.mu.Lock()
	if info, ok := server.sessions[pck.Sid]; ok {
		info.path = file
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
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.WithError(err).Error("Could not close File")
		}
	}(file)

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

func (server *Server) startTimeout(interruptChan chan bool) {
	running := true
	for running {
		select {
		case c := <-interruptChan:
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

func (server *Server) handleConnection(conn net.Conn) {
	reader := bufio.NewReader(conn)
	var buf [2048]byte
	r, err := reader.Read(buf[:])
	if err != nil {
		log.WithError(err).Warn("Could not read from Connection")
		err := conn.Close()
		if err != nil {
			log.WithError(err).Error("Could not close connection")
		}
		return
	}

	rsaPck := common.RsaPacketFromBytes(buf[0:r])
	key, err := rsaPck.ExtractKey(server.rsa)
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Warn("Could not extract Key")
		return
	}
	server.mu.Lock()
	server.sessions[rsaPck.Sid] = &info{
		key: key,
	}
	server.mu.Unlock()
	_, err = conn.Write([]byte("Yep"))
	if err != nil {
		log.WithError(err).Error("Could not write to TCP connection")
		return
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			log.WithError(err).Error("Could not close TCP connection")
		}
	}(conn)
	log.WithField("SessionID", hex.EncodeToString(rsaPck.Sid[:])).Info("Started Session")
}

func (server *Server) startManagement() {
	listener, err := net.Listen("tcp", "0.0.0.0:13375")
	if err != nil {
		log.Fatal("Could not start listening on TCP 0.0.0.0:13375")
	}
	defer func(listener net.Listener) {
		err := listener.Close()
		if err != nil {
			log.WithError(err).Error("Could not close TCP Listener")
		}
	}(listener)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.WithError(err).Warn("Could not accept TCP Connection")
		}

		go server.handleConnection(conn)
	}
}

func (server *Server) Serve() {
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%v:13374", server.options.Address))
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
	go server.startManagement()

	for {
		var buf [common.PacketSize]byte
		_, addr, err := conn.ReadFromUDP(buf[0:])
		if err != nil {
			log.Error("Could not retrieve UDP Packet")
			continue
		}

		secPck, err := common.SecurePacketFromBytes(buf[:])
		if err != nil {
			log.WithError(err).Warn("Received invalid Packet")
			continue
		}

		var key [32]byte
		server.mu.Lock()
		if info, ok := server.sessions[secPck.Sid]; ok {
			key = info.key
		} else {
			log.WithField("SessionID", hex.EncodeToString(secPck.Sid[:])).Warn("Invalid Session")
			server.mu.Unlock()
			continue
		}
		pck, err := secPck.ExtractPacket(key)
		if err != nil {
			log.Error("Could not extract Packet from Secure Packet")
		}
		server.mu.Unlock()
		go server.handlePacket(conn, addr, &pck)

	}
}
