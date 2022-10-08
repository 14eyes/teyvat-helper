package core

import (
	"os"

	"github.com/Jx2f/teyvat-helper/pkg/config"
	"github.com/Jx2f/teyvat-helper/pkg/kcp"
	"github.com/google/gopacket/pcap"
	"github.com/jhump/protoreflect/desc"
)

type Service struct {
	config *config.Config

	// packet sniffer
	rawlog   *os.File
	memory   *os.File
	handle   *pcap.Handle
	keyStore *KeyStore
	cmdStore map[uint16]string
	protoMap map[string]*desc.MessageDescriptor

	serverInst *kcp.KCP
	clientInst *kcp.KCP
}

func NewService(c *config.Config) (*Service, error) {
	s := &Service{config: c}
	if err := s.initSniffer(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Service) Start() error {
	go s.runSniffer()
	select {}
	return nil
}
