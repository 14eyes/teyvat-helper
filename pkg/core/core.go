package core

import (
	"os"

	"github.com/google/gopacket/pcap"
	"github.com/jhump/protoreflect/desc"
	"github.com/teyvat-helper/teyvat-helper/pkg/config"
	"github.com/teyvat-helper/teyvat-helper/pkg/kcp"
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
