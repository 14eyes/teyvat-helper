package core

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/desc/protoparse"
	"github.com/jhump/protoreflect/dynamic"
	"github.com/teyvat-helper/teyvat-helper/pkg/kcp"
)

func (s *Service) initSniffer() (err error) {
	s.keyStore = &KeyStore{kv: make(map[uint8][]byte)}
	s.protoMap = make(map[string]*desc.MessageDescriptor)
	s.cmdStore = make(map[uint16]string)

	p, err := os.ReadFile(s.config.Data.CmdID)
	if err != nil {
		return err
	}
	parser := protoparse.Parser{ImportPaths: []string{s.config.Data.Proto}}
	dsec, err := parser.ParseFiles("PacketHead.proto")
	if err != nil {
		panic(err)
	}
	s.protoMap["PacketHead"] = dsec[0].FindMessage("PacketHead")
	for _, line := range strings.Split(string(p), "\n") {
		parts := strings.Split(strings.TrimSpace(line), ",")
		if len(parts) != 2 {
			continue
		}
		if parts[0] == "DebugNotify" {
			continue
		}
		v, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			panic(err)
		}
		s.cmdStore[uint16(v)] = parts[0]
		dsec, err := parser.ParseFiles(parts[0] + ".proto")
		if err != nil {
			panic(err)
		}
		s.protoMap[parts[0]] = dsec[0].FindMessage(parts[0])
	}
	log.Printf("[SNIFFER] Loaded %d commands", len(s.cmdStore))

	s.memory, err = os.OpenFile(s.config.Memory, os.O_RDONLY, 0755)
	if err != nil {
		return err
	}
	s.handle, err = pcap.OpenLive(s.config.Device, 1500, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	if err := s.handle.SetBPFFilter("udp portrange 22101-22102"); err != nil {
		return err
	}
	return nil
}

func (s *Service) runSniffer() {
	pcapng, err := os.Create("data/" + time.Now().Format("2006-01-02 15-04-05") + ".pcapng")
	if err != nil {
		log.Printf("[SNIFFER] Failed to create pcapng file: %v", err)
		return
	}
	defer pcapng.Close()
	s.rawlog, err = os.Create("data/" + time.Now().Format("2006-01-02 15-04-05") + ".rawlog")
	if err != nil {
		log.Printf("[SNIFFER] Failed to create rawlog file: %v", err)
		return
	}
	defer s.rawlog.Close()
	pcapngWriter, err := pcapgo.NewNgWriter(pcapng, s.handle.LinkType())
	if err != nil {
		log.Printf("[SNIFFER] Failed to create pcapng writer: %v", err)
		return
	}
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	for packet := range packetSource.Packets() {
		err := pcapngWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		if err != nil {
			log.Printf("[SNIFFER] Failed to write packet: %v", err)
			return
		}
		p := packet.ApplicationLayer().Payload()
		if len(p) < kcp.IKCP_OVERHEAD {
			continue
		}
		udp := packet.TransportLayer().(*layers.UDP)
		s.handlePayload(p, udp.SrcPort == 22101 || udp.SrcPort == 22102, packet.Metadata().Timestamp)
	}
}

type KeyStore struct {
	mu   sync.Mutex
	wg   sync.WaitGroup
	once sync.Once
	kv   map[uint8][]byte
}

func (s *Service) keyStoreBin(data []byte) []byte {
	if (data[0]^0x45 == 0x61 && data[1]^0x67 == 0xE8) || (data[0]^0x45 == 0x4A && data[1]^0x67 == 0x8D) {
		log.Printf("[SNIFFER] Got [%02X %02X %02X %02X %02X %02X %02X %02X ...] len:%d", data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], len(data))
		log.Println("[SNIFFER] KeyStore is empty, skipping...")
		return nil
	}
	s.keyStore.once.Do(func() {
		s.keyStore.wg.Add(1)
		log.Println("[SNIFFER] KeyStore waiting")
	})
	if len(data) != 58129 {
		s.keyStore.wg.Wait()
	} else {
		log.Println("[SNIFFER] KeyStore is empty, decrypting...")
	}
	s.keyStore.mu.Lock()
	key, ok := s.keyStore.kv[data[0]]
	if !ok {
		log.Printf("[SNIFFER] Finding [%02X %02X ?? ?? %02X ?? %02X %02X ...]", data[0]^0x45, data[1]^0x67, data[4], data[6], data[7])
		s.memory.Seek(0, 0)
		code, _ := io.ReadAll(s.memory)
		chunk := make([]byte, 4096*2)
		for i := 0; i < 4096; i++ {
			copy(chunk, code[i:])
			for j := 0; j < 4096*2; j++ {
				chunk[j] = chunk[j] ^ data[4096+j]
			}
			if !bytes.Equal(chunk[:4096], chunk[4096:]) {
				continue
			}
			if chunk[0] == data[0]^0x45 && chunk[1] == data[1]^0x67 &&
				chunk[4] == data[4] && chunk[6] == data[6] && chunk[7] == data[7] {
				key = make([]byte, 4096)
				copy(key, chunk)
				s.keyStore.kv[data[0]] = key
				log.Printf("[SNIFFER] Matched [%02X %02X %02X %02X %02X %02X %02X %02X ...] at %d",
					key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], int64(i))
				fmt.Fprintf(s.rawlog, `********************************************************************************
********************************************************************************
* Pattern [%02X %02X ?? ?? %02X ?? %02X %02X ...]
********************************************************************************
* Key Dump
%s
********************************************************************************

`, data[0]^0x45, data[1]^0x67, data[4], data[6], data[7], base64.StdEncoding.EncodeToString(key))
				s.keyStore.wg.Done()
				break
			}
		}
	}
	s.keyStore.mu.Unlock()
	if key == nil {
		log.Println("[SNIFFER] Failed to find key in memory")
		return nil
	}
	return key
}

func (s *Service) keyStoreMem(data []byte) []byte {
	s.keyStore.mu.Lock()
	s.keyStore.wg.Wait()
	key, ok := s.keyStore.kv[data[0]]
	if !ok {
		s.keyStore.wg.Add(1)
		log.Printf("[SNIFFER] Finding [%02X %02X ?? ?? %02X ?? %02X %02X ...]", data[0]^0x45, data[1]^0x67, data[4], data[6], data[7])
		s.memory.Seek(0, 0)
		var n int64
		chunk := make([]byte, 4<<20)
		for key == nil {
			m, err := s.memory.Read(chunk[:cap(chunk)])
			if err != nil {
				break
			}
			chunk = chunk[:m]
			n += int64(m)
			for i := 0; i < 4<<20; i += 16 {
				if chunk[i] == data[0]^0x45 && chunk[i+1] == data[1]^0x67 &&
					chunk[i+4] == data[4] && chunk[i+6] == data[6] && chunk[i+7] == data[7] {
					key = make([]byte, 4096)
					copy(key, chunk[i:])
					s.keyStore.kv[data[0]] = key
					log.Printf("[SNIFFER] Matched [%02X %02X %02X %02X %02X %02X %02X %02X ...] at %d",
						key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], n+int64(i))
					fmt.Fprintf(s.rawlog, `********************************************************************************
********************************************************************************
* Pattern [%02X %02X ?? ?? %02X ?? %02X %02X ...]
********************************************************************************
* Key Dump
%s
********************************************************************************

`, data[0]^0x45, data[1]^0x67, data[4], data[6], data[7], base64.StdEncoding.EncodeToString(key))
					break
				}
			}
		}
		s.keyStore.wg.Done()
	}
	s.keyStore.mu.Unlock()
	if key == nil {
		log.Println("[SNIFFER] Failed to find key in memory")
		return nil
	}
	return key
}

func (s *Service) keyStoreXor(data []byte) {
	key := s.keyStoreBin(data)
	if key != nil {
		xor(data, key)
	}
}

func xor(data, key []byte) {
	for i := 0; i < len(data); i++ {
		data[i] ^= key[i%4096]
	}
}

type Packet struct {
	data []byte
	isIn bool
	time time.Time
}

func (s *Service) handlePayload(p []byte, d bool, t time.Time) {
	conv := binary.LittleEndian.Uint64(p)
	var inst *kcp.KCP
	if d {
		if s.serverInst == nil {
			s.serverInst = kcp.NewKCP(conv, func(buf []byte, size int) {})
			s.serverInst.SetMtu(1200)
			s.serverInst.NoDelay(1, 20, 2, 1)
			s.serverInst.WndSize(255, 255)
		}
		inst = s.serverInst
	} else {
		if s.clientInst == nil {
			s.clientInst = kcp.NewKCP(conv, func(buf []byte, size int) {})
			s.clientInst.SetMtu(1200)
			s.clientInst.NoDelay(1, 20, 2, 1)
			s.clientInst.WndSize(255, 255)
		}
		inst = s.clientInst
	}
	_ = inst.Input(p, true, true)
	size := inst.PeekSize()
	for size > 0 {
		packet := &Packet{}
		packet.data = make([]byte, size)
		packet.isIn = d
		packet.time = t
		_ = inst.Recv(packet.data)
		go s.handlePacket(packet)
		size = inst.PeekSize()
	}
	inst.Update()
}

type UnionCmdNotify struct {
	CmdList []*UnionCmd `json:"cmd_list"`
}

type UnionCmd struct {
	MessageID uint16           `json:"message_id"`
	Body      *dynamic.Message `json:"body"`
}

func (s *Service) handlePacket(packet *Packet) {
	s.keyStoreXor(packet.data)
	data := packet.data
	l := len(data)
	if data[0] != 0x45 || data[1] != 0x67 || data[l-2] != 0x89 || data[l-1] != 0xAB {
		log.Println("[SNIFFER] Failed to decrypt packet")
		return
	}
	cmdId := binary.BigEndian.Uint16(data[2:])
	cmd := s.cmdStore[cmdId]
	headLength := binary.BigEndian.Uint16(data[4:])
	bodyLength := binary.BigEndian.Uint32(data[6:])
	head := data[10 : 10+headLength]
	body := data[10+headLength : 10+uint32(headLength)+bodyLength]
	headPb := dynamic.NewMessage(s.protoMap["PacketHead"])
	_ = headPb.Unmarshal(head)
	clientSequenceId := headPb.GetFieldByName("client_sequence_id").(uint32)
	prefix := ""
	if packet.isIn {
		prefix = "RECV -->"
	} else {
		prefix = "SEND <--"
	}
	headJson, _ := json.Marshal(headPb)
	bodyPb := dynamic.NewMessage(s.protoMap[cmd])
	_ = bodyPb.Unmarshal(body)
	bodyJson, _ := json.Marshal(bodyPb)
	if cmd == "UnionCmdNotify" {
		notify := &UnionCmdNotify{}
		for _, v := range bodyPb.GetFieldByName("cmd_list").([]any) {
			v := v.(*dynamic.Message)
			item := &UnionCmd{
				MessageID: uint16(v.GetFieldByName("message_id").(uint32)),
			}
			item.Body = dynamic.NewMessage(s.protoMap[s.cmdStore[uint16(item.MessageID)]])
			_ = item.Body.Unmarshal(v.GetFieldByName("body").([]byte))
			notify.CmdList = append(notify.CmdList, item)
		}
		bodyJson, _ = json.Marshal(notify)
	}
	fmt.Fprintf(s.rawlog, "%s [SNIFFER] %s %5d - %5d:%s\n%s\n%s\n", packet.time.Format("2006-01-02 15:04:05.000000"), prefix, clientSequenceId, cmdId, cmd, headJson, bodyJson)
	s.HandleMessage(cmd, bodyPb)
}
