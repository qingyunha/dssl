package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"

	"mytls/tls"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var (
	conntrack = make(map[string]*tls.Conntrack)
	mu        sync.Mutex
)

func main() {
	pcapfile := flag.String("pcap", "", "pcap file")
	sslkeylog := flag.String("sslkeylog", "", "sslkeylog file")
	verbose := flag.Bool("v", false, "verbose")
	flag.Parse()

	var logger *log.Logger
	if *verbose {
		logger = log.New(os.Stderr, "", 0)
	} else {
		logger = log.New(ioutil.Discard, "", 0)
	}

	keys := make(map[string]*[2][]byte)
	loadkeys := func() {
		f, err := os.Open(*sslkeylog)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := s.Text()
			fields := strings.Fields(line)
			if len(fields) != 3 {
				continue
			}
			key := fields[1]
			if keys[key] == nil {
				keys[key] = new([2][]byte)
			}
			secret, _ := hex.DecodeString(fields[2])
			if fields[0] == "CLIENT_TRAFFIC_SECRET_0" {
				keys[key][0] = secret
			} else if fields[0] == "SERVER_TRAFFIC_SECRET_0" {
				keys[key][1] = secret
			} else if fields[0] == "CLIENT_RANDOM" {
				keys[key][0] = secret
			}
		}
	}
	loadkeys()
	getSecret := func(random []byte) (cSecret, sSecret []byte) {
		key := hex.EncodeToString(random)
		s := *keys[key]
		cSecret = s[0]
		sSecret = s[1]
		return
	}

	pf, err := os.Open(*pcapfile)
	if err != nil {
		panic(err)
	}
	rd, err := pcapgo.NewReader(pf)
	if err != nil {
		panic(err)
	}
	packetSource := gopacket.NewPacketSource(rd, rd.LinkType())
	packetSource.NoCopy = true

	wg := sync.WaitGroup{}

	for packet := range packetSource.Packets() {
		if l := packet.Layer(layers.LayerTypeTCP); l != nil {
			tcp, _ := l.(*layers.TCP)
			ll := packet.Layer(layers.LayerTypeIPv4)
			ip, ok := ll.(*layers.IPv4)
			if !ok {
				logger.Println("ERROR not support ipv6")
				continue
			}
			addr := fmt.Sprintf("%s:%d--%s:%d",
				ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
			raddr := fmt.Sprintf("%s:%d--%s:%d",
				ip.DstIP, tcp.DstPort, ip.SrcIP, tcp.SrcPort)

			mu.Lock()
			ct := conntrack[addr]
			rct := conntrack[raddr]
			mu.Unlock()

			if tcp.SYN && !tcp.ACK {
				if ct != nil {
					continue
				}
				ct := tls.NewConntrack(getSecret, os.Stdout, os.Stdout)
				ct.Addr = addr
				mu.Lock()
				conntrack[addr] = ct
				mu.Unlock()
				wg.Add(1)
				go func() {
					logger.Println("START Decrypt", ct.Addr)
					if err := ct.Decrypt(); err != nil {
						logger.Println("ERROR Decrypt", addr, err)
					}
					logger.Println("DONE. Decrypt", ct.Addr)
					wg.Done()
					mu.Lock()
					delete(conntrack, addr)
					mu.Unlock()
				}()
			}
			if tcp.FIN || tcp.RST {
				if ct != nil {
					ct.CloseClient()
				} else if rct != nil {
					rct.CloseServer()
				}
			}
			payload := l.LayerPayload()
			if len(payload) == 0 {
				continue
			}
			if ct != nil {
				err := ct.FeedClient(payload)
				if err != nil {
					logger.Println("ERROR WRITE..", addr, err, len(payload))
				}
				continue
			}
			if rct != nil {
				err := rct.FeedServer(payload)
				if err != nil {
					logger.Println("ERROR WRITE..", addr, err, len(payload))
				}
				continue
			}
		}
	}

	mu.Lock()
	for _, ct := range conntrack {
		logger.Println("Close Decrypt", ct.Addr)
		ct.Close()
	}
	mu.Unlock()

	wg.Wait()
}
