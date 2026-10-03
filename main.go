package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
	"gopkg.in/yaml.v3"
)

type hostEntry struct {
	name *regexp.Regexp
	addr netip.Addr
}

var hosts []hostEntry

func addrFromHostName(name string) netip.Addr {
	for _, host := range hosts {
		if !host.name.MatchString(name) {
			continue
		}

		return host.addr
	}

	return netip.Addr{}
}

func localIP() netip.Addr {
	const remote = "1.1.1.1:53" // meaningless

	conn, err := net.Dial("udp", remote)
	if err != nil {
		return netip.Addr{}
	}

	defer conn.Close()

	return conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
}

func main() {
	fmt.Println("MiniDNS by Pancakes (pancakes@mooglepowered.com)")
	fmt.Println()

	//// PARSING THE HOSTS FILE
	hostsPath := flag.String("hosts", "hosts.yml", "path to hosts file")
	flag.Parse()

	f, err := os.Open(*hostsPath)
	if err != nil {
		fmt.Printf("Error: failed to open hosts file: %s\n", err)
		os.Exit(1)
	}

	var h map[string]netip.Addr
	err = yaml.NewDecoder(f).Decode(&h)
	if err != nil {
		fmt.Printf("Error: failed to decode hosts file: %s\n", err)
		os.Exit(1)
	}

	f.Close()

	for hostRegex, addr := range h {
		re, err := regexp.Compile(hostRegex)
		if err != nil {
			fmt.Printf("Warning: '%s' in hosts file is not valid regex! ignoring...\n", hostRegex)
			continue
		}

		hosts = append(hosts, hostEntry{
			name: re,
			addr: addr,
		})
	}

	//// SETTING UP THE DNS SERVER
	conn, err := net.ListenPacket("udp4", ":53")
	if err != nil {
		fmt.Printf("Error: failed to create listener: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("Configure your DNS settings as shown below.")
	fmt.Println("  Primary:   ", localIP())
	fmt.Println("  Secondary: ", "1.1.1.1 (optional)")
	fmt.Println()

	buf := make([]byte, 512)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Fatalf("error reading packet: %s", err)
		}

		var msg dnsmessage.Message
		err = msg.Unpack(buf[:n])
		if err != nil {
			log.Printf("received invalid dns request: %s", err)
			continue
		}

		msg, err = handle(msg)
		if err != nil {
			log.Printf("failed to handle dns request: %s", err)
			continue
		}

		b, err := msg.Pack()
		if err != nil {
			log.Printf("failed to pack dns response: %s", err)
			continue
		}

		_, err = conn.WriteTo(b, addr)
		if err != nil {
			log.Fatalf("failed to write dns response: %s", err)
		}
	}
}

var ErrNoQuestions = errors.New("no questions in dns request")

func handle(msg dnsmessage.Message) (dnsmessage.Message, error) {
	if len(msg.Questions) < 1 {
		return dnsmessage.Message{}, ErrNoQuestions
	}

	question := msg.Questions[0]

	log.Printf("received dns request for %s", question.Name)

	msg.Header.Response = true
	msg.Header.Authoritative = true

	// we only handle A requests
	if question.Type != dnsmessage.TypeA {
		msg.Header.RCode = dnsmessage.RCodeNameError
		return msg, nil
	}

	// name sometimes has trailing . so remove it
	name := strings.TrimSuffix(question.Name.String(), ".")

	// get addr if known host
	addr := addrFromHostName(name)

	// write NXDOMAIN resposne if unknown
	if !addr.IsValid() {
		msg.Header.RCode = dnsmessage.RCodeNameError
		return msg, nil
	}

	// write the answer
	msg.Answers = append(msg.Answers, dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  question.Name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   60,
		},
		Body: &dnsmessage.AResource{
			A: addr.As4(),
		},
	})

	return msg, nil
}
