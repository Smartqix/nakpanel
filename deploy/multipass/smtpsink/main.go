// smtpsink is a minimal SMTP server used only by the phase 18 multipass
// verifier: it accepts every message and appends one "MAIL FROM=<...>" line
// per delivery to the output file, so the verifier can count what a
// smarthost relay actually received. It offers STARTTLS with a throwaway
// self-signed certificate because Stalwart requires TLS towards relays.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:2525", "listen address")
	out := flag.String("out", "/tmp/smtpsink.log", "delivery log file")
	flag.Parse()
	tlsConfig, err := selfSignedConfig()
	if err != nil {
		log.Fatal(err)
	}
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("smtpsink listening on %s, logging to %s", *addr, *out)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handle(conn, *out, tlsConfig)
	}
}

func selfSignedConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "smtpsink"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"smtpsink", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, nil
}

func handle(conn net.Conn, out string, tlsConfig *tls.Config) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	write := func(line string) { _, _ = fmt.Fprintf(conn, "%s\r\n", line) }
	write("220 smtpsink ready")
	var from string
	inData := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if inData {
			if line == "." {
				inData = false
				record(out, from)
				write("250 2.0.0 accepted")
			}
			continue
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			_, _ = fmt.Fprint(conn, "250-smtpsink\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
		case strings.HasPrefix(upper, "STARTTLS"):
			write("220 2.0.0 ready to start TLS")
			tlsConn := tls.Server(conn, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				log.Printf("tls handshake: %v", err)
				return
			}
			conn = tlsConn
			reader = bufio.NewReader(conn)
			write = func(line string) { _, _ = fmt.Fprintf(conn, "%s\r\n", line) }
			from = ""
		case strings.HasPrefix(upper, "MAIL FROM"):
			from = line
			write("250 2.1.0 ok")
		case strings.HasPrefix(upper, "RCPT TO"):
			write("250 2.1.5 ok")
		case upper == "DATA":
			inData = true
			write("354 go ahead")
		case upper == "QUIT":
			write("221 bye")
			return
		case upper == "RSET", upper == "NOOP":
			write("250 ok")
		default:
			write("250 ok")
		}
	}
}

func record(out, from string) {
	file, err := os.OpenFile(out, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Print(err)
		return
	}
	defer file.Close()
	_, _ = fmt.Fprintf(file, "%s\n", from)
}
