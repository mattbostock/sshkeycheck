package main

import (
	"net"
	"os"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func main() {
	log.SetOutput(os.Stderr)

	config := &ssh.ServerConfig{
		KeyboardInteractiveCallback: keyboardInteractiveCallback,
		PublicKeyCallback:           publicKeyCallback,
	}

	private, err := ssh.ParsePrivateKey([]byte(os.Getenv("HOST_PRIVATE_KEY")))
	if err != nil {
		log.Fatalln("Failed to parse host private key")
	}
	config.AddHostKey(private)

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = "localhost:2022"
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen for connection on %s, perhaps that port is already in use", addr)
	}

	log.Infoln("Listening on", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Warnln("Accept failed:", err)
			continue
		}

		go serve(config, conn)
	}
}
