package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	log "github.com/Sirupsen/logrus"

	"golang.org/x/crypto/ssh"
)

var sessions = struct {
	mu   sync.RWMutex
	keys map[string][]*publicKey
}{
	keys: make(map[string][]*publicKey),
}

func serve(config *ssh.ServerConfig, nConn net.Conn) {
	// Before use, a handshake must be performed on the incoming net.Conn
	conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Warnln("Failed to handshake:", err)
	}

	defer func() {
		sessions.mu.Lock()
		delete(sessions.keys, string(conn.SessionID()))
		sessions.mu.Unlock()
		conn.Close()
	}()

	// The incoming Request channel must be serviced
	go ssh.DiscardRequests(reqs)

	sessions.mu.RLock()
	keys := sessions.keys[string(conn.SessionID())]
	sessions.mu.RUnlock()

	// Service the incoming Channel channel
	for n := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if n.ChannelType() != "session" {
			n.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := n.Accept()
		defer channel.Close()
		if err != nil {
			log.Warnln("Could not accept channel:", err)
		}

		agentFwd, x11 := false, false
		reqLock := &sync.Mutex{}
		reqLock.Lock()
		timeout := time.AfterFunc(30*time.Second, func() { reqLock.Unlock() })

		go func(in <-chan *ssh.Request) {
			for req := range in {
				ok := false
				switch req.Type {
				case "shell":
					fallthrough
				case "pty-req":
					ok = true

					// "auth-agent-req@openssh.com" and "x11-req" always arrive
					// before the "pty-req", so we can go ahead now
					if timeout.Stop() {
						reqLock.Unlock()
					}

				case "auth-agent-req@openssh.com":
					agentFwd = true
				case "x11-req":
					x11 = true
				}

				if req.WantReply {
					req.Reply(ok, nil)
				}
			}
		}(requests)

		channel.Write([]byte("The public keys presented by your SSH client are:\n\r\n\r"))

		var table bytes.Buffer
		tabWriter := new(tabwriter.Writer)
		tabWriter.Init(&table, 5, 2, 2, ' ', 0)
		// Note that using tabwriter, columns are tab-terminated
		// not tab-delimited
		fmt.Fprint(tabWriter, "Bits\tType\tFingerprint\t\n")

		for _, k := range keys {
			length, err := k.BitLen()

			if err != nil {
				log.Errorf("Failed to determine key length for %s key: %s", k.key.Type(), err)
			}

			fmt.Fprintf(tabWriter, "%d\t%s\t%s\t\n", length, k.key.Type(), k.Fingerprint())
		}

		err = tabWriter.Flush()
		if err != nil {
			log.Errorln("Error when flushing tab writer:", err)
		}
		channel.Write([]byte(strings.Replace(table.String(), "\n", "\n\r", -1)))

		reqLock.Lock()
		if agentFwd {
			channel.Write(agentMsg)
		}
		if x11 {
			channel.Write(x11Msg)
		}

		// Explicitly close the channel to end the session
		channel.Close()
	}

}

func publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	sessions.mu.Lock()
	sessionID := string(conn.SessionID())
	sessions.keys[sessionID] = append(sessions.keys[sessionID], &publicKey{key: key})
	sessions.mu.Unlock()

	// Never succeed a key, or we might not see the next. See KeyboardInteractiveCallback.
	return nil, errors.New("")
}

func keyboardInteractiveCallback(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	// keyboard-interactive is tried when all public keys failed, and
	// since it's server-driven we can just pass without user
	// interaction to let the user in once we got all the public keys
	return nil, nil
}

var (
	agentMsg = []byte("WARNING: SSH agent forwarding is enabled\n\r")
	x11Msg   = []byte("WARNING: X11 forwarding is enabled\n\r")
)
