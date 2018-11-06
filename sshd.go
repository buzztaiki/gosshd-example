package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

type sshd struct {
	addr           string
	authKeyPath    string
	privateKeyPath string
	users          map[string]string
	config         *ssh.ServerConfig
}

func (d *sshd) readAuthorizedKeys() (map[string]bool, error) {
	authorizedKeysBytes, err := ioutil.ReadFile(d.authKeyPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to load authorized_keys, err: %v", err)
	}

	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			return nil, err
		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}
	return authorizedKeysMap, nil
}

func (d *sshd) serverConfig() (*ssh.ServerConfig, error) {
	authKeys, err := d.readAuthorizedKeys()
	if err != nil {
		return nil, err
	}

	config := &ssh.ServerConfig{
		// Remove to disable password auth.
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in
			// a production setting.
			if p, ok := d.users[c.User()]; ok && string(pass) == p {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},

		// Remove to disable public key auth.
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authKeys[string(pubKey.Marshal())] {
				return &ssh.Permissions{
					// Record the public key used for authentication.
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", c.User())
		},
	}
	return config, nil
}

func (d *sshd) readPrivateKey() (ssh.Signer, error) {
	privateBytes, err := ioutil.ReadFile(d.privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to load private key: %v", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse private key: %v", err)
	}

	return private, nil
}

func (d *sshd) handleConn(nConn net.Conn) error {
	// Before use, a handshake must be performed on the incoming
	// net.Conn.
	conn, chans, reqs, err := ssh.NewServerConn(nConn, d.config)
	if err != nil {
		return fmt.Errorf("failed to handshake: %v", err)
	}
	log.Printf("logged in with key %s", conn.Permissions.Extensions["pubkey-fp"])

	// The incoming Request channel must be serviced.
	go ssh.DiscardRequests(reqs)

	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return fmt.Errorf("Could not accept channel: %v", err)
		}

		// Sessions have out-of-band requests such as "shell",
		// "pty-req" and "env".  Here we handle only the
		// "shell" request.
		go func(in <-chan *ssh.Request) {
			for req := range in {
				req.Reply(req.Type == "shell", nil)
			}
		}(requests)

		term := terminal.NewTerminal(channel, "> ")

		go func() {
			defer channel.Close()
			for {
				line, err := term.ReadLine()
				if err != nil {
					break
				}
				fmt.Println(line)
			}
		}()
	}

	return nil
}

func (d *sshd) serve() error {
	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config, err := d.serverConfig()
	if err != nil {
		return err
	}

	private, err := d.readPrivateKey()
	if err != nil {
		return err
	}
	config.AddHostKey(private)
	d.config = config

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", d.addr)
	if err != nil {
		return fmt.Errorf("failed to listen for connection: %v", err)
	}

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept incoming connection: %v", err)
		}
		go func() {
			if err := d.handleConn(nConn); err != nil {
				log.Printf("failed to handle incoming connection: %v", err)
			}
		}()
	}
}
