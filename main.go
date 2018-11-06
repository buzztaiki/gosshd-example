package main

import (
	"flag"
	"log"
)

func main() {
	d := &sshd{users: map[string]string{}}

	flag.StringVar(&d.addr, "addr", ":2022", "")
	flag.StringVar(&d.authKeyPath, "auth-key", "./authorized_keys", "")
	flag.StringVar(&d.serverKeyPath, "server-key", "./id_rsa", "")

	user := flag.String("user", "scott", "user name for logged in")
	pass := flag.String("pass", "tiger", "user pass for logged in")

	flag.Parse()

	d.users[*user] = *pass
	if err := generateKeyIfNotFound(d.serverKeyPath); err != nil {
		log.Fatal(err)
	}

	if err := d.serve(); err != nil {
		log.Fatal(err)
	}
}
