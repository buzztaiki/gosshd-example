package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func generateKeyIfNotFound(name string) error {
	if _, err := os.Stat(name); os.IsNotExist(err) {
		return generateKey(name)
	}
	return nil
}

func generateKey(name string) error {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	pem.Encode(f, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k),
	})

	return nil
}
