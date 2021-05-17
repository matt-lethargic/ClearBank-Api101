package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
)

func Generate(text []byte, privateKey *rsa.PrivateKey) (string, error) {
	rng := rand.Reader
	message := []byte(text)
	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rng, privateKey, crypto.SHA256, hashed[:])

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func Verify(text []byte, digitalSignature []byte, publicKey *rsa.PublicKey) (bool, error) {

	message := []byte(text)
	hashed := sha256.Sum256(message)

	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], digitalSignature)
	if err != nil {
		return false, err
	}

	return true, nil
}
