package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
)

const (
	keyFile       = "aeskeyfile.key"
	encryptedFile = "encyptedtext.enc"
)

var x = []byte("1234567812345678")

func readSecretKey(filename string) ([]byte, error) {
	key, err := ioutil.ReadFile(filename)
	if err != nil {
		return key, err
	}
	block, _ := pem.Decode(key)
	return block.Bytes, nil
}

func generateSecretKey() []byte {
	genkey := make([]byte, 16)
	_, err := rand.Read(genkey)
	if err != nil {
		log.Fatalf("Failed to read encryption key: %s", err)
	}
	return genkey
}

func saveSecretKey(filename string, key []byte) {
	block := &pem.Block{
		Type:  "Encryption KEY",
		Bytes: key,
	}
	err := ioutil.WriteFile(filename, pem.EncodeToMemory(block), 0644)
	if err != nil {
		log.Fatalf("Failed in saving key to %s: %s", filename, err)
	}
}

func aesKey() []byte {
	file := fmt.Sprintf(keyFile)
	key, err := readSecretKey(file)
	if err != nil {
		log.Println("Creating an encryption key in directory")
		key = generateSecretKey()
		saveSecretKey(file, key)
	}
	return key
}

func createCipher() cipher.Block {
	c, err := aes.NewCipher(aesKey())
	if err != nil {
		log.Fatalf("Failed to create the cipher text: %s", err)
	}
	return c
}

func encryption(plainText string) {
	bytes := []byte(plainText)
	blockCipher := createCipher()
	stream := cipher.NewCTR(blockCipher, x)
	stream.XORKeyStream(bytes, bytes)
	err := ioutil.WriteFile(fmt.Sprintf(encryptedFile), bytes, 0644)
	if err != nil {
		log.Fatalf("Writing encryption file: %s", err)
	} else {
		fmt.Printf("Message encrypted in file: %s\n\n", encryptedFile)
	}
}

func decryption() []byte {
	bytes, err := ioutil.ReadFile(fmt.Sprintf(encryptedFile))
	if err != nil {
		log.Fatalf("Reading encrypted file: %s", err)
	}
	blockCipher := createCipher()
	stream := cipher.NewCTR(blockCipher, x)
	stream.XORKeyStream(bytes, bytes)
	return bytes
}

func main() {

	fmt.Println("Enter Your string: ")

	var plainText string

	fmt.Scanln(&plainText)

	encryption(plainText)

	fmt.Print("Do you want to  1. Encrypt or 2. Decrypt")
	var option int
	fmt.Scanln(&option)
	if option == 1 {
		encryption(plainText)
		fmt.Printf("in the same directory please find your encrypted text and keyfile")
	} else if option == 2 {
		fmt.Printf("Decrypted Message: %s", decryption())
	} else {
		fmt.Println("please choose the right option")
	}

}
