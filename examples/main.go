package main

import (
	"fmt"

	"github.com/marcsantiago/aes"
)

func main() {
	key := []byte("passphrasewhichneedstobe32bytes!")

	aesWrapper, err := aes.New(key)
	if err != nil {
		panic(err)
	}

	data := []byte("hello world 1")
	encryptedData, err := aesWrapper.Encrypt(data)
	if err != nil {
		panic(err)
	}

	fmt.Println("1", encryptedData)
	fmt.Println("D1", []byte(encryptedData))
	d, err := aesWrapper.Decrypt(encryptedData)
	fmt.Println("D1", d)

	encryptedData, err = aesWrapper.Encrypt([]byte("hello world 2"))
	fmt.Println("2", encryptedData)
	fmt.Println("D2", []byte(encryptedData))
	d, err = aesWrapper.Decrypt(encryptedData)
	fmt.Println("D2", d)

	encryptedData, err = aesWrapper.Encrypt([]byte("hello world 3"))
	fmt.Println("3", encryptedData)
	fmt.Println("D3", []byte(encryptedData))
	d, err = aesWrapper.Decrypt(encryptedData)
	fmt.Println("D3", d)

}
