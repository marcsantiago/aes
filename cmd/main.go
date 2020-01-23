package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/marcsantiago/aes"
	"github.com/urfave/cli/v2"
)

func main() {
	var key, data string
	var shouldEncrypt, withNonceParameter bool
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "key",
				Aliases:     []string{"k"},
				Value:       "",
				Usage:       "encryption or decryption key",
				Required:    true,
				Destination: &key,
				EnvVars:     []string{"AES-WRAPPER-KEY"},
			},
			&cli.StringFlag{
				Name:        "data",
				Aliases:     []string{"d"},
				Value:       "",
				Usage:       "encrypted or decrypted data",
				Required:    true,
				Destination: &data,
			},
			&cli.BoolFlag{
				Name:        "encrypt",
				Aliases:     []string{"e"},
				Value:       false,
				Usage:       "If true encrypt the data",
				Destination: &shouldEncrypt,
			},
			&cli.BoolFlag{
				Name:        "encrypt-with-nonce",
				Aliases:     []string{"n", "nonce"},
				Value:       false,
				Usage:       "If true a nonce parameter will be added to the data passed in",
				Destination: &withNonceParameter,
			},
		},
		Action: func(c *cli.Context) error {
			if len(key) != 16 && len(key) != 32 {
				return errors.New("key should be either 16 or 32 bytes long")
			}

			wrapper, err := aes.New([]byte(key), aes.WithNonce(withNonceParameter))
			if err != nil {
				return err
			}

			if shouldEncrypt {
				eData, err := wrapper.Encrypt([]byte(data))
				if err != nil {
					return err
				}
				fmt.Printf("\n\nEncrypted data: %s\n\n", eData)
				return nil
			}

			dData, nonce, err := wrapper.Decrypt(data)
			if err != nil {
				return err
			}
			fmt.Printf("\n\nDecrytped data: %s\nNonce:%s\n", dData, nonce)
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
