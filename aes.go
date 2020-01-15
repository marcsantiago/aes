package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"sync"
)

// Note do not reuse nonce
// https://github.com/miscreant/meta/wiki/Nonce-Reuse-Misuse-Resistance
type Wrapper struct {
	mu    sync.Mutex
	nonce []byte
	gcm   cipher.AEAD
}

var (
	ErrKeyInvalidLength             = errors.New("entered key should have been 32 bytes in length")
	ErrLengthOfDataSmallerThanNonce = errors.New("data is smaller than nonce size")
)

// New returns a wrapped AES implementation designed to reduce the number of
// new AES allocations
func New(key []byte) (Wrapper, error) {
	var w Wrapper
	if len(key) != 32 {
		return w, ErrKeyInvalidLength
	}

	// generate a new aes cipher using our 32 byte long key
	c, err := aes.NewCipher(key)
	if err != nil {
		return w, err
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return w, err
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal
	nonce := make([]byte, gcm.NonceSize())
	return Wrapper{
		gcm:   gcm,
		nonce: nonce,
	}, nil
}

// Encrypt encrypts and returns a URL safe base64 encoded string
func (w Wrapper) Encrypt(data []byte) (string, error) {
	// populates our nonce with a cryptographically secure
	// random sequence
	w.mu.Lock()
	w.nonce = w.nonce[:]
	_, err := io.ReadFull(rand.Reader, w.nonce)
	w.mu.Unlock()
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(w.gcm.Seal(w.nonce, w.nonce, data, nil)), nil
}

// Decrypt decrypts the encrypted the base64 URL encoded string
func (w Wrapper) Decrypt(data string) (string, error) {
	w.mu.Lock()
	w.nonce = w.nonce[:]
	_, err := io.ReadFull(rand.Reader, w.nonce)
	w.mu.Unlock()
	if err != nil {
		return "", err
	}

	nonceSize := w.gcm.NonceSize()
	if len(data) < nonceSize {
		return "", ErrLengthOfDataSmallerThanNonce
	}
	rawData, _ := base64.RawURLEncoding.DecodeString(data)
	nonce, cipherText := rawData[:nonceSize], rawData[nonceSize:]
	plaintext, err := w.gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
