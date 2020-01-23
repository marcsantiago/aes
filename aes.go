package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
)

type WrapperOption func(w *Wrapper)

var (
	ErrKeyInvalidLength             = errors.New("entered key should have been 16 or 32 bytes in length")
	ErrLengthOfDataSmallerThanNonce = errors.New("data is smaller than nonce size")
)

var (
	nonceParamAsBytes = []byte("&nonce=")
)

const (
	// NonceURLParameter is the url parameter used if the nonce is being stored with the encrypted URL data
	NonceURLParameter = "nonce"
)

// Note do not reuse nonce
// https://github.com/miscreant/meta/wiki/Nonce-Reuse-Misuse-Resistance
type Wrapper struct {
	mu    sync.Mutex
	nonce []byte
	gcm   cipher.AEAD

	// indicates that the generated nonce should be stored in the URL as a parameter before encoding
	// this is useful to check against at the decode level to check for replay attacks
	StoreNonce bool
}

// New returns a wrapped AES implementation designed to reduce the number of
// new AES allocations
func New(key []byte, options ...WrapperOption) (*Wrapper, error) {
	if len(key) != 16 && len(key) != 32 {
		return nil, ErrKeyInvalidLength
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	w := new(Wrapper)
	for _, option := range options {
		option(w)
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal
	w.gcm = gcm
	w.nonce = make([]byte, gcm.NonceSize())
	return w, nil
}

// Encrypt encrypts and returns a URL safe base64 encoded string
func (w *Wrapper) Encrypt(data []byte) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.nonce = w.nonce[:]
	generateNonce(w.nonce)
	if w.StoreNonce {
		data = append(append(data, nonceParamAsBytes...), w.nonce...)
	}

	return base64.RawURLEncoding.EncodeToString(w.gcm.Seal(w.nonce, w.nonce, data, nil)), nil
}

// Decrypt decrypts the encrypted the base64 URL encoded string and also returns the nonce to check against replay attacks
// this assumes that the encrypted data stored the nonce as well
func (w *Wrapper) Decrypt(data string) (string, string, error) {
	rawData, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return "", "", err
	}

	nonceSize := w.gcm.NonceSize()
	if len(rawData) < nonceSize {
		return "", "", ErrLengthOfDataSmallerThanNonce
	}

	nonce, cipherText := rawData[:nonceSize], rawData[nonceSize:]
	plaintext, err := w.gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", "", err
	}
	return string(plaintext), string(nonce), nil
}

// WithNonce indicates that the encryption nonce should be stored with the encrypted URL data as a parameter
func WithNonce(b bool) WrapperOption {
	return func(w *Wrapper) {
		w.StoreNonce = b
	}
}

func generateNonce(nonce []byte) error {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	_, err := rand.Read(nonce)
	if err != nil {
		return err
	}
	for i, b := range nonce {
		nonce[i] = letters[b%byte(len(letters))]
	}
	return nil
}
