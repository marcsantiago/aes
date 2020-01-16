package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"math/rand"
	"sync"
	"time"
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
	generateNonce(w.nonce, w.gcm.NonceSize())
	if w.StoreNonce {
		data = append(append(data, nonceParamAsBytes...), w.nonce...)
	}

	return base64.RawURLEncoding.EncodeToString(w.gcm.Seal(w.nonce, w.nonce, data, nil)), nil
}

// Decrypt decrypts the encrypted the base64 URL encoded string and also returns the nonce to check against replay attacks
// this assumes that the encrypted data stored the nonce as well
func (w *Wrapper) Decrypt(data string) (string, string, error) {
	nonceSize := w.gcm.NonceSize()
	if len(data) < nonceSize {
		return "", "", ErrLengthOfDataSmallerThanNonce
	}

	rawData, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return "", "", err
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

var src = rand.NewSource(time.Now().UnixNano())

const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func generateNonce(nonce []byte, n int) {
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			nonce[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return
}
