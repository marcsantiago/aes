package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"net/url"
	"testing"
)

var (
	_testKey32 = []byte("passphrasewhichneedstobe32bytes!")
	_testKey16 = []byte("I@Wu4*g68EJFoOEJ")
)

func TestWrapper_EncryptDecryptWithoutNonce(t *testing.T) {
	type args struct {
		key  []byte
		data []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "should encrypt and decrypt without issue 32 bit key",
			args: args{
				key:  _testKey32,
				data: []byte("hello world"),
			},
			want: "hello world",
		},
		{
			args: args{
				key:  _testKey32,
				data: []byte("hello world"),
			},
			want: "hello world",
		},
		{
			name: "should encrypt and decrypt without issue 16 bit key",
			args: args{
				key:  _testKey16,
				data: []byte("hello world"),
			},
			want: "hello world",
		},
		{
			args: args{
				key:  _testKey16,
				data: []byte("hello world"),
			},
			want: "hello world",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := New(tt.args.key)
			if err != nil {
				t.Fatal(err)
			}

			encryptedData, err := w.Encrypt(tt.args.data)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			plainText, _, err := w.Decrypt(encryptedData)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			if plainText != tt.want {
				t.Errorf("Decrypt() got = %v, want %v", plainText, tt.want)
			}
		})
	}
}

func TestWrapper_EncryptDecryptWithNonce(t *testing.T) {
	type args struct {
		key  []byte
		data []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "should encrypt and decrypt without issue and nonce values should be the same",
			args: args{
				key:  _testKey32,
				data: []byte("https://helloworld.com?"),
			},
			want: "helloworld.com",
		},
		{
			args: args{
				key:  _testKey32,
				data: []byte("https://helloworld.com?"),
			},
			want: "helloworld.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := New(tt.args.key, WithNonce(true))
			if err != nil {
				t.Fatal(err)
			}

			encryptedData, err := w.Encrypt(tt.args.data)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			plainText, nonce, err := w.Decrypt(encryptedData)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			urlData, err := url.Parse(plainText)
			if err != nil {
				t.Fatalf(" url.Parse() error = %v", err)
			}

			if urlData.Host != tt.want {
				t.Fatalf("Decrypt() got = %v, want %v", urlData.Host, tt.want)
			}

			values := urlData.Query()
			gotNonce := values.Get(NonceURLParameter)
			if nonce != gotNonce {
				t.Fatalf("gotNonce got = %v, want %v", gotNonce, nonce)
			}
		})
	}
}

var _testData = []byte("https://foo.bar?foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar&foo=bar")

//goos: darwin
//goarch: amd64
//pkg: github.com/marcsantiago/aes
//BenchmarkWrapper_EncryptWithoutNonce16-12    	  666382	      1752 ns/op	    3968 B/op	       3 allocs/op
//BenchmarkWrapper_EncryptWithoutNonce16-12    	  672789	      1776 ns/op	    3968 B/op	       3 allocs/op
//BenchmarkWrapper_EncryptWithoutNonce16-12    	  656556	      1769 ns/op	    3968 B/op	       3 allocs/op
func BenchmarkWrapper_EncryptWithoutNonce16(b *testing.B) {
	var encryptedData string
	var err error
	_ = encryptedData
	_ = err
	w, _ := New(_testKey16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encryptedData, err = w.Encrypt(_testData)
	}
}

//goos: darwin
//goarch: amd64
//pkg: github.com/marcsantiago/aes
//BenchmarkWrapper_EncryptWithoutNonce32-12    	  633075	      1874 ns/op	    3968 B/op	       3 allocs/op
//BenchmarkWrapper_EncryptWithoutNonce32-12    	  653932	      1896 ns/op	    3968 B/op	       3 allocs/op
//BenchmarkWrapper_EncryptWithoutNonce32-12    	  650206	      1849 ns/op	    3968 B/op	       3 allocs/op
func BenchmarkWrapper_EncryptWithoutNonce32(b *testing.B) {
	var encryptedData string
	var err error
	_ = encryptedData
	_ = err
	w, _ := New(_testKey32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encryptedData, err = w.Encrypt(_testData)
	}
}

//goos: darwin
//goarch: amd64
//pkg: github.com/marcsantiago/aes
//BenchmarkWrapper_EncryptWithNonce16-12       	  554881	      2133 ns/op	    6272 B/op	       4 allocs/op
//BenchmarkWrapper_EncryptWithNonce16-12       	  558675	      2075 ns/op	    6272 B/op	       4 allocs/op
//BenchmarkWrapper_EncryptWithNonce16-12       	  543390	      2087 ns/op	    6272 B/op	       4 allocs/op
func BenchmarkWrapper_EncryptWithNonce16(b *testing.B) {
	var encryptedData string
	var err error
	_ = encryptedData
	_ = err
	w, _ := New(_testKey16, WithNonce(true))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encryptedData, err = w.Encrypt(_testData)
	}
}

//goos: darwin
//goarch: amd64
//pkg: github.com/marcsantiago/aes
//BenchmarkWrapper_EncryptWithNonce32-12       	  532650	      2289 ns/op	    6272 B/op	       4 allocs/op
//BenchmarkWrapper_EncryptWithNonce32-12       	  466364	      2360 ns/op	    6272 B/op	       4 allocs/op
//BenchmarkWrapper_EncryptWithNonce32-12       	  545844	      2144 ns/op	    6272 B/op	       4 allocs/op
func BenchmarkWrapper_EncryptWithNonce32(b *testing.B) {
	var encryptedData string
	var err error
	_ = encryptedData
	_ = err
	w, _ := New(_testKey32, WithNonce(true))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encryptedData, err = w.Encrypt(_testData)
	}
}

//goos: darwin
//goarch: amd64
//pkg: github.com/marcsantiago/aes
//BenchmarkBasicAESEncryptWithoutNonce16-12    	  549015	      2112 ns/op	    4752 B/op	       9 allocs/op
//BenchmarkBasicAESEncryptWithoutNonce16-12    	  558584	      2072 ns/op	    4752 B/op	       9 allocs/op
//BenchmarkBasicAESEncryptWithoutNonce16-12    	  549009	      2122 ns/op	    4752 B/op	       9 allocs/op
func BenchmarkBasicAESEncryptWithoutNonce16(b *testing.B) {
	var encryptedData string
	var err error
	_ = encryptedData
	_ = err
	for i := 0; i < b.N; i++ {
		encryptedData, err = _encryptAES(_testKey16, _testData)
	}
}

//goos: darwin
//goarch: amd64
//pkg: github.com/marcsantiago/aes
//BenchmarkBasicAESEncryptWithoutNonce32-12    	  524796	      2232 ns/op	    4880 B/op	       9 allocs/op
//BenchmarkBasicAESEncryptWithoutNonce32-12    	  517574	      2198 ns/op	    4880 B/op	       9 allocs/op
//BenchmarkBasicAESEncryptWithoutNonce32-12    	  532609	      2173 ns/op	    4880 B/op	       9 allocs/op
func BenchmarkBasicAESEncryptWithoutNonce32(b *testing.B) {
	var encryptedData string
	var err error
	_ = encryptedData
	_ = err
	for i := 0; i < b.N; i++ {
		encryptedData, err = _encryptAES(_testKey32, _testData)
	}
}

//goos: darwin
//goarch: amd64
//pkg: github.com/marcsantiago/aes
//BenchmarkBasicAESEncryptWithNonce16-12       	  479899	      2449 ns/op	    7056 B/op	      10 allocs/op
//BenchmarkBasicAESEncryptWithNonce16-12       	  463212	      2438 ns/op	    7056 B/op	      10 allocs/op
//BenchmarkBasicAESEncryptWithNonce16-12       	  447985	      2554 ns/op	    7056 B/op	      10 allocs/op
func BenchmarkBasicAESEncryptWithNonce16(b *testing.B) {
	var encryptedData string
	var err error
	_ = encryptedData
	_ = err
	for i := 0; i < b.N; i++ {
		encryptedData, err = _encryptAESWithNonce(_testKey16, _testData)
	}
}

//goos: darwin
//goarch: amd64
//pkg: github.com/marcsantiago/aes
//BenchmarkBasicAESEncryptWithNonce32-12       	  445752	      2594 ns/op	    7184 B/op	      10 allocs/op
//BenchmarkBasicAESEncryptWithNonce32-12       	  440553	      2650 ns/op	    7184 B/op	      10 allocs/op
//BenchmarkBasicAESEncryptWithNonce32-12       	  449634	      2638 ns/op	    7184 B/op	      10 allocs/op
func BenchmarkBasicAESEncryptWithNonce32(b *testing.B) {
	var encryptedData string
	var err error
	_ = encryptedData
	_ = err
	for i := 0; i < b.N; i++ {
		encryptedData, err = _encryptAESWithNonce(_testKey32, _testData)
	}
}

//goos: darwin
//goarch: amd64
//pkg: github.com/marcsantiago/aes
//BenchmarkWrapper_Decrypt16-12    	  539811	      2235 ns/op	    4624 B/op	       5 allocs/op
//BenchmarkWrapper_Decrypt16-12    	  533332	      2234 ns/op	    4624 B/op	       5 allocs/op
//BenchmarkWrapper_Decrypt16-12    	  528891	      2212 ns/op	    4624 B/op	       5 allocs/op
func BenchmarkWrapper_Decrypt16(b *testing.B) {
	var decryptedData, nonce string
	var err error
	_ = decryptedData
	_ = err
	_ = nonce
	w, _ := New(_testKey16)
	encryptedData, _ := w.Encrypt(_testData)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decryptedData, nonce, err = w.Decrypt(encryptedData)
	}
}

//goos: darwin
//goarch: amd64
//pkg: github.com/marcsantiago/aes
//BenchmarkWrapper_Decrypt32-12    	  497193	      2312 ns/op	    4624 B/op	       5 allocs/op
//BenchmarkWrapper_Decrypt32-12    	  452444	      2366 ns/op	    4624 B/op	       5 allocs/op
//BenchmarkWrapper_Decrypt32-12    	  467012	      2355 ns/op	    4624 B/op	       5 allocs/op
func BenchmarkWrapper_Decrypt32(b *testing.B) {
	var decryptedData, nonce string
	var err error
	_ = decryptedData
	_ = err
	_ = nonce
	w, _ := New(_testKey32)
	encryptedData, _ := w.Encrypt(_testData)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decryptedData, nonce, err = w.Decrypt(encryptedData)
	}
}

//goos: darwin
//goarch: amd64
//pkg: github.com/marcsantiago/aes
//BenchmarkBasicAESDecrypt16-12    	  421969	      2594 ns/op	    5392 B/op	      10 allocs/op
//BenchmarkBasicAESDecrypt16-12    	  444854	      2640 ns/op	    5392 B/op	      10 allocs/op
//BenchmarkBasicAESDecrypt16-12    	  442753	      2702 ns/op	    5392 B/op	      10 allocs/op
func BenchmarkBasicAESDecrypt16(b *testing.B) {
	var decryptedData, nonce string
	var err error
	_ = decryptedData
	_ = err
	_ = nonce
	encryptedData, _ := _encryptAES(_testKey16, _testData)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decryptedData, nonce, err = _decryptAES(_testKey16, encryptedData)
	}
}

//goos: darwin
//goarch: amd64
//pkg: github.com/marcsantiago/aes
//BenchmarkBasicAESDecrypt32-12    	  414838	      2896 ns/op	    5520 B/op	      10 allocs/op
//BenchmarkBasicAESDecrypt32-12    	  411270	      2828 ns/op	    5520 B/op	      10 allocs/op
//BenchmarkBasicAESDecrypt32-12    	  427802	      2848 ns/op	    5520 B/op	      10 allocs/op
func BenchmarkBasicAESDecrypt32(b *testing.B) {
	var decryptedData, nonce string
	var err error
	_ = decryptedData
	_ = err
	_ = nonce
	encryptedData, _ := _encryptAES(_testKey32, _testData)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decryptedData, nonce, err = _decryptAES(_testKey32, encryptedData)
	}
}

func _encryptAES(key []byte, data []byte) (string, error) {
	if len(key) != 16 && len(key) != 32 {
		return "", ErrKeyInvalidLength
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	generateNonce(nonce)
	return base64.RawURLEncoding.EncodeToString(gcm.Seal(nonce, nonce, data, nil)), nil
}

func _encryptAESWithNonce(key []byte, data []byte) (string, error) {
	if len(key) != 16 && len(key) != 32 {
		return "", ErrKeyInvalidLength
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	generateNonce(nonce)
	data = append(append(data, nonceParamAsBytes...), nonce...)
	return base64.RawURLEncoding.EncodeToString(gcm.Seal(nonce, nonce, data, nil)), nil
}

func _decryptAES(key []byte, data string) (string, string, error) {
	if len(key) != 16 && len(key) != 32 {
		return "", "", ErrKeyInvalidLength
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", "", ErrLengthOfDataSmallerThanNonce
	}

	rawData, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return "", "", err
	}

	nonce, cipherText := rawData[:nonceSize], rawData[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", "", err
	}
	return string(plaintext), string(nonce), nil
}
