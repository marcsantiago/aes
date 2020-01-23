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
//BenchmarkWrapper_EncryptWithoutNonce16-12    	  515984	      2258 ns/op	    3968 B/op	       3 allocs/op
//BenchmarkWrapper_EncryptWithoutNonce16-12    	  544808	      2283 ns/op	    3968 B/op	       3 allocs/op
//BenchmarkWrapper_EncryptWithoutNonce16-12    	  514572	      2262 ns/op	    3968 B/op	       3 allocs/op
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
//BenchmarkWrapper_EncryptWithoutNonce32-12    	  495567	      2312 ns/op	    3968 B/op	       3 allocs/op
//BenchmarkWrapper_EncryptWithoutNonce32-12    	  482773	      2341 ns/op	    3968 B/op	       3 allocs/op
//BenchmarkWrapper_EncryptWithoutNonce32-12    	  496579	      2380 ns/op	    3968 B/op	       3 allocs/op
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
//BenchmarkWrapper_EncryptWithNonce16-12       	  456810	      2560 ns/op	    6272 B/op	       4 allocs/op
//BenchmarkWrapper_EncryptWithNonce16-12       	  418422	      2570 ns/op	    6272 B/op	       4 allocs/op
//BenchmarkWrapper_EncryptWithNonce16-12       	  441440	      2609 ns/op	    6272 B/op	       4 allocs/op
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
//BenchmarkWrapper_EncryptWithNonce16Goroutine-12    	  599726	      1680 ns/op	     533 B/op	       2 allocs/op
//BenchmarkWrapper_EncryptWithNonce16Goroutine-12    	 1000000	      1577 ns/op	     637 B/op	       1 allocs/op
//BenchmarkWrapper_EncryptWithNonce16Goroutine-12    	 1000000	      1441 ns/op	     690 B/op	       1 allocs/op
func BenchmarkWrapper_EncryptWithNonce16Goroutine(b *testing.B) {
	w, _ := New(_testKey16, WithNonce(true))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		go func() {
			encryptedData, err := w.Encrypt(_testData)
			_ = encryptedData
			_ = err
		}()
	}
}

//goos: darwin
//goarch: amd64
//pkg: github.com/marcsantiago/aes
//BenchmarkWrapper_EncryptWithNonce32-12       	  439687	      2655 ns/op	    6272 B/op	       4 allocs/op
//BenchmarkWrapper_EncryptWithNonce32-12       	  436164	      2683 ns/op	    6272 B/op	       4 allocs/op
//BenchmarkWrapper_EncryptWithNonce32-12       	  413631	      2780 ns/op	    6272 B/op	       4 allocs/op
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
//BenchmarkWrapper_EncryptWithNonce32Goroutine-12    	  751116	      1674 ns/op	     856 B/op	       2 allocs/op
//BenchmarkWrapper_EncryptWithNonce32Goroutine-12    	 1000000	      1389 ns/op	     935 B/op	       1 allocs/op
//BenchmarkWrapper_EncryptWithNonce32Goroutine-12    	 1000000	      1081 ns/op	     912 B/op	       1 allocs/op
func BenchmarkWrapper_EncryptWithNonce32Goroutine(b *testing.B) {
	w, _ := New(_testKey32, WithNonce(true))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		go func() {
			encryptedData, err := w.Encrypt(_testData)
			_ = encryptedData
			_ = err
		}()
	}
}

//goos: darwin
//goarch: amd64
//pkg: github.com/marcsantiago/aes
//BenchmarkBasicAESEncryptWithoutNonce16-12    	  411014	      2881 ns/op	    4752 B/op	       9 allocs/op
//BenchmarkBasicAESEncryptWithoutNonce16-12    	  430032	      2669 ns/op	    4752 B/op	       9 allocs/op
//BenchmarkBasicAESEncryptWithoutNonce16-12    	  436590	      2674 ns/op	    4752 B/op	       9 allocs/op
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
//BenchmarkBasicAESEncryptWithoutNonce32-12    	  416869	      2923 ns/op	    4880 B/op	       9 allocs/op
//BenchmarkBasicAESEncryptWithoutNonce32-12    	  444645	      2734 ns/op	    4880 B/op	       9 allocs/op
//BenchmarkBasicAESEncryptWithoutNonce32-12    	  429224	      2747 ns/op	    4880 B/op	       9 allocs/op
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
//BenchmarkBasicAESEncryptWithNonce16-12       	  405774	      2985 ns/op	    7056 B/op	      10 allocs/op
//BenchmarkBasicAESEncryptWithNonce16-12       	  380864	      2996 ns/op	    7056 B/op	      10 allocs/op
//BenchmarkBasicAESEncryptWithNonce16-12       	  406407	      2977 ns/op	    7056 B/op	      10 allocs/op
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
//BenchmarkBasicAESEncryptWithNonce32-12       	  381481	      3077 ns/op	    7184 B/op	      10 allocs/op
//BenchmarkBasicAESEncryptWithNonce32-12       	  380097	      3056 ns/op	    7184 B/op	      10 allocs/op
//BenchmarkBasicAESEncryptWithNonce32-12       	  370485	      3051 ns/op	    7184 B/op	      10 allocs/op
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
//BenchmarkWrapper_Decrypt16-12                	  570340	      2137 ns/op	    4624 B/op	       5 allocs/op
//BenchmarkWrapper_Decrypt16-12                	  554976	      2188 ns/op	    4624 B/op	       5 allocs/op
//BenchmarkWrapper_Decrypt16-12                	  541303	      2181 ns/op	    4624 B/op	       5 allocs/op
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
//BenchmarkWrapper_Decrypt32-12                	  515250	      2217 ns/op	    4624 B/op	       5 allocs/op
//BenchmarkWrapper_Decrypt32-12                	  535341	      2220 ns/op	    4624 B/op	       5 allocs/op
//BenchmarkWrapper_Decrypt32-12                	  499502	      2205 ns/op	    4624 B/op	       5 allocs/op
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
//BenchmarkBasicAESDecrypt16-12                	  447777	      2567 ns/op	    5392 B/op	      10 allocs/op
//BenchmarkBasicAESDecrypt16-12                	  458676	      2535 ns/op	    5392 B/op	      10 allocs/op
//BenchmarkBasicAESDecrypt16-12                	  474651	      2517 ns/op	    5392 B/op	      10 allocs/op
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
//BenchmarkBasicAESDecrypt32-12                	  439195	      2597 ns/op	    5520 B/op	      10 allocs/op
//BenchmarkBasicAESDecrypt32-12                	  443320	      2587 ns/op	    5520 B/op	      10 allocs/op
//BenchmarkBasicAESDecrypt32-12                	  431409	      2614 ns/op	    5520 B/op	      10 allocs/op
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
