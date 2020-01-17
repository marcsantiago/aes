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
//BenchmarkWrapper_EncryptWithoutNonce16-12    	  659404	      1800 ns/op	    3968 B/op	       3 allocs/op
//BenchmarkWrapper_EncryptWithoutNonce16-12    	  662394	      1814 ns/op	    3968 B/op	       3 allocs/op
//BenchmarkWrapper_EncryptWithoutNonce16-12    	  676144	      1831 ns/op	    3968 B/op	       3 allocs/op
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
//BenchmarkWrapper_EncryptWithoutNonce32-12    	  647694	      1843 ns/op	    3968 B/op	       3 allocs/op
//BenchmarkWrapper_EncryptWithoutNonce32-12    	  631762	      1823 ns/op	    3968 B/op	       3 allocs/op
//BenchmarkWrapper_EncryptWithoutNonce32-12    	  633357	      1824 ns/op	    3968 B/op	       3 allocs/op
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
//BenchmarkWrapper_EncryptWithNonce16-12       	  579730	      2048 ns/op	    6272 B/op	       4 allocs/op
//BenchmarkWrapper_EncryptWithNonce16-12       	  587854	      2034 ns/op	    6272 B/op	       4 allocs/op
//BenchmarkWrapper_EncryptWithNonce16-12       	  564966	      2043 ns/op	    6272 B/op	       4 allocs/op
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
//BenchmarkWrapper_EncryptWithNonce32-12       	  545180	      2118 ns/op	    6272 B/op	       4 allocs/op
//BenchmarkWrapper_EncryptWithNonce32-12       	  570616	      2116 ns/op	    6272 B/op	       4 allocs/op
//BenchmarkWrapper_EncryptWithNonce32-12       	  553452	      2125 ns/op	    6272 B/op	       4 allocs/op
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
//BenchmarkBasicAESEncrypt16-12                	  528060	      2176 ns/op	    4752 B/op	       9 allocs/op
//BenchmarkBasicAESEncrypt16-12                	  558070	      2137 ns/op	    4752 B/op	       9 allocs/op
//BenchmarkBasicAESEncrypt16-12                	  578755	      2152 ns/op	    4752 B/op	       9 allocs/op
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
//BenchmarkBasicAESEncryptWithoutNonce32-12    	  491658	      2426 ns/op	    4880 B/op	       9 allocs/op
//BenchmarkBasicAESEncryptWithoutNonce32-12    	  502287	      2200 ns/op	    4880 B/op	       9 allocs/op
//BenchmarkBasicAESEncryptWithoutNonce32-12    	  529857	      2202 ns/op	    4880 B/op	       9 allocs/op
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
//BenchmarkBasicAESEncryptWithNonce16-12       	  410562	      2500 ns/op	    7056 B/op	      10 allocs/op
//BenchmarkBasicAESEncryptWithNonce16-12       	  452568	      2513 ns/op	    7056 B/op	      10 allocs/op
//BenchmarkBasicAESEncryptWithNonce16-12       	  457440	      2728 ns/op	    7056 B/op	      10 allocs/op
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
//BenchmarkBasicAESEncryptWithNonce32-12       	  423657	      2608 ns/op	    7184 B/op	      10 allocs/op
//BenchmarkBasicAESEncryptWithNonce32-12       	  463635	      2564 ns/op	    7184 B/op	      10 allocs/op
//BenchmarkBasicAESEncryptWithNonce32-12       	  397566	      2573 ns/op	    7184 B/op	      10 allocs/op
func BenchmarkBasicAESEncryptWithNonce32(b *testing.B) {
	var encryptedData string
	var err error
	_ = encryptedData
	_ = err
	for i := 0; i < b.N; i++ {
		encryptedData, err = _encryptAESWithNonce(_testKey32, _testData)
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
	generateNonce(nonce, gcm.NonceSize())
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
	generateNonce(nonce, gcm.NonceSize())
	data = append(append(data, nonceParamAsBytes...), nonce...)
	return base64.RawURLEncoding.EncodeToString(gcm.Seal(nonce, nonce, data, nil)), nil
}
