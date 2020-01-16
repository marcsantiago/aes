package aes

import (
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
