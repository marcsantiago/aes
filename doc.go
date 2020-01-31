// Package aes is a wrapper around the Go STD lib, which is designed to reduce the number of
// object and nonce allocations for the same key. This is specifically to encode URL parameter data, so the
// returned string is returned using base64.RawURLEncoding.EncodeToString
package aeswrapper
