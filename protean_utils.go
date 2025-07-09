// Copyright 2025 protean Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"

	"github.com/cloudflare/circl/kem"
)

func xKemSKToX25519(key kem.PrivateKey) *ecdh.PrivateKey {
	data, _ := key.MarshalBinary()
	xsk, _ := ecdh.X25519().NewPrivateKey(data)
	return xsk
}

func ed25519SKToX25519(sk ed25519.PrivateKey) []byte {
	h := sha512.New()
	h.Write(sk.Seed())
	s := h.Sum(nil)
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
	return s[:32]
}

func aadFromClientHello(clientHello *clientHelloMsg) []byte {
	aad := make([]byte, 0, 2+len(clientHello.serverName))
	aad, _ = binary.Append(aad, binary.BigEndian, clientHello.vers)
	aad = append(aad, clientHello.serverName...)
	return aad
}
