// Copyright 2025 protean Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

type fpBox struct {
	hpke.Suite
	kem.Scheme
}

func newFpBox() *fpBox {
	kemID := hpke.KEM_X25519_HKDF_SHA256
	kdfID := hpke.KDF_HKDF_SHA512
	aeadID := hpke.AEAD_AES256GCM
	return &fpBox{
		Suite:  hpke.NewSuite(kemID, kdfID, aeadID),
		Scheme: kemID.Scheme(),
	}
}

func (f *fpBox) encodePublicKey(ctx hpke.Context, pk []byte, info []byte) {
	pkEncodeKeyLabel := append([]byte("h public key obfuscation key"), info...)
	pkEncodeIVLabel := append([]byte("h public key obfuscation iv"), info...)
	encodeKey := ctx.Export(pkEncodeKeyLabel, 32)
	block, _ := aes.NewCipher(encodeKey)
	encodeIV := ctx.Export(pkEncodeIVLabel, uint(block.BlockSize()))
	cipher.NewCTR(block, encodeIV).XORKeyStream(pk, pk)
}
