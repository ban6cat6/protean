// Copyright 2025 protean Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hmqv

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOnePassAgreement(t *testing.T) {
	pkA, skA, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	pkB, skB, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	var idA, idB [64]byte
	_, err = io.ReadFull(rand.Reader, idA[:])
	require.Nil(t, err)
	_, err = io.ReadFull(rand.Reader, idB[:])
	require.Nil(t, err)

	a, err := NewPrivateKey(skA)
	require.Nil(t, err)
	A, err := NewPublicKey(pkA)
	require.Nil(t, err)

	b, err := NewPrivateKey(skB)
	require.Nil(t, err)
	B, err := NewPublicKey(pkB)
	require.Nil(t, err)

	mqv := New(idB[:], idA[:])
	txAgreement, err := mqv.SenderOnePassAgree(rand.Reader, b, A)
	require.Nil(t, err)
	rxAgreement, err := mqv.ReceiverOnePassAgree(txAgreement.Epk, a, B)
	require.Nil(t, err)

	require.Equal(t, txAgreement.Sigma.Bytes(), rxAgreement.Sigma.Bytes())
}

func TestTwoPassAgreement(t *testing.T) {
	pkA, skA, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	pkB, skB, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	var idA, idB [64]byte
	_, err = io.ReadFull(rand.Reader, idA[:])
	require.Nil(t, err)
	_, err = io.ReadFull(rand.Reader, idB[:])
	require.Nil(t, err)

	a, err := NewPrivateKey(skA)
	require.Nil(t, err)
	A, err := NewPublicKey(pkA)
	require.Nil(t, err)

	b, err := NewPrivateKey(skB)
	require.Nil(t, err)
	B, err := NewPublicKey(pkB)
	require.Nil(t, err)

	mqv := New(idB[:], idA[:])
	txOnePass, err := mqv.SenderOnePassAgree(rand.Reader, b, A)
	require.Nil(t, err)
	rxOnePass, err := mqv.ReceiverOnePassAgree(txOnePass.Epk, a, B)
	require.Nil(t, err)
	rxTwoPass, err := mqv.ReceiverTwoPassAgree(rand.Reader, a, rxOnePass)
	require.Nil(t, err)
	txTwoPass, err := mqv.SenderTwoPassAgree(rxTwoPass.Epk, txOnePass)
	require.Nil(t, err)
	require.Equal(t, txTwoPass.Sigma.Bytes(), rxTwoPass.Sigma.Bytes())
}
