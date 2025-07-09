// Copyright 2025 protean Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hmqv

import (
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"hash"
	"io"
	"sync"

	"filippo.io/edwards25519"
)

var zeroPoint, _ = new(edwards25519.Point).SetBytes(
	[]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
)

var errInvalidHMQVSigma = errors.New("crypto/hmqv: sigma is a low order point")

type PrivateKey struct {
	once sync.Once

	s  *edwards25519.Scalar
	pk *edwards25519.Point
}

type PublicKey struct {
	*edwards25519.Point
}

func NewPublicKey(b []byte) (*PublicKey, error) {
	pk, err := new(edwards25519.Point).SetBytes(b)
	if err != nil {
		return nil, err
	}
	return &PublicKey{pk}, nil
}

func NewPrivateKey(sk ed25519.PrivateKey) (*PrivateKey, error) {
	return newPrivateKey(func(h hash.Hash) {
		h.Write(sk.Seed())
	})
}

func newPrivateKey(writer func(h hash.Hash)) (*PrivateKey, error) {
	hs := sha512.New()
	writer(hs)
	h := hs.Sum(make([]byte, 0, sha512.Size))
	s, err := new(edwards25519.Scalar).SetBytesWithClamping(h[:32])
	if err != nil {
		return nil, err
	}

	return &PrivateKey{s: s}, nil
}

func (sk *PrivateKey) PublicKey() *PublicKey {
	sk.once.Do(func() {
		sk.pk = new(edwards25519.Point).ScalarBaseMult(sk.s)
	})

	return &PublicKey{&*sk.pk}
}

type HMQV struct {
	senderID   []byte
	receiverID []byte
}

func New(senderID []byte, receiverID []byte) *HMQV {
	return &HMQV{
		senderID:   senderID,
		receiverID: receiverID,
	}
}

type SenderOnePassAgreement struct {
	Sigma *edwards25519.Point // A^z^f
	Epk   *PublicKey          // Y = g^y

	z *edwards25519.Scalar // z = y + be
}

func (mqv *HMQV) SenderOnePassAgree(
	rand io.Reader,
	senderSK *PrivateKey,
	receiverPK *PublicKey,
) (*SenderOnePassAgreement, error) {
	var seed [32]byte
	_, err := io.ReadFull(rand, seed[:])
	if err != nil {
		return nil, err
	}

	y, err := newPrivateKey(func(h hash.Hash) { h.Write(seed[:]) })
	if err != nil {
		return nil, err
	}

	Y := y.PublicKey()

	e, err := newPrivateKey(func(h hash.Hash) {
		h.Write(Y.Bytes())
		h.Write(mqv.receiverID)
		h.Write(mqv.senderID)
	})
	if err != nil {
		return nil, err
	}

	z := new(edwards25519.Scalar).MultiplyAdd(senderSK.s, e.s, y.s)

	sigma := new(edwards25519.Point).Set(receiverPK.Point) // A
	sigma.ScalarMult(z, sigma)                             // A^(y+be)
	sigma.MultByCofactor(sigma)                            // A^(y+be)^f

	if sigma.Equal(zeroPoint) > 0 {
		return nil, errors.New("invalid sigma")
	}

	return &SenderOnePassAgreement{
		z:     z,
		Sigma: sigma,
		Epk:   Y,
	}, nil
}

type SenderTwoPassAgreement struct {
	Sigma *edwards25519.Point
}

func (mqv *HMQV) SenderTwoPassAgree(epk *PublicKey, o *SenderOnePassAgreement) (*SenderTwoPassAgreement, error) {
	X := epk.Point
	sigma := new(edwards25519.Point).Set(X)
	sigma.ScalarMult(o.z, X) // X^z
	sigma.MultByCofactor(sigma)

	d, err := newPrivateKey(func(h hash.Hash) {
		h.Write(X.Bytes())
		h.Write(mqv.receiverID)
		h.Write(mqv.senderID)
	})
	if err != nil {
		return nil, err
	}

	sigma.Add(sigma, new(edwards25519.Point).ScalarMult(d.s, o.Sigma)) // X^z + Sigma^d
	if sigma.Equal(zeroPoint) > 0 {
		return nil, errInvalidHMQVSigma
	}

	return &SenderTwoPassAgreement{
		Sigma: sigma,
	}, nil
}

type ReceiverOnePassAgreement struct {
	Sigma *edwards25519.Point // (YB^e)^a^f
	ybar  *edwards25519.Point // YB^e
}

func (mqv *HMQV) ReceiverOnePassAgree(
	epk *PublicKey,
	receiverSK *PrivateKey,
	senderPK *PublicKey,
) (*ReceiverOnePassAgreement, error) {
	Y := epk.Point

	e, err := newPrivateKey(func(h hash.Hash) {
		h.Write(Y.Bytes())
		h.Write(mqv.receiverID)
		h.Write(mqv.senderID)
	})
	if err != nil {
		return nil, errInvalidHMQVSigma
	}

	sigma := new(edwards25519.Point).Set(senderPK.Point) // B
	sigma.ScalarMult(e.s, sigma)                         // B^e
	sigma.Add(sigma, Y)                                  // YB^e
	ybar := new(edwards25519.Point).Set(sigma)           // YB^e
	sigma.ScalarMult(receiverSK.s, sigma)                // (YB^e)^a
	sigma.MultByCofactor(sigma)                          // (YB^e)^a^f
	if sigma.Equal(zeroPoint) > 0 {
		return nil, errInvalidHMQVSigma
	}

	return &ReceiverOnePassAgreement{
		Sigma: sigma,
		ybar:  ybar,
	}, nil
}

type ReceiverTwoPassAgreement struct {
	Sigma *edwards25519.Point
	Epk   *PublicKey
}

func (mqv *HMQV) ReceiverTwoPassAgree(
	rand io.Reader,
	receiverSK *PrivateKey,
	o *ReceiverOnePassAgreement,
) (*ReceiverTwoPassAgreement, error) {
	var seed [32]byte
	_, err := io.ReadFull(rand, seed[:])
	if err != nil {
		return nil, err
	}

	x, err := newPrivateKey(func(h hash.Hash) { h.Write(seed[:]) })
	if err != nil {
		return nil, err
	}

	X := x.PublicKey()

	d, err := newPrivateKey(func(h hash.Hash) {
		h.Write(X.Bytes())
		h.Write(mqv.receiverID)
		h.Write(mqv.senderID)
	})
	if err != nil {
		return nil, err
	}

	z := new(edwards25519.Scalar).MultiplyAdd(receiverSK.s, d.s, x.s)

	sigma := new(edwards25519.Point).Set(o.ybar)
	sigma.ScalarMult(z, sigma)  // (YB^e)^(x + da)
	sigma.MultByCofactor(sigma) // (YB^e)^(x + da)^f

	return &ReceiverTwoPassAgreement{
		Sigma: sigma,
		Epk:   &PublicKey{X.Point},
	}, nil
}
